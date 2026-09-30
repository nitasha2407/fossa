import hashlib
from datetime import datetime
import io
import json
import math
import shutil
import subprocess
import tempfile
from PIL import Image
from PIL import ImageChops, ImageFilter, ImageStat
from PIL.ExifTags import TAGS
import numpy as np

DETERMINISTIC_DEFINITIONS = {
    "resolution": "Image width x height in pixels. Very low resolution limits forensic reliability.",
    "ela_score_percent": (
        "Multi-quality ELA score (avg across 4 JPEG levels, 0-100). Lower is generally cleaner; "
        ">=7 suggests review, >=12 suggests stronger recompression/editing indicators."
    ),
    "ela_per_quality": (
        "ELA score broken down per JPEG quality level (70/80/90/95). Consistent scores across levels "
        "indicate uniform compression; sharp spikes at specific levels can narrow down edit history."
    ),
    "max_channel_diff": (
        "Maximum per-channel pixel delta observed in ELA diff image. "
        "Spikes can indicate locally stronger recompression around edited regions."
    ),
    "noise_std_mean": (
        "Mean local noise level (tile std-dev) across the image. "
        "Lower values indicate smoother/flatter images; higher values indicate textured scenes."
    ),
    "noise_std_var": (
        "Variance of local noise levels across tiles. High variance suggests spatially inconsistent "
        "noise — a potential indicator of composited/pasted regions."
    ),
    "coverage_points": (
        "Tool coverage score (0-100). Includes built-in checks plus external tool execution "
        "(ExifTool and c2patool). Higher means broader deterministic coverage, not proof of authenticity."
    ),
    "exiftool": (
        "ExifTool provides detailed metadata extraction and can reveal export/edit software markers."
    ),
    "c2patool": (
        "c2patool inspects C2PA Content Credentials. Verified signatures strengthen provenance claims; "
        "no C2PA claim is common and not automatically suspicious."
    ),
    "entropy_bits_per_channel": (
        "Shannon entropy estimate per color channel (0-8). Very low values indicate flat graphics; "
        "high values indicate textured/noisy scenes."
    ),
    "edge_density_percent": (
        "Approximate proportion of high-gradient pixels from an edge-filtered image. "
        "Useful for context (UI-heavy screenshots usually have moderate edge density)."
    ),
    "file_mime_probe": "MIME type reported by OS `file` command; can catch extension/content mismatches.",
    "ocr_text_preview": "Text extracted with Tesseract OCR (if installed) to assist downstream manual/AI review.",
}

def calculate_hashes(file_bytes):
    """Calculates MD5 and SHA-256 hashes of the file bytes."""
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    return {
        "md5": md5_hash,
        "sha256": sha256_hash
    }

def extract_metadata(image_file):
    """Extracts basic metadata and EXIF data from an image file."""
    try:
        img = Image.open(image_file)
        metadata = {
            "Format": img.format,
            "Mode": img.mode,
            "Size (W x H)": f"{img.width} x {img.height}",
            "Extracted At": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Extract EXIF if available
        exif_data = {}
        info = img._getexif()
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                exif_data[decoded] = str(value)
        
        return metadata, exif_data
    except Exception as e:
        return {"error": f"Failed to extract metadata: {str(e)}"}, {}


# JPEG quality levels used for multi-quality ELA.
_ELA_QUALITY_LEVELS = [70, 80, 90, 95]


def _compute_ela_metrics(image):
    """
    Multi-quality Error Level Analysis (ELA).

    Recompresses the image at 4 JPEG quality levels and measures per-level
    pixel-difference intensity. The reported score is the average across all
    levels; the most visually revealing diff image (highest mean diff) is
    returned for display.
    """
    rgb_image = image.convert("RGB")
    scores = []
    max_diffs = []
    best_diff_img = None
    best_diff_mean = -1.0

    for quality in _ELA_QUALITY_LEVELS:
        buf = io.BytesIO()
        rgb_image.save(buf, format="JPEG", quality=quality)
        buf.seek(0)
        recompressed = Image.open(buf).convert("RGB")

        diff = ImageChops.difference(rgb_image, recompressed)
        stat = ImageStat.Stat(diff)
        mean_diff = sum(stat.mean) / len(stat.mean)
        max_diff = max(ch[1] for ch in stat.extrema)

        scores.append(round((mean_diff / 255.0) * 100.0, 2))
        max_diffs.append(int(max_diff))

        if mean_diff > best_diff_mean:
            best_diff_mean = mean_diff
            # Amplify 10x for visibility
            best_diff_img = diff.point(lambda p: min(p * 10, 255))

    ela_score_percent = round(sum(scores) / len(scores), 2)
    per_quality = dict(zip(_ELA_QUALITY_LEVELS, scores))

    return {
        "ela_score_percent": ela_score_percent,
        "ela_per_quality": per_quality,
        "max_channel_diff": max(max_diffs),
        "ela_diff_image": best_diff_img,
    }


def _compute_noise_inconsistency(image, tile_size=32):
    """
    Estimates noise inconsistency across the image using a high-pass residual.

    In UI screenshots, raw pixel variance is huge due to text edges vs solid backgrounds.
    By subtracting a median-filtered version, we isolate the high-frequency "noise" residual.
    If the block-wise variance of this residual is unusually high, it suggests patchwork editing.
    """
    gray_img = image.convert("L")
    smoothed = gray_img.filter(ImageFilter.MedianFilter(size=3))
    
    gray = np.array(gray_img, dtype=np.float32)
    smooth_arr = np.array(smoothed, dtype=np.float32)
    residual = np.abs(gray - smooth_arr)

    h, w = residual.shape
    stds = []
    for y in range(0, h - tile_size + 1, tile_size):
        for x in range(0, w - tile_size + 1, tile_size):
            tile = residual[y : y + tile_size, x : x + tile_size]
            stds.append(float(np.std(tile)))

    if not stds:
        return {"noise_std_mean": 0.0, "noise_std_var": 0.0, "noise_inconsistency_flag": False}

    std_mean = round(float(np.mean(stds)), 3)
    std_var = round(float(np.var(stds)), 3)
    # Using residual, the variance is drastically lower for clean text edges.
    # Set a robust threshold to avoid false positives on clean screenshots.
    flag = std_var > 250.0
    return {
        "noise_std_mean": std_mean,
        "noise_std_var": std_var,
        "noise_inconsistency_flag": flag,
    }


def _compute_entropy_metrics(image):
    rgb = image.convert("RGB")
    bands = rgb.split()
    entropies = []
    for band in bands:
        hist = band.histogram()
        total = float(sum(hist)) or 1.0
        e = 0.0
        for count in hist:
            if count:
                p = count / total
                e -= p * math.log2(p)
        entropies.append(e)
    return round(sum(entropies) / len(entropies), 3)


def _compute_edge_density(image):
    gray = image.convert("L")
    edges = gray.filter(ImageFilter.FIND_EDGES)
    hist = edges.histogram()
    total = float(sum(hist)) or 1.0
    # Pixels with noticeable edge strength.
    edge_pixels = sum(hist[40:])
    return round((edge_pixels / total) * 100.0, 2)


def _run_exiftool(file_path):
    if not shutil.which("exiftool"):
        return {"status": "not_installed", "summary": "ExifTool unavailable.", "sample_tags": {}}

    try:
        proc = subprocess.run(
            ["exiftool", "-j", "-n", file_path],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
    except Exception as exc:
        return {
            "status": "error",
            "summary": f"ExifTool execution failed: {exc}",
            "sample_tags": {},
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "summary": f"ExifTool returned code {proc.returncode}: {proc.stderr.strip()}",
            "sample_tags": {},
        }

    try:
        parsed = json.loads(proc.stdout) or []
        tags = parsed[0] if parsed and isinstance(parsed[0], dict) else {}
    except Exception as exc:
        return {
            "status": "error",
            "summary": f"ExifTool output parse failed: {exc}",
            "sample_tags": {},
        }

    interesting_keys = [
        "FileType",
        "MIMEType",
        "ImageWidth",
        "ImageHeight",
        "Software",
        "CreatorTool",
        "ModifyDate",
        "CreateDate",
    ]
    sample_tags = {k: tags.get(k) for k in interesting_keys if k in tags}
    return {
        "status": "ok",
        "summary": "ExifTool metadata extracted successfully.",
        "sample_tags": sample_tags,
    }


def _run_c2patool(file_path):
    if not shutil.which("c2patool"):
        return {"status": "not_installed", "summary": "c2patool unavailable.", "excerpt": ""}

    try:
        proc = subprocess.run(
            ["c2patool", file_path],
            capture_output=True,
            text=True,
            timeout=18,
            check=False,
        )
    except Exception as exc:
        return {
            "status": "error",
            "summary": f"c2patool execution failed: {exc}",
            "excerpt": "",
        }

    combined = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    excerpt = "\n".join(line for line in combined.splitlines()[:20]).strip()
    lowered = combined.lower()

    if proc.returncode == 0:
        if "no claim found" in lowered or "no manifest" in lowered:
            return {
                "status": "no_claim",
                "summary": "No C2PA claim found (common for ordinary screenshots).",
                "excerpt": excerpt,
            }
        return {
            "status": "ok",
            "summary": "C2PA claim data parsed successfully.",
            "excerpt": excerpt,
        }

    if "no claim found" in lowered or "no manifest" in lowered:
        return {
            "status": "no_claim",
            "summary": "No C2PA claim found (common for ordinary screenshots).",
            "excerpt": excerpt,
        }

    return {
        "status": "error",
        "summary": f"c2patool returned code {proc.returncode}.",
        "excerpt": excerpt,
    }


def _run_file_mime_probe(file_path):
    if not shutil.which("file"):
        return {"status": "not_installed", "summary": "`file` command unavailable.", "mime_type": ""}
    try:
        proc = subprocess.run(
            ["file", "--brief", "--mime-type", file_path],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except Exception as exc:
        return {"status": "error", "summary": f"`file` probe failed: {exc}", "mime_type": ""}

    mime_type = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return {
            "status": "error",
            "summary": f"`file` returned code {proc.returncode}: {proc.stderr.strip()}",
            "mime_type": mime_type,
        }
    return {"status": "ok", "summary": "MIME probe completed.", "mime_type": mime_type}


def _run_tesseract_ocr(file_path):
    if not shutil.which("tesseract"):
        return {
            "status": "not_installed",
            "summary": "Tesseract OCR unavailable.",
            "char_count": 0,
            "text_preview": "",
        }
    try:
        proc = subprocess.run(
            ["tesseract", file_path, "stdout", "--psm", "6"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        return {
            "status": "error",
            "summary": f"Tesseract execution failed: {exc}",
            "char_count": 0,
            "text_preview": "",
        }

    combined = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return {
            "status": "error",
            "summary": f"Tesseract returned code {proc.returncode}: {(proc.stderr or '').strip()}",
            "char_count": len(combined),
            "text_preview": combined[:800],
        }

    preview = combined[:800]
    if preview:
        return {
            "status": "ok",
            "summary": "OCR text extracted.",
            "char_count": len(combined),
            "text_preview": preview,
        }
    return {
        "status": "ok",
        "summary": "OCR ran but no text was extracted.",
        "char_count": 0,
        "text_preview": "",
    }


def _suffix_for_format(format_name):
    fmt = (format_name or "").upper().strip()
    mapping = {
        "PNG": ".png",
        "JPEG": ".jpg",
        "JPG": ".jpg",
        "WEBP": ".webp",
        "TIFF": ".tiff",
        "BMP": ".bmp",
        "GIF": ".gif",
    }
    return mapping.get(fmt, ".bin")


def run_tool_based_analysis(file_bytes, metadata=None, exif_data=None):
    """
    Runs deterministic forensic checks before AI analysis.
    Returns a structured report with indicators, warnings, and recommendations.
    """
    findings = []
    warnings = []
    info = []

    if metadata is None or exif_data is None:
        metadata, exif_data = extract_metadata(io.BytesIO(file_bytes))

    if isinstance(metadata, dict) and metadata.get("error"):
        return {
            "verdict": "Tool checks failed",
            "ai_next_step": "blocked",
            "findings": [metadata["error"]],
            "warnings": ["Unable to run deterministic checks on this image."],
            "info": [],
            "metrics": {},
            "tooling": {},
            "coverage_level": "none",
            "definitions": DETERMINISTIC_DEFINITIONS,
            "external_evidence": {},
        }

    image = Image.open(io.BytesIO(file_bytes))
    width, height = image.size

    if width < 400 or height < 300:
        warnings.append("Low resolution screenshot; forensic confidence is reduced.")
    else:
        info.append(f"Resolution check passed: {width} x {height}.")

    if "A" in image.getbands():
        info.append("Alpha channel present (common for PNG screenshots).")

    if exif_data:
        info.append("EXIF metadata present.")
        software_tag = exif_data.get("Software") or exif_data.get("ProcessingSoftware") or exif_data.get("Creator Tool")
        if software_tag:
            warnings.append(f"Image contains software processing tag: {software_tag}.")

        dt_original = exif_data.get("DateTimeOriginal")
        dt_modified = exif_data.get("DateTime")
        if dt_original and dt_modified and dt_original != dt_modified:
            warnings.append("EXIF DateTimeOriginal differs from DateTime (possible edit/export cycle).")
    else:
        info.append("No EXIF metadata detected (common for screenshots).")

    ela_metrics = _compute_ela_metrics(image)
    noise_metrics = _compute_noise_inconsistency(image)
    entropy_score = _compute_entropy_metrics(image)
    edge_density = _compute_edge_density(image)
    ela_score = ela_metrics["ela_score_percent"]
    if ela_score >= 12:
        findings.append(f"High ELA score ({ela_score}%). Possible localized recompression or edits.")
    elif ela_score >= 7:
        warnings.append(f"Moderate ELA score ({ela_score}%). Manual review recommended.")
    else:
        info.append(f"Low ELA score ({ela_score}%). No strong recompression anomaly detected.")

    if noise_metrics["noise_inconsistency_flag"]:
        findings.append(
            f"High noise inconsistency detected (var={noise_metrics['noise_std_var']}). "
            "Spatially inconsistent noise patterns may indicate composited regions."
        )
    else:
        info.append(
            f"Noise consistency check passed (var={noise_metrics['noise_std_var']}, "
            f"mean={noise_metrics['noise_std_mean']})."
        )

    tooling = {"exiftool_available": bool(shutil.which("exiftool")), "c2patool_available": bool(shutil.which("c2patool"))}

    temp_suffix = _suffix_for_format(metadata.get("Format") if isinstance(metadata, dict) else None)
    with tempfile.NamedTemporaryFile(suffix=temp_suffix, delete=True) as temp_file:
        temp_file.write(file_bytes)
        temp_file.flush()
        exiftool_result = _run_exiftool(temp_file.name)
        c2pa_result = _run_c2patool(temp_file.name)
        mime_probe = _run_file_mime_probe(temp_file.name)
        ocr_result = _run_tesseract_ocr(temp_file.name)

    external_evidence = {
        "exiftool": exiftool_result,
        "c2patool": c2pa_result,
        "file_mime_probe": mime_probe,
        "ocr": ocr_result,
    }

    declared_format = (metadata.get("Format") or "").upper() if isinstance(metadata, dict) else ""
    mime_type = mime_probe.get("mime_type", "")
    if mime_probe.get("status") == "ok" and declared_format:
        mapping = {
            "PNG": "image/png",
            "JPEG": "image/jpeg",
            "JPG": "image/jpeg",
            "WEBP": "image/webp",
            "TIFF": "image/tiff",
            "GIF": "image/gif",
            "BMP": "image/bmp",
        }
        expected_mime = mapping.get(declared_format)
        if expected_mime and mime_type and expected_mime != mime_type:
            warnings.append(
                f"Metadata format '{declared_format}' does not match MIME probe '{mime_type}'."
            )
    elif mime_probe.get("status") == "error":
        warnings.append("MIME probe failed; file-type validation incomplete.")

    if ocr_result.get("status") == "ok" and ocr_result.get("char_count", 0) > 0:
        info.append(f"OCR extracted {ocr_result['char_count']} characters for review.")

    coverage_points = 40
    if tooling["exiftool_available"]:
        coverage_points += 15
        if exiftool_result["status"] == "ok":
            coverage_points += 15
            editor_hint = exiftool_result["sample_tags"].get("Software") or exiftool_result["sample_tags"].get("CreatorTool")
            if editor_hint:
                warnings.append(f"ExifTool reports editing software marker: {editor_hint}.")
        elif exiftool_result["status"] == "error":
            warnings.append("ExifTool is installed but metadata extraction failed for this file.")
    else:
        warnings.append("ExifTool not found; deep metadata validation unavailable.")

    if tooling["c2patool_available"]:
        coverage_points += 15
        if c2pa_result["status"] in {"ok", "no_claim"}:
            coverage_points += 15
            if c2pa_result["status"] == "ok":
                info.append("C2PA claim data detected by c2patool.")
            else:
                info.append("No C2PA claim found (normal for most screenshots).")
        elif c2pa_result["status"] == "error":
            warnings.append("c2patool is installed but failed to inspect this file.")
    else:
        warnings.append("c2patool not found; signed provenance verification unavailable.")

    if findings:
        verdict = "Suspicious indicators detected by tool-based checks"
        ai_next_step = "recommended"
    elif warnings:
        verdict = "No hard failure, but tool checks found review warnings"
        ai_next_step = "recommended"
    else:
        verdict = "No strong manipulation indicators from deterministic checks"
        ai_next_step = "optional"

    coverage_level = "strong" if coverage_points >= 85 else "basic"

    return {
        "verdict": verdict,
        "ai_next_step": ai_next_step,
        "findings": findings,
        "warnings": warnings,
        "info": info,
        "metrics": {
            "resolution": f"{width} x {height}",
            "ela_score_percent": ela_metrics["ela_score_percent"],
            "ela_per_quality": ela_metrics["ela_per_quality"],
            "max_channel_diff": ela_metrics["max_channel_diff"],
            "noise_std_mean": noise_metrics["noise_std_mean"],
            "noise_std_var": noise_metrics["noise_std_var"],
            "noise_inconsistency_flag": noise_metrics["noise_inconsistency_flag"],
            "entropy_bits_per_channel": entropy_score,
            "edge_density_percent": edge_density,
            "coverage_points": coverage_points,
        },
        "ela_diff_image": ela_metrics["ela_diff_image"],
        "tooling": tooling,
        "coverage_level": coverage_level,
        "definitions": DETERMINISTIC_DEFINITIONS,
        "external_evidence": external_evidence,
    }
