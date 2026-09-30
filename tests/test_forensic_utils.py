import pytest
import io
from PIL import Image, ImageDraw, ExifTags
from src.forensic_utils import (
    calculate_hashes,
    extract_metadata,
    _compute_ela_metrics,
    _compute_noise_inconsistency,
    _compute_edge_density,
    _compute_entropy_metrics
)

def create_dummy_image(color="white", size=(400, 300), format="JPEG", with_exif=False):
    """Creates a basic image in memory for testing."""
    img = Image.new("RGB", size, color=color)
    
    # Add some text/shapes so it's not totally blank (affects entropy/edges)
    draw = ImageDraw.Draw(img)
    draw.rectangle([50, 50, 150, 150], fill="blue")
    draw.text((60, 60), "Hello World", fill="white")
    
    buf = io.BytesIO()
    
    if with_exif:
        # Create minimal EXIF
        exif = img.getexif()
        exif[271] = "TestMaker"  # Make
        exif[305] = "TestSoftware" # Software
        img.save(buf, format=format, exif=exif)
    else:
        img.save(buf, format=format)
        
    buf.seek(0)
    return buf.read()


def test_calculate_hashes():
    data = b"hello forensic world"
    hashes = calculate_hashes(data)
    
    assert "md5" in hashes
    assert "sha256" in hashes
    assert hashes["md5"] == "9bc23cf39f60a7435beb1dfc540c1c22"
    assert hashes["sha256"] == "8382d60bc4b92bde4d3dbecf6959954497cd56e5dfce916da65df3e5127ef3e3"


def test_extract_metadata_no_exif():
    img_bytes = create_dummy_image(format="PNG")
    metadata, exif = extract_metadata(io.BytesIO(img_bytes))
    
    assert metadata["Format"] == "PNG"
    assert metadata["Mode"] in ["RGB", "RGBA", "P"]
    assert metadata["Size (W x H)"] == "400 x 300"
    assert "Extracted At" in metadata
    assert len(exif) == 0


def test_extract_metadata_with_exif():
    img_bytes = create_dummy_image(format="JPEG", with_exif=True)
    metadata, exif = extract_metadata(io.BytesIO(img_bytes))
    
    assert metadata["Format"] == "JPEG"
    assert "Make" in exif or "Software" in exif
    if "Software" in exif:
        assert exif["Software"] == "TestSoftware"


def test_compute_ela_metrics():
    img_bytes = create_dummy_image()
    img = Image.open(io.BytesIO(img_bytes))
    
    metrics = _compute_ela_metrics(img)
    
    assert "ela_score_percent" in metrics
    assert "ela_per_quality" in metrics
    assert "max_channel_diff" in metrics
    assert "ela_diff_image" in metrics
    
    assert isinstance(metrics["ela_score_percent"], float)
    assert len(metrics["ela_per_quality"]) == 4  # 70, 80, 90, 95
    assert metrics["max_channel_diff"] >= 0
    
    # Image object returned
    assert isinstance(metrics["ela_diff_image"], Image.Image)


def test_compute_noise_inconsistency():
    img_bytes = create_dummy_image()
    img = Image.open(io.BytesIO(img_bytes))
    
    metrics = _compute_noise_inconsistency(img, tile_size=16)
    
    assert "noise_std_mean" in metrics
    assert "noise_std_var" in metrics
    assert "noise_inconsistency_flag" in metrics
    
    assert isinstance(metrics["noise_std_mean"], float)
    assert isinstance(metrics["noise_std_var"], float)
    assert isinstance(metrics["noise_inconsistency_flag"], bool)


def test_compute_entropy_metrics():
    img_bytes = create_dummy_image()
    img = Image.open(io.BytesIO(img_bytes))
    
    entropy_score = _compute_entropy_metrics(img)
    assert isinstance(entropy_score, float)
    assert entropy_score > 0.0  # since image is not totally blank


def test_compute_edge_density():
    img_bytes = create_dummy_image()
    img = Image.open(io.BytesIO(img_bytes))
    
    edge_density = _compute_edge_density(img)
    assert isinstance(edge_density, float)
    assert edge_density >= 0.0
