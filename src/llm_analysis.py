import google.generativeai as genai
import os
import json
import re
from PIL import Image
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# Cache model listing to reduce repeated network calls from Streamlit reruns.
_MODEL_CACHE = {"models": [], "timestamp": 0}

def _get_generate_content_models():
    """
    Returns available model names that support generateContent.
    Uses a simple cache to avoid repeated API calls.
    """
    now = datetime.now().timestamp()
    if _MODEL_CACHE["models"] and (now - _MODEL_CACHE["timestamp"] < 3600):
        return _MODEL_CACHE["models"]

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if api_key:
        genai.configure(api_key=api_key)

    try:
        available = []
        for model in genai.list_models():
            methods = getattr(model, "supported_generation_methods", [])
            if "generateContent" in methods:
                name = getattr(model, "name", "")
                if name.startswith("models/"):
                    name = name.split("/", 1)[1]
                if name:
                    available.append(name)

        _MODEL_CACHE["models"] = available
        _MODEL_CACHE["timestamp"] = now
        return available
    except Exception:
        return _MODEL_CACHE["models"] or []


def _resolve_model_name(requested_model=None):
    requested = (requested_model or os.getenv("GEMINI_MODEL", "")).strip()
    available = _get_generate_content_models()

    if requested and requested in available:
        return requested, available

    preferred_defaults = [
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-2.0-flash-001",
        "gemini-2.0-flash-lite",
        "gemini-2.0-flash-lite-001",
        "gemini-1.5-flash-latest",
        "gemini-1.5-pro-latest",
    ]
    for candidate in preferred_defaults:
        if candidate in available:
            return candidate, available

    if available:
        return available[0], available

    return requested or "gemini-2.5-flash", available


def _format_deterministic_context(deterministic_context):
    if not deterministic_context:
        return "No deterministic context provided."

    payload = {
        "verdict": deterministic_context.get("verdict"),
        "coverage_level": deterministic_context.get("coverage_level"),
        "metrics": deterministic_context.get("metrics", {}),
        "findings": deterministic_context.get("findings", []),
        "warnings": deterministic_context.get("warnings", []),
        "info": deterministic_context.get("info", []),
        "external_evidence": deterministic_context.get("external_evidence", {}),
        "definitions": deterministic_context.get("definitions", {}),
    }
    return json.dumps(payload, indent=2, ensure_ascii=True)


def _extract_screen_type(screen_context):
    for line in screen_context.splitlines():
        if line.strip().lower().startswith("screen_type"):
            _, _, value = line.partition(":")
            return value.strip().lower()
    return "other"


def _build_verification_next_steps(screen_type, screen_context):
    context_lower = screen_context.lower()

    is_whatsapp = ("whatsapp" in context_lower) or ("chat" in screen_type)
    is_payment = any(token in screen_type for token in ["payment", "bank"])

    if is_payment:
        return [
            "Request the original transaction record from the sender's banking/UPI app history (not a forwarded image).",
            "Cross-check UPI transaction ID / bank reference in official bank statement or passbook entries.",
            "Match amount, date/time, payer/payee handle, and status with bank or PSP backend logs.",
            "Ask the recipient to verify credit entry in their own bank statement for the same reference ID.",
            "If disputed, escalate through bank/PSP support and obtain an official confirmation ticket/reference.",
        ]

    if is_whatsapp:
        return [
            "Obtain screenshots from both sides of the conversation (sender and recipient devices).",
            "Verify message IDs/timestamps consistency across both devices and exported chat history.",
            "Use WhatsApp 'Export chat' output (without media and with media) to compare textual continuity.",
            "Check linked media metadata and whether the same media hash exists on both devices.",
            "If high-stakes, request forensic extraction from device backups with proper chain-of-custody.",
        ]

    return [
        "Collect the original file from the source device instead of forwarded/compressed copies.",
        "Corroborate claims with independent system-of-record logs (server logs, account history, audit trail).",
        "Compare the same event evidence from at least one counterparty or secondary source.",
        "Preserve hashes of every collected artifact and record acquisition timestamps.",
        "If disputed, perform device-level forensic acquisition under documented chain-of-custody.",
    ]


def _generate_text_with_image(model, prompt, img):
    response = model.generate_content([prompt, img])
    return (response.text or "").strip()


def _extract_json_block(text):
    """
    Extracts a JSON object from a model response that may contain markdown
    fences or surrounding prose.
    """
    # Try ```json ... ``` fence first
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_match:
        candidate = fence_match.group(1)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Try to extract the outermost { ... } block
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_screenshot(
    image_path_or_obj,
    analysis_type="forensic",
    model_name=None,
    deterministic_context=None,
    use_deterministic_context=False,
):
    """
    Analyzes a screenshot using Gemini for visual forensic anomalies.

    Returns a dict with keys:
      - screen_context  (str)  : pass-1 context mapping text
      - forensic_json   (dict) : structured forensic verdict (may be None if parse failed)
      - forensic_raw    (str)  : raw model text from pass-2 (fallback display)
      - next_steps      (list[str])
      - model_used      (str)
      - error           (str|None)
    """
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return {
            "screen_context": "",
            "forensic_json": None,
            "forensic_raw": "Gemini API key not found. Please set 'GEMINI_API_KEY' in your environment.",
            "next_steps": [],
            "model_used": model_name or "",
            "error": "missing_api_key",
        }

    genai.configure(api_key=api_key)
    model_name, available_models = _resolve_model_name(model_name)
    model = genai.GenerativeModel(model_name)

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    deterministic_block = _format_deterministic_context(deterministic_context)

    # ── Pass 1: Context Mapping ──────────────────────────────────────────────
    context_prompt = """
You are analyzing a screenshot. First, identify what this screenshot is about.

Return ONLY these sections:
1) SCREEN_TYPE: (payment receipt/chat/email/bank app/browser/settings/other)
2) PLATFORM_GUESS: (android/ios/web/desktop/unknown) + short reason
3) PURPOSE_SUMMARY: one short paragraph
4) ELEMENT_MAP: bullet list of key visible elements with exact observed text where possible
5) EDIT_SENSITIVE_FIELDS: fields likely edited in fake screenshots (amount, date, txn id, names, status, app label, etc.)
6) UNCERTAINTIES: things not clearly readable
"""

    deterministic_instructions = ""
    if use_deterministic_context:
        deterministic_instructions = f"""
Deterministic Stage-1 evidence (optional context):
```json
{deterministic_block}
```
Use this as supporting context, but still ground claims in visible image evidence.
"""

    # ── Pass 2: Forensic JSON Analysis ──────────────────────────────────────
    forensic_prompt = f"""
You are performing an element-level forensic review of a screenshot.
Analysis time: {current_time}

First-pass screenshot understanding:
{{SCREEN_CONTEXT}}

{deterministic_instructions}

Rules:
1) Work element-by-element from the ELEMENT_MAP.
2) Do not call manipulation solely due to expectations about brand/UI wording.
3) "highly_probable_manipulation" requires multiple direct visual artifacts.
4) If evidence is mixed, use "inconclusive".
5) Mark uncertain points explicitly.

You MUST respond with a single valid JSON object — no prose, no markdown fences.
Schema:
{{
  "verdict": "<likely_authentic | inconclusive | suspicious | highly_probable_manipulation>",
  "authenticity_score": <integer 0-100, 100 = fully authentic>,
  "confidence": "<high | medium | low>",
  "primary_evidence": "<strongest direct evidence or 'None strong'>",
  "element_review": [
    {{
      "element": "<element name>",
      "observation": "<what you see>",
      "integrity": "<ok | suspicious | tampered | uncertain>"
    }}
  ],
  "limitations": "<what cannot be concluded from one screenshot>",
  "reconstruction_hypothesis": "<if suspicious/manipulation, describe how; else null>",
  "next_steps_for_authenticity": ["<step1>", "<step2>"]
}}
"""

    try:
        if isinstance(image_path_or_obj, str):
            img = Image.open(image_path_or_obj)
        else:
            img = image_path_or_obj

        if analysis_type == "content_summary":
            text = _generate_text_with_image(model, context_prompt, img)
            return {
                "screen_context": text,
                "forensic_json": None,
                "forensic_raw": text,
                "next_steps": [],
                "model_used": model_name,
                "error": None,
            }

        screen_context = _generate_text_with_image(model, context_prompt, img)
        screen_type = _extract_screen_type(screen_context)
        playbook_steps = _build_verification_next_steps(screen_type, screen_context)

        phase2_prompt = forensic_prompt.replace("{SCREEN_CONTEXT}", screen_context)
        forensic_raw = _generate_text_with_image(model, phase2_prompt, img)

        forensic_json = _extract_json_block(forensic_raw)

        # Inject playbook steps if model omitted them or parse failed
        if forensic_json is not None:
            if not forensic_json.get("next_steps_for_authenticity"):
                forensic_json["next_steps_for_authenticity"] = playbook_steps
        else:
            # JSON parse failed — keep raw text for fallback rendering
            pass

        return {
            "screen_context": screen_context,
            "forensic_json": forensic_json,
            "forensic_raw": forensic_raw,
            "next_steps": playbook_steps,
            "model_used": model_name,
            "error": None,
        }

    except Exception as e:
        error_text = str(e)
        suffix = (
            f" (Available generateContent models: {', '.join(available_models[:10])})"
            if available_models
            else ""
        )
        return {
            "screen_context": "",
            "forensic_json": None,
            "forensic_raw": f"Error during analysis with model '{model_name}': {error_text}{suffix}",
            "next_steps": [],
            "model_used": model_name,
            "error": error_text,
        }
