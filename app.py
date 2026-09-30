import streamlit as st
from PIL import Image
import os
import io
from src.forensic_utils import calculate_hashes, extract_metadata, run_tool_based_analysis
from src.llm_analysis import analyze_screenshot
from src.report_gen import generate_pdf_report
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ── Session state init ───────────────────────────────────────────────────────
if "analysis_history" not in st.session_state:
    # OrderedDict-style: {md5: {filename, timestamp, verdict, score, tool_results, forensic_json}}
    st.session_state["analysis_history"] = {}

# Page config
st.set_page_config(page_title="Forensic Screenshot Authentication Tool", page_icon="🕵️", layout="wide")

st.title("🕵️ Forensic Screenshot Authentication Tool")
st.markdown("""
    This tool uses a two-stage forensic workflow:
    1. **Deterministic tool checks** (hashes, metadata, ELA heuristics, provenance-tool availability).
    2. **AI visual analysis** (Gemini) after deterministic findings are reviewed.
""")

# Sidebar for configuration
with st.sidebar:
    st.header("Configuration")
    api_key = st.text_input("Gemini API Key", value="", type="password")
    if api_key:
        os.environ["GEMINI_API_KEY"] = api_key

    priority_vision = [
        "gemini-flash-latest",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
    ]

    selected_model = st.selectbox(
        "Select AI model",
        priority_vision,
    )

    st.markdown("### AI Behavior")
    ai_independent_mode = st.checkbox(
        "Run AI independently from deterministic output",
        value=True,
        help="When enabled, AI uses only the screenshot image (plus its own first-pass context mapping).",
    )

    st.info("Get your free API key at [Google AI Studio](https://aistudio.google.com/)")

    # ── Analysis history panel ───────────────────────────────────────────────
    history = st.session_state["analysis_history"]
    if history:
        st.markdown("---")
        st.markdown("### 📁 Session History")
        for md5, entry in reversed(list(history.items())):
            verdict_short = entry.get("verdict", "—")
            score = entry.get("ai_score")
            score_str = f" | AI: {score}/100" if score is not None else ""
            label = f"`{entry['filename'][:22]}` {score_str}"
            with st.expander(label, expanded=False):
                st.caption(f"Analyzed: {entry['timestamp']}")
                st.caption(f"MD5: `{md5[:12]}…`")
                stage1 = entry.get("stage1_verdict", "—")
                if "Suspicious" in stage1:
                    st.error(f"Stage 1: {stage1}")
                elif "No hard failure" in stage1:
                    st.warning(f"Stage 1: {stage1}")
                else:
                    st.success(f"Stage 1: {stage1}")
                if score is not None:
                    st.metric("Authenticity", f"{score}/100")

# Main interface
uploaded_file = st.file_uploader("Upload a Screenshot (PNG, JPG, JPEG)", type=["png", "jpg", "jpeg"])

if uploaded_file is not None:
    # Read file once for hashing and once for PIL
    file_bytes = uploaded_file.getvalue()
    image = Image.open(io.BytesIO(file_bytes))
    hashes_early = calculate_hashes(file_bytes)
    current_md5 = hashes_early["md5"]

    # ── Duplicate detection ──────────────────────────────────────────────────
    if current_md5 in st.session_state["analysis_history"]:
        prev = st.session_state["analysis_history"][current_md5]
        st.info(
            f"ℹ️ This file was already analyzed in this session at **{prev['timestamp']}**. "
            "Results are shown fresh below; see the sidebar for a quick summary."
        )

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("Image Preview")
        st.image(image, use_container_width=True)

    with col2:
        st.subheader("Chain of Custody (Hashes)")
        hashes = calculate_hashes(file_bytes)
        st.code(f"MD5: {hashes['md5']}\nSHA-256: {hashes['sha256']}")

        st.subheader("Metadata Extraction")
        metadata, exif_data = extract_metadata(io.BytesIO(file_bytes))
        st.json(metadata)

        if exif_data:
            with st.expander("Show EXIF Data"):
                st.json(exif_data)
        else:
            st.info("No EXIF data found in this image.")

    st.divider()

    st.subheader("Stage 1: Deterministic Tool Checks")
    tool_results = run_tool_based_analysis(file_bytes, metadata=metadata, exif_data=exif_data)

    verdict = tool_results['verdict']
    score = tool_results['metrics'].get('coverage_points', 0)
    level = tool_results['coverage_level']

    # Use columns for top-level stats
    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Coverage Score",
        f"{score}/100",
        help=tool_results["definitions"].get("coverage_points", "Tool coverage score")
    )
    c2.metric(
        "Coverage Level",
        str(level).capitalize(),
        help="Overall depth of deterministic checks performed."
    )

    with c3:
        st.markdown("**Verdict**")
        if "Suspicious" in verdict:
            st.error(f"{verdict}")
        elif "No hard failure" in verdict:
            st.warning(f"{verdict}")
        else:
            st.success(f"{verdict}")

    st.markdown("---")

    col_find, col_warn = st.columns(2)
    with col_find:
        st.markdown("🚨 **Key Indicators**")
        if tool_results["findings"]:
            for item in tool_results["findings"]:
                st.error(f"- {item}")
        else:
            st.success("None detected")

    with col_warn:
        st.markdown("⚠️ **Review Warnings**")
        if tool_results["warnings"]:
            for item in tool_results["warnings"]:
                st.warning(f"- {item}")
        else:
            st.success("None detected")

    st.markdown("---")

    # ELA Diff visual — shown always so reviewers can spot editing hot-spots.
    ela_diff_img = tool_results.get("ela_diff_image")
    if ela_diff_img is not None:
        ela_col1, ela_col2 = st.columns(2)
        with ela_col1:
            st.markdown("**Original Image**")
            st.image(image, use_container_width=True)
        with ela_col2:
            ela_score = tool_results["metrics"]["ela_score_percent"]
            st.markdown(
                f"**ELA Diff Map** *(amplified 10×, score: {ela_score}%)*  \n"
                "<small>Bright regions indicate stronger recompression artifacts — potential edit hotspots.</small>",
                unsafe_allow_html=True,
            )
            st.image(ela_diff_img, use_container_width=True)

    with st.expander("Deterministic check details"):
        if tool_results["info"]:
            st.markdown("**Notes**")
            for item in tool_results["info"]:
                st.write(f"- {item}")
        st.markdown("**Detailed Metrics**")
        for key, val in tool_results["metrics"].items():
            definition = tool_results["definitions"].get(key, "")
            st.markdown(f"- **{key}**: `{val}`  \n  <small>{definition}</small>", unsafe_allow_html=True)

        st.markdown("**External tool availability**")
        st.json(tool_results["tooling"])
        if tool_results.get("external_evidence"):
            st.markdown("**External tool evidence**")
            st.json(tool_results["external_evidence"])

    st.divider()
    st.subheader("Stage 2: AI Visual Analysis")
    st.caption("AI first maps screenshot context, then performs element-level forensic review.")

    if tool_results["ai_next_step"] == "optional":
        st.info("Stage 1 checks look clean. AI is optional for an additional narrative review.")
    elif tool_results["ai_next_step"] == "recommended":
        st.warning("Stage 1 found indicators/warnings. AI review is recommended next.")

    reviewed_tools = st.checkbox(
        "I reviewed Stage 1 findings and want to run AI analysis",
        key=f"review_tools_{hashes['md5']}",
    )

    if not os.getenv("GEMINI_API_KEY"):
        st.warning("Please provide a Gemini API Key in the sidebar to perform visual analysis.")
    elif not reviewed_tools:
        st.info("Enable the checkbox above after reviewing Stage 1 results to run AI.")
    else:
        if st.button(f"Run Forensic Visual Analysis ({selected_model})"):
            with st.spinner(f"Analyzing with {selected_model}..."):
                result = analyze_screenshot(
                    image,
                    analysis_type="forensic",
                    model_name=selected_model,
                    deterministic_context=tool_results,
                    use_deterministic_context=not ai_independent_mode,
                )

            # ── Screen Context ─────────────────────────────────────────────
            if result["screen_context"]:
                with st.expander("📋 Screenshot Context (Pass 1)", expanded=False):
                    st.markdown(result["screen_context"])

            # ── Structured Verdict ─────────────────────────────────────────
            fj = result.get("forensic_json")
            if fj:
                st.markdown("### 🔍 Forensic Verdict")

                # Verdict badge + score + confidence in one row
                vdict = {
                    "likely_authentic": ("✅ Likely Authentic", "success"),
                    "inconclusive": ("⚠️ Inconclusive", "warning"),
                    "suspicious": ("🚨 Suspicious", "error"),
                    "highly_probable_manipulation": ("🔴 Highly Probable Manipulation", "error"),
                }
                raw_verdict = (fj.get("verdict") or "").lower().replace(" ", "_")
                verdict_label, verdict_type = vdict.get(raw_verdict, (fj.get("verdict", "Unknown"), "info"))
                auth_score = fj.get("authenticity_score", "N/A")
                confidence = fj.get("confidence", "N/A").capitalize()

                v1, v2, v3 = st.columns(3)
                with v1:
                    if verdict_type == "success":
                        st.success(f"**Verdict:** {verdict_label}")
                    elif verdict_type == "warning":
                        st.warning(f"**Verdict:** {verdict_label}")
                    else:
                        st.error(f"**Verdict:** {verdict_label}")
                v2.metric("Authenticity Score", f"{auth_score}/100")
                v3.metric("Confidence", confidence)

                # Primary evidence
                primary = fj.get("primary_evidence")
                if primary:
                    st.info(f"**Primary Evidence:** {primary}")

                # Element-by-element table
                el_review = fj.get("element_review", [])
                if el_review:
                    st.markdown("#### Element-Level Review")
                    integrity_icon = {
                        "ok": "✅",
                        "suspicious": "⚠️",
                        "tampered": "🔴",
                        "uncertain": "❓",
                    }
                    for el in el_review:
                        icon = integrity_icon.get((el.get("integrity") or "uncertain").lower(), "❓")
                        with st.expander(f"{icon} {el.get('element', 'Element')}"):
                            st.write(el.get("observation", ""))

                # Limitations
                limitations = fj.get("limitations")
                if limitations:
                    with st.expander("⚙️ Analysis Limitations"):
                        st.write(limitations)

                # Reconstruction hypothesis
                hypothesis = fj.get("reconstruction_hypothesis")
                if hypothesis and hypothesis not in (None, "null", "Not applicable", ""):
                    with st.expander("🔬 Reconstruction Hypothesis"):
                        st.warning(hypothesis)

                # Next steps
                next_steps = fj.get("next_steps_for_authenticity") or result.get("next_steps", [])
                if next_steps:
                    st.markdown("#### ✅ Next Steps for Authenticity Verification")
                    for i, step in enumerate(next_steps, 1):
                        st.markdown(f"{i}. {step}")

                # Conflict between deterministic baseline and AI
                det_clean = tool_results["verdict"] == "No strong manipulation indicators from deterministic checks"
                ai_bad = raw_verdict in ("suspicious", "highly_probable_manipulation")
                if det_clean and ai_bad:
                    st.warning(
                        "AI verdict conflicts with deterministic baseline. "
                        "Treat this as inconclusive until manually verified."
                    )

            else:
                # JSON parse failed — fall back to raw markdown
                st.markdown("### 🔍 Forensic Analysis (raw)")
                st.markdown(result["forensic_raw"])

            # ── Save to session history ────────────────────────────────────
            from datetime import datetime as _dt
            st.session_state["analysis_history"][hashes["md5"]] = {
                "filename": uploaded_file.name,
                "timestamp": _dt.now().strftime("%H:%M:%S"),
                "stage1_verdict": tool_results["verdict"],
                "ai_score": fj.get("authenticity_score") if fj else None,
            }

            # ── Report generation ──────────────────────────────────────────
            st.subheader("Download Report")
            report_path = "forensic_report.pdf"
            try:
                generate_pdf_report(
                    hashes,
                    metadata,
                    exif_data,
                    result["forensic_raw"],
                    report_path,
                    tool_results=tool_results,
                    forensic_json=fj,
                    image_obj=image,
                )
                with open(report_path, "rb") as f:
                    st.download_button(
                        label="Download PDF Report",
                        data=f,
                        file_name=f"forensic_report_{hashes['md5'][:8]}.pdf",
                        mime="application/pdf"
                    )
            except Exception as e:
                import traceback
                st.error(f"Failed to generate report: {str(e)}\n\n{traceback.format_exc()}")

else:
    st.info("Upload a screenshot to begin analysis.")
