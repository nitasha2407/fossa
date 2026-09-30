from fpdf import FPDF
from datetime import datetime
import tempfile
import markdown

class ForensicReportPDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 15)
        # Title
        self.cell(0, 10, "Forensic Screenshot Authentication Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "I", 10)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

def _get_html_verdict(forensic_json, tool_results):
    html = []
    html.append("<h2>1. Executive Summary</h2>")
    
    # Deterministic summary
    det_verd = tool_results.get("verdict", "N/A")
    det_color = "#d32f2f" if "Suspicious" in det_verd else "#f57c00" if "warning" in det_verd.lower() else "#388e3c"
    html.append(f"<b>Stage 1 (Deterministic):</b> <font color='{det_color}'>{det_verd}</font><br>")
    
    # AI summary
    if forensic_json:
        fj_verd = forensic_json.get("verdict", "N/A").replace("_", " ").title()
        ai_score = forensic_json.get("authenticity_score", "N/A")
        conf = forensic_json.get("confidence", "N/A").title()
        ai_color = "#d32f2f" if "suspicious" in fj_verd.lower() or "manipulation" in fj_verd.lower() else "#f57c00" if "inconclusive" in fj_verd.lower() else "#388e3c"
        html.append(f"<b>Stage 2 (AI Visual):</b> <font color='{ai_color}'>{fj_verd}</font> (Score: {ai_score}/100, Confidence: {conf})<br>")
        primary = forensic_json.get("primary_evidence")
        if primary:
            html.append(f"<i>Primary Evidence:</i> {primary}<br>")
    else:
        html.append("<b>Stage 2 (AI Visual):</b> Raw analysis generated (structured JSON parse failed).<br>")

    # Thumbnail row will go adjacent to this if we do it in PDF directly, 
    # but HTML doesn't support complex CSS layout in fpdf2 easily. We will draw the image using fpdf methods.
    return "".join(html)

def generate_pdf_report(hashes, metadata, exif_data, llm_findings, output_path, tool_results=None, forensic_json=None, image_obj=None):
    """
    Generates an HTML-styled fpdf2 report containing all deterministic and 
    visual analysis findings, plus artifact thumbnails.
    """
    pdf = ForensicReportPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=11)

    # Temporary files for images
    temp_files = []

    try:
        # Layout: If image is provided, put it top right
        if image_obj:
            # Save thumbnail
            img_copy = image_obj.copy()
            img_copy.thumbnail((200, 200))
            tmp_thumb = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
            img_copy.convert("RGB").save(tmp_thumb.name, format="JPEG")
            tmp_thumb.close()
            temp_files.append(tmp_thumb.name)
            
            # Place image
            pdf.image(tmp_thumb.name, x=140, y=35, w=50)

        # ── Executive Summary ─────────────────────
        pdf.set_font("helvetica", size=11)
        pdf.write_html(_get_html_verdict(forensic_json, tool_results or {}))
        pdf.ln(10)

        # Ensure we don't draw text over the top right thumbnail: 
        # actually fpdf's write_html ignores floats, so let's just make sure Y is past it
        if pdf.get_y() < 100:
            pdf.set_y(100)

        # ── Custody & Metadata ────────────────────
        html_custody = ["<h2>2. Chain of Custody & Metadata</h2>"]
        html_custody.append(f"<b>MD5:</b> <code>{hashes.get('md5')}</code><br>")
        html_custody.append(f"<b>SHA-256:</b> <code>{hashes.get('sha256')}</code><br>")
        html_custody.append("<br>")
        
        for k, v in metadata.items():
            html_custody.append(f"<b>{k}:</b> {str(v)[:80]}<br>")
        pdf.write_html("".join(html_custody))
        pdf.ln(5)

        # ── Stage 1 Deterministic Checks ──────────
        html_stage1 = ["<h2>3. Deterministic Tool Findings</h2>"]
        if tool_results:
            findings = tool_results.get("findings", [])
            warnings = tool_results.get("warnings", [])
            
            if findings:
                html_stage1.append("<b>Key Indicators:</b><ul>")
                for f in findings:
                    html_stage1.append(f"<li><font color='#d32f2f'>{f}</font></li>")
                html_stage1.append("</ul>")
                
            if warnings:
                html_stage1.append("<b>Review Warnings:</b><ul>")
                for w in warnings:
                    html_stage1.append(f"<li><font color='#f57c00'>{w}</font></li>")
                html_stage1.append("</ul>")
                
            html_stage1.append("<b>Metrics:</b><ul>")
            metrics = tool_results.get("metrics", {})
            for k, v in metrics.items():
                if k not in ["ela_per_quality"]:
                    html_stage1.append(f"<li><b>{k}:</b> {v}</li>")
            html_stage1.append("</ul>")

        pdf.write_html("".join(html_stage1))

        # ELA diff map
        if tool_results and "ela_diff_image" in tool_results and tool_results["ela_diff_image"]:
            try:
                # Need to save the diff to disk to embed it
                tmp_diff = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
                tool_results["ela_diff_image"].convert("RGB").save(tmp_diff.name, format="JPEG")
                tmp_diff.close()
                temp_files.append(tmp_diff.name)
                
                pdf.ln(5)
                pdf.set_font("helvetica", "B", 12)
                pdf.cell(0, 10, "Error Level Analysis Diff Map (Amplified)", new_x="LMARGIN", new_y="NEXT")
                pdf.image(tmp_diff.name, w=100)
                pdf.ln(5)
            except Exception as e:
                pdf.write_html(f"<br><i>Failed to embed ELA diff map: {str(e)}</i><br>")


        # ── Stage 2 AI Analysis ───────────────────
        pdf.add_page()
        html_stage2 = ["<h2>4. AI Visual Forensic Analysis</h2>"]

        if forensic_json:
            element_rev = forensic_json.get("element_review", [])
            if element_rev:
                html_stage2.append("<h3>Element-by-Element Review</h3><ul>")
                for el in element_rev:
                    name = el.get("element", "Unknown")
                    obs = el.get("observation", "")
                    integ = el.get("integrity", "uncertain").lower()
                    color = "#d32f2f" if integ in ("tampered", "suspicious") else "#388e3c" if integ == "ok" else "#616161"
                    html_stage2.append(f"<li><b><font color='{color}'>[{integ.upper()}]</font> {name}</b>: {obs}</li>")
                html_stage2.append("</ul>")

            hypothesis = forensic_json.get("reconstruction_hypothesis")
            if hypothesis and str(hypothesis).lower() not in ("none", "null", "not applicable", ""):
                html_stage2.append(f"<h3>Reconstruction Hypothesis</h3><p><font color='#d32f2f'>{hypothesis}</font></p>")

            limitations = forensic_json.get("limitations")
            if limitations:
                html_stage2.append(f"<h3>Limitations</h3><p><i>{limitations}</i></p>")

            next_steps = forensic_json.get("next_steps_for_authenticity", [])
            if next_steps:
                html_stage2.append("<h3>Next Steps For Authentication</h3><ul>")
                for step in next_steps:
                    html_stage2.append(f"<li>{step}</li>")
                html_stage2.append("</ul>")
                
            pdf.write_html("".join(html_stage2))
        else:
            # Fallback to markdown -> html
            try:
                import re
                # Strip emojis from raw LLM findings before rendering to avoid latin-1 crashes
                safe_findings = re.sub(r'[^\x00-\x7F]+', '', llm_findings)
                raw_html = markdown.markdown(safe_findings)
                pdf.write_html("".join(html_stage2) + raw_html)
            except Exception as e:
                pdf.multi_cell(0, 5, llm_findings.encode("ascii", "ignore").decode("ascii"))
        
        pdf.output(output_path)

    finally:
        import os
        for tf in temp_files:
            if os.path.exists(tf):
                try:
                    os.unlink(tf)
                except:
                    pass

    return output_path
