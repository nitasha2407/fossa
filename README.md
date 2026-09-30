# 🕵️ Forensic Screenshot Authentication Tool

> **⚠️ CAUTION:** This tool was completely "vibe-coded" (AI-generated without rigorous manual security audits). Use it at your own risk. It may contain bugs, hallucinated logic, or security flaws. Do not rely on it as the sole source of truth in legal or high-stakes environments without expert verification.

A professional-grade forensic tool for visual screenshot analysis, combining traditional metadata extraction and multimodal LLM anomaly detection.

## Features
- **Chain of Custody**: Automatic MD5 and SHA-256 hash generation for every uploaded file.
- **Metadata Extraction**: Extraction of image format, mode, dimensions, and EXIF data.
- **Deterministic Tool Checks (Stage 1)**: Runs metadata consistency checks, lightweight ELA heuristics, and reports availability of forensic CLI tools (`exiftool`, `c2patool`).
- **Supplemental Tools**: Uses MIME probing (`file`) and OCR (`tesseract`, if installed) to enrich technical inspection.
- **Deterministic Definitions**: Explains what each metric means (`ela_score_percent`, `max_channel_diff`, `coverage_points`) and how to interpret it.
- **Two-Pass LLM Analysis**: Stage 2 first understands screenshot context, then performs element-by-element forensic review.
- **Independent AI Mode**: AI can run independently from deterministic output (default), with optional grounding from Stage 1.
- **Forensic Reporting**: Generates a professional PDF report of all findings for legal or investigative use.

## Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd screenshot-authentication
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
   Open `.env` and add your **Gemini API Key** (Get one for free at [Google AI Studio](https://aistudio.google.com/)).
   Optional: set a model explicitly with `GEMINI_MODEL` (for example `gemini-2.5-flash`).

4. **Run the Application**:
   If you are running this on a remote server, WSL, or a headless environment, you should run Streamlit in headless mode to prevent it from hanging while trying to open a local browser:
   ```bash
   streamlit run app.py --server.headless=true
   ```
   *(Alternatively, you can set `headless = true` in `~/.streamlit/config.toml`)*

## Project Structure
- `app.py`: Main Streamlit UI entry point.
- `src/forensic_utils.py`: Logic for hashing and metadata extraction.
- `src/llm_analysis.py`: Integration with Google Gemini for visual forensic analysis.
- `src/report_gen.py`: Logic for generating PDF forensic reports.
- `requirements.txt`: Project dependencies.

## Forensic Methodology
This tool follows a standard forensic approach:
1. **Preservation**: Immediate hashing ensures the integrity of the original evidence.
2. **Identification**: Metadata extraction identifies the origins and technical properties of the file.
3. **Deterministic Validation**: Local tool-based checks provide reproducible indicators before AI use.
4. **AI Analysis**: Multimodal LLMs provide deeper contextual reasoning on top of deterministic findings.
5. **Presentation**: A structured PDF report summarizes all findings for documentation.
