# Architecture

The Forensic Screenshot Authentication Tool is divided into four main logical components that map directly to the files in the repository.

```mermaid
flowchart TD
    %% Define styles
    classDef UI fill:#4B4B4B,stroke:#fff,stroke-width:2px,color:#fff
    classDef Logic fill:#2E7D32,stroke:#fff,stroke-width:2px,color:#fff
    classDef AI fill:#1565C0,stroke:#fff,stroke-width:2px,color:#fff
    classDef External fill:#E65100,stroke:#fff,stroke-width:2px,color:#fff

    %% Nodes
    User([User])
    
    subapp["app.py<br>(Streamlit Frontend)"]
    
    subgraph DetChecks ["src/forensic_utils.py"]
        Hash["MD5 / SHA-256 Hashing"]
        Meta["Metadata & EXIF Extraction"]
        ELA["Error Level Analysis<br>& Noise Inconsistency"]
        SubP["External Tooling<br>ExifTool, c2patool, OCR"]
    end

    subgraph LLMProc ["src/llm_analysis.py"]
        Context["Pass 1: Visual Context Mapping"]
        Verdict["Pass 2: JSON Forensic Verdict"]
        Gemini(("Google Gemini API"))
    end
    
    subgraph RepGen ["src/report_gen.py"]
        PDF["PDF Report Generator<br>(FPDF2)"]
    end

    %% Flow
    User -- Uploads Screenshot --> subapp:::UI
    
    %% Stage 1 Flow
    subapp -- Raw Bytes --> Hash:::Logic
    subapp -- Image Object --> Meta:::Logic
    subapp -- Run Stage 1 --> ELA:::Logic
    subapp -- Run Stage 1 --> SubP:::Logic
    
    Hash -. Duplicate Check .-> SessionState[("Streamlit<br>Session State")]
    
    ELA -- Deterministic Metrics --> subapp
    Meta -- Format/Dates --> subapp
    SubP -. Executes .-> Tools["OS Binaries"]:::External
    SubP -- Tool Findings --> subapp
    
    %% Stage 2 Flow
    subapp -- User triggers AI Review --> Context:::AI
    subapp -- Pass deterministic baseline --> Verdict:::AI
    
    Context -- Extracts Intent --> Gemini:::External
    Context -- Passes mapping --> Verdict
    Verdict -- Requests Element-by-Element Review --> Gemini
    Verdict -- JSON Result & Next Steps --> subapp
    
    %% Reporting Flow
    subapp -- Deterministic + LLM Findings --> PDF:::Logic
    PDF -- Downloadable forensic_report.pdf --> User
```

## Architectural Breakdown

### 1. Frontend Orchestrator (`app.py`)
- Acts as the central coordinator. 
- Uses Streamlit's `session_state` to prevent redundant analysis of the same screenshot by caching previously generated hashes (MD5).
- Manages UI columns, configuration states (like `GEMINI_API_KEY`), and toggles between the deterministic baseline and AI steps.

### 2. Stage 1: Deterministic Engine (`src/forensic_utils.py`)
- Focuses strictly on mathematically reproducible evidence.
- **Internal Checks**: Uses `Pillow` (PIL) and `NumPy` to calculate Error Level Analysis (ELA) scores at various JPEG qualities, track spatial noise inconsistencies (to spot composited elements), and extract Shannon entropy.
- **External Checks**: Spawns non-blocking subprocesses to system binaries (like `exiftool` for metadata, `c2patool` for C2PA provenance credentials, `file` for MIME probing, and `tesseract` for text extraction).

### 3. Stage 2: AI Multi-Modal Engine (`src/llm_analysis.py`)
- Follows a strictly engineered **Two-Pass AI Strategy** using the Google Gemini SDK:
  - **Pass 1 (Context)**: The AI first builds a textual "map" of the image (what type of screen it is, what the key UI elements are, what fields are highly sensitive to forgery).
  - **Pass 2 (Forensics)**: The map is fed back into a rigorous JSON-enforced prompt alongside the deterministic findings from Stage 1 (if the user elected to ground the AI). The model then grades elements individually and enforces an ultimate verdict.

### 4. Reporting Engine (`src/report_gen.py`)
- Aggregates the multi-stage findings.
- Converts the textual/JSON outputs and visual metrics (like the 10x Amplified ELA diff image) into a sanitized, professional PDF using `FPDF2` and HTML rendering.
