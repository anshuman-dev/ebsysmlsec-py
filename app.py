"""
EBSysMLSec-Py: LLM-Assisted HAZOP Threat Analyzer
Gradio demo for Hugging Face Spaces.

Demonstrates the AI-assisted HAZOP step from:
  Poorhadi & Troubitsyna (IMBSA 2022, RSSRail 2023, SAFECOMP 2024)

Users describe any safety-critical system and receive a structured
HAZOP threat analysis — the formal safety-security interaction analysis
that feeds into Event-B modelling.
"""

import json
import os
from pathlib import Path

import gradio as gr
import pandas as pd

from hazop.hazop_analyzer import analyze_system, INSULIN_PUMP_MODEL

# ── Pre-loaded threats (cached from the insulin pump analysis) ──────────────

PRELOADED_THREATS_PATH = Path("hazop/threats.json")


def _load_preloaded() -> list[dict]:
    if PRELOADED_THREATS_PATH.exists():
        return json.loads(PRELOADED_THREATS_PATH.read_text(encoding="utf-8"))
    return []


def _threats_to_df(threats: list[dict]) -> pd.DataFrame:
    if not threats:
        return pd.DataFrame()
    rows = []
    for t in threats:
        rows.append({
            "ID":               t.get("id", ""),
            "Component":        t.get("component", ""),
            "Flow":             t.get("flow", ""),
            "Guide Word":       t.get("guide_word", ""),
            "Deviation":        t.get("deviation", ""),
            "Consequence":      t.get("consequence", ""),
            "Attack Vector":    t.get("attack_vector", ""),
            "Violated Invariant": t.get("violated_invariant", "none"),
            "Severity":         t.get("severity", ""),
            "Event-B Event":    t.get("event_b_attack_event", "none"),
            "Attack Machine":   t.get("attack_machine", "none"),
        })
    return pd.DataFrame(rows)


def _severity_summary(threats: list[dict]) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in threats:
        sev = t.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    parts = [f"**{k.upper()}**: {v}" for k, v in counts.items() if v > 0]
    return f"Total threats: **{len(threats)}** — " + " | ".join(parts)


# ── Default system description (shown on load) ───────────────────────────────

DEFAULT_SYSTEM = """\
System: Autonomous Insulin Pump Controller

Components:
- GlucoseSensor: reads blood glucose level; states: IDLE, MEASURING, TRANSMITTING, ERROR
- DoseCalculator [AttackSurface]: computes insulin dose; states: WAITING, COMPUTING, DONE, ERROR
- SafetyMonitor: validates dose against safety bounds; states: MONITORING, CHECKING, APPROVED, REJECTED
- PumpActuator: delivers insulin; states: IDLE, PRIMING, DELIVERING, DONE
- NetworkInterface [AttackSurface]: external communication; states: IDLE, RECEIVING, TRANSMITTING
- PatientProfile: stores patient parameters (MAX_SAFE_DOSE=50, HYPO_THRESHOLD=70, MIN_BATTERY=10)

Information Flows:
- F1: GlucoseSensor → DoseCalculator  (GlucoseReading)
- F2: PatientProfile → DoseCalculator (PatientParams)
- F3: DoseCalculator → SafetyMonitor  (DoseRequest)
- F4: SafetyMonitor → PumpActuator    (DoseCommand)
- F5: NetworkInterface → DoseCalculator (ExternalCmd)  [ATTACK SURFACE FLOW]

Safety Invariants (Event-B):
- INV1: delivered_dose ≤ MAX_SAFE_DOSE
- INV2: delivered_dose > 0 ⇒ glucose_reading ≥ HYPO_THRESHOLD
- INV3: delivered_dose > 0 ⇒ battery_level ≥ MIN_BATTERY_LEVEL
- INV4: delivered_dose > 0 ⇒ command_approved = TRUE
- INV5: dose_request ≤ MAX_SAFE_DOSE\
"""


def _parse_freetext_model(text: str) -> dict:
    """
    Convert the freetext system description into the model_info dict
    that hazop_analyzer.analyze_system() expects.
    """
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]

    name = "System"
    components, flows, invariants = [], [], []
    section = None

    for line in lines:
        if line.startswith("System:"):
            name = line.replace("System:", "").strip()
        elif line.lower().startswith("component"):
            section = "components"
        elif line.lower().startswith("information flow") or line.lower().startswith("flow"):
            section = "flows"
        elif line.lower().startswith("safety invariant"):
            section = "invariants"
        elif line.startswith("-"):
            item = line[1:].strip()
            if section == "components":
                is_attack = "[AttackSurface]" in item or "[attacksurface]" in item.lower()
                comp_name = item.split(":")[0].replace("[AttackSurface]", "").strip()
                desc = item.split(":", 1)[1].strip() if ":" in item else ""
                components.append({"name": comp_name, "is_attack_surface": is_attack, "description": desc})
            elif section == "flows":
                # Try to parse "F1: A → B (Signal)" or "A → B via Signal"
                parts = item.split(":", 1)
                flow_id = parts[0].strip() if len(parts) > 1 else f"F{len(flows)+1}"
                rest = parts[1].strip() if len(parts) > 1 else item
                is_attack = "[ATTACK" in rest.upper()
                rest_clean = rest.split("[")[0].strip()
                if "→" in rest_clean:
                    src_dst, *sig_parts = rest_clean.split("(")
                    src, dst = src_dst.split("→")
                    signal = sig_parts[0].rstrip(")").strip() if sig_parts else "Data"
                    flows.append({
                        "id": flow_id,
                        "source": src.strip(),
                        "target": dst.strip(),
                        "signal": signal,
                        "flow_type": "attack" if is_attack else "normal",
                    })
            elif section == "invariants":
                if ":" in item:
                    inv_name, inv_text = item.split(":", 1)
                    invariants.append({"name": inv_name.strip(), "text": inv_text.strip()})

    return {"name": name, "components": components, "flows": flows, "invariants": invariants}


# ── Gradio callbacks ──────────────────────────────────────────────────────────

def run_hazop_analysis(system_text: str, use_preloaded: bool):
    """Main callback: run HAZOP and return (DataFrame, summary, JSON)."""
    if use_preloaded:
        threats = _load_preloaded()
        source_note = "Pre-generated threats from the insulin pump analysis (no API call made)."
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return (
                pd.DataFrame(),
                "⚠️ Set the ANTHROPIC_API_KEY environment variable to run live analysis.",
                "",
            )
        model_info = _parse_freetext_model(system_text)
        try:
            threats = analyze_system(model_info)
        except Exception as e:
            return pd.DataFrame(), f"Error: {e}", ""
        source_note = f"Live LLM analysis ({len(threats)} threats generated)."

    df      = _threats_to_df(threats)
    summary = _severity_summary(threats) + f"\n\n*{source_note}*"
    raw_json = json.dumps(threats, indent=2, ensure_ascii=False)
    return df, summary, raw_json


# ── Layout ────────────────────────────────────────────────────────────────────

with gr.Blocks(
    title="EBSysMLSec-Py — LLM HAZOP Analyzer",
    theme=gr.themes.Soft(),
) as demo:

    gr.Markdown("""
# EBSysMLSec-Py: LLM-Assisted HAZOP Threat Analyzer

Reproduces and extends the safety-security interaction analysis methodology of
**Poorhadi & Troubitsyna** (IMBSA 2022 · RSSRail 2023 · SAFECOMP 2024).

**What this does:** Applies the seven HAZOP guide words (NO, MORE, LESS, AS WELL AS, PART OF, REVERSE, OTHER THAN)
to each information flow in your SysML model, producing structured threat scenarios that feed directly
into Event-B formal verification (the `ATK_*` events in the `.bum` files).

**Full repo:** `sysml/` → `translator/` → `eventb/` → `verification/` — see the GitHub repository.
""")

    with gr.Row():
        with gr.Column(scale=1):
            system_input = gr.Textbox(
                label="System Description",
                info="Describe your system: components, information flows, safety invariants",
                value=DEFAULT_SYSTEM,
                lines=22,
                max_lines=40,
            )
            use_preloaded = gr.Checkbox(
                label="Use pre-generated results (no API key needed)",
                value=True,
            )
            analyze_btn = gr.Button("Run HAZOP Analysis", variant="primary", size="lg")

        with gr.Column(scale=2):
            summary_md = gr.Markdown("*Run the analysis to see results.*")
            threats_df = gr.Dataframe(
                label="HAZOP Threat Table",
                wrap=True,
                interactive=False,
            )

    with gr.Accordion("Raw JSON output", open=False):
        json_out = gr.Code(language="json", label="threats.json")

    gr.Markdown("""
---
### How results connect to the formal model

| HAZOP threat | Event-B artifact |
|---|---|
| `T-001` (MORE on F1) | `ATK_SpoofGlucoseReading` in `Attack_Spoofing.bum` → INV2 fails |
| `T-009` (OTHER THAN on F4) | `ATK_InjectDeliveryCommand` in `Attack_Injection.bum` → INV4 fails |
| `T-013` (OTHER THAN on F5) | `ATK_ReplayHighDoseCommand` in `Attack_Replay.bum` → INV1 fails |

Each failing proof obligation in Rodin corresponds to a row in this table where **Violated Invariant ≠ none**.

### Reference
Poorhadi, E., Troubitsyna, E., Dán, G. (2024). *Automating an Integrated Model-Driven Approach to Analysing the Impact of Cyberattacks on Safety.* SAFECOMP 2024. DOI: 10.1007/978-3-031-68738-9_5
""")

    analyze_btn.click(
        fn=run_hazop_analysis,
        inputs=[system_input, use_preloaded],
        outputs=[threats_df, summary_md, json_out],
    )

    demo.load(
        fn=lambda: run_hazop_analysis(DEFAULT_SYSTEM, True),
        outputs=[threats_df, summary_md, json_out],
    )


if __name__ == "__main__":
    demo.launch()
