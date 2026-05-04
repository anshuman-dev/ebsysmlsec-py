"""
LLM-Assisted HAZOP Threat Analyzer
Extension of the Poorhadi & Troubitsyna methodology.

Original methodology (2022–2024): HAZOP was applied manually to SysML models.
This module automates the HAZOP step using Claude via the Anthropic API.

HAZOP guide words applied to each InformationFlow in the SysML model:
  NO        — the flow is absent (denial of data)
  MORE      — the flow carries a higher value than intended
  LESS      — the flow carries a lower value than intended
  AS WELL AS — additional unintended data accompanies the flow
  PART OF   — only a portion of the intended data is present
  REVERSE   — the flow direction is reversed or source is spoofed
  OTHER THAN — the flow carries entirely different data than expected

Output: list of structured threat objects (JSON), each with:
  - component, flow, guide_word, deviation, consequence,
    attack_vector, violated_invariant, severity, event_b_attack_event
"""

import json
import os
from pathlib import Path

import anthropic

SYSTEM_PROMPT = """You are an expert in formal safety-security analysis for safety-critical embedded systems, applying the HAZOP (Hazard and Operability Study) methodology described in:

  Poorhadi, E., Troubitsyna, E., Dán, G. (2022). Analysing the Impact of Security Attacks on Safety Using SysML and Event-B. IMBSA 2022.
  Poorhadi, E., Troubitsyna, E. (2024). Automating an Integrated Model-Driven Approach to Analysing the Impact of Cyberattacks on Safety. SAFECOMP 2024.

Your task: systematically apply the seven HAZOP guide words to each information flow in a SysML model and produce structured threat scenarios for formal Event-B analysis.

HAZOP guide words:
  NO        — complete absence of the intended flow
  MORE      — higher than intended magnitude or frequency
  LESS      — lower than intended magnitude or frequency
  AS WELL AS — additional, unintended data alongside the intended flow
  PART OF   — incomplete or truncated intended data
  REVERSE   — flow occurs in the wrong direction, or source is impersonated
  OTHER THAN — flow carries semantically different data than expected

For each threat, produce a JSON object with exactly these fields:
  id                   — unique identifier e.g. "T-001"
  component            — the target/receiver component
  flow                 — flow name and direction e.g. "GlucoseSensor → DoseCalculator"
  guide_word           — one of the seven HAZOP guide words
  deviation            — one sentence: what is different from intended behaviour
  consequence          — the safety impact on the patient or system
  attack_vector        — a concrete attack mechanism that causes this deviation
  violated_invariant   — the formal invariant label violated, or "none"
  severity             — "critical" | "high" | "medium" | "low"
  event_b_attack_event — the name of the Event-B attack event that models this, or "none"
  attack_machine       — the .bum file that contains the attack event, or "none"

Return ONLY a valid JSON array. No markdown, no explanations, just the JSON array."""


def _build_system_description(model_info: dict) -> str:
    """
    Format the system model information into the prompt body.
    model_info keys: name, components, flows, invariants
    """
    lines = [f"System: {model_info.get('name', 'Unknown')}"]
    lines.append("")
    lines.append("Components (SysML Blocks):")
    for c in model_info.get("components", []):
        attack_tag = " <<AttackSurface>>" if c.get("is_attack_surface") else ""
        lines.append(f"  - {c['name']}{attack_tag}: {c.get('description', '')}")

    lines.append("")
    lines.append("Information Flows (SysML InformationFlows):")
    for f in model_info.get("flows", []):
        flow_tag = " [ATTACK SURFACE FLOW]" if f.get("flow_type") == "attack" else ""
        lines.append(f"  - {f['id']}: {f['source']} → {f['target']} via {f['signal']}{flow_tag}")

    lines.append("")
    lines.append("Safety Invariants (Event-B):")
    for inv in model_info.get("invariants", []):
        lines.append(f"  - {inv['name']}: {inv['text']}")

    return "\n".join(lines)


def analyze_system(model_info: dict, max_threats_per_flow: int = 4) -> list[dict]:
    """
    Run LLM-assisted HAZOP on a structured system model description.

    Args:
        model_info: dict with keys: name, components, flows, invariants
        max_threats_per_flow: cap on threats generated per flow

    Returns:
        list of threat dicts
    """
    client = anthropic.Anthropic()
    system_description = _build_system_description(model_info)

    prompt = f"""{system_description}

Apply all seven HAZOP guide words to each information flow listed above.
Prioritise flows marked as [ATTACK SURFACE FLOW] and flows that carry safety-critical data.
Limit to {max_threats_per_flow} threats per flow. Focus on threats that directly violate one of the stated safety invariants.
Return a JSON array of threat objects."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},  # cache the long methodology prompt
            }
        ],
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()
    # Strip any accidental markdown code fences
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
    if raw.endswith("```"):
        raw = "\n".join(raw.split("\n")[:-1])

    return json.loads(raw)


def analyze_from_xmi(xmi_path: str) -> list[dict]:
    """
    Convenience wrapper: parse the SysML XMI and run HAZOP.
    Adds the translator as a dependency only when called from pipeline.
    """
    import sys
    sys.path.insert(0, str(Path(xmi_path).parent.parent))
    from translator.sysml_to_eventb import XMIParser

    parser = XMIParser(xmi_path)
    model  = parser.parse()

    model_info = {
        "name": model.name,
        "components": [
            {
                "name": b.name,
                "is_attack_surface": b.is_attack_surface,
                "description": f"{len(b.states)} states, "
                               f"{len(b.flow_ports)} flow ports",
            }
            for b in model.blocks
        ],
        "flows": [
            {
                "id": f.xmi_id,
                "source": f.source_block,
                "target": f.target_block,
                "signal": f.signal_type,
                "flow_type": f.flow_type,
            }
            for f in model.flows
        ],
        "invariants": [
            {"name": r.name, "text": r.formal_text}
            for r in model.safety_requirements
        ],
    }

    return analyze_system(model_info)


# ── Pre-built insulin pump model info (used when not calling from pipeline) ──

INSULIN_PUMP_MODEL = {
    "name": "Autonomous Insulin Pump Controller",
    "components": [
        {"name": "GlucoseSensor",    "is_attack_surface": False,
         "description": "reads blood glucose level; states: IDLE, MEASURING, TRANSMITTING, ERROR"},
        {"name": "DoseCalculator",   "is_attack_surface": True,
         "description": "computes insulin dose from glucose reading and patient profile; states: WAITING, COMPUTING, DONE, ERROR"},
        {"name": "SafetyMonitor",    "is_attack_surface": False,
         "description": "validates dose against safety bounds; states: MONITORING, CHECKING, APPROVED, REJECTED"},
        {"name": "PumpActuator",     "is_attack_surface": False,
         "description": "delivers insulin dose; states: IDLE, PRIMING, DELIVERING, DONE"},
        {"name": "NetworkInterface", "is_attack_surface": True,
         "description": "external communication channel; states: IDLE, RECEIVING, TRANSMITTING"},
        {"name": "PatientProfile",   "is_attack_surface": False,
         "description": "stores patient parameters: MAX_SAFE_DOSE=50, HYPO_THRESHOLD=70, HYPER_THRESHOLD=180, MIN_BATTERY_LEVEL=10"},
    ],
    "flows": [
        {"id": "F1", "source": "GlucoseSensor",    "target": "DoseCalculator",  "signal": "GlucoseReading", "flow_type": "normal"},
        {"id": "F2", "source": "PatientProfile",   "target": "DoseCalculator",  "signal": "PatientParams",  "flow_type": "normal"},
        {"id": "F3", "source": "DoseCalculator",   "target": "SafetyMonitor",   "signal": "DoseRequest",    "flow_type": "normal"},
        {"id": "F4", "source": "SafetyMonitor",    "target": "PumpActuator",    "signal": "DoseCommand",    "flow_type": "normal"},
        {"id": "F5", "source": "NetworkInterface", "target": "DoseCalculator",  "signal": "ExternalCmd",    "flow_type": "attack"},
    ],
    "invariants": [
        {"name": "INV1", "text": "delivered_dose ≤ MAX_SAFE_DOSE"},
        {"name": "INV2", "text": "delivered_dose > 0 ⇒ glucose_reading ≥ HYPO_THRESHOLD"},
        {"name": "INV3", "text": "delivered_dose > 0 ⇒ battery_level ≥ MIN_BATTERY_LEVEL"},
        {"name": "INV4", "text": "delivered_dose > 0 ⇒ command_approved = TRUE"},
        {"name": "INV5", "text": "dose_request ≤ MAX_SAFE_DOSE"},
    ],
}


if __name__ == "__main__":
    import sys

    out_path = Path("hazop/threats.json")
    print("Running LLM-assisted HAZOP on the insulin pump model...")
    threats = analyze_system(INSULIN_PUMP_MODEL)
    out_path.write_text(json.dumps(threats, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Generated {len(threats)} threats → {out_path}")
    print(f"\nSeverity breakdown:")
    for sev in ("critical", "high", "medium", "low"):
        n = sum(1 for t in threats if t.get("severity") == sev)
        if n:
            print(f"  {sev}: {n}")
