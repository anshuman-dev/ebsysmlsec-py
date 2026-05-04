---
title: EBSysMLSec-Py LLM HAZOP Analyzer
emoji: 🔒
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: false
---

# EBSysMLSec-Py: Formal Safety-Security Analysis with LLM-Assisted HAZOP

A Python reimplementation of the **EBSysMLSec** model transformation pipeline
(Poorhadi & Troubitsyna, SAFECOMP 2024), applied to a new domain and extended
with LLM-assisted HAZOP threat analysis.

**Domain:** Autonomous Insulin Pump Controller (medical safety-critical system)  
**Original domain:** Railway moving-block signalling (CBTC)  
**Contribution:** Python translator + LLM-assisted HAZOP — neither present in the original ATL/Eclipse toolchain

---

## What this project does

The original EBSysMLSec tool (written in ATL — ATLAS Transformation Language) takes
a SysML model of a safety-critical system and automatically generates Event-B machines
and contexts that can be formally verified in the Rodin prover. Security attacks are
injected as Event-B events; failing proof obligations show which safety invariants are
violated under attack.

This project reproduces that pipeline in Python and extends it:

```
sysml/insulin_pump.xmi
        │
        ▼
translator/sysml_to_eventb.py        ← Python reimplementation of EBSysMLSec ATL rules
        │
        ├─▶ eventb/InsulinPump.buc   ← Event-B context (sets, constants, axioms)
        ├─▶ eventb/InsulinPump.bum   ← Event-B machine (normal operation)
        ├─▶ eventb/attacks/Attack_Spoofing.bum    ← Attack A: sensor spoofing
        ├─▶ eventb/attacks/Attack_Injection.bum   ← Attack B: command injection
        └─▶ eventb/attacks/Attack_Replay.bum      ← Attack C: replay attack
                │
                ▼
        hazop/hazop_analyzer.py      ← LLM-assisted HAZOP via Anthropic API  [NEW]
                │
                ▼
        hazop/threats.json           ← 18 structured threat scenarios
                │
                ▼
        verification/proof_results.md ← which Rodin POs hold / fail per attack
```

---

## System: Autonomous Insulin Pump Controller

Six SysML blocks connected by five information flows:

```
PatientProfile ──F2──▶ DoseCalculator ──F3──▶ SafetyMonitor ──F4──▶ PumpActuator
                              ▲
GlucoseSensor ──F1────────────┘
NetworkInterface ──F5──▶ DoseCalculator   ← attack surface
```

### Safety invariants (Event-B)

| Label | Predicate | Protection |
|---|---|---|
| **INV1** | `delivered_dose ≤ MAX_SAFE_DOSE` | Overdose prevention |
| **INV2** | `delivered_dose > 0 ⇒ glucose_reading ≥ HYPO_THRESHOLD` | Hypoglycaemia protection |
| **INV3** | `delivered_dose > 0 ⇒ battery_level ≥ MIN_BATTERY_LEVEL` | Power safety |
| **INV4** | `delivered_dose > 0 ⇒ command_approved = TRUE` | Authorisation gate |
| **INV5** | `dose_request ≤ MAX_SAFE_DOSE` | Calculator output bound |

### Attack scenarios and violated invariants

| Attack | HAZOP guide word | Flow | Violated | Event-B machine |
|---|---|---|---|---|
| A: Sensor spoofing | MORE on F1 | GlucoseSensor → DoseCalculator | **INV2** | `Attack_Spoofing.bum` |
| B: Command injection | AS WELL AS on F5 | NetworkInterface → DoseCalculator | **INV4** | `Attack_Injection.bum` |
| C: Replay attack | OTHER THAN on F5 | NetworkInterface → DoseCalculator | **INV1** | `Attack_Replay.bum` |

---

## Running the pipeline

```bash
pip install -r requirements.txt

# Full pipeline (Event-B generation + LLM HAZOP)
export ANTHROPIC_API_KEY=sk-ant-...
python run_pipeline.py

# Event-B generation only (no API key needed)
python run_pipeline.py --skip-hazop

# Gradio demo (uses pre-generated threats by default)
python app.py
```

---

## Verifying in Rodin

1. Download [Rodin Platform 3.7](http://www.event-b.org/install.html)
2. Install the [Camille plugin](https://wiki.event-b.org/index.php/Camille) (textual Event-B import)
3. Create a new Event-B project in Rodin
4. Add a new Context: paste content of `eventb/InsulinPump.buc`
5. Add a new Machine: paste content of `eventb/InsulinPump.bum` — Run Provers → **all POs discharge**
6. Add attack machines from `eventb/attacks/` — Run Provers → **specific POs fail**

Expected results per `verification/proof_results.md`:

| Machine | INV1 | INV2 | INV3 | INV4 | INV5 |
|---|---|---|---|---|---|
| Normal | ✓ | ✓ | ✓ | ✓ | ✓ |
| + Spoofing | ✓ | **✗** | ✓ | ✓ | ✓ |
| + Injection | ✓ | ✓ | ✓ | **✗** | ✓ |
| + Replay | **✗** | ✓ | ✓ | ✓ | ✓ |

✓ Rodin proof obligation discharged · **✗** Proof obligation fails = invariant violated under attack

---

## LLM-Assisted HAZOP: the AI contribution

In the original Poorhadi & Troubitsyna papers, the HAZOP analysis is **manual** — a domain expert applies the seven guide words to each flow by hand. This project automates that step using Claude:

```python
from hazop.hazop_analyzer import analyze_system, INSULIN_PUMP_MODEL

threats = analyze_system(INSULIN_PUMP_MODEL)
# → list of 18 structured threat dicts, each linked to an Event-B attack event
```

The LLM receives the system model (blocks, flows, invariants) and applies HAZOP guide words systematically to produce the same structured threat table a human analyst would — but for any system, in seconds.

This is a direct demonstration of the PhD position's research question:
> *"how formally specified safety constraints can be derived using AI"*

---

## Repository structure

```
insulin-pump-formal/
├── sysml/
│   └── insulin_pump.xmi          SysML/XMI model (NCS style)
├── translator/
│   └── sysml_to_eventb.py        Python SysML → Event-B translator
├── eventb/
│   ├── InsulinPump.buc            Event-B context
│   ├── InsulinPump.bum            Event-B machine (normal operation)
│   └── attacks/
│       ├── Attack_Spoofing.bum    Attack A: INV2 violated
│       ├── Attack_Injection.bum   Attack B: INV4 violated
│       └── Attack_Replay.bum      Attack C: INV1 violated
├── hazop/
│   ├── hazop_analyzer.py          LLM-assisted HAZOP (Anthropic API)
│   └── threats.json               Pre-generated threat analysis
├── verification/
│   └── proof_results.md           Proof obligation results per scenario
├── app.py                         Gradio demo (HF Spaces)
├── run_pipeline.py                Full pipeline entry point
└── requirements.txt
```

---

## References

1. Poorhadi, E., Troubitsyna, E., Dán, G. (2022). *Analysing the Impact of Security Attacks on Safety Using SysML and Event-B.* IMBSA 2022. DOI: 10.1007/978-3-031-15842-1_13
2. Poorhadi, E., Troubitsyna, E. (2023). *Automating an Analysis of Safety-Security Interactions for Railway Systems.* RSSRail 2023. DOI: 10.1007/978-3-031-43366-5_1
3. Poorhadi, E., Troubitsyna, E. (2024). *Automating an Integrated Model-Driven Approach to Analysing the Impact of Cyberattacks on Safety.* SAFECOMP 2024. DOI: 10.1007/978-3-031-68738-9_5
4. Troubitsyna, E. (2024). *Formal Analysis of Interactions Between Safety and Security Requirements.* In: The Practice of Formal Methods. DOI: 10.1007/978-3-031-66673-5_8
5. Abrial, J.R. (2010). *Modeling in Event-B.* Cambridge University Press.

---

## What makes this original

| Aspect | Original EBSysMLSec | This project |
|---|---|---|
| Transformation language | ATL (Eclipse/EMF) | Python |
| Domain | Railway (CBTC moving block) | Medical device (insulin pump) |
| HAZOP | Manual | LLM-assisted (new contribution) |
| Attack modelling | Railway-specific attacks | Spoofing, injection, replay |
| Formal artefacts | Rodin XML format | Textual Event-B (Camille notation) |
| Distribution | Eclipse plugin | Python + Gradio + HF Spaces |
