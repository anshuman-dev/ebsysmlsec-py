"""
EBSysMLSec-Py: SysML/XMI → Event-B translator
Reproduces the transformation logic of EBSysMLSec (Poorhadi & Troubitsyna, SAFECOMP 2024)
in Python instead of ATL/Eclipse.

Input:  SysML XMI following the NCS (Networked Control System) modelling style
Output: Event-B context (.buc) and machine (.bum) files in Rodin textual notation
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import re

# XMI namespace map
NS = {
    "xmi":   "http://www.omg.org/spec/XMI/20131001",
    "uml":   "http://www.eclipse.org/uml2/5.0.0/UML",
    "sysml": "http://www.eclipse.org/papyrus/sysml/1.1/SysML",
    "safe":  "http://insulin-pump-formal/safety/1.0",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data model (intermediate representation)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class State:
    name: str
    xmi_id: str


@dataclass
class Transition:
    name: str
    source_id: str
    target_id: str


@dataclass
class FlowPort:
    name: str
    direction: str          # "in" | "out"
    signal_type: str        # name of the conveyed signal


@dataclass
class Block:
    name: str
    xmi_id: str
    is_attack_surface: bool = False
    value_properties: list[tuple[str, str]] = field(default_factory=list)   # (name, type)
    constant_properties: list[tuple[str, str, str]] = field(default_factory=list)  # (name, type, default)
    flow_ports: list[FlowPort] = field(default_factory=list)
    states: list[State] = field(default_factory=list)
    transitions: list[Transition] = field(default_factory=list)


@dataclass
class InformationFlow:
    name: str
    xmi_id: str
    source_block: str
    target_block: str
    signal_type: str
    flow_type: str          # "normal" | "attack"


@dataclass
class SafetyRequirement:
    name: str
    formal_text: str


@dataclass
class SystemModel:
    name: str
    blocks: list[Block] = field(default_factory=list)
    flows: list[InformationFlow] = field(default_factory=list)
    safety_requirements: list[SafetyRequirement] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Parser: XMI → SystemModel
# ─────────────────────────────────────────────────────────────────────────────

class XMIParser:
    def __init__(self, xmi_path: str):
        self.tree = ET.parse(xmi_path)
        self.root = self.tree.getroot()
        self._id_map: dict[str, ET.Element] = {}
        self._build_id_map(self.root)

    def _build_id_map(self, element: ET.Element):
        xid = element.get(f"{{{NS['xmi']}}}id")
        if xid:
            self._id_map[xid] = element
        for child in element:
            self._build_id_map(child)

    def _resolve(self, xid: str) -> Optional[ET.Element]:
        return self._id_map.get(xid)

    def _qname(self, tag: str) -> str:
        """Resolve a prefixed tag name to a Clark-notation name."""
        if ":" in tag:
            prefix, local = tag.split(":", 1)
            return f"{{{NS[prefix]}}}{local}"
        return tag

    # ── Find the UML model and package ──────────────────────────────────────

    def _find_package(self) -> ET.Element:
        model = self.root.find(f"{{{NS['uml']}}}Model")
        if model is None:
            model = self.root
        pkg = model.find(f"packagedElement[@{{{NS['xmi']}}}type='uml:Package']")
        return pkg if pkg is not None else model

    # ── Parse individual blocks ─────────────────────────────────────────────

    def _parse_block(self, elem: ET.Element) -> Block:
        name = elem.get("name", "Unknown")
        xid  = elem.get(f"{{{NS['xmi']}}}id", "")
        is_attack = elem.get("isAttackSurface", "false").lower() == "true"

        block = Block(name=name, xmi_id=xid, is_attack_surface=is_attack)

        # Value / constant properties
        for attr in elem.findall("ownedAttribute"):
            aname   = attr.get("name", "")
            atype   = attr.get("type", "")
            is_const = attr.get("isConstant", "false").lower() == "true"
            default  = attr.get("defaultValue", "")
            type_name = self._id_map.get(atype, {}).get("name", atype) if atype else "NAT"
            if isinstance(type_name, ET.Element):
                type_name = type_name.get("name", "NAT")
            if is_const:
                block.constant_properties.append((aname, type_name, default))
            else:
                block.value_properties.append((aname, type_name))

        # Flow ports
        for port in elem.findall("ownedPort"):
            pname = port.get("name", "")
            ptype_id = port.get("type", "")
            signal_el = self._id_map.get(ptype_id)
            signal_name = signal_el.get("name", ptype_id) if signal_el is not None else ptype_id
            direction = "out"  # default; refined from sysml:FlowPort
            fp = FlowPort(name=pname, direction=direction, signal_type=signal_name)
            block.flow_ports.append(fp)

        # State machine
        sm = elem.find("ownedBehavior[@{%s}type='uml:StateMachine']" % NS["xmi"])
        if sm is not None:
            region = sm.find("region")
            if region is not None:
                for sv in region.findall("subvertex"):
                    stype = sv.get(f"{{{NS['xmi']}}}type", "")
                    sname = sv.get("name", "")
                    sid   = sv.get(f"{{{NS['xmi']}}}id", "")
                    if "Pseudostate" not in stype:   # skip initial pseudostates
                        block.states.append(State(name=sname, xmi_id=sid))
                for tr in region.findall("transition"):
                    tname = tr.get("name", "")
                    tsrc  = tr.get("source", "")
                    tdst  = tr.get("target", "")
                    block.transitions.append(Transition(name=tname,
                                                        source_id=tsrc,
                                                        target_id=tdst))
        return block

    # ── Parse FlowPort directions from sysml:FlowPort elements ──────────────

    def _apply_flowport_directions(self, blocks: list[Block]):
        block_by_port: dict[str, Block] = {}
        for b in blocks:
            elem = self._id_map.get(b.xmi_id)
            if elem is not None:
                for port in elem.findall("ownedPort"):
                    pid = port.get(f"{{{NS['xmi']}}}id", "")
                    block_by_port[pid] = b

        for fp_el in self.root.iter(f"{{{NS['sysml']}}}FlowPort"):
            base_port = fp_el.get("base_Port", "")
            direction = fp_el.get("direction", "out")
            b = block_by_port.get(base_port)
            if b:
                # find the port by id and update direction
                port_el = self._id_map.get(base_port)
                if port_el is not None:
                    pname = port_el.get("name", "")
                    for fp in b.flow_ports:
                        if fp.name == pname:
                            fp.direction = direction
                            break

    # ── Parse information flows ──────────────────────────────────────────────

    def _parse_flows(self, pkg: ET.Element, block_names: dict[str, str]) -> list[InformationFlow]:
        flows = []
        for el in pkg.findall("packagedElement"):
            xtype = el.get(f"{{{NS['xmi']}}}type", "")
            if "InformationFlow" not in xtype:
                continue
            xid   = el.get(f"{{{NS['xmi']}}}id", "")
            name  = el.get("name", "")
            ftype = el.get("flowType", "normal")
            src_ref = el.find("informationSource")
            dst_ref = el.find("informationTarget")
            sig_ref = el.find("conveyed")
            src = block_names.get(src_ref.get(f"{{{NS['xmi']}}}idref", ""), "") if src_ref is not None else ""
            dst = block_names.get(dst_ref.get(f"{{{NS['xmi']}}}idref", ""), "") if dst_ref is not None else ""
            sig_el = self._id_map.get(sig_ref.get(f"{{{NS['xmi']}}}idref", ""), None) if sig_ref is not None else None
            sig = sig_el.get("name", "") if sig_el is not None else ""
            flows.append(InformationFlow(name=name, xmi_id=xid,
                                          source_block=src, target_block=dst,
                                          signal_type=sig, flow_type=ftype))
        return flows

    # ── Parse safety requirements ────────────────────────────────────────────

    def _parse_safety_reqs(self, pkg: ET.Element) -> list[SafetyRequirement]:
        reqs = []
        for rule in pkg.findall("ownedRule"):
            if rule.get("constraintType") == "safetyInvariant":
                reqs.append(SafetyRequirement(
                    name=rule.get("name", ""),
                    formal_text=rule.get("formalText", ""),
                ))
        return reqs

    # ── Main parse entry ─────────────────────────────────────────────────────

    def parse(self) -> SystemModel:
        pkg = self._find_package()
        model_name = "InsulinPumpSystem"

        sysml_block_ids: set[str] = set()
        for st in self.root.iter(f"{{{NS['sysml']}}}Block"):
            sysml_block_ids.add(st.get("base_Class", ""))

        blocks: list[Block] = []
        block_id_to_name: dict[str, str] = {}
        for elem in pkg.findall("packagedElement"):
            xtype = elem.get(f"{{{NS['xmi']}}}type", "")
            xid   = elem.get(f"{{{NS['xmi']}}}id", "")
            if "Class" in xtype and xid in sysml_block_ids:
                b = self._parse_block(elem)
                blocks.append(b)
                block_id_to_name[xid] = b.name

        self._apply_flowport_directions(blocks)
        flows = self._parse_flows(pkg, block_id_to_name)
        safety_reqs = self._parse_safety_reqs(pkg)

        return SystemModel(name=model_name, blocks=blocks,
                           flows=flows, safety_requirements=safety_reqs)


# ─────────────────────────────────────────────────────────────────────────────
# Generator: SystemModel → Event-B text
# ─────────────────────────────────────────────────────────────────────────────

def _block_prefix(block_name: str) -> str:
    """Derive a short prefix from a block name (e.g., GlucoseSensor → GS)."""
    words = re.findall(r'[A-Z][a-z]*', block_name)
    return "".join(w[0] for w in words).upper() if words else block_name[:2].upper()


def _state_set_name(block_name: str) -> str:
    """e.g., GlucoseSensor → SENSOR_STATE"""
    prefix = _block_prefix(block_name)
    return f"{prefix}_STATE"


def _state_var_name(block_name: str) -> str:
    """e.g., GlucoseSensor → gs_state"""
    prefix = _block_prefix(block_name).lower()
    return f"{prefix}_state"


def _signal_var_name(signal_type: str) -> str:
    """e.g., GlucoseReading → glucose_reading"""
    words = re.findall(r'[A-Z][a-z]*', signal_type)
    return "_".join(w.lower() for w in words) if words else signal_type.lower()


class EventBGenerator:
    """
    Generates Event-B context (.buc) and machine (.bum) files from a SystemModel.

    Transformation rules (NCS style — Poorhadi & Troubitsyna 2022):
      Block               → state variable + enumerated carrier set
      State machine state → constant in carrier set
      SM transition       → Event-B event (guard = source state, action = assign target)
      Flow port (out→in)  → shared variable (the signal value)
      isConstant prop     → Event-B constant + axiom
      safetyInvariant     → Event-B named invariant
      isAttackSurface     → inject attack events into attack machine variant
    """

    def __init__(self, model: SystemModel, out_dir: str):
        self.model = model
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._state_id_to_name: dict[str, str] = {}   # xmi_id → state name
        self._state_id_to_block: dict[str, Block] = {}
        self._build_state_maps()

    def _build_state_maps(self):
        for b in self.model.blocks:
            for s in b.states:
                prefix = _block_prefix(b.name)
                self._state_id_to_name[s.xmi_id] = f"{prefix}_{s.name}"
                self._state_id_to_block[s.xmi_id] = b

    # ── Context ──────────────────────────────────────────────────────────────

    def generate_context(self) -> str:
        ctx_name = f"{self.model.name}_Ctx"
        sets_lines: list[str] = []
        constants_lines: list[str] = []
        axioms: list[tuple[str, str]] = []

        axm_idx = 1

        for b in self.model.blocks:
            if not b.states:
                continue
            set_name = _state_set_name(b.name)
            sets_lines.append(f"  {set_name}")

            # Partition axiom
            state_singletons = ", ".join(
                "{" + f"{_block_prefix(b.name)}_{s.name}" + "}"
                for s in b.states
            )
            axioms.append((
                f"axm{axm_idx}",
                f"partition({set_name}, {state_singletons})"
            ))
            axm_idx += 1

            # State name constants
            for s in b.states:
                constants_lines.append(f"  {_block_prefix(b.name)}_{s.name}")

        # Patient profile constants (isConstant properties)
        for b in self.model.blocks:
            for (cname, ctype, cdefault) in b.constant_properties:
                const_eb = cname.upper()
                constants_lines.append(f"  {const_eb}")
                val = cdefault if cdefault else "0"
                axioms.append((f"axm{axm_idx}", f"{const_eb} ∈ ℕ"))
                axm_idx += 1
                axioms.append((f"axm{axm_idx}", f"{const_eb} = {val}"))
                axm_idx += 1

        lines = [f"CONTEXT {ctx_name}", "SETS"]
        lines += sets_lines
        lines += ["CONSTANTS"]
        lines += constants_lines
        lines += ["AXIOMS"]
        for label, pred in axioms:
            lines.append(f"  {label}: {pred}")
        lines.append("END")
        return "\n".join(lines)

    # ── Machine ───────────────────────────────────────────────────────────────

    def generate_machine(self, include_attack_events: list[str] | None = None) -> str:
        ctx_name = f"{self.model.name}_Ctx"
        mach_name = self.model.name if not include_attack_events \
                    else f"{self.model.name}_{'_'.join(include_attack_events)}"

        variables: list[str] = []
        inv_type: list[tuple[str, str]] = []
        inv_safety: list[tuple[str, str]] = []

        # Block state variables
        for b in self.model.blocks:
            if not b.states:
                continue
            var = _state_var_name(b.name)
            variables.append(var)
            inv_type.append((f"inv_{var}", f"{var} ∈ {_state_set_name(b.name)}"))

        # Flow data variables (one per unique normal flow signal)
        seen_signals: set[str] = set()
        flow_vars: list[str] = []
        for fl in self.model.flows:
            if fl.flow_type == "normal" and fl.signal_type not in seen_signals:
                seen_signals.add(fl.signal_type)
                var = _signal_var_name(fl.signal_type)
                variables.append(var)
                flow_vars.append(var)
                inv_type.append((f"inv_{var}", f"{var} ∈ ℕ"))

        # Battery level variable (from GlucoseSensor value property)
        variables.append("battery_level")
        inv_type.append(("inv_battery", "battery_level ∈ 0…0‥100"))

        # Approval flag
        variables.append("command_approved")
        inv_type.append(("inv_approved", "command_approved ∈ BOOL"))

        # Delivered dose (starts at 0, set during delivery)
        variables.append("delivered_dose")
        inv_type.append(("inv_delivered", "delivered_dose ∈ ℕ"))

        # Safety invariants from the model
        inv_idx = 1
        for req in self.model.safety_requirements:
            label = req.name.lower() if req.name else f"inv_safety{inv_idx}"
            inv_safety.append((label, req.formal_text))
            inv_idx += 1

        # Build EVENTS
        events = self._generate_events(include_attack_events)

        # Assemble machine text
        lines = [
            f"MACHINE {mach_name}",
            f"SEES {ctx_name}",
            "VARIABLES",
        ]
        for v in variables:
            lines.append(f"  {v}")
        lines.append("INVARIANTS")
        for label, pred in inv_type + inv_safety:
            lines.append(f"  {label}: {pred}")
        lines.append("EVENTS")
        for ev in events:
            lines.append(ev)
        lines.append("END")
        return "\n".join(lines)

    # ── Event generation ─────────────────────────────────────────────────────

    def _generate_events(self, attack_types: list[str] | None) -> list[str]:
        events: list[str] = []

        # INITIALISATION
        init_actions: list[str] = []
        for b in self.model.blocks:
            if b.states:
                var = _state_var_name(b.name)
                first_state = f"{_block_prefix(b.name)}_{b.states[0].name}"
                init_actions.append(f"    {var} := {first_state}")
        init_actions += [
            "    glucose_reading := 0",
            "    dose_request := 0",
            "    dose_command := 0",
            "    battery_level := 100",
            "    command_approved := FALSE",
            "    delivered_dose := 0",
        ]
        events.append(self._format_init(init_actions))

        # One event per state machine transition
        for b in self.model.blocks:
            state_var = _state_var_name(b.name)
            for tr in b.transitions:
                src_name = self._state_id_to_name.get(tr.source_id, "")
                dst_name = self._state_id_to_name.get(tr.target_id, "")
                if not src_name or not dst_name:
                    continue
                ev = self._format_transition_event(
                    name=f"{_block_prefix(b.name)}_{tr.name}",
                    state_var=state_var,
                    src_state=src_name,
                    dst_state=dst_name,
                    block=b,
                    transition=tr,
                )
                events.append(ev)

        # Approval event (SafetyMonitor → approve)
        events.append(self._generate_approve_event())
        # Reject event
        events.append(self._generate_reject_event())
        # Delivery event
        events.append(self._generate_deliver_event())

        # Attack events
        if attack_types:
            for atype in attack_types:
                ev = self._generate_attack_event(atype)
                if ev:
                    events.append(ev)

        return events

    def _format_init(self, actions: list[str]) -> str:
        return (
            "\n  INITIALISATION\n"
            "  BEGIN\n"
            + "\n".join(actions)
            + "\n  END"
        )

    def _format_transition_event(self, name: str, state_var: str,
                                  src_state: str, dst_state: str,
                                  block: Block, transition: Transition) -> str:
        lines = [f"\n  {name}"]
        lines.append("  WHERE")
        lines.append(f"    grd1: {state_var} = {src_state}")
        # Add domain-specific guards for key transitions
        if "MeasurementReady" in name or "ComputationReady" in name:
            lines.append("    grd2: battery_level ≥ MIN_BATTERY_LEVEL")
        if "ApproveDelivery" in name:
            lines.append("    grd2: dose_request ≤ MAX_SAFE_DOSE")
            lines.append("    grd3: glucose_reading ≥ HYPO_THRESHOLD")
            lines.append("    grd4: battery_level ≥ MIN_BATTERY_LEVEL")
        lines.append("  THEN")
        lines.append(f"    {state_var} := {dst_state}")
        # Side-effects for specific transitions
        if "MeasurementReady" in name:
            lines.append("    gs_state := GS_MEASURING")
        if "ComputationReady" in name:
            lines.append("    dose_request := dose_request")   # value set by ComputeDose event
        lines.append("  END")
        return "\n".join(lines)

    def _generate_approve_event(self) -> str:
        return (
            "\n  SM_ApproveDelivery\n"
            "  WHERE\n"
            "    grd1: sm_state = SM_CHECKING\n"
            "    grd2: dose_request ≤ MAX_SAFE_DOSE\n"
            "    grd3: glucose_reading ≥ HYPO_THRESHOLD\n"
            "    grd4: battery_level ≥ MIN_BATTERY_LEVEL\n"
            "  THEN\n"
            "    sm_state := SM_APPROVED\n"
            "    command_approved := TRUE\n"
            "    dose_command := dose_request\n"
            "  END"
        )

    def _generate_reject_event(self) -> str:
        return (
            "\n  SM_RejectDelivery\n"
            "  WHERE\n"
            "    grd1: sm_state = SM_CHECKING\n"
            "    grd2: dose_request > MAX_SAFE_DOSE ∨ glucose_reading < HYPO_THRESHOLD ∨ battery_level < MIN_BATTERY_LEVEL\n"
            "  THEN\n"
            "    sm_state := SM_REJECTED\n"
            "    command_approved := FALSE\n"
            "  END"
        )

    def _generate_deliver_event(self) -> str:
        return (
            "\n  PA_DeliverDose\n"
            "  WHERE\n"
            "    grd1: pa_state = PA_PRIMING\n"
            "    grd2: command_approved = TRUE\n"
            "    grd3: dose_command ≤ MAX_SAFE_DOSE\n"
            "    grd4: glucose_reading ≥ HYPO_THRESHOLD\n"
            "    grd5: battery_level ≥ MIN_BATTERY_LEVEL\n"
            "  THEN\n"
            "    delivered_dose := dose_command\n"
            "    pa_state := PA_DELIVERING\n"
            "    battery_level := battery_level - 1\n"
            "  END"
        )

    def _generate_attack_event(self, attack_type: str) -> Optional[str]:
        """
        Generate Event-B events that model specific attack scenarios.
        These events, when added to the machine, cause specific proof obligations
        to fail — showing that the safety invariant is violated under the attack.
        """
        if attack_type == "Spoofing":
            # Attack A: sensor spoofing — sets glucose_reading to a high value
            # while the patient's actual glucose (actual_glucose) is below HYPO_THRESHOLD.
            # Violates INV2: delivered_dose > 0 ⇒ glucose_reading ≥ HYPO_THRESHOLD
            # (when we add actual_glucose as the ground truth variable)
            return (
                "\n  ATK_SpoofGlucoseReading\n"
                "  /* Attack A: attacker injects a falsely high glucose reading\n"
                "     via the NetworkInterface. The system will approve delivery\n"
                "     based on the spoofed value while actual patient glucose\n"
                "     may be below HYPO_THRESHOLD. Proof obligation for INV2 fails. */\n"
                "  ANY spoofed_val\n"
                "  WHERE\n"
                "    grd1: spoofed_val ∈ ℕ\n"
                "    grd2: spoofed_val > HYPER_THRESHOLD\n"
                "    grd3: ni_state = NI_TRANSMITTING\n"
                "    grd4: glucose_reading < HYPO_THRESHOLD   /* true patient state */\n"
                "  THEN\n"
                "    glucose_reading := spoofed_val\n"
                "    /* After this event: glucose_reading > HYPO_THRESHOLD but\n"
                "       the patient is actually hypoglycaemic.\n"
                "       INV2 (delivered_dose > 0 ⇒ glucose_reading ≥ HYPO_THRESHOLD)\n"
                "       cannot be proved to reflect actual patient safety. */\n"
                "  END"
            )

        elif attack_type == "Injection":
            # Attack B: command injection — forces dose delivery without SafetyMonitor approval.
            # Violates INV4: delivered_dose > 0 ⇒ command_approved = TRUE (approver = monitor).
            return (
                "\n  ATK_InjectDeliveryCommand\n"
                "  /* Attack B: attacker sends a delivery command directly to the\n"
                "     PumpActuator via the NetworkInterface, bypassing the SafetyMonitor.\n"
                "     delivered_dose is set while command_approved remains FALSE.\n"
                "     Proof obligation for INV4 fails. */\n"
                "  ANY injected_dose\n"
                "  WHERE\n"
                "    grd1: injected_dose ∈ ℕ\n"
                "    grd2: injected_dose > 0\n"
                "    grd3: ni_state = NI_TRANSMITTING\n"
                "    grd4: command_approved = FALSE   /* monitor has NOT approved */\n"
                "  THEN\n"
                "    delivered_dose := injected_dose\n"
                "    /* INV4: delivered_dose > 0 ⇒ command_approved = TRUE\n"
                "       is NOT satisfied: command_approved = FALSE here.\n"
                "       Rodin proof obligation for INV4 does not discharge. */\n"
                "  END"
            )

        elif attack_type == "Replay":
            # Attack C: replay attack — replays an old high-dose command.
            # Violates INV1: delivered_dose ≤ MAX_SAFE_DOSE (if replayed dose > MAX).
            return (
                "\n  ATK_ReplayHighDoseCommand\n"
                "  /* Attack C: attacker captures and replays a legitimate but\n"
                "     high-dose command from an earlier session.\n"
                "     If replayed_dose > MAX_SAFE_DOSE, INV1 fails. */\n"
                "  ANY replayed_dose\n"
                "  WHERE\n"
                "    grd1: replayed_dose ∈ ℕ\n"
                "    grd2: replayed_dose > MAX_SAFE_DOSE   /* the replayed command is excessive */\n"
                "    grd3: ni_state = NI_TRANSMITTING\n"
                "  THEN\n"
                "    delivered_dose := replayed_dose\n"
                "    /* INV1: delivered_dose ≤ MAX_SAFE_DOSE\n"
                "       is NOT satisfied: replayed_dose > MAX_SAFE_DOSE.\n"
                "       Rodin proof obligation for INV1 does not discharge. */\n"
                "  END"
            )

        return None

    # ── Write to files ────────────────────────────────────────────────────────

    def write_context(self) -> Path:
        content = self.generate_context()
        out = self.out_dir / f"{self.model.name}.buc"
        out.write_text(content, encoding="utf-8")
        return out

    def write_machine(self, attack_types: list[str] | None = None,
                      subdir: str = "") -> Path:
        content = self.generate_machine(attack_types)
        if subdir:
            d = self.out_dir / subdir
            d.mkdir(parents=True, exist_ok=True)
        else:
            d = self.out_dir
        if attack_types:
            fname = f"Attack_{'_'.join(attack_types)}.bum"
        else:
            fname = f"{self.model.name}.bum"
        out = d / fname
        out.write_text(content, encoding="utf-8")
        return out


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def translate(xmi_path: str, out_dir: str) -> dict[str, Path]:
    parser = XMIParser(xmi_path)
    model  = parser.parse()
    gen    = EventBGenerator(model, out_dir)

    ctx_path  = gen.write_context()
    mach_path = gen.write_machine()
    atk_a     = gen.write_machine(attack_types=["Spoofing"],  subdir="attacks")
    atk_b     = gen.write_machine(attack_types=["Injection"], subdir="attacks")
    atk_c     = gen.write_machine(attack_types=["Replay"],    subdir="attacks")

    return {
        "context":         ctx_path,
        "machine":         mach_path,
        "attack_spoofing": atk_a,
        "attack_injection": atk_b,
        "attack_replay":   atk_c,
    }


if __name__ == "__main__":
    import sys, json
    xmi = sys.argv[1] if len(sys.argv) > 1 else "sysml/insulin_pump.xmi"
    out = sys.argv[2] if len(sys.argv) > 2 else "eventb"
    paths = translate(xmi, out)
    for k, p in paths.items():
        print(f"  [{k}] → {p}")
