"""Dependency-free parser and validator for Lifecycle DSL v1."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

CATALOG_SCHEMA = "lifecycle.diagnostics/v1"
REPORT_SCHEMA = "lifecycle.validation/v1"
AUDIT_SCHEMA = "lifecycle.compaction-audit/v1"
SEVERITIES = {"INFO", "WARNING", "ERROR", "CRITICAL"}
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9_]*$")
LIFECYCLE_NAME = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
PROFILE_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){2,}$")
CORE_CODE = re.compile(r"^LFC-[A-Z]+-[0-9]{3}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
EMBEDDED_CATALOG_ROWS = (
    ("LFC-IO-001", "ERROR", "Lifecycle input could not be read."),
    ("LFC-SYNTAX-001", "ERROR", "Lifecycle input is not valid UTF-8."),
    ("LFC-SYNTAX-002", "ERROR", "Lifecycle statement syntax is invalid."),
    ("LFC-DOC-001", "ERROR", "Lifecycle document boundary is invalid."),
    ("LFC-DOC-002", "ERROR", "Lifecycle name is duplicated in the bundle."),
    ("LFC-MODEL-001", "ERROR", "Lifecycle identifier or scalar is invalid."),
    ("LFC-MODEL-002", "ERROR", "Lifecycle declaration is duplicated."),
    ("LFC-MODEL-003", "ERROR", "Lifecycle must declare exactly one initial state."),
    ("LFC-MODEL-004", "ERROR", "Lifecycle statement references an undeclared symbol."),
    ("LFC-MODEL-005", "ERROR", "State and event pair has more than one decision."),
    ("LFC-MODEL-006", "ERROR", "Lifecycle state is unreachable from the initial state."),
    ("LFC-MODEL-007", "ERROR", "Terminal state has an outgoing transition."),
    ("LFC-ERROR-001", "ERROR", "Profile error declaration is invalid."),
    ("LFC-ERROR-002", "ERROR", "Profile error binding is unresolved or unused."),
    ("LFC-ERROR-003", "ERROR", "Profile error code is duplicated in the bundle."),
    ("LFC-CATALOG-001", "CRITICAL", "Core diagnostic catalog is invalid."),
)
REQUIRED_CORE_CODES = {code for code, _, _ in EMBEDDED_CATALOG_ROWS}


class CatalogError(RuntimeError):
    """The trusted core diagnostic catalog cannot be used."""


class CatalogEntry(NamedTuple):
    code: str
    severity: str
    message: str


class Diagnostic(NamedTuple):
    code: str
    severity: str
    message: str
    path: str
    line: int
    document: str | None
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return self._asdict()


class State(NamedTuple):
    name: str
    initial: bool
    terminal: bool
    line: int


class Transition(NamedTuple):
    source: str
    target: str
    event: str
    evidence: str | None
    line: int


class Reject(NamedTuple):
    state: str
    event: str
    error: str
    line: int


class ProfileError(NamedTuple):
    code: str
    severity: str
    message: str
    line: int


def embedded_catalog() -> dict[str, CatalogEntry]:
    result = {c: CatalogEntry(c, s, m) for c, s, m in EMBEDDED_CATALOG_ROWS}
    if set(result) != REQUIRED_CORE_CODES:
        raise CatalogError("LFC-CATALOG-001: embedded diagnostic set is invalid")
    return result


@dataclass
class Lifecycle:
    name: str
    version: int
    line: int
    description: str | None = None
    description_line: int = 0
    states: dict[str, State] = field(default_factory=dict)
    events: dict[str, int] = field(default_factory=dict)
    evidence: dict[str, int] = field(default_factory=dict)
    transitions: list[Transition] = field(default_factory=list)
    rejects: list[Reject] = field(default_factory=list)
    errors: dict[str, ProfileError] = field(default_factory=dict)
    uncompacted_states: list[State] = field(default_factory=list)
    uncompacted_events: list[str] = field(default_factory=list)
    uncompacted_evidence: list[str] = field(default_factory=list)
    uncompacted_transitions: list[Transition] = field(default_factory=list)
    uncompacted_rejects: list[Reject] = field(default_factory=list)
    batch_state_count: int = 0
    batch_event_count: int = 0
    batch_evidence_count: int = 0
    state_set_transition_count: int = 0
    state_set_reject_count: int = 0

    def summary(self) -> dict[str, Any]:
        initial = sorted(s.name for s in self.states.values() if s.initial)
        terminal = sorted(s.name for s in self.states.values() if s.terminal)
        return {
            "name": self.name, "version": self.version, "initial_state": initial[0] if len(initial) == 1 else None,
            "terminal_states": terminal, "state_count": len(self.states), "event_count": len(self.events),
            "evidence_count": len(self.evidence), "transition_count": len(self.transitions),
            "reject_count": len(self.rejects), "error_count": len(self.errors),
        }


@dataclass
class ValidationReport:
    source: str
    lifecycles: list[Lifecycle]
    diagnostics: list[Diagnostic]

    @property
    def valid(self) -> bool:
        return not self.diagnostics

    def as_dict(self) -> dict[str, Any]:
        ordered = sorted(self.diagnostics, key=lambda d: (d.line, d.code, d.document or "", d.detail))
        return {
            "schema": REPORT_SCHEMA, "status": "valid" if self.valid else "invalid", "source": self.source,
            "lifecycle_count": len(self.lifecycles), "lifecycles": [item.summary() for item in self.lifecycles],
            "diagnostics": [item.as_dict() for item in ordered],
        }


def load_catalog(path: Path) -> dict[str, CatalogEntry]:
    from lifecycle_catalog import load_catalog_impl
    return load_catalog_impl(path)


class Emitter:
    def __init__(self, path: str, catalog: dict[str, CatalogEntry]) -> None:
        self.path, self.catalog, self.diagnostics = path, catalog, []

    def emit(self, code: str, line: int, detail: str, document: str | None = None) -> None:
        if code not in self.catalog:
            raise CatalogError(f"LFC-CATALOG-001: emitted unknown core code {code}")
        entry = self.catalog[code]
        self.diagnostics.append(Diagnostic(code, entry.severity, entry.message, self.path, line, document, detail))


def _extract_bracketed_list(tokens: list[str], start_index: int) -> tuple[list[str], int] | None:
    if start_index >= len(tokens) or not tokens[start_index].startswith("["):
        return None
    end_index = -1
    for idx in range(start_index, len(tokens)):
        if "]" in tokens[idx]:
            if not tokens[idx].endswith("]") or "[" in tokens[idx][1:]:
                return None
            end_index = idx
            break
        if idx > start_index and "[" in tokens[idx]:
            return None
    if end_index == -1:
        return None
    inner = " ".join(tokens[start_index : end_index + 1])[1:-1].strip()
    if not inner:
        return None
    items = [raw.strip() for raw in inner.split(",")]
    return None if any(not x or any(ch.isspace() for ch in x) for x in items) else (items, end_index + 1)


def _parse_statement(tokens: list[str], line: int, model: Lifecycle, emitter: Emitter) -> None:
    def declare(values: dict[str, Any], name: str, val: Any, kind: str) -> None:
        if IDENTIFIER.fullmatch(name) is None:
            emitter.emit("LFC-MODEL-001", line, f"invalid {kind} identifier {name!r}", model.name)
        elif name in values:
            emitter.emit("LFC-MODEL-002", line, f"duplicate {kind} {name}", model.name)
        else:
            values[name] = val

    kw = tokens[0]
    if kw == "DESCRIPTION":
        if len(tokens) != 2 or not tokens[1].strip():
            emitter.emit("LFC-SYNTAX-002", line, "DESCRIPTION requires one quoted value", model.name)
        elif model.description is not None:
            emitter.emit("LFC-MODEL-002", line, "duplicate DESCRIPTION", model.name)
        else:
            model.description, model.description_line = tokens[1], line
        return
    if kw in {"STATE", "STATES"}:
        parsed = ([tokens[1]], 2) if kw == "STATE" and len(tokens) >= 2 else _extract_bracketed_list(tokens, 1) if kw == "STATES" else None
        if parsed is None:
            emitter.emit("LFC-SYNTAX-002", line, f"{kw} syntax is invalid", model.name)
            return
        names, mods = parsed[0], tokens[parsed[1] :]
        if any(m not in {"INITIAL", "TERMINAL"} for m in mods) or len(set(mods)) != len(mods):
            emitter.emit("LFC-SYNTAX-002", line, f"{kw} syntax is invalid", model.name)
            return
        for name in names:
            st = State(name, "INITIAL" in mods, "TERMINAL" in mods, line)
            declare(model.states, st.name, st, "state")
            if kw == "STATE":
                model.uncompacted_states.append(st)
            else:
                model.batch_state_count += 1
        return
    if kw in {"EVENT", "EVIDENCE", "EVENTS", "EVIDENCES"}:
        kind = "event" if kw.startswith("EVENT") else "evidence"
        target = model.events if kind == "event" else model.evidence
        if not kw.endswith("S"):
            if len(tokens) != 2:
                emitter.emit("LFC-SYNTAX-002", line, f"{kw} requires one identifier", model.name)
                return
            declare(target, tokens[1], line, kind)
            (model.uncompacted_events if kind == "event" else model.uncompacted_evidence).append(tokens[1])
            return
        parsed = _extract_bracketed_list(tokens, 1)
        if parsed is None or parsed[1] != len(tokens):
            emitter.emit("LFC-SYNTAX-002", line, f"{kw} syntax is invalid", model.name)
            return
        for name in parsed[0]:
            declare(target, name, line, kind)
            if kind == "event":
                model.batch_event_count += 1
            else:
                model.batch_evidence_count += 1
        return
    if kw in {"TRANSITION", "REJECT"}:
        is_batch = len(tokens) >= 2 and tokens[1].startswith("[")
        parsed = _extract_bracketed_list(tokens, 1) if is_batch else ([tokens[1]], 2) if len(tokens) >= 2 else None
        if parsed is None:
            emitter.emit("LFC-SYNTAX-002", line, f"{kw} syntax is invalid", model.name)
            return
        subjects, rest = parsed[0], tokens[parsed[1] :]
        if kw == "TRANSITION":
            if len(rest) not in {4, 6} or rest[0] != "->" or rest[2] != "ON" or (len(rest) == 6 and rest[4] != "REQUIRES"):
                emitter.emit("LFC-SYNTAX-002", line, "TRANSITION syntax is invalid", model.name)
                return
            tgt, ev, evd = rest[1], rest[3], (rest[5] if len(rest) == 6 else None)
            if any(IDENTIFIER.fullmatch(x) is None for x in [*subjects, tgt, ev]):
                emitter.emit("LFC-MODEL-001", line, "TRANSITION identifiers are invalid", model.name)
                return
            if evd is not None and IDENTIFIER.fullmatch(evd) is None:
                emitter.emit("LFC-MODEL-001", line, "TRANSITION evidence identifier is invalid", model.name)
                return
            for src in subjects:
                tr = Transition(src, tgt, ev, evd, line)
                model.transitions.append(tr)
                if is_batch:
                    model.state_set_transition_count += 1
                else:
                    model.uncompacted_transitions.append(tr)
            return
        if len(rest) != 4 or rest[0] != "ON" or rest[2] != "WITH":
            emitter.emit("LFC-SYNTAX-002", line, "REJECT syntax is invalid", model.name)
            return
        if any(IDENTIFIER.fullmatch(x) is None for x in [*subjects, rest[1]]):
            emitter.emit("LFC-MODEL-001", line, "REJECT identifiers are invalid", model.name)
            return
        for st in subjects:
            rj = Reject(st, rest[1], rest[3], line)
            model.rejects.append(rj)
            if is_batch:
                model.state_set_reject_count += 1
            else:
                model.uncompacted_rejects.append(rj)
        return
    if kw == "ERROR":
        if len(tokens) != 6 or tokens[2] != "SEVERITY" or tokens[4] != "MESSAGE":
            emitter.emit("LFC-SYNTAX-002", line, "ERROR syntax is invalid", model.name)
            return
        code, sev, msg = tokens[1], tokens[3], tokens[5]
        if PROFILE_ERROR_CODE.fullmatch(code) is None or code.startswith("LFC-") or sev not in SEVERITIES or not msg.strip():
            emitter.emit("LFC-ERROR-001", line, f"invalid profile error {code!r}", model.name)
        elif code in model.errors:
            emitter.emit("LFC-MODEL-002", line, f"duplicate error {code}", model.name)
        else:
            model.errors[code] = ProfileError(code, sev, msg, line)
        return
    emitter.emit("LFC-SYNTAX-002", line, f"unknown statement {kw!r}", model.name)


def parse_bundle(text: str, emitter: Emitter) -> list[Lifecycle]:
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    raw_lines = [] if not norm else (norm[:-1].split("\n") if norm.endswith("\n") else norm.split("\n"))
    models: list[Lifecycle] = []
    current: Lifecycle | None = None
    for line_no, raw_line in enumerate(raw_lines, start=1):
        try:
            lexer = shlex.shlex(raw_line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError as err:
            emitter.emit("LFC-SYNTAX-002", line_no, f"tokenization failed: {err}", current.name if current else None)
            continue
        if not tokens:
            continue
        if tokens[0] == "LIFECYCLE":
            if current is not None:
                emitter.emit("LFC-DOC-001", line_no, "new lifecycle before END", current.name)
                models.append(current)
            if len(tokens) != 4 or tokens[2] != "VERSION":
                emitter.emit("LFC-SYNTAX-002", line_no, "LIFECYCLE header is invalid")
                current = None
                continue
            name, raw_ver = tokens[1], tokens[3]
            ver = int(raw_ver) if POSITIVE_INTEGER.fullmatch(raw_ver) else 0
            current = Lifecycle(name=name, version=ver, line=line_no)
            if LIFECYCLE_NAME.fullmatch(name) is None or ver != 1:
                emitter.emit("LFC-MODEL-001", line_no, f"invalid lifecycle name or unsupported version: {name!r} v{raw_ver!r}", name)
            continue
        if tokens[0] == "END":
            if len(tokens) != 1 or current is None:
                emitter.emit("LFC-DOC-001", line_no, "END without one open lifecycle")
            else:
                models.append(current)
                current = None
            continue
        if current is None:
            emitter.emit("LFC-SYNTAX-002", line_no, "statement outside lifecycle document")
            continue
        _parse_statement(tokens, line_no, current, emitter)
    if current is not None:
        emitter.emit("LFC-DOC-001", current.line, "lifecycle reaches EOF without END", current.name)
        models.append(current)
    if not models:
        emitter.emit("LFC-DOC-001", 0, "bundle contains no lifecycle document")
    seen: dict[str, int] = {}
    for m in models:
        if m.name in seen:
            emitter.emit("LFC-DOC-002", m.line, f"lifecycle {m.name!r} first declared at line {seen[m.name]}", m.name)
        else:
            seen[m.name] = m.line
    return models


def _check_ref(decl: dict[str, Any], val: str, kind: str, ln: int, doc: str, emitter: Emitter) -> None:
    if val not in decl:
        emitter.emit("LFC-MODEL-004", ln, f"undeclared {kind} {val}", doc)


def validate_models(models: Iterable[Lifecycle], emitter: Emitter) -> None:
    global_errors: dict[str, tuple[str, int]] = {}
    for m in models:
        initials = [s for s in m.states.values() if s.initial]
        if len(initials) != 1:
            emitter.emit("LFC-MODEL-003", m.line, f"found {len(initials)} initial states", m.name)
        for pe in m.errors.values():
            prev = global_errors.get(pe.code)
            if prev is not None:
                emitter.emit("LFC-ERROR-003", pe.line, f"{pe.code} first declared in {prev[0]} at line {prev[1]}", m.name)
            else:
                global_errors[pe.code] = (m.name, pe.line)
        decisions: dict[tuple[str, str], tuple[str, int]] = {}
        ordered = sorted([("transition", t) for t in m.transitions] + [("reject", r) for r in m.rejects], key=lambda x: x[1].line)
        for kind, dec in ordered:
            st = dec.source if isinstance(dec, Transition) else dec.state
            prev_dec = decisions.get((st, dec.event))
            if prev_dec is not None:
                emitter.emit("LFC-MODEL-005", dec.line, f"{st}/{dec.event} already has {prev_dec[0]} at line {prev_dec[1]}", m.name)
            else:
                decisions[(st, dec.event)] = (kind, dec.line)
        used_errors: set[str] = set()
        for tr in m.transitions:
            _check_ref(m.states, tr.source, "state", tr.line, m.name, emitter)
            _check_ref(m.states, tr.target, "state", tr.line, m.name, emitter)
            _check_ref(m.events, tr.event, "event", tr.line, m.name, emitter)
            if tr.evidence is not None:
                _check_ref(m.evidence, tr.evidence, "evidence", tr.line, m.name, emitter)
            src_st = m.states.get(tr.source)
            if src_st is not None and src_st.terminal:
                emitter.emit("LFC-MODEL-007", tr.line, f"terminal state {src_st.name} transitions on {tr.event}", m.name)
        for rj in m.rejects:
            _check_ref(m.states, rj.state, "state", rj.line, m.name, emitter)
            _check_ref(m.events, rj.event, "event", rj.line, m.name, emitter)
            if rj.error not in m.errors:
                emitter.emit("LFC-ERROR-002", rj.line, f"reject references undeclared error {rj.error}", m.name)
            else:
                used_errors.add(rj.error)
        for code, pe in m.errors.items():
            if code not in used_errors:
                emitter.emit("LFC-ERROR-002", pe.line, f"declared error {code} is unused", m.name)
        if len(initials) == 1:
            edges: dict[str, set[str]] = {name: set() for name in m.states}
            for tr in m.transitions:
                if tr.source in edges and tr.target in m.states:
                    edges[tr.source].add(tr.target)
            reached, queue = {initials[0].name}, deque([initials[0].name])
            while queue:
                for tgt in sorted(edges.get(queue.popleft(), ())):
                    if tgt not in reached:
                        reached.add(tgt)
                        queue.append(tgt)
            for cand in sorted(m.states.values(), key=lambda s: (s.line, s.name)):
                if cand.name not in reached:
                    emitter.emit("LFC-MODEL-006", cand.line, f"state {cand.name} is unreachable from {initials[0].name}", m.name)


def validate_text(text: str, *, source: str, catalog: dict[str, CatalogEntry]) -> ValidationReport:
    emitter = Emitter(source, catalog)
    models = parse_bundle(text, emitter)
    validate_models(models, emitter)
    return ValidationReport(source, models, emitter.diagnostics)


def validate_path(path: Path, catalog: dict[str, CatalogEntry]) -> ValidationReport:
    emitter = Emitter(str(path), catalog)
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        emitter.emit("LFC-SYNTAX-001", 0, str(error))
        return ValidationReport(str(path), [], emitter.diagnostics)
    except OSError as error:
        emitter.emit("LFC-IO-001", 0, str(error))
        return ValidationReport(str(path), [], emitter.diagnostics)
    return validate_text(text, source=str(path), catalog=catalog)


def render_text(report: ValidationReport) -> str:
    if report.valid:
        rows = [f"VALID {s['name']} v{s['version']} states={s['state_count']} events={s['event_count']} transitions={s['transition_count']} rejects={s['reject_count']}" for s in (x.summary() for x in report.lifecycles)]
        return "\n".join([*rows, f"PASS {report.source}: {len(report.lifecycles)} lifecycle(s)"])
    ordered = sorted(report.diagnostics, key=lambda d: (d.line, d.code, d.document or "", d.detail))
    rows = [f"{d.path}:{d.line} {d.code} {d.severity}: {d.message} ({d.detail})" for d in ordered]
    return "\n".join([*rows, f"FAIL {report.source}: {len(ordered)} diagnostic(s)"])


def audit_compaction(text: str, *, source: str = "<memory>", catalog: dict[str, CatalogEntry] | None = None) -> dict[str, Any]:
    from lifecycle_audit import audit_compaction_impl
    return audit_compaction_impl(text, source=source, catalog=catalog)


def audit_path(path: Path, catalog: dict[str, CatalogEntry] | None = None) -> dict[str, Any]:
    from lifecycle_audit import audit_path_impl
    return audit_path_impl(path, catalog)


def render_audit_text(audit: dict[str, Any]) -> str:
    from lifecycle_audit import render_audit_text_impl
    return render_audit_text_impl(audit)


def default_catalog_path() -> Path:
    return Path(__file__).resolve().parents[1] / "errors" / "catalog.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lifecycle", description="Validate Lifecycle DSL v1")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("validate", "validate one lifecycle bundle"), ("audit", "audit one lifecycle bundle")):
        sub = subcommands.add_parser(name, help=help_text)
        sub.add_argument("path", type=Path)
        sub.add_argument("--format", choices=("text", "json"), default="text")
        sub.add_argument("--catalog", type=Path)
    try:
        args = parser.parse_args(argv)
        catalog = load_catalog(args.catalog) if args.catalog else embedded_catalog()
        if args.command == "audit":
            audit = audit_path(args.path, catalog)
            print(json.dumps(audit, indent=2, sort_keys=True) if args.format == "json" else render_audit_text(audit))
            return 0 if audit["valid"] else 1
        report = validate_path(args.path, catalog)
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True) if args.format == "json" else render_text(report))
        return 0 if report.valid else 1
    except CatalogError as error:
        print(str(error), file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 - fail closed at the CLI trust boundary
        print(f"lifecycle internal error: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
