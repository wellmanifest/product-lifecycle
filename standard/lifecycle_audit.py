"""Static compaction analyzer for Lifecycle DSL v1 bundles."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lifecycle import CatalogEntry, ValidationReport

AUDIT_SCHEMA = "lifecycle.compaction-audit/v1"


def _finding(
    code: str, document: str, message: str, suggestion: str, saved: int
) -> dict[str, Any]:
    return {
        "code": code,
        "document": document,
        "message": message,
        "suggestion": suggestion,
        "estimated_lines_saved": saved,
    }


def audit_from_report(report: ValidationReport) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for model in report.lifecycles:
        doc: list[dict[str, Any]] = []
        plain = [
            s.name
            for s in model.uncompacted_states
            if not s.initial and not s.terminal
        ]
        if len(plain) >= 3:
            doc.append(
                _finding(
                    "LFC-COMPACT-001",
                    model.name,
                    f"{len(plain)} plain STATE declarations can be compacted into STATES [...]",
                    f"STATES [{', '.join(plain)}]",
                    len(plain) - 1,
                )
            )
        terms = [
            s.name for s in model.uncompacted_states if not s.initial and s.terminal
        ]
        if len(terms) >= 2:
            doc.append(
                _finding(
                    "LFC-COMPACT-001",
                    model.name,
                    f"{len(terms)} terminal STATE declarations can be compacted into STATES [...] TERMINAL",
                    f"STATES [{', '.join(terms)}] TERMINAL",
                    len(terms) - 1,
                )
            )
        if len(model.uncompacted_events) >= 3:
            ev = model.uncompacted_events
            doc.append(
                _finding(
                    "LFC-COMPACT-002",
                    model.name,
                    f"{len(ev)} EVENT declarations can be compacted into EVENTS [...]",
                    f"EVENTS [{', '.join(ev)}]",
                    len(ev) - 1,
                )
            )
        if len(model.uncompacted_evidence) >= 3:
            evd = model.uncompacted_evidence
            doc.append(
                _finding(
                    "LFC-COMPACT-003",
                    model.name,
                    f"{len(evd)} EVIDENCE declarations can be compacted into EVIDENCES [...]",
                    f"EVIDENCES [{', '.join(evd)}]",
                    len(evd) - 1,
                )
            )
        tr_groups: dict[tuple[str, str, str | None], list[str]] = {}
        for tr in model.uncompacted_transitions:
            grp = tr_groups.setdefault((tr.target, tr.event, tr.evidence), [])
            if tr.source not in grp:
                grp.append(tr.source)
        for (tgt, ev_name, req_ev), srcs in tr_groups.items():
            if len(srcs) >= 2:
                req = f" REQUIRES {req_ev}" if req_ev else ""
                doc.append(
                    _finding(
                        "LFC-COMPACT-004",
                        model.name,
                        f"{len(srcs)} transitions into {tgt} on {ev_name} share identical target/event/evidence",
                        f"TRANSITION [{', '.join(srcs)}] -> {tgt} ON {ev_name}{req}",
                        len(srcs) - 1,
                    )
                )
        rj_groups: dict[tuple[str, str], list[str]] = {}
        for rj in model.uncompacted_rejects:
            rgrp = rj_groups.setdefault((rj.event, rj.error), [])
            if rj.state not in rgrp:
                rgrp.append(rj.state)
        for (ev_name, err_code), sts in rj_groups.items():
            if len(sts) >= 2:
                doc.append(
                    _finding(
                        "LFC-COMPACT-005",
                        model.name,
                        f"{len(sts)} reject rules on {ev_name} with {err_code} can be compacted",
                        f"REJECT [{', '.join(sts)}] ON {ev_name} WITH {err_code}",
                        len(sts) - 1,
                    )
                )
        findings.extend(doc)
        summaries.append(
            {
                "name": model.name,
                "state_count": len(model.states),
                "event_count": len(model.events),
                "evidence_count": len(model.evidence),
                "transition_count": len(model.transitions),
                "reject_count": len(model.rejects),
                "batch_states": model.batch_state_count,
                "batch_events": model.batch_event_count,
                "batch_evidence": model.batch_evidence_count,
                "state_set_transitions": model.state_set_transition_count,
                "state_set_rejects": model.state_set_reject_count,
                "finding_count": len(doc),
            }
        )
    return {
        "schema": AUDIT_SCHEMA,
        "source": report.source,
        "valid": report.valid,
        "lifecycle_count": len(report.lifecycles),
        "finding_count": len(findings),
        "estimated_lines_saved": sum(f["estimated_lines_saved"] for f in findings),
        "lifecycles": summaries,
        "findings": findings,
        "diagnostics": report.as_dict()["diagnostics"],
    }


def audit_compaction_impl(
    text: str,
    *,
    source: str = "<memory>",
    catalog: dict[str, CatalogEntry] | None = None,
) -> dict[str, Any]:
    import lifecycle

    active = catalog if catalog is not None else lifecycle.embedded_catalog()
    return audit_from_report(lifecycle.validate_text(text, source=source, catalog=active))


def audit_path_impl(
    path: Path, catalog: dict[str, CatalogEntry] | None = None
) -> dict[str, Any]:
    import lifecycle

    active = catalog if catalog is not None else lifecycle.embedded_catalog()
    return audit_from_report(lifecycle.validate_path(path, active))


def render_audit_text_impl(audit: dict[str, Any]) -> str:
    header = (
        f"AUDIT {audit['source']}: lifecycles={audit['lifecycle_count']} "
        f"findings={audit['finding_count']} estimated_lines_saved={audit['estimated_lines_saved']}"
    )
    diags = [
        f"{d['path']}:{d['line']} {d['code']} {d['severity']}: {d['message']} ({d['detail']})"
        for d in audit.get("diagnostics", ())
    ]
    items = [
        f"- [{f['code']}] {f['document']}: {f['message']} => {f['suggestion']}"
        for f in audit["findings"]
    ]
    return "\n".join([header, *diags, *items])
