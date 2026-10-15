"""Markdown case report with a disclosure checklist naming the DFINITY channels.

DFINITY contact facts (checked 2026-10-15, OPEN_QUESTIONS.md T16):

* Protocol vulnerabilities: report through HackenProof, per https://dfinity.org/bug-bounty
  ("Reports sent to DFINITY email addresses are not monitored").
* Malicious canisters (Code of Conduct for the icp0.io / ic0.app boundary nodes): the
  DFINITY support article below. It could not be fetched automatically (HTTP 403), so the
  checklist tells the operator to confirm it before use. Nothing is invented.
"""

from icp_threat_intel.core.models import Case
from icp_threat_intel.publishing.case import GatedExporter

DFINITY_ABUSE_URL = (
    "https://support.dfinity.org/hc/en-us/articles/6365309327380-I-came-across-a-malicious-"
    "website-or-scam-on-the-Internet-Computer-How-do-I-report-the-violation"
)
DFINITY_BUG_BOUNTY_URL = "https://dfinity.org/bug-bounty"
DFINITY_CONTACT = (
    f"DFINITY Code of Conduct report for malicious canisters: {DFINITY_ABUSE_URL} "
    "(UNVERIFIED: confirm the channel before sending); protocol vulnerabilities only via "
    f"HackenProof as described at {DFINITY_BUG_BOUNTY_URL} (DFINITY email is not monitored)"
)


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def checklist(case: Case) -> list[str]:
    contact = case.disclosure_contact or DFINITY_CONTACT
    disclosed = case.disclosed_at.isoformat() if case.disclosed_at else "NOT DISCLOSED"
    return [
        "## Disclosure checklist",
        "",
        f"- [x] Disclosed to DFINITY at {disclosed}",
        f"- [ ] DFINITY security contact used: {contact}",
        "- [ ] Every detection is `verified` (two signals from different source types)",
        "- [ ] Body excerpts reviewed: no secrets, nothing executable left in the report",
        "- [ ] ThreatFox policy: only vetted IOCs, none older than 10 days, submitted by hand",
        "- [ ] MISP event reviewed before raising distribution above 0",
        "- [ ] No package or sample was uploaded anywhere (guardrail 6)",
    ]


class MarkdownExporter(GatedExporter):
    format = "markdown"

    def render(self, case: Case) -> bytes:
        lines = [
            f"# {case.title}",
            "",
            f"Case `{case.case_id}`, created {case.created_at.isoformat()}.",
        ]
        if case.summary:
            lines += ["", case.summary]
        lines += ["", "## Detections", ""]
        if case.detections:
            lines += ["| Rule | Subject | Score | Confidence | Signals | Evidence |",
                      "|---|---|---|---|---|---|"]  # fmt: skip
            for d in case.detections:
                evidence = ", ".join(f"{r.source_type.value}#{r.id}" for r in d.evidence_refs)
                lines.append(
                    f"| {d.rule_id} | `{_cell(d.subject_id)}` | {d.score:.2f} | "
                    f"{d.weighted_confidence:.2f} | {_cell(', '.join(sorted(d.signals)))} | "
                    f"{_cell(evidence)} |"
                )
                lines.append(f"|  | {_cell(d.explanation)} |  |  |  |  |")
        else:
            lines.append("None.")
        lines += [
            "",
            "## Indicators",
            "",
            "| Type | Value | Source | Reference |",
            "|---|---|---|---|",
        ]
        for i in case.iocs:
            lines.append(
                f"| {i.ioc_type.value} | `{_cell(i.value)}` | {i.source_type.value}:"
                f"{_cell(i.source_ref)} | {_cell(i.source_url or '-')} |"
            )
        lines += ["", *checklist(case), ""]
        return "\n".join(lines).encode()
