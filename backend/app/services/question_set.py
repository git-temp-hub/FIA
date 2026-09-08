"""
The department's twenty forensic questions, as posed to the platform.

These are the phrasings the batch harness (``scripts/run_question_set.py``)
submits. They are held here rather than in the harness so that the routing
table and the questions it is meant to serve stay together and can be checked
against each other by a test.

The wording is derived from the department's question-to-plugin mapping, not
copied verbatim from their document. Where a question is reworded on their
side, change it here: routing is keyword-driven, so a rephrasing that drops a
keyword changes which evidence is searched.

``expected`` records the route each question must reach. That is the harness's
first assertion: an answer drawn from the wrong evidence can still read well,
so routing is verified before the answer is judged.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DepartmentQuestion:
    """One question, and the route it is expected to reach."""

    qid: str
    question: str
    expected: str


QUESTIONS: tuple[DepartmentQuestion, ...] = (
    DepartmentQuestion(
        "Q1",
        "Identify suspicious and malicious processes, including abnormal "
        "process execution and process relationships",
        "Q1",
    ),
    DepartmentQuestion(
        "Q2",
        "Is there evidence of code injection, process hollowing, or "
        "in-memory execution",
        "Q2",
    ),
    DepartmentQuestion(
        "Q3",
        "Is there evidence of LSASS access or credential dumping activity",
        "Q3",
    ),
    DepartmentQuestion(
        "Q4",
        "Was PowerShell, CMD, WMI or other scripting used to execute "
        "commands, including encoded commands",
        "Q4",
    ),
    DepartmentQuestion(
        "Q5",
        "What command history or console activity was recorded before "
        "acquisition",
        "Q5",
    ),
    DepartmentQuestion(
        "Q6",
        "What network connections were present, and which processes owned "
        "them",
        "Q6",
    ),
    DepartmentQuestion(
        "Q7",
        "Do any network connections correlate with the known malicious IP "
        "range 109.21.12.0/24",
        "Q7",
    ),
    DepartmentQuestion(
        "Q8",
        "Is there evidence of headless Chrome or browser automation such as "
        "chromedriver or remote-debugging",
        "Q8",
    ),
    DepartmentQuestion(
        "Q9",
        "What M365 or browser authentication and session artifacts are "
        "present",
        "Q9",
    ),
    DepartmentQuestion(
        "Q10",
        "Is any malware or suspicious executable communicating with external "
        "infrastructure",
        "Q10",
    ),
    DepartmentQuestion(
        "Q11",
        "Are there indications of Mimikatz, Potato-family privilege "
        "escalation tools, or credential dumping",
        "Q11",
    ),
    DepartmentQuestion(
        "Q12",
        "Are there indicators of APT28 or a tunnel implant, and can this "
        "activity be attributed to that threat actor",
        "Q12",
    ),
    DepartmentQuestion(
        "Q13",
        "Is there evidence of cryptomining or CoinMiner activity",
        "Q13",
    ),
    DepartmentQuestion(
        "Q14",
        "Identify persistence mechanisms and suspicious autorun or scheduled "
        "execution",
        "Q14",
    ),
    DepartmentQuestion(
        "Q15",
        "Were any remote access, lateral movement, or administration tools "
        "present on this system",
        "Q15",
    ),
    DepartmentQuestion(
        "Q16",
        "Is there evidence of Cobalt Strike or other post-exploitation "
        "frameworks",
        "Q16",
    ),
    DepartmentQuestion(
        "Q17",
        "Are there suspicious files, DLLs or executable artifacts, including "
        "unsigned or non-standard modules",
        "Q17",
    ),
    DepartmentQuestion(
        "Q18",
        "What YARA signature matches were found and what malware do they "
        "indicate",
        "Q18",
    ),
    DepartmentQuestion(
        "Q19",
        "Is there evidence of compromised accounts or unauthorized access, "
        "including privilege context",
        "Q19",
    ),
    DepartmentQuestion(
        "Q20",
        "Give an integrated assessment of this incident: what happened, in "
        "what order, and what is the overall forensic conclusion",
        "Q20",
    ),
)


__all__ = ["DepartmentQuestion", "QUESTIONS"]
