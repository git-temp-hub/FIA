# Indicator sets

Department-supplied network indicators, correlated against collected network
evidence by `app/services/ioc_matching.py`.

**This directory ships empty on purpose.** No threat-actor indicator lists are
bundled with the platform. An invented indicator produces a confident answer
about infrastructure that does not exist, and an attribution question answered
from fabricated indicators is worse than one left unanswered. Where a question
needs a set that has not been supplied, the model is told so and the question
is reported as unanswerable rather than guessed at.

## Format

One JSON file per set. Any `*.json` file here is loaded at answer time.

```json
{
  "name": "APT28 infrastructure",
  "source": "CERT-XX advisory 2026-041, retrieved 2026-09-08",
  "networks": [
    "203.0.113.0/24",
    "198.51.100.17"
  ]
}
```

| Field | Meaning |
|---|---|
| `name` | Shown in the prompt and in the answer's provenance. |
| `source` | Where the indicators came from, and when. Record this — an indicator without provenance cannot be defended in a report. |
| `networks` | IPv4/IPv6 addresses or CIDR ranges. A bare address is treated as a single host. |

Unparseable entries are skipped with a warning rather than failing the load, so
one malformed line cannot take out a whole set.

## Matching semantics

Addresses are parsed with Python's `ipaddress` module and tested for numeric
containment. There is no string or fuzzy matching: `109.21.12.44` matches
`109.21.12.0/24` and `109.21.120.44` does not.

Both endpoints of each connection are tested. A match on the remote address
means the host communicated with the range; a match on the local address means
the host itself held an address in it. These are different findings and are
reported separately.

## What a negative result means

When network evidence was collected and no address falls in the range, that is
a **meaningful negative** and is reported as one. When no network evidence was
collected, membership could not be evaluated at all, and that is reported as an
unperformed check — never as an absence of activity.

The check covers connections still resident in memory at acquisition. A
connection that closed early enough for its structures to be reused will not
appear, and the answer says so.

## Adding a set

Drop a JSON file here. No restart is required — sets are read at answer time.
Prefer one file per source so provenance stays attached, and keep the `source`
field accurate: it is the difference between a finding an analyst can defend
and one they cannot.
