# YARA rules

Rules used by `windows.vadyarascan` during investigation. Everything under
`vendor/` is downloaded unmodified from public repositories; anything under
`derived/` is a documented modification of a vendor rule.

## Provenance

| File | Rules | Origin | Licence |
|---|---|---|---|
| `vendor/gen_mimikatz.yar` | 11 | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — Florian Roth / Nextron Systems | DRL 1.1 |
| `vendor/gen_invoke_mimikatz.yar` | 1 | Neo23x0/signature-base | DRL 1.1 |
| `vendor/gen_gcti_cobaltstrike.yar` | 88 | Neo23x0/signature-base — authored by Google Cloud Threat Intelligence | DRL 1.1 |
| `vendor/crime_crypto_miner.yar` | 2 | Neo23x0/signature-base | DRL 1.1 |
| `vendor/gen_remote_potato0.yar` | 1 | Neo23x0/signature-base — authored by SentinelOne | DRL 1.1 |
| `vendor/MALW_XMRIG_Miner.yar` | 1 | [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | GPL-2.0 |
| `derived/remote_potato0_memory.yar` | 1 | Adapted from `vendor/gen_remote_potato0.yar` | DRL 1.1 (inherited) |

[Detection Rule License 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE)
places no non-commercial restriction on use. The single GPL-2.0 file is kept
separable in case that licence is ever inconvenient.

## Memory-scanning caveat

Some vendor rules were written to scan **files** and use conditions that cannot
be satisfied when scanning **memory**:

- `uint16(0) == 0x5A4D` requires an MZ header at offset 0. A VAD region is an
  arbitrary slice of process memory, so this is effectively never true.
- `filesize` is undefined when scanning a memory buffer.

Measured across the sourced set: **98 of 104 rules can fire against memory.**
The six that cannot are both CoinMiner rules, the original Potato rule, and
three Mimikatz rules.

Deliberate decisions:

- **Potato** — adapted (`derived/`). Its remaining condition requires four
  independent indicators, so dropping the file-header guard does not
  meaningfully weaken it.
- **CoinMiner** — left unmodified, accepting zero coverage. Their strings
  (`xmrig.exe`, `miner running`) are generic, and the `filesize` guards were
  doing real false-positive suppression. Removing them would fire on any
  antivirus signature database resident in memory.

## False positives are expected

A raw-memory test scan matched `XMRIG_Miner` (whose whole condition is the
single string `stratum+tcp`) inside what appeared to be Microsoft Defender's
signature database — adjacent bytes contained `!Emotet.PAN!MTB` and similar
Defender signature names.

This is why scanning uses `windows.vadyarascan` rather than raw `yarascan`:
VAD scanning attributes each hit to an owning PID and process name, which is
what makes a hit triageable. A match inside `MsMpEng.exe` is an antivirus
definition; the same match inside `rundll32.exe` is worth investigating.

**A YARA hit is a lead, not a conclusion.** Hits are classified as
medium severity and require corroborating evidence before being reported as a
finding.
