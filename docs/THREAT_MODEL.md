# Threat Model - LogSentinel itself (STRIDE)

| # | Threat | STRIDE | Mitigation | Residual risk |
|---|---|---|---|---|
| 1 | Attacker plants `<script>` in username / User-Agent so it executes when the analyst opens the report | Tampering / Elevation | `html.escape` on every log-derived field; unit test `test_attacker_controlled_fields_are_escaped_in_html` | Low |
| 2 | Attacker forges log lines to frame another IP | Spoofing | Out of scope for the tool - protect log integrity (remote syslog, append-only storage); allowlist for known hosts | Medium |
| 3 | Attacker deletes or truncates logs before analysis | Repudiation | Recommend centralised log shipping; tool reports only on what it receives | Medium |
| 4 | Huge or crafted log file exhausts memory / CPU | Denial of service | Linear passes, simple regexes without nested quantifiers; files are read as text with `errors="replace"`. Very large logs should be split by day | Low-Medium |
| 5 | Blocklist applied blindly blocks legitimate users (shared NAT) | Denial of service | No auto-blocking; header says "review before applying"; scores and evidence included | Low |
| 6 | Attacker stays below thresholds ("low and slow") | Evasion | Configurable windows; documented limitation | Medium |
| 7 | Reports contain attacker IPs and usernames (sensitive) | Information disclosure | Keep `output/` out of git (`.gitignore`); share only sanitised samples | Low |
