# Threat Model: Vigía

**Version:** 0.1  
**Scope:** Small business web infrastructure monitored by Vigía, and the Vigía platform itself.

---

## 1. Assets to Protect

| Asset | Description | Why it matters |
|---|---|---|
| Public web application | Company website, login portal, APIs | Main entry point for attackers |
| SSH-accessible servers | Linux servers managed remotely | Full system compromise if breached |
| User credentials | Employee and customer accounts | Enable account takeover and lateral movement |
| Business database | Customer data, orders, records | Data breach, legal and reputational impact |
| Logs | Evidence of activity on all systems | Without them, attacks are invisible |

## 2. Threat Actors

- **Opportunistic attackers / bots**: automated scanners and credential-stuffing botnets hitting any exposed IP.
- **Low-skill attackers**: people using public tools (sqlmap, Hydra, Nikto) against known weaknesses.
- **Targeted attackers**: less common for SMBs, but capable of chaining several techniques.

## 3. Threats to Detect (MVP)

| # | Threat | MITRE ATT&CK | Data source | Detection signal | Severity |
|---|---|---|---|---|---|
| 1 | SSH brute force | T1110.001 – Password Guessing | `auth.log` | ≥ 10 failed logins from the same IP within 60 s | High |
| 2 | Credential stuffing on web login | T1110.004 – Credential Stuffing | nginx / app logs | Many `POST /login` failures from one IP across different usernames | High |
| 3 | SQL injection attempts | T1190 – Exploit Public-Facing Application | nginx access log | Payloads like `' OR 1=1`, `UNION SELECT`, `SLEEP(` in URL or parameters | Critical |
| 4 | Path traversal / LFI | T1190 – Exploit Public-Facing Application | nginx access log | `../`, `%2e%2e%2f`, `/etc/passwd` in requested paths | High |
| 5 | Vulnerability and directory scanning | T1595.002 / T1595.003 – Active Scanning | nginx access log | Burst of 404 responses from one IP, or known scanner User-Agents (Nikto, sqlmap, gobuster) | Medium |

## 4. Threats to Vigía Itself

Vigía is a security tool, so it is a target too.

| Threat | Risk | Planned mitigation |
|---|---|---|
| Unauthorized dashboard access | Attacker reads or deletes alerts | Authentication, hashed passwords (argon2), role-based access |
| Leaked ingestion API keys | Fake logs injected to hide attacks | Per-source API keys, rotation, rate limiting |
| Log injection / XSS via log content | Malicious strings rendered in dashboard | Treat all log data as untrusted, escape output, strict CSP |
| Denial of service on ingestion | Flooding the API to blind detections | Rate limiting and payload size limits |

## 5. Out of Scope (MVP)

- Malware and endpoint (EDR) detection
- Network packet inspection (IDS/IPS)
- Cloud provider logs (AWS CloudTrail, Azure), planned for future versions

## 6. Purple Team Validation

Each threat in section 3 will have:

1. **A red team script** in `attack-sim/` that emulates the technique in the isolated lab.
2. **A blue team rule** in `detections/` that detects it.
3. **A test result** in the coverage report confirming that the rule fired.