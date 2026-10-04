# Paths

### P-001
- title: iOS HTTPS capture callflow
- path_type: callflow
- start: An authorized target App sends an HTTPS request
- goal: ProxyPin displays and exports the decrypted HTTP request and response
- steps:
  1. action: Manager selects the target Bundle ID and enables the injection module — evidence: E-005 — finding: F-003
  2. action: Hook dylib accepts the user-trusted ProxyPin certificate at the applicable trust layer — evidence: E-002, E-005 — finding: F-001
  3. action: ProxyPin Packet Tunnel routes HTTP/HTTPS traffic through its proxy — evidence: E-003 — finding: F-002
  4. action: ProxyPin records, filters, rewrites or exports the request — evidence: E-003, E-004 — finding: F-002
  5. action: Optional per-App adapter observes application-layer encryption before or after crypto calls — evidence: E-005 — finding: F-004
- residual_risks: QUIC without TCP fallback, statically linked native TLS, jailbreak detection, target-specific payload encryption, and untested iOS versions.
