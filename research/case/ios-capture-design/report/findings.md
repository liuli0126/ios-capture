# Findings

### F-001
- title: The supplied Android JS is a TLS-unpinning layer, not a packet-capture engine
- severity: n/a_re
- category: reverse_algo
- status: validated
- evidence_ids: [E-001, E-002]
- location: Android(1).js SSLContext/TrustManagerImpl/CertificatePinner hooks
- impact: The iOS project must retain a separate proxy/VPN capture component.
- confidence: high
- repro_steps:
  1. Hash the supplied JS.
  2. Search its hook targets and protocol strings.
- remediation: n/a
- optional_attack:

### F-002
- title: ProxyPin can serve as the first iOS capture layer
- severity: n/a_re
- category: design
- status: validated
- evidence_ids: [E-003, E-004]
- location: ProxyPin iOS PacketTunnelProvider and VPN entitlements
- impact: The first product version can focus on injection, compatibility and management instead of rebuilding an HTTP proxy.
- confidence: high
- repro_steps:
  1. Inspect the pinned PacketTunnelProvider source.
  2. Inspect release v1.3.3 and iOS project settings.
- remediation: Keep ProxyPin separately installed until redistribution and update contracts are defined.
- optional_attack:

### F-003
- title: A single universal iOS package is not a reliable delivery model
- severity: n/a_re
- category: design
- status: candidate
- evidence_ids: [E-004, E-005]
- location: rootful/rootless injection and ProxyPin iOS deployment boundary
- impact: iOS 13 rootful and iOS 15+ rootless need separate package paths and validation.
- confidence: medium
- repro_steps:
  1. Compare supported jailbreak injection frameworks and package roots.
  2. Validate each build on physical devices.
- remediation: Use a front-end installer that selects a separately built rootful or rootless package.
- optional_attack:

### F-004
- title: Custom request-body encryption requires per-App adapters
- severity: n/a_re
- category: design
- status: validated
- evidence_ids: [E-002, E-005]
- location: capture layer versus application crypto layer
- impact: TLS bypass exposes transport plaintext, but cannot automatically decode a second encrypted payload format.
- confidence: high
- repro_steps:
  1. Confirm TLS hooks do not contain protocol-specific payload algorithms.
  2. Observe request bodies in an authorized test App after TLS unpinning.
- remediation: Add opt-in CommonCrypto/Security hooks and target-specific decoding rules.
- optional_attack:

### F-005
- title: The previous direct build could launch while all C hooks remained inactive
- severity: n/a_re
- category: implementation
- status: validated
- evidence_ids: [E-006, E-007]
- location: direct-injection Hook runtime resolution
- impact: Resolving only Substrate paths is insufficient on Dopamine/ElleKit and can present as a successful injection with no captured traffic.
- confidence: high
- repro_steps:
  1. Compare Dopamine's rootless ElleKit path with the v0.1.4 candidate paths.
  2. Build v0.1.5 and confirm explicit `libellekit.dylib` runtime resolution.
- remediation: Resolve ElleKit first, expose Hook count in the target App, and rescan when new Mach-O images load.
- optional_attack:
