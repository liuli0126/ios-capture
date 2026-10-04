# Case Scope

## meta
- case_id: ios-capture-design
- created: 2026-10-04T17:51:54+08:00
- corrected: 2026-10-04T18:08:00+08:00
- operator: local
- project_root: E:\1\ios-capture
- primary_skill: mobile-reverse/SKILL.md
- secondary_skill: apk-reverse/SKILL.md
- lead_role: lead
- specialist_roles: []
- hint: Design a standalone jailbreak iOS packet-capture plugin using the functional layering of the supplied Android ProxyPin, Xposed/Frida APK and Hook JS as references only
- preset: owner-operated-reference-samples

## auth
- status: granted
- basis: own_system
- evidence_of_auth: user supplied local samples and requested analysis/design for their own project
- MUST NOT proceed if status != granted

## in_scope
- assets:
  - C:\Users\15911\Downloads\算法助手Pro.apk
  - C:\Users\15911\Downloads\Android(1).js
  - https://github.com/wanghongenpin/proxypin (public source and release metadata)
- surfaces: [Android reference static structure, supplied TLS Hook JS, public ProxyPin iOS Packet Tunnel implementation, jailbreak iOS product architecture]
- activities: [offline static analysis, public-source review, architecture design, operator workflow design, compatibility planning]

## out_of_scope
- assets: [AppleLive source and binaries, third-party target App binaries, user traffic]
- activities: [live interception, credential collection, unrestricted exfiltration, modifying AppleLive, injecting unapproved target Apps]

## network_profile
- mode: lab_only
- notes: Public GitHub source and release metadata review only. No target device or target service traffic.

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {}
- stealth: low
- data_handling: anonymize

## signoff
- ready_for_act: true
- checklist:
  - [x] auth.status = granted
  - [x] in_scope assets non-empty
  - [x] network_profile.mode chosen
  - [x] out_of_scope reviewed
  - [x] roles assigned

## ops_refs
- skills/ops/scope-contract.md
- skills/ops/evidence-finding-path.md
- skills/ops/role-map.md
- skills/ops/timeline-workitem.md
