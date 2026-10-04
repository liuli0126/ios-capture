# Timeline (append-only)

## 2026-10-04T17:51:54.9682952+08:00 | lead | init
- action: case-init
- command_or_ref: skills/scripts/case-init.ps1
- result_summary: case directory created; scope ready_for_act=true
- artifacts: [scope.md, workitems.md]
- evidence_ids: []
- decision_delta: [case_initialized]
- carry_forward_refs: [scope.md]
- next: open PRIMARY SKILL.md and ACT within scope

## 2026-10-04T18:02:04+08:00 | lead | scope-correction
- action: Corrected the product target from an Android capture product to a standalone jailbreak iOS capture product; Android files remain reference samples only.
- command_or_ref: user clarification and route-20261004-180204
- result_summary: Mobile reverse is the applicable design workflow; AppleLive remains out of scope.
- artifacts: [scope.md]
- evidence_ids: []
- decision_delta: [target=standalone_iOS_capture, android_assets=reference_only]
- carry_forward_refs: [scope.md]
- next: map reference functions and confirm the iOS capture layer

## 2026-10-04T18:12:00+08:00 | lead | architecture
- action: Completed static reference mapping and public ProxyPin iOS source review.
- command_or_ref: supplied sample string review; GitHub API source and release metadata at ProxyPin commit 0de13228ac1f325558067625060c4b2c3379fc0e
- result_summary: ProxyPin Packet Tunnel can provide capture; a native iOS dylib and manager App provide unpinning, scope and diagnostics.
- artifacts: [evidence/E-001.md, evidence/E-002.md, evidence/E-003.md, evidence/E-004.md, evidence/E-005.md, findings.md, paths.md, report/analysis-report.md]
- evidence_ids: [E-001, E-002, E-003, E-004, E-005]
- decision_delta: [capture_layer=ProxyPin_iOS_or_desktop, hook_layer=native_iOS_dylib, delivery=rootful_and_rootless]
- carry_forward_refs: [scope.md, workitems.md]
- next: build a controlled iOS 15 rootless prototype and then the iOS 13 rootful variant
