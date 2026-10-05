# Work Items

| ID | title | role | targets | surface | status | evidence | notes |
|----|-------|------|---------|---------|--------|----------|-------|
| WI-001 | Establish corrected iOS scope and auth | lead | case | process | done | scope.md | AppleLive is out of scope |
| WI-002 | Identify Android APK and JS reference roles | lead | supplied samples | static | done | E-001, E-002 | Reference behavior only |
| WI-003 | Confirm ProxyPin iOS capture architecture | lead | public ProxyPin source | architecture | done | E-003, E-004 | Packet Tunnel and entitlements confirmed |
| WI-004 | Map Android Hook layers to iOS | lead | proposed product | architecture | done | E-002, E-005 | Security.framework through native TLS |
| WI-005 | Produce reproducible prototype guide | lead | proposed product | documentation | done | E-003, E-004 | Separate iOS 13/14 and 15+ paths |
| WI-006 | Define compatibility and delivery plan | lead | proposed product | packaging | done | E-004, E-005 | Separate rootful/rootless packages |
| WI-007 | Research modern Dopamine and TTNet trust paths | lead | public source | static | done | E-006 | ElleKit, TTHttpTask, async trust, QUIC |
| WI-008 | Build and verify v0.1.5 rootless artifacts | lead | iOS 15+ package | build | done | E-007 | Runtime device capture remains pending |

## Coverage
- [x] Recon/analysis complete for in-scope reference assets
- [x] Critical/High candidates triaged as N/A for architecture-only assessment
- [x] Findings have Evidence
- [x] Callflow Path documented
- [x] Timeline continuous across major phases
- [x] Report written
- [ ] Physical iPhone prototype tested
- [x] field-journal written (anonymized)
