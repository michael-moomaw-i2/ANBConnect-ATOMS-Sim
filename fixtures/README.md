# ATOMS simulator fixtures

`example-nodes-store.json` is the deterministic acceptance fixture for the ANBConnect **ATOMS Example Test**.

It is derived from the Query for Nodes example in `docs/Example GraphQL Queries.pdf`, with one supplemental cross-node relationship added to prove normal link endpoint wiring. The original self-links remain present.

Use the reset script rather than copying this file manually:

```powershell
.\scripts\reset-store.ps1 -Profile ExampleNodes
```
