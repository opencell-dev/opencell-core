# OpenCell network core (oc-core)

The central network software of [OpenCell](https://github.com/opencell-dev/opencell): subscriber database (HSS/AuC with MILENAGE), activation, registration, call routing and switching, the echo service, and — for several servers — asynchronous replication, block (NPA) transfer between tenants and OCSS, the core-to-core signalling system.

Status: design approved, implementation not started.

- Design: `docs/superpowers/specs/2026-09-27-network-core-design.md`
- First plan: `docs/superpowers/plans/2026-09-27-net-core-1-lc-core.md` (`oc_core` and the async network side of `oc_sig`, host-only)
- Deployment target: a Debian 13 VM on the Proxmox server (spec §16).

The core shares the `oc_sig` signalling library with the terminal firmware in [opencell-firmware](https://github.com/opencell-dev/opencell-firmware); how the two repositories share it is decided when the first plan runs.
