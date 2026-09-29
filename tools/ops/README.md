# Operations tools

## oc-ntp-nearest

Run this on each host whose clock matters: the cores and their VMs. It finds the nearest good NTP servers from that host and makes chrony use them.

- **What it measures:**
  - Each candidate address gets a few SNTP queries: round-trip delay, stratum, leap status and refid.
  - It drops unsynchronised servers and kiss-o'-death replies.
  - It never offers leap-smearing servers (Google, AWS, Facebook), because chrony can't mix smeared and unsmeared time.
- **Dry run** (prints the table and the sources it would write): `tools/ops/oc-ntp-nearest [--ipv6] [--count 4]`
- **Apply** (as root): `sudo tools/ops/oc-ntp-nearest --apply [--ipv6]`
  - It writes `/etc/chrony/sources.d/opencell-nearest.sources` with the best `--count` servers.
  - It comments out the distribution's default `pool` line, unless `--keep-pool` is given, then restarts or reloads chrony.
  - It waits for a source to be selected, then prints `chronyc sources`, `tracking` and the NTS state.
  - NTS-capable servers (Cloudflare, TimeNL, Netnod) are written with `nts`.
- **Undo:** remove the sources file and uncomment the pool line in `/etc/chrony/chrony.conf`. `--apply` doesn't back up the config itself; take a copy before the first run (e.g. `sudo cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.bak-oc-ntp`).

**First run (2026-09-29).** Both cores chose Cloudflare over NTS:

| Host | Location | Cloudflare delay | Backups |
|---|---|---|---|
| oc-core-1 | VM on the Proxmox host, Virginia | 1.8 ms | a pool server (6.6 ms), NIST stratum 1 (43 ms) |
| oc-core-2 | OVH VPS, Oregon, using IPv6 | 4.6 ms | a pool server (4.6 ms), NIST stratum 1 (31 ms) |

`ntp.ovh.net` resolves to France (about 120 ms) and is never nearest from the US.
