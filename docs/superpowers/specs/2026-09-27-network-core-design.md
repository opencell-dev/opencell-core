# OpenCell: Network Core — Cell Daemon, HSS, Registry and Inter-Cell Switching (design)

**Status:** Approved 2026-09-27. The user accepted every recommended answer in §13 (recorded there as decisions) and added:
- deployment of `oc-core` in a VM on the user's Proxmox server (§16);
- several cores: a **home core** per numbering block with **asynchronous replicas**, block transfer between tenants (§14);
- an inter-core signalling system, **OCSS** (§15), specified here at the architecture level;
- numbering v2 (`numbering-plan.md` v0.2 and `2026-09-27-numbering-v2-design.md`, branch `numbers-v2`), applied to every number below.

Sections 1–13 keep their numbers from the draft; §14–16 are new.

**Builds on:** `2026-09-26-activation-registration-calls-design.md` (plan 5: `lc_sig`, `lcbench net`), plan 4 (`docs/superpowers/plans/2026-09-25-rhu-scheduler.md`, not yet implemented), `2026-09-23-lr2021-hardware-design.md`, `security-model.md`, `numbering-plan.md` v0.2 and `2026-09-27-numbering-v2-design.md` (branch `numbers-v2`), `architecture.md`.

## 1. Goals and scope

"Switching and routing" in OpenCell today means four things (from `architecture.md` §Network-Side Call State and plan-5 spec §5, §7, §11):

1. **The cell's network role on the Pi**, replacing `lcbench net`: drive the base-station W12s over lc_link (plan 4's scheduler), run `lc_sig_net` for every terminal the cell hears, and switch calls between two terminals of the same cell (already in `lc_sig_net`, `local_setup()` in `firmware/components/lc_sig/lc_sig_net.c`).
2. **A persistent HSS**: subscribers, activation tokens, TMID bindings, K, OPc and SQN, with the keys encrypted at rest. Today this is `lcb_hss`, a 0600 text file of at most 16 subscribers (`tools/lcbench/lcb_hss.h`).
3. **A location registry**: which cell (Pi) each registered number is on now.
4. **Inter-cell switching**: a call from a terminal on one Pi to a terminal on another Pi, with its app data (later voice) relayed between them.

Scope:

| Topic | Decision |
|---|---|
| In scope | 1–4 above; activation and registration through the core; MO/MT calls within a cell and across cells; busy, unreachable, no answer; a terminal moving between cells *while idle*; Pi, core and backhaul failures; an admin CLI that replaces `lcbench mkqr`. At the architecture level: several cores with home cores and replicas, block transfer (§14), inter-core signalling OCSS (§15), and the first server deployment (§16). |
| Out of scope | Voice codec and audio (app data frames stand in, as in plan 5); PSTN/SIP gateway (`numbering-plan.md` §Future); Direct Connect / push-to-talk (`direct-connect.md`); the web portal (the admin CLI stands in); handover of an *active* call between cells; paging across several cells; automatic failover between cores (promotion is an operator command, §14.4); OCSS message layouts (their own spec, §15.7); RF backhaul between base stations (plan 4 R11) as the core's transport; emergency calls (none: plan-5 spec §1). |
| Replaces from the 2026-05 vision | The central "phone RAN" that ran every call's signalling (`architecture.md` §Phone RAN Plane), RADIUS/EAP-AKA, Diameter, OAI HSS, etcd, Redis and PostgreSQL (`implementation-plan.md` Phases 2–4, §Technology Stack). Plan 5 already moved signalling into `lc_sig`; the core only needs what `lc_sig_net` cannot do alone. |

**Done means:**
- `oc-cell` + `oc-core` on one machine with board A replace `lcbench net`, and the plan-5 done list (plan-5 spec §1) passes again with T and T2.
- With two cells (board A and a second bs-radio board) and one core: T on cell 1 calls T2 on cell 2 — ring, connect, app data both ways, hang-up from each side, reject, busy, unreachable.
- T moves from cell 1 to cell 2 while idle; a call to T then rings on cell 2.
- Killing `oc-cell` on one cell, or the core, never leaves a half-open call on the other side for more than 10 s, and every terminal is registered again within one re-attach after the process is back.
- `oc-core` runs in its VM on the Proxmox server (§16) and a cell on the laptop or a Pi reaches it over the internet with mTLS.
- Later (plans 10–11): with two cores (the VM and the laptop), a call between cells on different cores; a block promoted on its secondary after its home core is stopped, with registrations continuing without a resync; a block transferred between the two cores.

## 2. What exists (the ground this stands on)

| Piece | Where | What it gives the core | Gap |
|---|---|---|---|
| `lc_sig_net` | `firmware/components/lc_sig/include/lc_sig_net.h`, `lc_sig_net.c` | Activation, MILENAGE registration and resync, call control, local terminal-to-terminal switching with per-leg voice keys, a far-end "peer" API (`lc_sig_net_peer_alert/answer/release`, `lc_sig_net_call_in`), app data in/out (`lc_sig_net_data_in/out`). Host-only C, no OS calls. | HSS access is **synchronous** (`by_token`, `by_tmid`, `by_number` return `lc_sig_sub_t *` and the library reads `sub->k`, `sub->opc`, `sub->sqn` itself, e.g. `new_av()`), and activation needs the network private key in `cfg.sk`. Only `LC_SIG_NET_TERMS` = 4 sessions. No event when a far-end MT leg rings, and `lc_sig_net_call_in` returns the same -1 for busy and unreachable. |
| `lc_sig_term` | `lc_sig_term.c` | The terminal registers again whenever it re-attaches after losing the cell (`lc_sig_term_link`, the "ruling in plan 5"): the key to surviving a Pi restart and to moving between cells. | — |
| `lcb_net` + `lcb_hss` + `lcb_cell` | `tools/lcbench/` | The working glue: `lc_sig_net_io_t` ↔ cell hooks (`on_ul`, `on_upper`), DL queue (`lcb_cell_dl_push`, 8 deep), page/grant/release on `channel(on/off)`, app data forwarding, simulated far end. Verified over the air with two W12s (commit 0ca8b22). | Laptop tool, at most 2 terminals (`LCB_CELL_MAX_TERMS`), one board, text-file HSS. |
| Plan 4 (`rhu_bs`) | `docs/superpowers/plans/2026-09-25-rhu-scheduler.md` | The Pi scheduler: CONFIG/TIME/SCHEDULE per W12, admission, persistent grants, paging, band policy, W12 reset, PPS gating; a fronthaul callback set (`rhu_fronthaul_t {up_data, up_rach, term_event}`, `rhu_bs_send_dl`, `rhu_bs_page`). | **Not implemented**: no commit mentions it on any branch (`git log --all --oneline | grep -i rhu` is empty in `~/Documents/opencell`). Written before plan 5: it ends at a loopback UDP fronthaul "to the phone RAN" (Task 9), keeps one DL payload per terminal (`rhu_term_t.dl_buf`), and has no idle attach and no grant release, all of which `lc_sig_net`'s `channel(on/off)` model needs (§10). |

## 3. Architecture options

### 3.1 Options

- **(A) Autonomous Pi.** One C daemon per Pi links the scheduler, `lc_sig_net` and an SQLite HSS holding every subscriber's K and OPc. A small central registry/switch joins cells for cross-cell calls and location. This is what plan-5 spec §11 assumed ("the Pi HSS and switch").
- **(B) Central core, thin Pi.** The Pi runs only the scheduler and forwards link payloads (plan 4's fronthaul datagrams `UP_DATA`, `UP_RACH`, `EVENT`, `DL_DATA`, `PAGE`, which map one-to-one onto `lc_sig_net_io_t`) over TLS to a central server that runs `lc_sig_net` for every cell, the HSS and the switch. This is the 2026-05 `architecture.md` model.
- **(C) Edge cell + home core (split HSS).** The Pi daemon (`oc-cell`) runs the scheduler, `lc_sig_net` sessions and local switching. A separate program (`oc-core`) owns the subscriber keys, activation, authentication vectors (AVs), the location registry and inter-cell switching. The cell asks the core for AVs, as an LTE MME asks the HSS. **For a single site both programs run on the Pi**, over a Unix socket. For several sites the core runs on a server and cells connect to it over mutually authenticated TLS.

### 3.2 Trade-offs

| | (A) Autonomous Pi | (B) Central core | (C) Edge + home core |
|---|---|---|---|
| Subscriber keys and network activation key on user-managed Pis (`architecture.md` §Responsibility Model: "Pi RHU hardware — User") | **Every Pi holds every K, OPc and SKn**: any Pi owner can clone any subscriber or impersonate the network. Homing each subscriber on one Pi instead makes that Pi a single point of failure and needs Pi-to-Pi connections through home NAT. | Only on the core | Only on the core. A cell sees CK/IK-derived session keys only for terminals it serves. |
| Works without backhaul | Fully | **Not at all**, not even calls within one cell | Registered terminals keep local calls; new registrations use cached AVs (§7.8); activation needs the core |
| Radio timing across the WAN | None | Every signalling fragment, every `channel()`/grant decision and every voice frame crosses the WAN. `lc_sig_net` expects `heard()` and `link()` updates every frame (`lcb_net_tick`) and drops an active call after 5 s without data | None |
| Local call path | On the Pi | Hairpins through the server | On the Pi |
| Pi restart | Loses in-memory sessions and calls; HSS persists | Loses the radio state only | Loses sessions and calls; the core notices (§7.9) |
| New code | Registry/switch service; HSS store | WAN fronthaul, many-cell `lc_sig_net` host, HSS, switch | Core (HSS, AV, registry, switch), cell↔core protocol, an **async HSS interface in `lc_sig_net`** (§4.3) |
| Reuses | `lcb_net` pattern almost as is | `lc_sig_net` unchanged, plan 4 Task 9 datagrams | `lcb_net` pattern; MILENAGE and activation KDF from `lc_sig` in the core |

### 3.3 Decision: (C), always two programs

- `oc-cell` (one per Pi) and `oc-core` (one per network) are **always separate processes speaking one protocol** (§6). A single-site network runs both on the Pi over a Unix socket; a multi-site network moves `oc-core` to a server and switches the transport to mTLS. No "local HSS" code path exists to diverge.
- This also keeps SQLite writes (with fsync on an SD card) out of the scheduler loop: plan 4 Review Focus 2 already warns that a stall past `schedule_lead_us` loses frames.
- It keeps the one thing (B) does well: keys never sit on a Pi someone else owns. And it keeps what (A) does well: the radio loop, sessions and local calls stay on the Pi.

```
 Terminal W12s        Pi (oc-cell)                                         Server or same Pi (oc-core)
 ─────────────        ──────────────────────────────────────────           ─────────────────────────────────
                LoRa  radio backend: lcb_cell (bench) | rhu_bs (plan 4)     HSS (SQLite, keys AES-GCM at rest)
 lc_sig_term  ◄─────► lc_sig_net sessions, local switching         core     activation (holds SKn), AV + resync
 lc_term              AV cache, leg table, core client           ◄──────►   location registry
                                                        Unix socket / mTLS  inter-cell switch + media relay
                                                                            echo service, CDR, audit, admin CLI
```

## 4. Components

### 4.1 `oc-cell` (Pi daemon)

- **Radio backend**, behind one small interface: `dl_push`, `page`, `release`, `granted`, and upward `on_ul`, `on_upper`, `on_link`.
  - `lcb_cell` over USB, as `lcbench net` does today: lets all of this proceed on the laptop with board A before plan 4 exists.
  - `rhu_bs` over the Pi UARTs, once plan 4 lands with the changes in §10.
- **`lc_sig_net`** with the async HSS interface (§4.3) and `LC_SIG_NET_TERMS` raised to at least plan 4's `RHU_MAX_TERMS` (32), made a build-time setting.
- **Glue**, grown from `lcb_net.c`:
  - demultiplexes UL payload kinds (`LC_SIG_KIND_SIG` / `_DATA`, `_SVC` on RACH UPPER);
  - forwards app data between two local legs (`lc_sig_net_local_peer`) or to the core for a cross-cell leg;
  - keeps a **leg table** that maps its `lc_sig_net` call ids to core call refs.
- **Core client**: reconnects with backoff, sends HELLO with a random `boot_id`, keeps a small AV cache (§7.8), and releases every cross-cell leg with cause 5 (network failure) when the link to the core drops.
- **Config**: a key=value file like plan 4's `rhu_config`, plus `cell_id`, the core address, and the certificate paths.

### 4.2 `oc-core`

- **Portable C11 core library** (`lc_core`: no OS calls, driven by messages and `tick(now)`, like `lc_sig` and plan 4's `rhu_bs`), with Linux glue for SQLite, sockets, TLS and the clock.
- **HSS/AuC:**
  - activation, using the same checks and KDF as `on_act_req()` / `lc_sig_act_keys()` in `lc_sig_net.c`;
  - AV generation with `lc_milenage()`, with SQN stepped and committed *before* the AV leaves;
  - resync from AUTS (the logic in `lc_sig_net.c` around line 357).
- **Location registry:** number → (cell, TMID, expiry).
- **Switch:** routes a number, offers the call to the callee's cell, relays ALERT/ANSWER/RELEASE and MEDIA between the two legs, and runs the ring and setup timers.
- **Echo service:** `lcb_net`'s simulated far end (answers after 3 s, echoes app data) becomes a configured service number, `+883160655500100` (`LCB_NET_PEER_NUMBER`; subscriber 00100 is in the service range of `numbering-plan.md` v0.2). It stays useful on the bench and in the field.
- **Records:** a CDR per call attempt, and an audit log of the `security-model.md` §Audit Logging events.
- **Admin CLI:** `oc-core admin sub add|issue|disable|list`, `cell add|revoke`, `loc`, `cdr`. It replaces `lcbench mkqr` (QR text plus `qrencode`), and the portal later drives the same operations.

### 4.3 `lc_sig_net` changes (async HSS)

The library stops holding K, OPc, SQN and SKn. It asks and gets answered later; a test or single-process backend may answer inside the call.

| Now (`lc_sig_net_io_t`) | Proposed |
|---|---|
| `by_token` + `cfg.sk` + writes `sub->k/opc/sqn`, `unbind`, `save` | `act_req(ctx, tmid, token_id, pkt, tag)` → `lc_sig_net_act_done(n, tmid, msg)`: the core returns the finished `ACT_ACK`/`ACT_NAK` (it needs K for `confirm` and the token secret for the NAK tag). |
| `by_tmid` + `new_av()` computing MILENAGE | `av_req(ctx, tmid)` → `lc_sig_net_av_done(n, tmid, status, number, av)`. `av` = RAND, AUTN, XRES, CK, IK. `status` ∈ ok / not activated / bound elsewhere / disabled / core unavailable (no answer: the terminal backs off as today). |
| resync inside `handle(AUTH_FAIL)` | `resync_req(ctx, tmid, rand, auts)` → `av_done` with a fresh AV |
| — | `registered(ctx, tmid, number, rand, res)`: fired when `AUTH_RSP` matches (the cell sends `LOC_UPDATE`, §7.7) |
| `by_number` for the local-callee test | The session keeps its `number` (from `av_done`); `lc_sig_net` finds a local callee among its own **registered** sessions. Anything else goes out as `LC_SIG_NET_MO`. |
| `by_tmid` for the caller's number | The session's `number` |
| — | New event `LC_SIG_NET_ALERTING` for a far-end MT leg; `lc_sig_net_call_in` returns distinct busy / unreachable codes; `lc_sig_net_drop(n, tmid, cause)` for `LOC_CANCEL`. |

The existing fixes stay: a REG_REQ never touches a registered session until `AUTH_RSP` matches (fix round 1, commit 58b3dc2), and pending and confirmed vectors stay separate (rounds 2–3). `test_sig_e2e.c`, `test_sig_local.c` and `test_term_sim.c` move to a synchronous fake core.

## 5. Data model (`oc-core`, SQLite, WAL, `synchronous=FULL`)

| Table | Columns | Notes |
|---|---|---|
| `network` | `key_id` PK, `sk_enc`, `pk`, `period_s`, `created` | The X25519 pair for activation (QR carries `key_id` + `pk`, plan-5 spec §3.1). Several rows allow key rotation. With several cores, each pair belongs to a block's tenant and moves with the block (§14.7). |
| `cell` | `cell_id` PK (u32), `name`, `cert_fpr`, `mode` (part15/part97), `enabled`, `boot_id`, `last_seen` | The `cert_fpr` column is `security-model.md`'s planned `certificate_fingerprint`. |
| `subscriber` | `number` PK (full form, text `+883160655501234`: 15 digits for NANP, ≤ 15 otherwise), `state` (active/disabled), `tmid`, `activated`, `k_enc`, `opc_enc`, `sqn` (int), `created`, `updated` | One bound terminal per number (plan-5 spec §3.2 step 3). Always the full form (`numbering-plan.md` v0.2 §Display Formatting), never a dialled short form. |
| `token` | `token_id` PK (8 B: block index 2 ‖ random 6, §14.3), `number` FK, `secret_enc`, `expiry`, `used_at`, `used_by_tmid` | At most one unused token per number (partial unique index). Issuing a new token voids the old one. |
| `av_issued` | `number`, `rand`, `xres`, `sqn`, `cell_id`, `issued`, `confirmed` | Lets the core verify a cell's `LOC_UPDATE` (§8). Rows are pruned after 24 h. |
| `location` | `number` PK, `cell_id`, `tmid`, `expires` | Current location only, no history (`security-model.md` §Number and Subscriber Privacy). Persisted so a core restart keeps it. |
| `cdr` | `id`, `caller`, `called`, `cell_a`, `cell_b`, `setup`, `answer`, `end`, `cause` | |
| `audit` | `ts`, `event`, `number`, `tmid`, `cell_id`, `detail` | Append-only. Events: ACTIVATE, ACT_FAIL, REGISTER, AUTH_FAIL, RESYNC, LOC_CANCEL, TOKEN_ISSUE, SUB_DISABLE, CELL_REJECT; with several cores also PROMOTE, DEMOTE, TRANSFER, TABLE_UPDATE, PEER_REJECT. |
| `route` | `version`, `blob`, `sig`, `received` | The signed routing table (§14.2), newest valid version wins; older rows kept for audit. A single-core network has one version listing itself. |
| `block` | `prefix` PK (digits, e.g. `8831606`), `block_idx` (u16), `tenant`, `home_core`, `secondaries`, `epoch`, `role` (home/secondary/none), `repl_pos` | This core's view of the table plus its own role and replication position per block (§14). Derived from `route` and takeover records. |
| `binding_idx` | `tmid` PK, `block_idx`, `updated` | TMID → block, replicated to every core so a serving core can find a terminal's home core (§14.3). No number, no keys. |

**Keys at rest.** `k`, `opc`, `sk` and token `secret` are sealed with AES-256-GCM under a 32-byte master key. The GCM nonce is random (12 B, stored with the ciphertext), and the AAD is `table ‖ column ‖ primary key ‖ key_version`.
- This deviates from `security-model.md`, which uses `aad = tmid`: the TMID changes on re-activation, the number does not.
- The master key is not in the database. It comes from a systemd credential file (`LoadCredential=`, root-only, 0400), or from `--key-file` on the bench.
- SQN, numbers and TMIDs are stored in the clear.
- Backups copy the database; the master key is backed up separately.

## 6. Cell ↔ core protocol

- **Transport:**
  - Single site: a Unix stream socket (`/run/opencell/core.sock`, owner-only).
  - Multi-site: TLS 1.3 over TCP to one port (7443 in the deployment, §16), ALPN `oc-cell/1`. Both sides present certificates from an OpenCell CA; the core checks the client certificate's fingerprint against `cell.cert_fpr`, and the cell checks the core against the bundled CA (the "mTLS upgrade path" in `security-model.md`, taken now instead of bearer tokens).
  - Connections always go out from the cell, so cells behind home NAT work.
- **Framing:** `len (2, BE) ‖ type (1) ‖ body`, at most 512 B, little-endian fields like lc_link; numbers are 8 BCD bytes, full form (numbering-v2 design §4.1). Signalling and media share the connection: a call carries at most 18 B per 120 ms each way.
- **Liveness:** PING every 5 s. The link counts as down after 15 s without traffic.
- **Call refs:** a leg is named by `(cell, leg_ref)`, where `leg_ref` is the cell's `lc_sig_net` call id. Core-created legs (offers) carry a core `call_ref`, which the cell maps to its own call id.

| Type | Name | Dir | Body |
|---|---|---|---|
| 0x01 | HELLO | C→K | proto 1, cell_id 4, boot_id 8, sw_version 3 |
| 0x02 | HELLO_ACK | K→C | mode 1, period_s 2, key_id 2, echo_number 8 |
| 0x03 | HELLO_NAK | K→C | reason 1 (unknown cell, disabled, bad version) |
| 0x04 / 0x05 | PING / PONG | both | — |
| 0x10 | ACT_FWD | C→K | req 2, tmid 4, token_id 8, PKt 32, tag 8 |
| 0x11 | ACT_RES | K→C | req 2, tmid 4, lc_sig message (ACT_ACK or ACT_NAK, ≤ 20 B) |
| 0x12 | AV_REQ | C→K | req 2, tmid 4, count 1 (1–4) |
| 0x13 | AV_RES | K→C | req 2, tmid 4, status 1, number 8, count 1, count × {RAND 16, AUTN 16, XRES 8, CK 16, IK 16} |
| 0x14 | RESYNC | C→K | req 2, tmid 4, RAND 16, AUTS 14 (answered by AV_RES) |
| 0x18 | LOC_UPDATE | C→K | tmid 4, number 8, RAND 16, RES 8 |
| 0x19 | LOC_PURGE | C→K | tmid 4, number 8 (session expired or dropped) |
| 0x1A | LOC_CANCEL | K→C | tmid 4, cause 1 (moved, reactivated, disabled) |
| 0x20 | CALL_ROUTE | C→K | leg_ref 4, caller 8, called 8 |
| 0x21 | CALL_OFFER | K→C | call_ref 4, callee 8, caller 8 |
| 0x22 | CALL_ALERT | both | ref 4 |
| 0x23 | CALL_ANSWER | both | ref 4 |
| 0x24 | CALL_RELEASE | both | ref 4, cause 1 (lc_sig causes) |
| 0x28 | MEDIA | both | ref 4, seq 2, data ≤ 18 |

## 7. Flows

### 7.1 Activation

1. The terminal sends `ACT_REQ`.
2. The cell sends `ACT_FWD`.
3. The core runs the plan-5 §3.2 checks (token exists, unused, unexpired, tag), derives K/OPc, sets `SQN = 0`, binds the TMID, marks the token used and commits.
4. If the number was bound to another TMID with a location, the core sends `LOC_CANCEL(reactivated)` to that cell (as `lc_sig_net` fix round 1 "cut off old terminal on reactivation").
5. The core answers `ACT_RES` with the finished `ACT_ACK`, or with `ACT_NAK` (1 unknown, 2 used, 3 expired, 4 bad tag).
6. The cell queues it to the terminal.

Timing: the terminal retransmits after 1 s, up to 3 times (plan-5 spec §4.4). A core round trip must fit in that budget, so the cell answers a retransmitted `ACT_REQ` from its pending state and never forwards it twice.

### 7.2 Registration

1. `REG_REQ` arrives. If the cache has a vector for this TMID, the cell uses it at once. Otherwise it sends `AV_REQ` and waits (the terminal's retries cover ≈ 3 s).
2. On `AV_RES` ok, the cell sends `AUTH_REQ`. For `not activated`, `bound elsewhere` or `disabled` it sends `REG_REJ(not activated)`.
3. On a matching `AUTH_RSP`, the cell sends `REG_ACK` and `LOC_UPDATE`.
4. For `AUTH_FAIL` cause 2, the cell sends `RESYNC` and challenges again with the new AV.

### 7.3 MO/MT within a cell

Unchanged from plan 5: `lc_sig_net` switches the call when the called number is a **registered session on this cell**. The core is not involved and `CALL_ROUTE` is not sent. A CDR notice for local calls can be added later; it is not in §6.

### 7.4 Cross-cell call (T_A on cell A calls T_B on cell B)

1. T_A sends `CALL_SETUP`. `lc_sig_net` answers `CALL_PROC` and raises `LC_SIG_NET_MO`, and cell A sends `CALL_ROUTE(leg_ref, caller, called)`.
2. The core looks up the called number:
   - not a subscriber and not a service number → `CALL_RELEASE(4 unreachable)`;
   - no live location → `CALL_RELEASE(4)`;
   - the echo service → the core answers as the peer does today;
   - otherwise → `CALL_OFFER` to cell B.
3. Cell B calls `lc_sig_net_call_in`:
   - busy → `CALL_RELEASE(2)`;
   - no session (stale location) → `CALL_RELEASE(4)`, and the core drops the location;
   - otherwise T_B gets `SETUP_IND` (paged if idle).
4. T_B's `ALERTING` → `CALL_ALERT` → cell A calls `lc_sig_net_peer_alert` (T_A hears it ring).
5. T_B's `CONNECT` → `CALL_ANSWER` → `lc_sig_net_peer_answer`.
6. App data: cell A decrypts with leg A's `K_voice` (`lc_sig_net_data_in`) → `MEDIA` → core → cell B encrypts with leg B's key (`lc_sig_net_data_out`). This is hop-by-hop, as local calls are today (plan-5 spec §5); the plaintext travels only inside the TLS link.
7. A `RELEASE` from either terminal becomes `CALL_RELEASE` with the same cause on the other leg, and the core writes the CDR.

Timers:
- The core allows 10 s from `CALL_ROUTE` to an alert or a release. After that it sends `CALL_RELEASE(5)` to cell A and `CALL_RELEASE` to B.
- Ringing is limited to 60 s by `lc_sig_net` on the MT leg (cause 3), and the core relays that release.
- Cell A with no core link releases the leg at once with cause 5.

### 7.5 MT from the core (echo service, later a gateway)

This is `CALL_OFFER` to the callee's cell, then the same as steps 3–7 above.

### 7.6 Busy and unreachable summary

| Situation | Where it is decided | Cause to the caller |
|---|---|---|
| Callee in a call (same or other cell), or the caller dialled itself | `lc_sig_net` (`local_setup`, `call_in`) | 2 busy |
| Number unknown, not activated, not registered anywhere, stale location | core, or cell B | 4 unreachable |
| No answer in 60 s / callee rejects | cell B | 3 / 1 |
| Core or backhaul down, or core timeout | cell A or the core | 5 network failure |
| Radio link lost in a call | `lc_sig_net` (5 s without data) | 6 link lost |

### 7.7 Location

- The core moves a number's location **only on `LOC_UPDATE`**, never on `AV_REQ`: an unauthenticated `REG_REQ` must not move anyone, just as it may not deregister anyone in `lc_sig_net`.
- The core checks the update's `RES` against the stored `XRES` of an AV it issued to that cell (§8).
- Expiry is 2 × `period_s` (plan-5 spec §4.3). `LOC_PURGE` clears the location early.

### 7.8 A terminal moves between cells (idle)

1. T loses cell A, attaches to cell B, and registers again by itself (`lc_sig_term_link`).
2. Cell B sends `LOC_UPDATE`. The core sends `LOC_CANCEL(moved)` to cell A.
3. Cell A calls `lc_sig_net_drop`, and its cached AVs for T are discarded.
4. If T was in a call, the call ends with cause 6 (no handover; out of scope).
5. Cell selection is the terminal's: it takes the first beacon it acquires. No reselection policy exists yet.

**AV cache and SQN.** The core issues AVs with strictly rising SQN. A vector cached at cell A that is older than one T already used at cell B fails with `AUTH_FAIL(2)` and resyncs through the core. That is correct, only slower. Cached vectors therefore stay few, and are dropped on `LOC_CANCEL`.

### 7.9 Pi (oc-cell) restart

- **Radio side.** The W12s stay silent on a missed schedule (plan 4 constraint "no beacon replay"). The beacon stops, every terminal loses the cell, and each registers again on re-attach.
- **Core side.** A `HELLO` with a new `boot_id` makes the core purge that cell's locations, release every call with a leg on it (cause 5 to the other leg), and discard its unconfirmed AVs. A reconnect with the same `boot_id` (the link dropped, the process did not) keeps locations; calls that spanned the link were already released on both sides.
- **`lc_sig_net` call ids** restart at 1 after a restart. That is safe: they are unique within a registration, K_voice also binds RAND, and the core names legs by `(cell, leg_ref)`.

### 7.10 Core restart and backhaul outage

- **Core restart.** Every cell sees its link drop and releases its cross-cell legs with cause 5. Locations and SQN persist in SQLite, so nothing else is lost. Cells reconnect with their existing `boot_id`s.
- **Backhaul outage at a cell.**
  - Registered terminals keep working and local calls go on, until each registration's `reg_until` passes.
  - New registrations use cached AVs. Activation and cross-cell calls fail: activation times out on the terminal, and calls get cause 5.
  - After reconnection, the cell sends `LOC_UPDATE` for registrations made offline; they are verifiable because the core kept those AVs' XRES.

### 7.11 Numbering

Numbering v2 (`numbering-plan.md` v0.2): a number is 883 · country code · national number, at most 15 digits; NANP numbers are `+883 1 NPA NXX SSSSS`, exactly 15 (`+883-1-606-555-01234`). `lc_sig` carries only the full form, 8 BCD bytes (`LC_SIG_NUMBER_LEN` = 8). Terminals normalize what the user dials (`lc_sig_number_normalize`, with the subscriber's own number as the home context; numbering-v2 design §5), so no short form reaches a cell or a core.
- The core checks the encoding (`lc_sig_number_valid`) and its policy: the number lies in a known block (§14.2) and is not reserved (00000, 00911, 09911, 99999, and the service range 00001–00999 except configured service numbers such as the echo service 00100).
- `admin sub add` auto-assigns a random free number (01000–99998, not 09911) in a block this core is home for (`numbering-plan.md` §Assignment Modes); `admin` commands accept any full form, e.g. `+883-1-606-555-1234`, and store the canonical `+883160655501234`.
- Routing is the longest-prefix match of the full number on the block table (§14.2). In a single-core network every block is at home.
- Numbers outside 883 get cause 4 until a gateway exists.

## 8. Security

| Asset | Where | Protection |
|---|---|---|
| K, OPc, token secrets, network SKn | `oc-core` only | AES-256-GCM at rest (§5); never sent to a cell. Single-site: the core runs on the Pi, and this is only as strong as that Pi. |
| AVs (RAND, AUTN, XRES, CK, IK) | Core → cell, over mTLS | CK/IK give a cell its own terminals' session keys, as in 3GPP. |
| Location claims | Core | A cell must return the `RES` matching an `XRES` it was issued (the 5G "home control" idea), so a rogue or compromised cell cannot pull another cell's subscribers' MT calls to itself. |
| App data in the network | Cells and core | Plaintext inside processes and inside TLS, as in plan-5 local calls. End-to-end encryption is a later option. |
| Cell identity | Core | Per-cell certificate; revoke = `cell.enabled = 0` or a new fingerprint. |
| Abuse by a cell | Core | Per-cell rate limit on `AV_REQ`, `ACT_FWD` and `CALL_ROUTE`; audit log. |
| Routing table (several cores) | Every core | Signed by the routing authority's offline Ed25519 key; takeover records only from a listed secondary, signed by its core key; the newest valid version wins (§14.2). |
| Key replicas (several cores) | A block's secondaries only | Chosen per block by its tenant; re-sealed under each core's own master key; never on cells or other cores (§14.7). |
| Core identity (several cores) | Every core | Per-core certificate from the OpenCell CA, checked against the fingerprint in the signed core directory (§15.2). |

`security-model.md` needs these updates on approval:
- the HSS lives in `oc-core` (SQLite), not RADIUS/OAI HSS;
- base stations use mTLS now, not bearer tokens;
- key-at-rest AAD is the number, not the TMID;
- WireGuard is optional, not required;
- several cores: the signed routing table, key replicas on secondaries, and OCSS (§14–15).

## 9. Testing

1. **`lc_core` host tests** (Unity, like `host-tests/`):
   - the codec with golden bytes;
   - HSS on an in-memory SQLite database;
   - AES-GCM seal/open, including a wrong AAD;
   - activation, AV and resync checked against `lc_sig_term` as the reference terminal;
   - SQN monotonic across restarts;
   - token expiry and reuse;
   - LOC_UPDATE with a bad RES;
   - routing tables.
2. **Multi-cell simulation** (new `host-tests/test_net_sim.c`, in the style of `test_sig_local.c`): N cells (`lc_sig_net` + glue), M `lc_sig_term` terminals on fake links, and the core over an in-memory transport with injectable delay, loss and disconnect. Scenarios:
   - cross-cell call, reject, busy, unreachable, no answer, hang-up from each side;
   - echo service;
   - a terminal moves while idle;
   - reactivation on a new terminal while the old one is registered elsewhere;
   - a cell restart mid-call; a core restart mid-call;
   - a backhaul outage with the AV cache;
   - a stale cached AV → resync;
   - a rogue cell claiming a location.
3. **Radio stack in simulation:** `test_term_sim.c` (lc_term against `lcb_cell` over simulated air) runs with the new glue and a fake core, so the plan-5 air path is covered unchanged.
4. **Process-level:** `oc-core` and two `oc-cell --radio sim` processes on localhost, over Unix sockets and then over TLS with throw-away test certificates; kill/restart tests.
5. **Bench** (the laptop first, then the Pi once plan 4 lands):
   - (a) `oc-core` + one `oc-cell` with board A: the plan-5 done list with T and T2;
   - (b) two `oc-cell` processes, board A and a second bs-radio board, on different `cell_seed`s, one process per serial port (bench rule): cross-cell calls and an idle move. Terminals are placed by starting one cell at a time and switching a cell off (`lcb_cell.off`).
   - Two co-located cells on 915 MHz are new ground for the radio layer (beacon collisions on sync channels); if they interfere, the bench staggers frames or falls back to a cabled attenuator setup.
   - (c) plan 9: one `oc-cell` on the laptop with board A, `oc-core` in the VM (§16), over the internet with mTLS.
6. **Several cores** (plans 10–11): `test_net_sim.c` grows to N cores over in-memory OCSS links with injectable partitions. Scenarios:
   - a call between cells on different cores; LOCATE answered by a secondary while the home is down;
   - promotion with the SQN jump, checked against `lc_sig_term`: the first AV is accepted without a resync for every lag L < M, and a larger gap resyncs;
   - the old home returning, demoting itself and logging its tail;
   - a block transfer with registrations and calls during the freeze;
   - a forged takeover or replication record, a stale table version, a core not in the directory: all refused.
   - Process level: two `oc-core` processes, the laptop and the VM.

## 10. Relation to plan 4 (scheduler)

Plan 4 is a separate, radio-only concern and stays so. `oc-cell` uses it as its Pi radio backend. Before it is implemented, the plan should be amended with what `lcb_cell` learned in plans 3 and 5:

1. An **in-process fronthaul**: `rhu_fronthaul_t` callbacks go straight into the `oc-cell` glue. Task 9's loopback UDP datagrams become an optional debug tap, or are dropped; the "phone RAN" target is gone.
2. A **DL queue per terminal** (≥ 8 payloads, like `LCB_CELL_DLQ`) in place of the single `rhu_term_t.dl_buf`: a signalling message is up to 4 fragments.
3. **Idle attach and release**: terminals attach without legs, get legs on `SERVICE_REQ` or a page, and `lc_sig_net`'s `channel(off)` sends an empty grant (`lcb_cell_release`). Otherwise `RHU_MAX_TERMS` idle terminals hold legs that fit only about 2 calls (plan 4 R5).
4. **`SERVICE_REQ` on RACH UPPER** reaches `up_rach` with its TMID; attach/release events feed `lc_sig_net_link`, and UL data feeds `lc_sig_net_heard`.
5. **Two-terminal SCHEDULE order**: all DL legs before UL legs (commit c9a4541).
6. Naming: `loravoice-rhu` → `oc-cell` (the project was renamed OpenCell on 2026-09-25).

## 11. Implementation plans

| Plan | Content | Depends on |
|---|---|---|
| **6a, 6b: numbering v2** | 8-byte numbers, dial normalization, QR v2, identity blob v2, BLE contract v3 (6a, C side), and the app (6b): `2026-09-27-numbering-v2-design.md` §10, branch `numbers-v2`. | plan 5 |
| **7: `lc_core` and async `lc_sig_net`** | §4.3 library changes with the existing tests moved over; `lc_core` (codec, HSS logic over a storage interface, AV/resync/activation, registry, switch, echo service); the multi-cell simulation (§9.2). Host-only. Numbers are 8 bytes from the start. Routing already goes through a one-core block table (longest prefix, "am I home?" checks), and token ids carry the block index (§14.3), so plan 10 adds cores without reshaping `lc_core`. | plan 5, 6a |
| **8: `oc-core` and `oc-cell` on the bench** | SQLite store with sealed keys, admin CLI (replaces `mkqr`), Unix-socket transport, `oc-cell` on the `lcb_cell` backend (replaces `lcbench net`; `lcb_net` and `lcb_hss` retire), process tests, bench §9.5a. | 7 |
| **9: Multi-site and the first server** | TLS/mTLS transport, cell certificates and a small CA script, reconnect and outage handling, AV cache, two-cell bench (§9.5b); the `oc-core-1` VM on the Proxmox server with its port forward and backups (§16), and bench §9.5c. | 8 |
| **10: OCSS and several cores** | The OCSS spec first (§15.7). Then the signed routing table, core directory and `admin route sign`; OCSS links; table and takeover distribution; activation, AV and location relay, LOCATE and the binding index; calls and media between cores; the cell's ordered core list (§14.6). Two cores: the VM and the laptop. | 9 |
| **11: Replication, failover and block transfer** | Replication streams, snapshot and catch-up; manual promotion with the SQN jump; demotion and the conflict log; block transfer (freeze, final replication, flip, margin); §9.6 tests. | 10 |
| **4 (amended)** | `rhu_bs` with the §10 changes as `oc-cell`'s Pi backend, then Pi 5 bring-up. | can run in parallel with 7–11 |

Plan 6 (the Android app) is unaffected by the core: the BLE contract does not change with it. Numbering v2 changes the app (plan 6b).

## 12. Out of scope

Voice codec and audio. PSTN/SIP gateway. Direct Connect, push-to-talk and group calls. Web portal (admin CLI only). Active-call handover and multi-cell paging. Automatic failover and consensus between cores (v1 promotion is manual, §14.4). OCSS message layouts (their own spec, §15.7). RF backhaul as the core transport. CDR billing and user-visible call history. End-to-end media encryption. Emergency calls.

## 13. Decisions (2026-09-27)

The user accepted every recommended answer of the draft, with the changes marked.

1. Architecture: edge cell + home core, always two programs (a single site runs both on the Pi), as in §3.3: **option (C).**
2. Subscriber keys live only in cores, and cells get AVs. With several cores: only in a block's home core and its secondaries (§14.7).
3. Core stack: **C11 + SQLite + OpenSSL**, reusing `lc_sig`; RADIUS, Diameter, etcd and Redis are dropped.
4. Cell↔core transport: **TLS 1.3 with per-cell certificates (mTLS) over TCP**, signalling and media on one connection; UDP/DTLS media only if WAN loss proves it necessary.
5. Part 15 / Part 97 mode: **per cell** (`cell.mode`); terminals already re-register when the beacon mode changes.
6. Offline cells: **2 cached AVs per terminal**, refilled after use; activation always needs the core.
7. Where `oc-core` runs: **the laptop (localhost) on the bench; the first server is a VM on the user's Proxmox server** (§16), in place of the draft's "small VPS".
8. Master key for keys at rest: **a systemd credential file** (root-only; in the VM, on a disk excluded from backups, §16.4), `--key-file` on the bench.
9. Order of work: **the `lcb_cell` backend first**; plan 4 is amended per §10 before it runs.
10. `lcb_net`'s simulated far end becomes the core's **echo service**, now `+883160655500100`.
11. *Added:* several cores as **home core + asynchronous replicas**: each block's home core owns its subscribers' writes; secondaries replicate and serve location; failover promotes a secondary, which jumps SQN by M = 2^24; cells attach to the nearest core (§14).
12. *Added:* blocks (NPAs, or NPA-NXXs) can be **transferred to another tenant**, whose core becomes the home; the previous home becomes a secondary (§14.5).
13. *Added:* cores talk **OCSS**, the OpenCell Signalling System (§15); its message design gets its own spec in plan 10.
14. *Added:* **numbering v2** throughout (`numbering-plan.md` v0.2).

Still for the user (none blocks plans 6a–8):
- the VM's ID and address (recommended 115 and 10.0.0.60, §16.2);
- whether the additional IPv4 15.204.144.144 is free for OpenCell (§16.3 option b);
- who holds the routing authority key (recommended: the user, offline on the laptop, §14.2).

## 14. Several cores: home core and asynchronous replicas

One `oc-core` is enough for one community. Several are needed to spread load, to survive the loss of a server, and to let a community run its own core near its cells. The user chose **home core + asynchronous replicas**: every numbering block has one core that owns its subscribers' writes, other cores hold asynchronous copies, and consistency problems are confined to the SQN, which a jump on failover makes safe.

### 14.1 Roles

| Role | Per | Holds | Does |
|---|---|---|---|
| Tenant | block | — | An operator (a community, a club) that holds blocks and runs or chooses cores. |
| **Home core** | block | Everything for the block's subscribers: sealed K/OPc, tokens and their secrets, SQN, TMID bindings, subscriber state, location, `av_issued`, and the block's activation key pair (SKn) | Every write for the block: activation, AV generation (the only place SQN steps), resync, location updates, admin. Streams its changes to the secondaries. |
| **Secondary core** | block (0–2, chosen by the tenant) | An asynchronous replica of the above, re-sealed under its own master key | Answers LOCATE for the block (§15) while the home is unreachable; can be promoted to home (§14.4). Never writes the block while secondary. |
| **Serving core** | cell | AVs for the terminals on its cells, their registrations, its CDRs | The core a cell connects to, the nearest one (§14.6). Runs the cell↔core protocol (§6), relays activation, AV and location requests to home cores, and switches calls over OCSS (§15). |
| Other cores | — | The routing table, the binding index | Route by number prefix; hold no keys and no locations of the block. |

One core usually plays several roles: home for its tenant's blocks, secondary for a neighbour's, serving core for its cells.

### 14.2 The routing table

The table has two parts:
- a **core directory**: `core_id` (u16), name, OCSS address, certificate fingerprint, region;
- **blocks**: prefix (883 · CC · NPA, or 883 · CC · NPA · NXX), `block_idx` (u16, never reused), tenant, home core, ordered secondaries, epoch.

The **longest prefix wins**, so an exchange block can sit inside another tenant's area-code block. With the rows below, `+883-1-606-555-01234` routes to core 2 and `+883-1-606-777-01234` to core 1.

| Prefix | Block | Tenant | Home | Secondaries | Epoch |
|---|---|---|---|---|---|
| `883 1 606` | 1 | A | core 1 (the Proxmox VM) | core 2 | 1 |
| `883 1 606 555` | 2 | B | core 2 (B's server) | core 1 | 3 |
| `883 1 859` | 3 | A | core 1 | — | 1 |

- **Signed** as a whole (version number, Ed25519) by the **routing authority**: an offline key held by the network's operator (today the user) and used by `oc-core admin route sign` on the laptop. Adding a core or a block, changing secondaries, and a block transfer (§14.5) are new versions.
- **Takeover records** (§14.4) change one block's home and epoch without the authority. They are signed by the promoted core's key and valid only if that core is a listed secondary of the block and the epoch is exactly one higher.
- Every core keeps the newest valid version and the takeover records, and passes them on over OCSS (§15.3). A core that sees a higher epoch for a block it holds as home stops writing it at once.
- A single-core network has a table with one core and every block at home: the same code path, no OCSS links.

### 14.3 Finding a subscriber's home core

| Request at the serving core | What it has | How it finds the home |
|---|---|---|
| A call; LOCATE | The called number (full form) | Longest-prefix match on the table |
| `AV_REQ`, `RESYNC`, `LOC_UPDATE` | The TMID | `binding_idx` (TMID → block), which every home core replicates to every core. On a miss (a binding newer than the replication) it asks the other cores (`WHO_TMID`, §15.3). It also learns the TMID → block pair from any activation it relays, so a terminal that registers right after activating never misses. |
| `ACT_FWD` | The token id | The token id's first 2 bytes are the block index, set when the token is issued; the other 6 stay random (the tag, keyed by the 16-byte secret, carries the security). `ACT_REQ` does not change. |

### 14.4 Failover: promoting a secondary

- **While the home is unreachable, before promotion:**
  - secondaries answer LOCATE from their replica, so calls to registered subscribers still connect;
  - serving cores keep using cached AVs (§7.8, 2 per terminal);
  - new AVs, resyncs, activations and location changes for the block wait.
- **Promotion is an operator command in v1:** `oc-core admin block promote 883-1-606` on a secondary. Automatic promotion needs a way to tell a dead home from a partition, and comes later.
  1. The secondary writes a takeover record `{block, new home = itself, epoch + 1, last replication position applied}`, signs it, and sends it to every core it can reach.
  2. **SQN jump:** in the same transaction it adds **M = 2^24** to the SQN of every subscriber in the block, before it issues any AV.
  3. It serves the block's writes. Serving cores send AV, activation and location requests to it as soon as they accept the record.
- **Why the jump makes asynchronous replication safe.** A terminal accepts an AV only if `SQN_ms < SQN ≤ SQN_ms + 2^28` (`lc_sig_term.c`, the check near line 355; plan-5 spec §4.3). The replica's SQN lags the lost home's by L, the AVs issued but not yet replicated for that subscriber (a few at most: 2 cached per cell plus any in flight). After the jump the new home's next SQN is SQN_replica + M + 1:
  - it is above everything the old home issued as long as L < M, so the first new AV is accepted without a resync, and any AV the old home still had out becomes stale;
  - it stays inside the terminal's window as long as M + (unused AVs) ≤ 2^28;
  - outside these bounds the existing resync takes over (`AUTH_FAIL` cause 2 → AUTS → the new home sets SQN from it), so nothing gets stuck;
  - a 48-bit SQN allows 2^24 jumps: never a limit.
- **Writes lost in the lag window** (the last seconds before the home died):
  - an activation the old home confirmed but had not replicated: the terminal gets `REG_REJ(not activated)`; the new home still sees its token as unused, so the same QR code (if unexpired) or a new one activates it again;
  - a location update: the next registration restores it.
- **The old home comes back:** it sees the higher epoch, becomes a secondary, stops writing, puts its unreplicated tail (records after the takeover's position) in a conflict log for the operator, and resubscribes to the new home's stream. Nothing in the tail is applied automatically.
- **Split brain** (both alive, partitioned): the old home writes until it hears of the takeover. The SQN jump keeps authentication safe; the rest ends up in the conflict log. This is why promotion is manual in v1.

### 14.5 Block transfer between tenants

A block (an NPA or an NPA-NXX) can move to another tenant so that tenant runs the home core in its own location. The receiving core (R) becomes the home; the core it moved from (H) becomes a **secondary**.

1. **Prepare.** The authority signs a table version that adds R as a secondary of the block, and prepares (unsigned) the version that flips ownership. R subscribes to H's stream: a snapshot, then live records. The block's activation key pair travels in the snapshot, so outstanding QR codes stay valid.
2. **Freeze.** `oc-core admin block transfer 883-1-606 --to R` on H. H stops accepting writes for the block: activation, token issue, AV generation, resync and admin get the OCSS status `frozen` (serving cores retry every 1 s, inside the terminals' retry budget); `LOC_UPDATE`s are queued, not refused. Calls go on: neither H nor R is in a call's path unless it serves one of its cells.
3. **Final replication.** H sends the stream up to position P and `FREEZE_DONE(P)`; R applies everything up to P and answers `FREEZE_ACK(P)`.
4. **Ownership flip.** The authority signs the prepared version: home R, secondaries [H, …], epoch + 1. The signature is how both tenants' consent is recorded. Every core receives it over OCSS.
5. **SQN margin.** R adds M to every SQN in the block before its first AV, as a promoted secondary does. After a clean freeze nothing needs it; it costs nothing and covers any AV that left H after the freeze began.
6. **Hand-over.** H forwards its queued `LOC_UPDATE`s to R and from then on answers requests for the block with `moved(R)`. Serving cores switch as soon as they hold the new version.
7. **After.** H stays a secondary (a replica that serves LOCATE) until the tenant removes it in a later version.

The freeze lasts from step 2 to step 4: one round trip plus one signing command, since the flip was prepared in step 1. If step 4 does not happen, `oc-core admin block unfreeze` on H resumes writes and nothing has changed.

### 14.6 Cells attach to the nearest core

- A cell's config lists cores in order of preference, nearest first (`core = oc1.example:7443, oc2.example:7443`). The cell connects to the first that answers and falls back down the list. It moves back to a preferred core only after that core has been reachable for 10 min, so a flapping link does not bounce its terminals.
- A change of serving core keeps the cell's `boot_id`. The cell re-sends `LOC_UPDATE` for each registered terminal (it keeps each registration's RAND and RES), and each home core moves the location after checking the RES against its `av_issued` (§7.7).
- A cell's terminals need not be homed on its serving core: a visitor registers wherever it is, with AVs from its home core, as roaming works in 3GPP.

### 14.7 What is replicated

| Data | Written by | Replicated to | Notes |
|---|---|---|---|
| Subscriber: state, sealed K/OPc, SQN, TMID | home | secondaries | Re-sealed under each receiver's master key; travels only inside OCSS mTLS. |
| Tokens (sealed secrets) | home | secondaries | |
| The block's activation key pair | home | secondaries | Keeps QR codes valid across failover and transfer. |
| Location | home (from serving cores' `LOC_UPDATE`) | secondaries | So secondaries can answer LOCATE. |
| `av_issued` | home | — | Only the home checks RES proofs. Lost on failover; the next registration makes new ones. |
| `binding_idx` (TMID → block) | home | every core | No number, no key. |
| Routing table, takeover records | authority, promoted core | every core | §14.2 |
| CDR, audit | each core, for its own legs and events | — | |

Replication is one ordered stream of records per block, with positions. A secondary acknowledges positions; `oc-core admin block status` shows each secondary's lag in records and seconds.

## 15. OCSS: the OpenCell Signalling System

### 15.1 Purpose

The cell↔core protocol (§6) does not change with several cores: a cell speaks only to its serving core. **OCSS** is the core-to-core protocol that joins cores into one network. Like SS7 it separates finding where a subscriber is from setting up the call; unlike SS7 it also carries replication and routing-table distribution.

| OCSS family | SS7 analogue | Purpose |
|---|---|---|
| Link | MTP2/MTP3 | mTLS connections between cores, liveness, versions |
| Routing | SCCP global-title translation | Number prefix, TMID or token → block → home core; table and takeover distribution |
| Mobility | MAP: SendAuthInfo, UpdateLocation, CancelLocation, SendRoutingInfo | Activation, AV and resync relay; location update and cancel; LOCATE |
| Call control | ISUP: IAM, ACM, ANM, REL | Setup, alert, answer and release between two serving cores, and media |
| Replication | — | Block streams to secondaries; freeze and transfer |

### 15.2 Links

- TLS 1.3 over TCP on the core's cell port (7443), ALPN `ocss/1` (cells use `oc-cell/1`).
- Both sides present core certificates from the OpenCell CA, and each checks the peer's fingerprint against the signed core directory, not only the CA: a core removed from the table drops out with the next version.
- A full mesh between the cores in the directory (a community network has a handful). For each pair the core with the lower `core_id` dials; a core without a reachable address is marked `dial_only` in the directory and dials everyone.
- HELLO carries the protocol version, `core_id` and each side's table version; the side with the older table fetches the newer first.
- PING every 5 s; the link is down after 15 s without traffic, as in §6.
- Framing as in §6 (`len ‖ type ‖ body`), with its own type space; numbers are 8 BCD bytes.

### 15.3 Messages (architecture level)

| Family | Messages | Between |
|---|---|---|
| Link | HELLO, HELLO_ACK, PING, PONG | any two cores |
| Routing | TABLE_OFFER(version), TABLE_GET, TABLE(blob, sig), TAKEOVER(record, sig), WHO_TMID(tmid) → TMID_IS(block) | any two cores |
| Mobility | ACT_RELAY → ACT_RES; AV_RELAY, RESYNC_RELAY → AV_RES; LOC_UPDATE → LOC_ACK; LOC_CANCEL; LOCATE(number) → LOCATE_RES(serving core, cell, tmid) or not reachable | serving core → home; LOC_CANCEL home → previous serving core; LOCATE to the home, or to a secondary when the home is unreachable |
| Call control | CALL_SETUP(call_ref, caller, called, hop), CALL_ALERT, CALL_ANSWER, CALL_RELEASE(cause), MEDIA(call_ref, seq, data ≤ 18) | the caller's serving core ↔ the callee's serving core |
| Replication | REPL_SUBSCRIBE(block, position), REPL_SNAPSHOT, REPL_RECORD(position, record), REPL_ACK(position), FREEZE, FREEZE_DONE(P), FREEZE_ACK(P) | home ↔ secondaries |

Status codes, shared with §6 where they overlap: ok, not activated, bound elsewhere, disabled, frozen, moved(core), not home, unavailable. Release causes are the `lc_sig` causes, carried end to end.

### 15.4 Routing

- **Numbers:** the longest-prefix match of the full form on the block table: 883 · CC · NPA [· NXX] → home core. Short forms never reach OCSS: terminals normalize (numbering-v2 design §5).
- **TMIDs and tokens:** §14.3.
- **Numbers outside 883:** no route, cause 4. A gateway core would later be listed as the home of non-883 prefixes.
- A core asked about a block it is not home for answers `moved(home)` from its own table, or `not home`; the requester re-routes once.

### 15.5 A call between cores

T_A, on a cell served by core A, calls T_B, whose block's home is core H and who is registered on a cell served by core B.

1. Core A gets `CALL_ROUTE` from its cell (§7.4). If T_B is registered on one of A's own cells, §7.4 applies unchanged.
2. A sends `LOCATE(called)` to H, or to a secondary of the block if H is unreachable. The answer is `LOCATE_RES(core B, cell, tmid)`, or not reachable (cause 4).
3. A sends `CALL_SETUP` to B, and B offers the call to its cell (`CALL_OFFER`, §6). Busy, a stale location and the rest become `CALL_RELEASE` with the causes of §7.6.
4. Alert, answer and release travel B → A → T_A's cell as in §7.4 steps 4–7. `MEDIA` flows **directly between A and B**: the home core is never in the call path, so a distant home adds no delay.
5. Timers: A allows 10 s from `CALL_ROUTE` to an alert or a release, as in §7.4. `hop` starts at 0; a core refuses a setup with hop > 2, which leaves room for one re-LOCATE after a stale location.
6. A lost OCSS link releases every call that uses it, with cause 5 on both sides. Each serving core writes the CDR for its own leg.

### 15.6 Security

- Only a block's home core may send replication records for it, and only a listed secondary may send a takeover record; anything else is refused and audited (`PEER_REJECT`).
- `LOC_UPDATE` needs the RES proof (§7.7) whichever core relays it, so a rogue core cannot pull another tenant's subscribers' calls to itself.
- Per-peer rate limits on LOCATE, AV_RELAY, ACT_RELAY and CALL_SETUP. LOCATE reveals a subscriber's serving core and cell, and is answered only to cores in the directory.
- A tenant trusts its secondaries with its subscribers' keys; the choice is the tenant's, recorded in the signed table.

### 15.7 Its own spec

Message layouts, state machines, version negotiation, the replication record format, snapshot transfer, the conflict log and the OCSS test plan go into `docs/superpowers/specs/<date>-ocss-design.md`, written at the start of plan 10.

## 16. Deployment: `oc-core` in a VM on the Proxmox server

### 16.1 The server (facts gathered read-only on 2026-09-27)

| Item | Value |
|---|---|
| Host | Proxmox VE 9.2.10; SSH `root@147.135.11.61`, port 222, keys on the laptop |
| CPU, RAM | 8 cores; 31 GB, about 13 GB available |
| Storage | `local` (directory), about 1.7 TB free |
| Bridges | `vmbr0` public: 147.135.11.61/24, plus an additional IPv4 15.204.144.144/32 and IPv6 2604:2dc0:100:23d::1/128; `internal`: 10.0.0.1/24, private, NAT; `vmbr1` |
| Other | Tailscale on the host (100.90.73.42); an `nginx-proxy` LXC (100); guest IDs in use 100–114, 200–203, 500–501 |

### 16.2 The VM

| | |
|---|---|
| ID, name | **115**, `oc-core-1` (the next free ID in the 1xx range; the user may prefer another) |
| OS | Debian 13 (trixie), the official `genericcloud` amd64 qcow2 image, imported to `local` |
| Resources | 2 vCPU (type `host`), 2 GB RAM, 32 GB system disk (virtio-scsi, qcow2), and a second 1 GB disk for the master key with `backup=0` |
| Provisioning | cloud-init: user `opencell` with the laptop's SSH key, a static address, packages (`sqlite3`, `openssl`, `chrony`, `nftables`, `unattended-upgrades`, `qemu-guest-agent`) |
| Network | one virtio NIC on `internal`, fixed address **10.0.0.60/24** (to be checked free against the other guests), gateway 10.0.0.1 |

Provisioning sketch, run on the host (plan 9 turns it into `tools/deploy/pve-oc-core.sh`, driven from the laptop over `ssh -p 222`):

```
qm create 115 --name oc-core-1 --cores 2 --cpu host --memory 2048 --agent 1 \
  --scsihw virtio-scsi-single --net0 virtio,bridge=internal \
  --scsi0 local:0,import-from=/var/lib/vz/template/iso/debian-13-genericcloud-amd64.qcow2,format=qcow2 \
  --scsi1 local:1,format=qcow2,backup=0 \
  --ide2 local:cloudinit --boot order=scsi0 --serial0 socket --vga serial0 \
  --ciuser opencell --sshkeys opencell.pub --ipconfig0 ip=10.0.0.60/24,gw=10.0.0.1
qm resize 115 scsi0 32G
qm start 115
```

An ISO install works too. The cloud image is recommended because the same script can rebuild this core or make a second one.

### 16.3 How cells reach it

| Option | How | For | Against |
|---|---|---|---|
| **(a) Port forward on the main address (recommended now)** | A host nftables rule, next to the existing NAT for `internal`: TCP `147.135.11.61:7443` → `10.0.0.60:7443`, plus a forward accept for that port only | One rule; the VM stays private; nothing else on the host changes | A non-standard port, which some guest networks block |
| (b) The additional IPv4 | `15.204.144.144` forwarded to the VM (443 and 7443), or routed to it as a /32 | Port 443 passes almost everywhere; a dedicated address and DNS name for OpenCell | Only if the address is not already in use (not checked); it is the host's only spare IPv4 |
| (c) Tailscale | Tailscale in the VM, or the host advertising 10.0.0.0/24 as a subnet route; Pis join the tailnet | No public port; convenient for the user's own Pis | Every cell needs a tailnet login; not for other tenants' cells |

- **Recommendation:** (a) now; (b) once the user confirms 15.204.144.144 is free, and cells then use port 443. (c) serves admin SSH (the VM's SSH is reachable only from the host and the tailnet) and, optionally, the user's own Pis during bring-up.
- mTLS is required on every path: neither Tailscale nor NAT is the trust boundary. Cell connections always go out from the cell (§6), so a Pi behind home NAT needs no port forwarding with any option.
- Not through `nginx-proxy`: `oc-core` terminates its own mTLS and checks client certificates, which an HTTP proxy would break. If port 443 on the main address is ever wanted, nginx's `stream` module with SNI passthrough can forward it without terminating TLS.
- No IPv6 for the VM: the host has a single /128.

### 16.4 Inside the VM

- `oc-core` runs as a systemd service under its own user. The master key comes from the second disk through `LoadCredential=` (decision 8), so `vzdump` backups of the system disk never contain it. The key is also copied once, offline, to the laptop's encrypted storage.
- The SQLite database lives on the system disk; a nightly `vzdump` of the VM goes to `local`, and to an off-host copy once one exists.
- nftables in the VM: 7443/tcp from anywhere; 22/tcp from 10.0.0.1 and the tailnet only.
- chrony (token expiry, CDRs and certificate validity depend on the clock); unattended security upgrades.
- The core's server certificate and the OpenCell CA come from plan 9's CA script on the laptop; the CA key never goes to the VM.

### 16.5 The bench

The laptop keeps running `oc-core` locally (Unix socket, or TLS on 127.0.0.1) for development and the plan-8 bench. The VM is the first deployed core (plan 9). In plan 10 the laptop's core and the VM are the two cores for the OCSS tests.
