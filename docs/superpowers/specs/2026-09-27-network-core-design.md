# OpenCell: Network Core — Cell Daemon, HSS, Registry and Inter-Cell Switching (design)

> **DRAFT — not approved; open questions in §13.** Written overnight on 2026-09-27 from the repo docs and the `lc-sig` code, without a brainstorming session. Every decision below is a *recommendation* until the user answers §13.

**Status:** Draft for review.
**Builds on:** `2026-09-26-activation-registration-calls-design.md` (plan 5: `lc_sig`, `lcbench net`), plan 4 (`docs/superpowers/plans/2026-09-25-rhu-scheduler.md`, not yet implemented), `2026-09-23-lr2021-hardware-design.md`, `security-model.md`, `numbering-plan.md`, `architecture.md`.

## 1. Goals and scope

"Switching and routing" in OpenCell today means four things (from `architecture.md` §Network-Side Call State and plan-5 spec §5, §7, §11):

1. **The cell's network role on the Pi**, replacing `lcbench net`: drive the base-station W12s over lc_link (plan 4's scheduler), run `lc_sig_net` for every terminal the cell hears, and switch calls between two terminals of the same cell (already in `lc_sig_net`, `local_setup()` in `firmware/components/lc_sig/lc_sig_net.c`).
2. **A persistent HSS**: subscribers, activation tokens, TMID bindings, K, OPc and SQN, with the keys encrypted at rest. Today this is `lcb_hss`, a 0600 text file of at most 16 subscribers (`tools/lcbench/lcb_hss.h`).
3. **A location registry**: which cell (Pi) each registered number is on now.
4. **Inter-cell switching**: a call from a terminal on one Pi to a terminal on another Pi, with its app data (later voice) relayed between them.

Recommended scope for this spec:

| Topic | Recommendation |
|---|---|
| In scope | 1–4 above; activation and registration through the core; MO/MT calls within a cell and across cells; busy, unreachable, no answer; a terminal moving between cells *while idle*; Pi, core and backhaul failures; an admin CLI that replaces `lcbench mkqr`. |
| Out of scope | Voice codec and audio (app data frames stand in, as in plan 5); PSTN/SIP gateway (`numbering-plan.md` §Future); Direct Connect / push-to-talk (`direct-connect.md`); the web portal (the admin CLI stands in); handover of an *active* call between cells; paging across several cells; high availability of the core; RF backhaul between base stations (plan 4 R11) as the core's transport; emergency calls (none: plan-5 spec §1). |
| Replaces from the 2026-05 vision | The central "phone RAN" that ran every call's signalling (`architecture.md` §Phone RAN Plane), RADIUS/EAP-AKA, Diameter, OAI HSS, etcd, Redis and PostgreSQL (`implementation-plan.md` Phases 2–4, §Technology Stack). Plan 5 already moved signalling into `lc_sig`; the core only needs what `lc_sig_net` cannot do alone. |

**Done means** (to be confirmed):
- `oc-cell` + `oc-core` on one machine with board A replace `lcbench net`, and the plan-5 done list (plan-5 spec §1) passes again with T and T2.
- With two cells (board A and a second bs-radio board) and one core: T on cell 1 calls T2 on cell 2 — ring, connect, app data both ways, hang-up from each side, reject, busy, unreachable.
- T moves from cell 1 to cell 2 while idle; a call to T then rings on cell 2.
- Killing `oc-cell` on one cell, or the core, never leaves a half-open call on the other side for more than 10 s, and every terminal is registered again within one re-attach after the process is back.

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

### 3.3 Recommendation: (C), always two programs

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
- **Echo service:** `lcb_net`'s simulated far end (answers after 3 s, echoes app data) becomes a configured service number, `+8836065550100` (`LCB_NET_PEER_NUMBER`). It stays useful on the bench and in the field.
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
| `network` | `key_id` PK, `sk_enc`, `pk`, `period_s`, `created` | The X25519 pair for activation (QR carries `key_id` + `pk`, plan-5 spec §3.1). Several rows allow key rotation. |
| `cell` | `cell_id` PK (u32), `name`, `cert_fpr`, `mode` (part15/part97), `enabled`, `boot_id`, `last_seen` | The `cert_fpr` column is `security-model.md`'s planned `certificate_fingerprint`. |
| `subscriber` | `number` PK (E.164 text, 13 digits), `state` (active/disabled), `tmid`, `activated`, `k_enc`, `opc_enc`, `sqn` (int), `created`, `updated` | One bound terminal per number (plan-5 spec §3.2 step 3). |
| `token` | `token_id` PK (8 B), `number` FK, `secret_enc`, `expiry`, `used_at`, `used_by_tmid` | At most one unused token per number (partial unique index). Issuing a new token voids the old one. |
| `av_issued` | `number`, `rand`, `xres`, `sqn`, `cell_id`, `issued`, `confirmed` | Lets the core verify a cell's `LOC_UPDATE` (§8). Rows are pruned after 24 h. |
| `location` | `number` PK, `cell_id`, `tmid`, `expires` | Current location only, no history (`security-model.md` §Number and Subscriber Privacy). Persisted so a core restart keeps it. |
| `cdr` | `id`, `caller`, `called`, `cell_a`, `cell_b`, `setup`, `answer`, `end`, `cause` | |
| `audit` | `ts`, `event`, `number`, `tmid`, `cell_id`, `detail` | Append-only. Events: ACTIVATE, ACT_FAIL, REGISTER, AUTH_FAIL, RESYNC, LOC_CANCEL, TOKEN_ISSUE, SUB_DISABLE, CELL_REJECT. |

**Keys at rest.** `k`, `opc`, `sk` and token `secret` are sealed with AES-256-GCM under a 32-byte master key. The GCM nonce is random (12 B, stored with the ciphertext), and the AAD is `table ‖ column ‖ primary key ‖ key_version`.
- This deviates from `security-model.md`, which uses `aad = tmid`: the TMID changes on re-activation, the number does not.
- The master key is not in the database. It comes from a systemd credential file (`LoadCredential=`, root-only, 0400), or from `--key-file` on the bench.
- SQN, numbers and TMIDs are stored in the clear.
- Backups copy the database; the master key is backed up separately.

## 6. Cell ↔ core protocol

- **Transport:**
  - Single site: a Unix stream socket (`/run/opencell/core.sock`, owner-only).
  - Multi-site: TLS 1.3 over TCP to one port. Both sides present certificates from an OpenCell CA; the core checks the client certificate's fingerprint against `cell.cert_fpr`, and the cell checks the core against the bundled CA (the "mTLS upgrade path" in `security-model.md`, taken now instead of bearer tokens).
  - Connections always go out from the cell, so cells behind home NAT work.
- **Framing:** `len (2, BE) ‖ type (1) ‖ body`, at most 512 B, little-endian fields like lc_link. Signalling and media share the connection: a call carries at most 18 B per 120 ms each way.
- **Liveness:** PING every 5 s. The link counts as down after 15 s without traffic.
- **Call refs:** a leg is named by `(cell, leg_ref)`, where `leg_ref` is the cell's `lc_sig_net` call id. Core-created legs (offers) carry a core `call_ref`, which the cell maps to its own call id.

| Type | Name | Dir | Body |
|---|---|---|---|
| 0x01 | HELLO | C→K | proto 1, cell_id 4, boot_id 8, sw_version 3 |
| 0x02 | HELLO_ACK | K→C | mode 1, period_s 2, key_id 2, echo_number 7 |
| 0x03 | HELLO_NAK | K→C | reason 1 (unknown cell, disabled, bad version) |
| 0x04 / 0x05 | PING / PONG | both | — |
| 0x10 | ACT_FWD | C→K | req 2, tmid 4, token_id 8, PKt 32, tag 8 |
| 0x11 | ACT_RES | K→C | req 2, tmid 4, lc_sig message (ACT_ACK or ACT_NAK, ≤ 20 B) |
| 0x12 | AV_REQ | C→K | req 2, tmid 4, count 1 (1–4) |
| 0x13 | AV_RES | K→C | req 2, tmid 4, status 1, number 7, count 1, count × {RAND 16, AUTN 16, XRES 8, CK 16, IK 16} |
| 0x14 | RESYNC | C→K | req 2, tmid 4, RAND 16, AUTS 14 (answered by AV_RES) |
| 0x18 | LOC_UPDATE | C→K | tmid 4, number 7, RAND 16, RES 8 |
| 0x19 | LOC_PURGE | C→K | tmid 4, number 7 (session expired or dropped) |
| 0x1A | LOC_CANCEL | K→C | tmid 4, cause 1 (moved, reactivated, disabled) |
| 0x20 | CALL_ROUTE | C→K | leg_ref 4, caller 7, called 7 |
| 0x21 | CALL_OFFER | K→C | call_ref 4, callee 7, caller 7 |
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

`lc_sig` carries only full 13-digit E.164 (`LC_SIG_NUMBER_LEN` = 7 BCD bytes), so dial-plan normalization (`numbering-plan.md` §Dial Plan) belongs to the app.
- The core validates `+883` and the reserved subscriber numbers (0000, 9911, 9999).
- `admin sub add` auto-assigns a random free number in a configured NPA-NXX block (`numbering-plan.md` §Assignment Modes).
- Non-+883 numbers get cause 4 until a gateway exists.

## 8. Security

| Asset | Where | Protection |
|---|---|---|
| K, OPc, token secrets, network SKn | `oc-core` only | AES-256-GCM at rest (§5); never sent to a cell. Single-site: the core runs on the Pi, and this is only as strong as that Pi. |
| AVs (RAND, AUTN, XRES, CK, IK) | Core → cell, over mTLS | CK/IK give a cell its own terminals' session keys, as in 3GPP. |
| Location claims | Core | A cell must return the `RES` matching an `XRES` it was issued (the 5G "home control" idea), so a rogue or compromised cell cannot pull another cell's subscribers' MT calls to itself. |
| App data in the network | Cells and core | Plaintext inside processes and inside TLS, as in plan-5 local calls. End-to-end encryption is a later option. |
| Cell identity | Core | Per-cell certificate; revoke = `cell.enabled = 0` or a new fingerprint. |
| Abuse by a cell | Core | Per-cell rate limit on `AV_REQ`, `ACT_FWD` and `CALL_ROUTE`; audit log. |

`security-model.md` needs these updates on approval:
- the HSS lives in `oc-core` (SQLite), not RADIUS/OAI HSS;
- base stations use mTLS now, not bearer tokens;
- key-at-rest AAD is the number, not the TMID;
- WireGuard is optional, not required.

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
| **7: `lc_core` and async `lc_sig_net`** | §4.3 library changes with the existing tests moved over; `lc_core` (codec, HSS logic over a storage interface, AV/resync/activation, registry, switch, echo service); the multi-cell simulation (§9.2). Host-only. | plan 5 (lc-sig branch) |
| **8: `oc-core` and `oc-cell` on the bench** | SQLite store with sealed keys, admin CLI (replaces `mkqr`), Unix-socket transport, `oc-cell` on the `lcb_cell` backend (replaces `lcbench net`; `lcb_net` and `lcb_hss` retire), process tests, bench §9.5a. | 7 |
| **9: Multi-site** | TLS/mTLS transport, cell certificates and a small CA script, reconnect and outage handling, AV cache, two-cell bench (§9.5b). | 8 |
| **4 (amended)** | `rhu_bs` with the §10 changes as `oc-cell`'s Pi backend, then Pi 5 bring-up. | can run in parallel with 7–9 |

Plan 6 (the Android app) is unaffected: the BLE contract does not change.

## 12. Out of scope

Voice codec and audio. PSTN/SIP gateway. Direct Connect, push-to-talk and group calls. Web portal (admin CLI only). Active-call handover and multi-cell paging. Core high availability (single `oc-core`, with backups). RF backhaul as the core transport. CDR billing and user-visible call history. End-to-end media encryption. Emergency calls.

## 13. Open questions (recommended answers in **bold**)

1. Architecture: edge cell + home core, always two programs (single site = both on the Pi), as in §3.3? **Yes, option (C).**
2. In a multi-site network, do subscriber keys live only in the core, with cells getting AVs, or are they replicated to every Pi? **Core only; cells get AVs.**
3. Core stack: C11 + SQLite + OpenSSL reusing `lc_sig`, or Python/Go with the 2026-05 stack (RADIUS, Postgres, Redis, etcd)? **C11 + SQLite + OpenSSL; drop RADIUS, Diameter, etcd and Redis.**
4. Cell↔core transport: TLS 1.3 with per-cell certificates (mTLS) over TCP, signalling and media on one connection? **Yes; UDP/DTLS media only if WAN loss proves it necessary.**
5. Part 15 / Part 97 mode: per cell (core's `cell.mode`), or network-wide? **Per cell. Terminals already re-register when the beacon mode changes.**
6. Offline cells: how many cached AVs per terminal? **2, refilled after use; activation always needs the core.**
7. Where does `oc-core` run for the first multi-site deployment? **Laptop localhost on the bench, then a small VPS, so NAT'd Pis can reach it.**
8. Master key for keys at rest: a systemd credential file, a passphrase typed at start, or Vault? **A systemd credential file (root-only), `--key-file` on the bench.**
9. Order of work: build `oc-cell` on the `lcb_cell` backend (laptop + board A) first and amend plan 4 in parallel, or finish plan 4 first? **`lcb_cell` backend first; amend plan 4 per §10 before running it.**
10. Keep `lcb_net`'s simulated far end as a core echo service on `+8836065550100`? **Yes.**
