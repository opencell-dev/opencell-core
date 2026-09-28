# Network core 1: `lc_core` and async `lc_sig_net` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take subscriber keys out of `lc_sig_net` (it asks a core and is answered later), build the network core as a portable C library (`lc_core`: the cell↔core codec, HSS/AuC over a storage interface, location registry, switch, echo service, a one-core block table, and the channel list per group of cells), build the cell's side of the protocol (`lc_cell`), and prove them together in a host-only multi-cell simulation.

**Architecture:**
- Two repositories. `lc_sig` stays in **`opencell-firmware`**, where the terminal firmware and lcbench build it; this plan changes it there, on branch `net-core`. `lc_core`, `lc_cell` and the simulation live in **`opencell-core`**, on branch `lc-core`, which uses `lc_sig` through a git submodule (`third_party/opencell-firmware`) pinned to a firmware commit and builds it with its own host CMake.
- `lc_sig_net` keeps sessions, calls and local switching, but asks for activation, vectors and resync through three new io questions (`act_req`, `av_req`, `resync_req`) and gets the answers through `lc_sig_net_act_done` / `lc_sig_net_av_done`. The keyed arithmetic moves to pure functions in `lc_sig_hss.c`, which the core, lcbench's stand-in and the tests' fake core all call. `chan-list`'s channel-list code in `lc_sig_net` stays as it is.
- `lc_core` is one core: links and HELLO, HSS/AuC, registry, switch and echo service, and a channel list per list group, driven by decoded messages and `lc_core_tick`, over `lc_core_store_t` (an in-memory store here; plan 8 adds SQLite with sealed keys). Routing already goes through a block table (longest prefix, "am I home?"), and token ids carry their block index, so plan 10 adds cores without reshaping it.
- `lc_cell` is a cell's network side: `lc_sig_net` plus the core client and the leg table. `tests/net_sim.h` puts three cells, five `lc_sig_term` terminals and one core on fake radio links and an in-memory transport that carries encoded frames.

**Tech Stack:** C11 (`-Wall -Wextra -Werror`), OpenSSL 3 through `lc_sig`'s host crypto, Unity host tests, CMake, a git submodule. Host-only: nothing here runs on a board.

**Spec:** `docs/superpowers/specs/2026-09-27-network-core-design.md` (approved 2026-09-27), §11 row "7: `lc_core` and async `lc_sig_net`". Read §1–§9 and §14.2–§14.3 before Task 1. Task 16 also implements the core's side of `docs/superpowers/specs/2026-09-27-channel-list-design.md` §8 (approved). This plan is that row, renamed **Network core 1** because "plan 7" is already BLE pairing. Plans 8–11 of the spec's table follow it as network core 2–5. The specs are in the docs repository (`/home/devin/Documents/opencell/docs`); `opencell-core` carries copies.

**Revised 2026-09-27 for the multi-repo layout.** The first version of this plan (in this file's git history) was written for the monorepo (`net/lc_core`, `net/lc_cell` next to `firmware/components/lc_sig`, branches `terminal`/`numbers-v2`/`net-core`). Its task content is kept; tasks are renumbered and reordered so that the core work that doesn't need the `lc_sig` changes can start now. Old → new: 0 → 0 and 7, 1 → 8, 2 → 9, 3 → 10, 4 → 1, 5 → 2, 6 → 3, 7 → 4, 8 → 5 (admin) and 11 (questions), 9 → 12, 10 → 6, 11 → 13, 12 → 14, 13 → 15, new 16 (the channel list), 14 → 17.

**The controller's rulings (2026-09-27) for this revision:**
1. **The core's code lives in `opencell-core`** (`lc_core`, `lc_cell`, the simulation; later `oc-core`/`oc-cell`). It uses `lc_sig` (with `lc_link` and `lc_phy`, which `lc_sig` links) through the submodule `third_party/opencell-firmware`, pinned to a firmware commit and compiled by the core's own host CMake (C11, OpenSSL backend, `-Wall -Wextra -Werror`). No copies of `lc_sig` in the core repository. (Task 0; checked in Task 17.)
2. **Tasks that change `lc_sig`/lcbench (8–10: `lc_sig_hss`, the async `lc_sig_net`, ALERTING and busy/unreachable codes, 32 sessions) run in `opencell-firmware` on `net-core`, off firmware `main` after `chan-list` has merged**, on top of `chan-list`'s `lc_sig` changes (CHAN_LIST, the reliable channel's fixes, `lc_sig_net_set_chan_list`). Task 9 ports what `chan-list`'s plan asked the second branch to port (its "Before you start" and Task 8). The core then moves its submodule to that firmware commit (Task 11).
3. **Tasks that don't need those changes run now** in `opencell-core` on `lc-core` off core `main`, with the submodule at current firmware `main` (Tasks 0–6: build, codec, block table and number policy, store and contract test, links, subscribers/tokens/disable, switch and echo service). Where an early task needs a type the later `lc_sig` change brings, the core defines its own and a later task wires it: the codec's `lc_core_av_t`/`lc_core_av_status_t` (Task 1) become `lc_sig_av_t` and a compile-time check against `lc_sig_av_status_t` in Task 11. The HSS's questions (activation, vectors, resync) need `lc_sig_hss` and wait for Task 11.
4. **The channel-list seam is replaced by the real thing (Task 16)**, not kept as a stub: the core owns one list per group of cells (stored, versioned by the core), sends it to the group's cells in a new cell↔core message `CELL_CFG` (0x06, K→C: the channel-list spec §8 lets the net-core side choose HELLO_ACK or `CELL_CFG`; this plan takes `CELL_CFG`) after HELLO_ACK and on every change, and `lc_cell` serves it through `lc_sig_net_set_chan_list`, so terminals get `CHAN_LIST` after REG_ACK and on a config service request. What stays for network core 2, with `oc-cell`, the SQLite store and the admin CLI: the operator's anchors (`cell.sync_ch`, `cell.sync_fixed`), the unique-anchor-per-group check, and the beacon's `cfg_ver` (Task 16 gives `oc-cell` `lc_cell_list_ver()` for it).

**Validated while writing** (by script: every file directive of this plan applied in order, every `Run:` command run and compared with its Expected):
- Tasks 0–6 on a clone of `opencell-core` `main` (`5288d72`) with the submodule at firmware `main` `809fbb8`: after each task the core suite built without warnings and passed (1, 2, … 6 tests); after Task 6 it passes under AddressSanitizer and UBSan too.
- Tasks 7–10 on a clone of firmware **`chan-list` at `943a093`** (its fix round 3; not merged, still changing when this was written: this is the commit pinned for validation). N = 33 → 34; `test_sig_e2e` 40 → 45 → 47; the suite passes under the sanitizers; lcbench builds standalone; the ESP-IDF firmware build completes. An earlier pass on `chan-list` `4b0dad3` also passed; moving to `943a093` changed two anchors in Task 9 and added one edit (its new `net_restart()`).
- Tasks 11–16 on that core clone with the submodule on the resulting scratch `net-core` (`943a093` + Tasks 8–10): 6 → 8 tests, `test_net_sim` 16; the suite passes under the sanitizers.
- Not validated: `chan-list`'s Tasks 9–16 (after `943a093`; they touch `lcb_net.c`, `test_term_sim.c`, `test_lcbench.c`, `lc_term`), which will be in firmware `main` when Task 7 starts. Task 7 Step 3 says how to find out and what to do.

## Before you start: sequencing

| Task | Repo, branch | Starts | What |
|---|---|---|---|
| 0 | `opencell-core`, `lc-core` (new) | **now** | branch, submodule at firmware `main`, host build |
| 1 | `opencell-core`, `lc-core` | **now** | the cell↔core codec |
| 2 | `opencell-core`, `lc-core` | **now** | block table, token block index, number policy |
| 3 | `opencell-core`, `lc-core` | **now** | storage interface, in-memory store, contract test |
| 4 | `opencell-core`, `lc-core` | **now** | links: HELLO, liveness, cells, network key |
| 5 | `opencell-core`, `lc-core` | **now** | subscribers, tokens, disabling, location helpers |
| 6 | `opencell-core`, `lc-core` | **now** | switch and echo service |
| 7 | `opencell-firmware`, `net-core` (new) | after `chan-list` merges into firmware `main` | branch and baseline |
| 8 | `opencell-firmware`, `net-core` | after 7 | `lc_sig_hss` |
| 9 | `opencell-firmware`, `net-core` | after 8 | async `lc_sig_net`, fake core, lcbench as its own core |
| 10 | `opencell-firmware`, `net-core` | after 9 | ALERTING, busy/unreachable, 32 sessions; push `net-core` |
| 11 | `opencell-core`, `lc-core` | after 6 and 10 | submodule on `net-core`; activation, vectors, resync |
| 12 | `opencell-core`, `lc-core` | after 11 | location registry |
| 13 | `opencell-core`, `lc-core` | after 12 | `lc_cell` and the simulation |
| 14 | `opencell-core`, `lc-core` | after 13 | simulation: calls |
| 15 | `opencell-core`, `lc-core` | after 14 | simulation: moves, restarts, outages, resync, rogue cell |
| 16 | `opencell-core`, `lc-core` | after 15 | the channel list, core to terminals |
| 17 | both | after 16 | final checks |

Tasks 0–6 and Tasks 7–10 are independent: two implementers can run them at the same time, one per repository. Task 11 joins them.

**`chan-list`** (firmware, `docs/superpowers/plans/2026-09-27-channel-list.md`) is approved and was in its Task 8 fix rounds when this revision was written. Task 7 checks that it has merged; until then Tasks 7–10 wait. This plan adds no `lc_sig` message types: `CHAN_LIST` 0x16 / `CHAN_LIST_ACK` 0x17 and SERVICE_REQ cause 4 are `chan-list`'s, used as they are.

**Files other branches touch.** Every firmware snippet was written against `chan-list` at `943a093`. If a "replace" text is not there verbatim, find the same code and make the same change; never drop another branch's line to make a replacement fit.

| File | Touched by | Here |
|---|---|---|
| `firmware/components/lc_sig/lc_sig_net.c`, `include/lc_sig_net.h` | `chan-list` Task 8 and fix rounds (CHAN_LIST push, `drop_chan_list`, `cl_ver`/`cl_again`) | Tasks 9–10 |
| `host-tests/test_sig_e2e.c` | `chan-list` Task 8 and fix rounds (CHAN_LIST tests, `net_restart()`) | Tasks 9–10 |
| `host-tests/test_term_sim.c`, `host-tests/test_lcbench.c`, `tools/lcbench/lcb_net.c` | `chan-list` Tasks 6 and 9 (`lcb_cell` anchors, `lcb_net_set_chan_list`) | Task 9 (`test_term_sim.c`, `lcb_net.c`) |
| `firmware/components/lc_sig/CMakeLists.txt` | nobody since plan 5 | Tasks 8, 10 |

## Global Constraints

- **Where to work:** the core in `/home/devin/Documents/opencell/core` on branch `lc-core`; the firmware in `/home/devin/Documents/opencell/firmware` on branch `net-core`. Each task names its repository in its **Repo:** line; check with `git -C <repo> branch --show-current` before the first edit. Never commit to either `main`. When everything is done, report back: merging is the controller's decision.
- **The core never copies `lc_sig`:** everything `lc_sig` is changed in the firmware repository and reaches the core by moving the submodule (`git -C third_party/opencell-firmware checkout <commit>`, then `git add third_party/opencell-firmware`). The submodule's commit must be pushed to `origin` first (Task 10 Step 7).
- **Commits:** one per task, at the task's last step. Every commit message ends with exactly these two lines, with your own model name in the first:

  ```
  Co-Authored-By: <your model name> <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL
  ```
- **Language and warnings:** C11 with `-Wall -Wextra -Werror` (core, firmware host tests, lcbench). Fix what the compiler reports; never silence it.
- **Portable libraries:** `lc_sig`, `lc_core` and `lc_cell` make no OS calls (no clocks, files, sockets or `malloc`). Time comes in as `now_us`, randomness and unix time through io callbacks. Host crypto is `lc_sig`'s (OpenSSL); `lc_core` and `lc_cell` add no crypto of their own.
- **No hardware.** No task flashes a board, opens a serial port or runs `lcbench` against devices.
- **Numbers (numbering v2, network-core spec §7.11):** "`lc_sig` carries only the full form, 8 BCD bytes (`LC_SIG_NUMBER_LEN` = 8)." Stored always in full form (`+883160655501234`). The echo service is "`+883160655500100`". Reserved subscriber numbers: "00000, 00911, 09911, 99999, and the service range 00001–00999 except configured service numbers such as the echo service 00100". Auto-assigned numbers: "a random free number (01000–99998, not 09911) in a block this core is home for".
- **Framing (spec §6):** "`len (2, BE) ‖ type (1) ‖ body`, at most 512 B, little-endian fields like lc_link; numbers are 8 BCD bytes, full form". Message types and bodies exactly as the §6 table: HELLO 0x01 … MEDIA 0x28, plus this plan's CELL_CFG 0x06 (Task 16).
- **Liveness (spec §6):** "PING every 5 s. The link counts as down after 15 s without traffic."
- **Call refs (spec §6):** "a leg is named by `(cell, leg_ref)`, where `leg_ref` is the cell's `lc_sig_net` call id. Core-created legs (offers) carry a core `call_ref`."
- **Timers (spec §7.4):** "The core allows 10 s from `CALL_ROUTE` to an alert or a release. After that it sends `CALL_RELEASE(5)` to cell A and `CALL_RELEASE` to B." "Ringing is limited to 60 s by `lc_sig_net` on the MT leg (cause 3)." "Cell A with no core link releases the leg at once with cause 5." The echo service "answers after 3 s, echoes app data".
- **Vectors (spec §4.2, §6):** "AV generation with `lc_milenage()`, with SQN stepped and committed *before* the AV leaves"; `AV_REQ` count 1–4.
- **Locations (spec §7.7):** "The core moves a number's location **only on `LOC_UPDATE`**"; it "checks the update's `RES` against the stored `XRES` of an AV it issued to that cell"; "Expiry is 2 × `period_s`".
- **Token ids (spec §14.3):** "The token id's first 2 bytes are the block index, set when the token is issued; the other 6 stay random."
- **Channel list (channel-list spec §7–8):** "The core owns the channel plan"; "a `chan_list` table (`list_id`, `ver`, ordered entries)"; "The core sends it to the cell at HELLO and on change"; "The cell serves `CHAN_LIST` and puts `ver & 3` in `cfg_ver`"; at most 12 entries (`LC_SIG_CHAN_MAX`).
- **Host test commands:**
  - core, one target: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target NAME 2>&1 | grep -E "error|warning"; build/tests/NAME | tail -3`
  - core, whole suite: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
  - firmware, one target: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build --target NAME 2>&1 | grep -E "error|warning"; host-tests/build/NAME | tail -3`
  - firmware, whole suite: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3)`
  - under ASan/UBSan: the whole-suite command with `-B build/asan` (core) or `-B host-tests/build/asan` (firmware) and `-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"` on the configure line.

## Review Focus

1. **A terminal registers while its cell's core link is still coming up** (right after a cell or core restart, before HELLO_ACK). Expected: the vector question waits and is asked when HELLO_ACK arrives, so registration completes, instead of the terminal timing out and backing off for 30 s. Pinned by `test_net_sim` `test_registration_while_the_core_link_comes_up` (Task 13).
2. **The core offers a call to a cell that no longer has the callee** (it moved, or its cell restarted unnoticed). Expected: the caller gets cause 4 and the core drops the stale location, so the next call is refused at once instead of offered to the wrong cell again (spec §7.4 step 3). Pinned by `test_core_switch` `test_stale_location_is_dropped` (Task 6).
3. **Two terminals on different cells dial each other at the same moment.** Expected: both calls end busy (cause 2); nobody is left ringing or half-connected. Pinned by `test_net_sim` `test_both_dial_each_other_at_once` (Task 14).
4. **The store fails in the middle of an activation.** Expected: no ACT_RES (the terminal times out as with a lost message), the token is not consumed, no binding is half-written, and the same QR works on the next attempt. Pinned by `test_core_hss` `test_failed_activation_commit_leaves_the_token_usable` (Task 11).
5. **A CALL_ROUTE arrives twice for the same leg** (a duplicated frame, a buggy cell), or with a core-style ref. Expected: no second offer and no second call record. Pinned by `test_core_switch` `test_repeated_route_is_ignored` (Task 6).

## Decisions where the spec is silent

**`lc_sig_net` (§4.3)**
- **The keyed arithmetic stays in `lc_sig`, outside `lc_sig_net`:** `lc_sig_hss.c` holds pure functions (`lc_sig_av_make`, `lc_sig_av_auts`, `lc_sig_act_answer`) and a flat-array HSS (`lc_sig_flat_*`, over the old `lc_sig_sub_t`, which moves there). `lc_core`, lcbench's stand-in and the tests' fake core (`host-tests/sig_fake_core.h`) all use them, so there is one implementation of the plan-5 checks. `lc_sig_net.c` includes none of it.
- **Answers carry `now_us`:** `lc_sig_net_act_done(n, tmid, msg, now_us)`, `lc_sig_net_av_done(n, tmid, status, number, av, now_us)`, `lc_sig_net_drop(n, tmid, cause, now_us)`, as every other entry point of the library.
- **AV statuses:** 0 ok, 1 not activated, 2 bound elsewhere, 3 disabled, 4 core unavailable, and a new **5 auth failed** (a resync whose AUTS does not verify; the old code answered `REG_REJ(auth failed)`, and so does the cell now). 1–3 give `REG_REJ(not activated)`; 4 gives no answer (the terminal times out). Status 2 is on the wire but no core in this plan sends it.
- **One question at a time, for 3 s** (`LC_SIG_NET_ASK_US`): while an activation or vector question is open, another REG_REQ or ACT_REQ from that terminal waits for the same answer; after 3 s a new request asks again. An answer nobody is waiting for returns -1 and changes nothing.
- **Re-activation cuts off the old terminals through the core**, as `LOC_CANCEL(reactivated)` → `lc_sig_net_drop`, sent before `ACT_RES`. `lc_sig_net_act_done(ACK)` itself only clears a half-finished vector and ends a call left from the terminal's previous life; it never deregisters, so a replayed ACT_REQ (answered again with the same ACK) can't knock a terminal off.
- **New event `LC_SIG_NET_ALERTING`** for every incoming leg that rings (local legs too; `peer_tmid` tells them apart), and `lc_sig_net_call_in` returns `LC_SIG_NET_IN_UNREACHABLE` (-1) or `LC_SIG_NET_IN_BUSY` (-2). New io callback `unregistered` (a registration lapsed: the cell sends `LOC_PURGE`) next to the spec's `registered`, and a getter `lc_sig_net_number`.
- **`LC_SIG_NET_TERMS`** defaults to 32 and is a CMake cache variable (`-DLC_SIG_NET_TERMS=64`) passed as a PUBLIC compile definition, so the library and every user (the core's `lc_cell` too, through the submodule) agree on the struct.
- **lcbench keeps its bench behaviour:** it is its own single-process core (`lc_sig_flat_*` over its text-file HSS, saved before any answer leaves). A call to a number of its HSS that is not registered gets cause 4, as before, not the simulated far end. `chan-list`'s `lcbench net --chan-list` keeps working: the list lives in `lc_sig_net`, which this plan leaves alone.
- **`chan-list`'s code in `lc_sig_net` is kept as it is** (Task 9): the async questions change who computes the vector, not when REG_ACK and its CHAN_LIST push go out.

**The protocol (§6)**
- `len` counts the bytes after it (type and body); a whole frame is at most 512 bytes. `ACT_RES` carries the `lc_sig` message as its type byte then its body. A number field that is not a valid number makes the frame undecodable, except `AV_RES`'s when the status is not ok.
- **Refs:** core call refs have the top bit set (`LC_CORE_REF_CORE`); `lc_sig_net` call ids never reach 2^31. Every message about a leg carries the ref the leg started with, in both directions, so `(cell, ref)` is unambiguous.
- `req` is echoed back; the cell matches answers by TMID (lc_sig_net ignores an answer it isn't waiting for).
- **The codec's vector type:** `lc_core_av_t` (RAND, AUTN, XRES, CK, IK) and `lc_core_av_status_t` (the §6 status values) are the codec's own until `lc_sig_hss.h` is in the submodule (Tasks 1–6); from Task 11, `lc_core_av_t` is a typedef of `lc_sig_av_t` and a `_Static_assert` keeps the statuses equal to `lc_sig_av_status_t`'s. Core code uses `LC_CORE_AV_*` (the wire's), `lc_cell` hands them to `lc_sig_net_av_done` as they are.
- **`CELL_CFG` (0x06, K→C, Task 16)** carries a `CHAN_LIST` body exactly as `lc_sig_body_encode` writes it (ver, count, entries with big-endian frequencies, as in `lc_sig`), so the cell passes it through without a second encoding. Count 0 is a list with no entries (the operator emptied it), not "no list".

**The core**
- **The registration period** comes from the network key's row (spec §5 `network.period_s`): HELLO_ACK announces it, and a location expires 2 × it after its LOC_UPDATE.
- **HELLO:** refused as "disabled" when the core has no network key; a cell's first HELLO (boot id 0 stored) counts as a new boot; one link per cell, the newest wins (the old link is dropped and its calls released).
- **One core, blocks at home (§14.2):** a token whose block index names no block of this core is "unknown"; a vector for a subscriber outside the home blocks is "unavailable"; a call to a number outside them gets cause 4. Block index 0 is refused, so a zeroed token id never routes. Plan 10 replaces the three with LOCATE and relays.
- **Reserved numbers** apply to NANP (country code 1) only; other country codes have no plan yet. Auto-assignment picks from the first NANP block this core is home for, and never lands in a longer block inside it that belongs to someone else.
- **Location claims (§8):** a LOC_UPDATE without the RES of a vector issued to that very cell is refused and audited (AUTH_FAIL). One that does prove itself, for a binding the core has since cancelled (re-activated or disabled while the cell was cut off), is answered with `LOC_CANCEL` so an honest cell drops the stale registration.
- **Caller id:** a CALL_ROUTE is refused (cause 5) unless its caller is registered on that same cell, so a cell can't call as someone else. A callee whose cell has no link gets cause 5 (§7.6 "backhaul down"); a callee's cell answering cause 4 while the call is still being offered means its location was stale: the core deletes it (§7.4 step 3).
- **Records:** a CDR for every call attempt, refusals included (`cell_b` 0 for the echo service); issued vectors are pruned hourly once older than a day (§5 "pruned after 24 h").
- **A failed commit sends nothing that depends on it:** a vector question gets status 4 and SQN stays where it was; an activation gets no answer at all.
- **Channel lists (channel-list spec §8):** one per list group (`cell.list_id`, 1–65535; 0 is "no group"), in the store (`list_get`/`list_put`, so plan 8's SQLite store keeps them and a core restart doesn't lose them). The core numbers the versions (1, 2, … 255, then 1; the operator's `ver` is ignored), so a change always moves `cfg_ver`. A cell gets its group's list after every HELLO_ACK and whenever it changes; a cell keeps serving the last list it got while its core link is down.

**Deferred, per spec §11 (and the channel-list spec)**
- AES-256-GCM sealing at rest, and §9.1's seal/open tests, belong to plan 8's SQLite store (network core 2); the store interface here carries keys in the clear.
- §9.3 (`test_term_sim` on the new glue) comes with plan 8, when `oc-cell` replaces `lcb_net`. Here `test_term_sim`'s bare `lc_sig_net` runs on the fake core and its `lcb_net` part on lcbench's own HSS, so the plan-5 air path stays covered unchanged.
- The cell's AV cache (2 per terminal, §7.8) and per-cell rate limits (§8) belong to plan 9 (network core 3). The cell asks for one vector at a time. §9.2's two cache scenarios become "a backhaul outage without a cache" and "the HSS behind the terminal → resync through the core".
- The channel list's operator side (`cell.sync_ch`, `cell.sync_fixed`, anchor uniqueness per group, `sync_fixed ⇒ part97`) and the beacon's `cfg_ver` belong to network core 2 (`oc-cell`, the admin CLI).

**Layout**
- `opencell-core`: `CMakeLists.txt` (the project; `lc_phy`, `lc_link`, `lc_sig` from the submodule), `lc_core/` (library, codec included), `lc_cell/` (the §9.2 "glue", written once as a library so plan 8's `oc-cell` wraps it instead of growing it again from `lcb_net.c`), `tests/` (Unity; `tests/<name>.c` per test). Plan 8 adds the programs next to the libraries. A test that needs `lc_core`'s internal header adds `lc_core/` to its include path (Task 5).
- `opencell-firmware`: unchanged layout; `lc_sig_hss.[ch]` next to the rest of `lc_sig`, `host-tests/sig_fake_core.h` next to its tests.
- The simulation's transport is a stream (as TCP/TLS will be): frames are never lost one by one. A test can mute a cell (its frames to the core vanish) or cut its link.

## File Structure

| File | Repo | Responsibility | Task |
|---|---|---|---|
| `.gitmodules`, `third_party/opencell-firmware` | core | The firmware at a pinned commit | 0, 11 |
| `CMakeLists.txt`, `tests/CMakeLists.txt`, `.gitignore` | core | The host build: `lc_sig` from the submodule, the libraries, Unity tests | 0, 1, 13 |
| `lc_core/CMakeLists.txt` | core | The `lc_core` library | 1–6 |
| `lc_core/include/lc_core_msg.h`, `lc_core_msg.c` | core | Cell↔core codec | 1, 11, 16 |
| `lc_core/include/lc_core_route.h`, `lc_core_route.c` | core | Block table, token block index, number policy | 2 |
| `lc_core/include/lc_core_store.h` | core | Records and the storage interface | 3, 16 |
| `lc_core/include/lc_core_mem.h`, `lc_core_mem.c` | core | In-memory store | 3, 16 |
| `lc_core/include/lc_core.h`, `lc_core.c`, `lc_core_int.h` | core | The core: links, HELLO, liveness, dispatch, cells, network key, channel lists | 4–6, 11, 12, 16 |
| `lc_core/lc_core_hss.c` | core | Subscribers, tokens (5); activation, vectors, resync (11) | 5, 11 |
| `lc_core/lc_core_reg.c` | core | Location registry | 5, 12 |
| `lc_core/lc_core_switch.c` | core | Switch, echo service, CDRs | 6 |
| `lc_cell/CMakeLists.txt`, `include/lc_cell.h`, `lc_cell.c` | core | A cell's network side: `lc_sig_net` + core client + leg table | 13, 16 |
| `tests/core_store_contract.h`, `tests/test_core_store.c` | core | The store contract (plan 8 runs it on SQLite), the memory store | 3, 16 |
| `tests/core_fixture.h` | core | A core with cells as bare message endpoints | 4 |
| `tests/test_core_msg.c`, `test_core_route.c`, `test_core_link.c`, `test_core_hss.c`, `test_core_switch.c`, `test_core_reg.c` | core | `lc_core`, piece by piece | 1–6, 11, 12, 16 |
| `tests/net_sim.h`, `tests/test_net_sim.c` | core | The multi-cell simulation (§9.2) | 13–16 |
| `firmware/components/lc_sig/include/lc_sig_hss.h`, `lc_sig_hss.c` | firmware | Home side of activation and AKA as pure functions; the flat-array HSS and `lc_sig_sub_t` | 8 |
| `firmware/components/lc_sig/include/lc_sig_net.h`, `lc_sig_net.c` | firmware | Network role without keys: questions to the core, answers, drop, events, 32 sessions | 8–10 |
| `firmware/components/lc_sig/CMakeLists.txt` | firmware | `lc_sig_hss.c` in the host library; `LC_SIG_NET_TERMS` cache variable | 8, 10 |
| `host-tests/sig_fake_core.h` | firmware | Synchronous fake core for `lc_sig_net` tests (answers now, later, or never) | 9 |
| `host-tests/test_sig_hss.c` | firmware | `lc_sig_hss` against the terminal's own checks | 8 |
| `host-tests/test_sig_e2e.c`, `test_sig_local.c`, `test_term_sim.c` | firmware | Moved onto the fake core; async and event tests | 9–10 |
| `tools/lcbench/lcb_net.c` | firmware | lcbench as its own single-process core | 9 |
| `host-tests/CMakeLists.txt` | firmware | `test_sig_hss` | 8 |

---

### Task 0: The core repository's branch, the firmware submodule, and the host build

**Repo:** `opencell-core`, branch `lc-core` (new, off `main`), at `/home/devin/Documents/opencell/core`. **Starts:** now.

The core repository has no code yet. This task makes the branch, brings `lc_sig` in as a submodule pinned to a firmware commit, and sets up the host build every later core task adds to: the core's own CMake project (C11, `-Wall -Wextra -Werror`), which builds `lc_sig` and what it links (`lc_link`, `lc_phy`) from the submodule with the firmware's own host `CMakeLists.txt` (the OpenSSL backend), and a `tests/` directory with Unity.

**Files:**
- Create: `.gitmodules` (by `git submodule add`), `third_party/opencell-firmware` (the submodule), `CMakeLists.txt`, `tests/CMakeLists.txt`, `.gitignore`
- Replace: `docs/superpowers/plans/2026-09-27-net-core-1-lc-core.md` (this plan, from the docs repository)

**Interfaces:**
- Produces: CMake targets `lc_sig` (and `lc_link`, `lc_phy`) from the submodule; the CMake function `lc_test(name lib)` in `tests/CMakeLists.txt` (one Unity test per `tests/<name>.c`, linked with `lib`); the variable `OC_FW` (the submodule's path). The core test count starts at 0.

- [ ] **Step 1: The branch**

Run: `cd /home/devin/Documents/opencell/core && git status --short && git switch main && git pull -q && git switch -c lc-core && git branch --show-current`
Expected: `git status` prints nothing (a clean tree), then `lc-core`.

- [ ] **Step 2: The firmware as a submodule, pinned to firmware `main`**

```bash
cd /home/devin/Documents/opencell/core
git submodule add ../opencell-firmware.git third_party/opencell-firmware
git -C third_party/opencell-firmware checkout -q origin/main
git -C third_party/opencell-firmware log --oneline -1
cat .gitmodules
```

Expected: the log line of firmware `main`'s head, and `.gitmodules` with `path = third_party/opencell-firmware` and `url = ../opencell-firmware.git` (relative to this repository's `origin`, so HTTPS and SSH clones both work). Write the commit hash down in the commit message of Step 5. This plan was validated with firmware `main` at `809fbb8`; if `chan-list` has merged since, `main` is newer, which is fine: Tasks 1–6 use nothing that `chan-list` changed.

- [ ] **Step 3: The build**

Create `CMakeLists.txt`:
```cmake
# The OpenCell network core (network-core spec §4.2). Host-only for now: the
# portable libraries lc_core and lc_cell, and their tests. lc_sig comes from
# the firmware repository (third_party/opencell-firmware, a submodule pinned
# to a firmware commit) and is built here by the firmware's own host
# CMakeLists (the OpenSSL backend), under this project's flags. It is never
# copied into this repository.
cmake_minimum_required(VERSION 3.16)
project(opencell_core C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror)

set(OC_FW ${CMAKE_CURRENT_SOURCE_DIR}/third_party/opencell-firmware)
if(NOT EXISTS ${OC_FW}/firmware/components/lc_sig/CMakeLists.txt)
  message(FATAL_ERROR "third_party/opencell-firmware is empty: run git submodule update --init")
endif()
add_subdirectory(${OC_FW}/firmware/components/lc_phy lc_phy)
add_subdirectory(${OC_FW}/firmware/components/lc_link lc_link)
add_subdirectory(${OC_FW}/firmware/components/lc_sig lc_sig)

enable_testing()
add_subdirectory(tests)
```

Create `tests/CMakeLists.txt`:
```cmake
# Host tests (Unity), one executable per tests/<name>.c.
include(FetchContent)
FetchContent_Declare(unity
  GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
  GIT_TAG v2.6.1)
FetchContent_MakeAvailable(unity)

function(lc_test name lib)
  add_executable(${name} ${name}.c)
  target_link_libraries(${name} PRIVATE ${lib} unity)
  add_test(NAME ${name} COMMAND ${name})
endfunction()
```

Create `.gitignore`:
```
build/
```

- [ ] **Step 4: It builds, with no tests yet**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; ls build/lc_sig/liblc_sig.a; (cd build && ctest 2>&1 | tail -1)`
Expected: no compiler output (the firmware's `lc_sig`, `lc_link` and `lc_phy` compile cleanly under this project's `-Wall -Wextra -Werror`), then `build/lc_sig/liblc_sig.a`, then `No tests were found!!!`. Tasks 1–6 add one test each.

- [ ] **Step 5: This plan into the repository, and commit**

The plan's copy in this repository predates the multi-repo layout; the docs repository's is the one to follow.

```bash
cd /home/devin/Documents/opencell/core
git -C /home/devin/Documents/opencell/docs pull -q
cp /home/devin/Documents/opencell/docs/docs/superpowers/plans/2026-09-27-net-core-1-lc-core.md docs/superpowers/plans/
git add .gitmodules third_party/opencell-firmware CMakeLists.txt tests/CMakeLists.txt .gitignore docs/superpowers/plans
git commit -m "Host build: lc_sig from the firmware submodule (pinned to firmware main <hash>), Unity tests

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

(`<hash>`: the short hash from Step 2.)

---

### Task 1: The cell↔core codec (`lc_core_msg`)

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** now (after Task 0).

The §6 protocol as a codec over whole frames, the first piece of the new `lc_core` library. Numbers are checked on decode, so neither side ever acts on a malformed number.

An AV_RES carries vectors and a status. Their `lc_sig` types (`lc_sig_av_t`, `lc_sig_av_status_t`) arrive with `lc_sig_hss.h` in firmware Task 8, which this task can't wait for, so the codec defines its own wire types with the same layout and values: `lc_core_av_t` and `lc_core_av_status_t` (`LC_CORE_AV_OK` … `LC_CORE_AV_AUTH_FAILED`). Task 11 turns `lc_core_av_t` into a typedef of `lc_sig_av_t` and checks the status values against `lc_sig`'s at compile time; nothing else changes.

**Files:**
- Create: `lc_core/CMakeLists.txt`, `lc_core/include/lc_core_msg.h`, `lc_core/lc_core_msg.c`
- Modify: `CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/test_core_msg.c`

**Interfaces:**
- Consumes: `lc_sig_msg_t`, `lc_sig_body_encode/decode`, `lc_sig_number_valid` (all on firmware `main`).
- Produces (`lc_core_msg.h`): `lc_core_av_t` (`rand[16], autn[16], xres[8], ck[16], ik[16]`), `lc_core_av_status_t` (`LC_CORE_AV_OK` 0, `_NOT_ACTIVATED` 1, `_BOUND_ELSEWHERE` 2, `_DISABLED` 3, `_UNAVAILABLE` 4, `_AUTH_FAILED` 5), `LC_CORE_FRAME_MAX` (512u), `LC_CORE_PROTO` (1u), `LC_CORE_AV_MAX` (4u), `LC_CORE_REF_CORE` (0x80000000u); `lc_core_type_t` with every type of the §6 table, `LC_CORE_HELLO` (0x01) to `LC_CORE_MEDIA` (0x28); `lc_core_nak_t` (`LC_CORE_NAK_UNKNOWN_CELL` 1, `_DISABLED` 2, `_VERSION` 3); `lc_core_cancel_t` (`LC_CORE_CANCEL_MOVED` 1, `_REACTIVATED` 2, `_DISABLED` 3); `lc_core_msg_t`, a `type` and a union with one member per body: `hello`, `hello_ack`, `hello_nak`, `act_fwd`, `act_res`, `av_req`, `av_res`, `resync`, `loc_update`, `loc_purge`, `loc_cancel`, `call_route`, `call_offer`, `call` (`{ uint32_t ref; uint8_t cause; }` for CALL_ALERT, CALL_ANSWER and CALL_RELEASE) and `media`. And:
  ```c
  size_t lc_core_encode(const lc_core_msg_t *m, uint8_t *out, size_t cap); /* the whole frame; 0 on error */
  int    lc_core_decode(const uint8_t *in, size_t len, lc_core_msg_t *m);  /* one whole frame; 0 or -1 */
  ```

- [ ] **Step 1: Write the failing test**

Create `tests/test_core_msg.c`:
```c
/* The cell <-> core protocol codec (network-core spec §6): golden bytes,
 * a round trip of every type, and what must not decode. */
#include "unity.h"

#include <string.h>

#include "lc_core_msg.h"

void setUp(void) {}
void tearDown(void) {}

static void num(const char *text, uint8_t out[LC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT(0, lc_sig_number_to_bcd(text, strlen(text), out));
}

static void golden(const lc_core_msg_t *m, const uint8_t *want, size_t n)
{
    uint8_t buf[LC_CORE_FRAME_MAX];
    lc_core_msg_t back;
    TEST_ASSERT_EQUAL_size_t(n, lc_core_encode(m, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, buf, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_decode(buf, n, &back));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(m, &back, sizeof(back));
}

static void test_golden_bytes(void)
{
    lc_core_msg_t m;

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO;
    m.u.hello.proto = 1;
    m.u.hello.cell_id = 0x01020304u;
    m.u.hello.boot_id = 0x1122334455667788ull;
    m.u.hello.sw_version[1] = 7;
    static const uint8_t hello[] = { 0x00, 0x11, 0x01, 0x01, 0x04, 0x03, 0x02, 0x01, 0x88, 0x77,
                                     0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x07, 0x00 };
    golden(&m, hello, sizeof(hello));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO_ACK;
    m.u.hello_ack.mode = LC_SIG_MODE_PART15;
    m.u.hello_ack.period_s = 1800;
    m.u.hello_ack.key_id = 1;
    num("+883160655500100", m.u.hello_ack.echo_number);
    static const uint8_t ack[] = { 0x00, 0x0E, 0x02, 0x01, 0x08, 0x07, 0x01, 0x00,
                                   0x88, 0x31, 0x60, 0x65, 0x55, 0x00, 0x10, 0x0F };
    golden(&m, ack, sizeof(ack));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = 7;
    num("+883160655501234", m.u.call_route.caller);
    num("+883160655501235", m.u.call_route.called);
    static const uint8_t route[] = { 0x00, 0x15, 0x20, 0x07, 0x00, 0x00, 0x00, 0x88, 0x31, 0x60, 0x65, 0x55,
                                     0x01, 0x23, 0x4F, 0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x5F };
    golden(&m, route, sizeof(route));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_MEDIA;
    m.u.media.ref = LC_CORE_REF_CORE | 1u;
    m.u.media.seq = 0x0102;
    m.u.media.len = 2;
    memcpy(m.u.media.data, "HI", 2);
    static const uint8_t media[] = { 0x00, 0x09, 0x28, 0x01, 0x00, 0x00, 0x80, 0x02, 0x01, 0x48, 0x49 };
    golden(&m, media, sizeof(media));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_RELEASE;
    m.u.call.ref = 7;
    m.u.call.cause = LC_SIG_CAUSE_UNREACHABLE;
    static const uint8_t rel[] = { 0x00, 0x06, 0x24, 0x07, 0x00, 0x00, 0x00, 0x04 };
    golden(&m, rel, sizeof(rel));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_ACT_RES;
    m.u.act_res.req = 0x0102;
    m.u.act_res.tmid = 0x76ad0488u;
    m.u.act_res.msg.type = LC_SIG_ACT_NAK;
    m.u.act_res.msg.u.act_nak.reason = LC_SIG_ACT_USED;
    for (int i = 0; i < 8; i++) m.u.act_res.msg.u.act_nak.tag[i] = (uint8_t)(i + 1);
    static const uint8_t res[] = { 0x00, 0x11, 0x11, 0x02, 0x01, 0x88, 0x04, 0xAD, 0x76, 0x03,
                                   0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    golden(&m, res, sizeof(res));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_RES;
    m.u.av_res.req = 1;
    m.u.av_res.tmid = 0x76ad0488u;
    m.u.av_res.status = LC_CORE_AV_NOT_ACTIVATED; /* no number, no vectors */
    static const uint8_t avres[] = { 0x00, 0x11, 0x13, 0x01, 0x00, 0x88, 0x04, 0xAD, 0x76, 0x01,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    golden(&m, avres, sizeof(avres));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_CANCEL;
    m.u.loc_cancel.tmid = 0x76ad0488u;
    m.u.loc_cancel.cause = LC_CORE_CANCEL_MOVED;
    static const uint8_t cancel[] = { 0x00, 0x06, 0x1A, 0x88, 0x04, 0xAD, 0x76, 0x01 };
    golden(&m, cancel, sizeof(cancel));

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_PING;
    static const uint8_t ping[] = { 0x00, 0x01, 0x04 };
    golden(&m, ping, sizeof(ping));
}

/* Every type once, with every field set: encode, decode, compare. */
static void test_every_type_round_trips(void)
{
    lc_core_msg_t ms[19];
    int k = 0;
    memset(ms, 0, sizeof(ms));
    ms[k].type = LC_CORE_HELLO;
    ms[k].u.hello.proto = 1;
    ms[k].u.hello.cell_id = 9;
    ms[k++].u.hello.boot_id = 0xFEDCBA9876543210ull;
    ms[k].type = LC_CORE_HELLO_ACK;
    ms[k].u.hello_ack.mode = 2;
    num("+883160655500100", ms[k++].u.hello_ack.echo_number);
    ms[k].type = LC_CORE_HELLO_NAK;
    ms[k++].u.hello_nak.reason = LC_CORE_NAK_DISABLED;
    ms[k++].type = LC_CORE_PING;
    ms[k++].type = LC_CORE_PONG;
    ms[k].type = LC_CORE_ACT_FWD;
    ms[k].u.act_fwd.req = 0xBEEF;
    ms[k].u.act_fwd.tmid = 0x11223344u;
    memset(ms[k].u.act_fwd.token_id, 0x01, 8);
    memset(ms[k].u.act_fwd.pkt, 0x02, 32);
    memset(ms[k++].u.act_fwd.tag, 0x03, 8);
    ms[k].type = LC_CORE_ACT_RES;
    ms[k].u.act_res.msg.type = LC_SIG_ACT_ACK;
    num("+883160655501234", ms[k].u.act_res.msg.u.act_ack.number);
    memset(ms[k++].u.act_res.msg.u.act_ack.confirm, 0x44, 8);
    ms[k].type = LC_CORE_AV_REQ;
    ms[k].u.av_req.tmid = 5;
    ms[k++].u.av_req.count = 2;
    ms[k].type = LC_CORE_AV_RES;
    ms[k].u.av_res.status = LC_CORE_AV_OK;
    num("+883160655501234", ms[k].u.av_res.number);
    ms[k].u.av_res.count = LC_CORE_AV_MAX;
    for (unsigned i = 0; i < LC_CORE_AV_MAX; i++) memset(&ms[k].u.av_res.av[i], (int)(0x10 + i), sizeof(lc_core_av_t));
    k++;
    ms[k].type = LC_CORE_RESYNC;
    memset(ms[k].u.resync.rand, 0x55, 16);
    memset(ms[k++].u.resync.auts, 0x66, 14);
    ms[k].type = LC_CORE_LOC_UPDATE;
    ms[k].u.loc_update.tmid = 77;
    num("+883160655501234", ms[k].u.loc_update.number);
    memset(ms[k].u.loc_update.rand, 0x77, 16);
    memset(ms[k++].u.loc_update.res, 0x88, 8);
    ms[k].type = LC_CORE_LOC_PURGE;
    num("+883160655501234", ms[k++].u.loc_purge.number);
    ms[k].type = LC_CORE_LOC_CANCEL;
    ms[k++].u.loc_cancel.cause = LC_CORE_CANCEL_DISABLED;
    ms[k].type = LC_CORE_CALL_ROUTE;
    num("+883160655501234", ms[k].u.call_route.caller);
    num("+883442079460000", ms[k++].u.call_route.called);
    ms[k].type = LC_CORE_CALL_OFFER;
    ms[k].u.call_offer.call_ref = LC_CORE_REF_CORE | 3u;
    num("+883160655501235", ms[k].u.call_offer.callee);
    num("+883160655501234", ms[k++].u.call_offer.caller);
    ms[k].type = LC_CORE_CALL_ALERT;
    ms[k++].u.call.ref = 3;
    ms[k].type = LC_CORE_CALL_ANSWER;
    ms[k++].u.call.ref = 4;
    ms[k].type = LC_CORE_CALL_RELEASE;
    ms[k].u.call.ref = 5;
    ms[k++].u.call.cause = LC_SIG_CAUSE_BUSY;
    ms[k].type = LC_CORE_MEDIA;
    ms[k].u.media.len = LC_SIG_APP_MAX;
    memset(ms[k++].u.media.data, 0x99, LC_SIG_APP_MAX);
    TEST_ASSERT_EQUAL_INT(19, k);
    for (int i = 0; i < k; i++) {
        uint8_t buf[LC_CORE_FRAME_MAX];
        lc_core_msg_t back;
        size_t n = lc_core_encode(&ms[i], buf, sizeof(buf));
        TEST_ASSERT_TRUE_MESSAGE(n >= 3, "encode");
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, lc_core_decode(buf, n, &back), "decode");
        TEST_ASSERT_EQUAL_HEX8_ARRAY(&ms[i], &back, sizeof(back));
        TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&ms[i], buf, n - 1)); /* one byte short */
    }
}

static void test_what_does_not_decode(void)
{
    lc_core_msg_t m;
    uint8_t buf[LC_CORE_FRAME_MAX];
    size_t n;

    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_ROUTE;
    num("+883160655501234", m.u.call_route.caller);
    num("+883160655501235", m.u.call_route.called);
    n = lc_core_encode(&m, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, lc_core_decode(buf, n, &m));
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n - 1, &m)); /* short */
    buf[1]++;                                                   /* length prefix disagrees */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n, &m));
    buf[1]--;
    buf[n - 1] = 0x5A; /* the called number ends in nibble A: not a number */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n, &m));

    static const uint8_t unknown[] = { 0x00, 0x01, 0x07 }; /* a free type */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(unknown, sizeof(unknown), &m));
    static const uint8_t ping_long[] = { 0x00, 0x02, 0x04, 0x00 };
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(ping_long, sizeof(ping_long), &m));

    memset(&m, 0, sizeof(m)); /* AV_RES with 5 vectors */
    m.type = LC_CORE_AV_RES;
    m.u.av_res.status = LC_CORE_AV_NOT_ACTIVATED;
    m.u.av_res.count = LC_CORE_AV_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&m, buf, sizeof(buf)));
    m.u.av_res.count = 1;
    n = lc_core_encode(&m, buf, sizeof(buf));
    buf[2 + 1 + 2 + 4 + 1 + 8] = 5; /* the count byte */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(buf, n, &m));

    memset(&m, 0, sizeof(m)); /* ACT_RES carrying something other than ACT_ACK/NAK */
    m.type = LC_CORE_ACT_RES;
    m.u.act_res.msg.type = LC_SIG_REG_REJ;
    TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&m, buf, sizeof(buf)));

    memset(&m, 0, sizeof(m)); /* MEDIA with 19 bytes */
    m.type = LC_CORE_MEDIA;
    m.u.media.len = LC_SIG_APP_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&m, buf, sizeof(buf)));
    uint8_t big[3 + 4 + 2 + 19] = { 0x00, 3 + 4 + 2 + 19 - 2, LC_CORE_MEDIA };
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(big, sizeof(big), &m));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_golden_bytes);
    RUN_TEST(test_every_type_round_trips);
    RUN_TEST(test_what_does_not_decode);
    return UNITY_END();
}
```

In `CMakeLists.txt`, replace:
```cmake
add_subdirectory(${OC_FW}/firmware/components/lc_sig lc_sig)
```
with:
```cmake
add_subdirectory(${OC_FW}/firmware/components/lc_sig lc_sig)
add_subdirectory(lc_core)
```

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_core_msg lc_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build 2>&1 | grep -m1 -A1 "add_subdirectory given source"`
Expected: `add_subdirectory given source "lc_core" which is not an existing directory.`: the library does not exist yet.

- [ ] **Step 3: The library and the codec**

Create `lc_core/CMakeLists.txt`:
```cmake
# lc_core: the network core as a portable C11 library (network-core spec
# §4.2): no OS calls, driven by messages and tick(now). oc-core (network core
# 2) adds SQLite, sockets, TLS and the clock around it.
add_library(lc_core STATIC lc_core_msg.c)
target_include_directories(lc_core PUBLIC include)
target_link_libraries(lc_core PUBLIC lc_sig)
```

Create `lc_core/include/lc_core_msg.h`:
```c
/* The cell <-> core protocol (network-core spec §6): one frame is
 *   len (2, big-endian: the bytes after it) | type (1) | body
 * at most LC_CORE_FRAME_MAX bytes in all. Body fields are little-endian, as
 * in lc_link; numbers are 8 BCD bytes in the full form (numbering v2), and a
 * frame whose number is not valid does not decode.
 *
 * Call refs: a leg a cell starts (CALL_ROUTE) is named by the cell's
 * lc_sig_net call id, which stays below 2^31; a leg the core starts
 * (CALL_OFFER) by a core call ref with LC_CORE_REF_CORE set. Every later
 * message about a leg, in either direction, carries the ref it started with.
 *
 * Types not listed here are free. */
#ifndef LC_CORE_MSG_H
#define LC_CORE_MSG_H

#include "lc_sig_msg.h" /* lc_sig_msg_t, lc_sig_body_encode/decode */

#define LC_CORE_FRAME_MAX 512u
#define LC_CORE_PROTO     1u
#define LC_CORE_AV_MAX    4u
#define LC_CORE_REF_CORE  0x80000000u

typedef enum {
    LC_CORE_HELLO = 0x01, LC_CORE_HELLO_ACK = 0x02, LC_CORE_HELLO_NAK = 0x03, LC_CORE_PING = 0x04, LC_CORE_PONG = 0x05,
    LC_CORE_ACT_FWD = 0x10, LC_CORE_ACT_RES = 0x11, LC_CORE_AV_REQ = 0x12, LC_CORE_AV_RES = 0x13,
    LC_CORE_RESYNC = 0x14,
    LC_CORE_LOC_UPDATE = 0x18, LC_CORE_LOC_PURGE = 0x19, LC_CORE_LOC_CANCEL = 0x1A,
    LC_CORE_CALL_ROUTE = 0x20, LC_CORE_CALL_OFFER = 0x21, LC_CORE_CALL_ALERT = 0x22, LC_CORE_CALL_ANSWER = 0x23,
    LC_CORE_CALL_RELEASE = 0x24, LC_CORE_MEDIA = 0x28
} lc_core_type_t;

typedef enum { LC_CORE_NAK_UNKNOWN_CELL = 1, LC_CORE_NAK_DISABLED = 2, LC_CORE_NAK_VERSION = 3 } lc_core_nak_t;

/* One authentication vector as AV_RES carries it (TS 33.102 §6.3.2). The
 * layout of lc_sig_av_t (lc_sig_hss.h), which it becomes once lc_sig has it. */
typedef struct {
    uint8_t rand[16], autn[16], xres[8], ck[16], ik[16];
} lc_core_av_t;

/* AV_RES status (§6; network-core spec §4.3). The values of lc_sig_hss.h's
 * lc_sig_av_status_t, which lc_sig_net_av_done takes. */
typedef enum {
    LC_CORE_AV_OK = 0,
    LC_CORE_AV_NOT_ACTIVATED = 1,   /* no subscriber bound to the TMID */
    LC_CORE_AV_BOUND_ELSEWHERE = 2, /* reserved: no core in this plan sends it */
    LC_CORE_AV_DISABLED = 3,
    LC_CORE_AV_UNAVAILABLE = 4,     /* no answer possible now (store, core link): the terminal retries */
    LC_CORE_AV_AUTH_FAILED = 5      /* resync refused: AUTS did not verify */
} lc_core_av_status_t;
typedef enum { LC_CORE_CANCEL_MOVED = 1, LC_CORE_CANCEL_REACTIVATED = 2, LC_CORE_CANCEL_DISABLED = 3 } lc_core_cancel_t;

typedef struct {
    uint8_t type; /* lc_core_type_t */
    union {
        struct { uint8_t proto; uint32_t cell_id; uint64_t boot_id; uint8_t sw_version[3]; } hello;
        struct { uint8_t mode; uint16_t period_s, key_id; uint8_t echo_number[LC_SIG_NUMBER_LEN]; } hello_ack;
        struct { uint8_t reason; } hello_nak;
        struct { uint16_t req; uint32_t tmid; uint8_t token_id[8], pkt[32], tag[8]; } act_fwd;
        struct { uint16_t req; uint32_t tmid; lc_sig_msg_t msg; } act_res; /* msg: ACT_ACK or ACT_NAK */
        struct { uint16_t req; uint32_t tmid; uint8_t count; } av_req;
        struct {
            uint16_t    req;
            uint32_t    tmid;
            uint8_t      status; /* lc_core_av_status_t; number and vectors only when LC_CORE_AV_OK */
            uint8_t      number[LC_SIG_NUMBER_LEN];
            uint8_t      count;
            lc_core_av_t av[LC_CORE_AV_MAX];
        } av_res;
        struct { uint16_t req; uint32_t tmid; uint8_t rand[16], auts[14]; } resync;
        struct { uint32_t tmid; uint8_t number[LC_SIG_NUMBER_LEN], rand[16], res[8]; } loc_update;
        struct { uint32_t tmid; uint8_t number[LC_SIG_NUMBER_LEN]; } loc_purge;
        struct { uint32_t tmid; uint8_t cause; } loc_cancel; /* lc_core_cancel_t */
        struct { uint32_t leg_ref; uint8_t caller[LC_SIG_NUMBER_LEN], called[LC_SIG_NUMBER_LEN]; } call_route;
        struct { uint32_t call_ref; uint8_t callee[LC_SIG_NUMBER_LEN], caller[LC_SIG_NUMBER_LEN]; } call_offer;
        struct { uint32_t ref; uint8_t cause; } call; /* CALL_ALERT, CALL_ANSWER (no cause), CALL_RELEASE */
        struct { uint32_t ref; uint16_t seq; uint8_t len; uint8_t data[LC_SIG_APP_MAX]; } media;
    } u;
} lc_core_msg_t;

/* The whole frame into out; its length, or 0 (unknown type, a field out of
 * range, or cap too small). */
size_t lc_core_encode(const lc_core_msg_t *m, uint8_t *out, size_t cap);

/* Exactly one whole frame (len bytes, the length prefix included). 0, or -1:
 * bad length, unknown type, a field out of range, or a number not valid.
 * *m is zeroed first. */
int lc_core_decode(const uint8_t *in, size_t len, lc_core_msg_t *m);

#endif
```

Create `lc_core/lc_core_msg.c`:
```c
#include "lc_core_msg.h"

#include <string.h>

/* ---- little-endian writer and reader over one frame ---- */

typedef struct {
    uint8_t *p;
    size_t   n, cap;
    int      bad;
} wr_t;

static void w8(wr_t *w, uint8_t v)
{
    if (w->n >= w->cap) {
        w->bad = 1;
        return;
    }
    w->p[w->n++] = v;
}
static void w16(wr_t *w, uint16_t v) { w8(w, (uint8_t)v); w8(w, (uint8_t)(v >> 8)); }
static void w32(wr_t *w, uint32_t v) { w16(w, (uint16_t)v); w16(w, (uint16_t)(v >> 16)); }
static void w64(wr_t *w, uint64_t v) { w32(w, (uint32_t)v); w32(w, (uint32_t)(v >> 32)); }
static void wb(wr_t *w, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) w8(w, b[i]);
}

typedef struct {
    const uint8_t *p;
    size_t         n, at;
    int            bad;
} rd_t;

static uint8_t r8(rd_t *r)
{
    if (r->at >= r->n) {
        r->bad = 1;
        return 0;
    }
    return r->p[r->at++];
}
static uint16_t r16(rd_t *r) { uint16_t lo = r8(r); return (uint16_t)(lo | (uint16_t)(r8(r) << 8)); }
static uint32_t r32(rd_t *r) { uint32_t lo = r16(r); return lo | ((uint32_t)r16(r) << 16); }
static uint64_t r64(rd_t *r) { uint64_t lo = r32(r); return lo | ((uint64_t)r32(r) << 32); }
static void rb(rd_t *r, uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) b[i] = r8(r);
}
static void rnum(rd_t *r, uint8_t num[LC_SIG_NUMBER_LEN])
{
    rb(r, num, LC_SIG_NUMBER_LEN);
    if (!lc_sig_number_valid(num)) r->bad = 1;
}

static void w_av(wr_t *w, const lc_core_av_t *av)
{
    wb(w, av->rand, 16);
    wb(w, av->autn, 16);
    wb(w, av->xres, 8);
    wb(w, av->ck, 16);
    wb(w, av->ik, 16);
}
static void r_av(rd_t *r, lc_core_av_t *av)
{
    rb(r, av->rand, 16);
    rb(r, av->autn, 16);
    rb(r, av->xres, 8);
    rb(r, av->ck, 16);
    rb(r, av->ik, 16);
}

size_t lc_core_encode(const lc_core_msg_t *m, uint8_t *out, size_t cap)
{
    wr_t w = { out, 0, cap < LC_CORE_FRAME_MAX ? cap : LC_CORE_FRAME_MAX, 0 };
    uint8_t sig[LC_SIG_MAX_MSG];
    size_t sn;
    w16(&w, 0); /* the length, filled in below */
    w8(&w, m->type);
    switch (m->type) {
    case LC_CORE_HELLO:
        w8(&w, m->u.hello.proto);
        w32(&w, m->u.hello.cell_id);
        w64(&w, m->u.hello.boot_id);
        wb(&w, m->u.hello.sw_version, 3);
        break;
    case LC_CORE_HELLO_ACK:
        w8(&w, m->u.hello_ack.mode);
        w16(&w, m->u.hello_ack.period_s);
        w16(&w, m->u.hello_ack.key_id);
        wb(&w, m->u.hello_ack.echo_number, LC_SIG_NUMBER_LEN);
        break;
    case LC_CORE_HELLO_NAK:
        w8(&w, m->u.hello_nak.reason);
        break;
    case LC_CORE_PING:
    case LC_CORE_PONG:
        break;
    case LC_CORE_ACT_FWD:
        w16(&w, m->u.act_fwd.req);
        w32(&w, m->u.act_fwd.tmid);
        wb(&w, m->u.act_fwd.token_id, 8);
        wb(&w, m->u.act_fwd.pkt, 32);
        wb(&w, m->u.act_fwd.tag, 8);
        break;
    case LC_CORE_ACT_RES:
        if (m->u.act_res.msg.type != LC_SIG_ACT_ACK && m->u.act_res.msg.type != LC_SIG_ACT_NAK) return 0;
        sn = lc_sig_body_encode(&m->u.act_res.msg, sig, sizeof(sig));
        if (sn == 0) return 0;
        w16(&w, m->u.act_res.req);
        w32(&w, m->u.act_res.tmid);
        w8(&w, m->u.act_res.msg.type);
        wb(&w, sig, sn);
        break;
    case LC_CORE_AV_REQ:
        w16(&w, m->u.av_req.req);
        w32(&w, m->u.av_req.tmid);
        w8(&w, m->u.av_req.count);
        break;
    case LC_CORE_AV_RES:
        if (m->u.av_res.count > LC_CORE_AV_MAX) return 0;
        w16(&w, m->u.av_res.req);
        w32(&w, m->u.av_res.tmid);
        w8(&w, m->u.av_res.status);
        wb(&w, m->u.av_res.number, LC_SIG_NUMBER_LEN);
        w8(&w, m->u.av_res.count);
        for (uint8_t i = 0; i < m->u.av_res.count; i++) w_av(&w, &m->u.av_res.av[i]);
        break;
    case LC_CORE_RESYNC:
        w16(&w, m->u.resync.req);
        w32(&w, m->u.resync.tmid);
        wb(&w, m->u.resync.rand, 16);
        wb(&w, m->u.resync.auts, 14);
        break;
    case LC_CORE_LOC_UPDATE:
        w32(&w, m->u.loc_update.tmid);
        wb(&w, m->u.loc_update.number, LC_SIG_NUMBER_LEN);
        wb(&w, m->u.loc_update.rand, 16);
        wb(&w, m->u.loc_update.res, 8);
        break;
    case LC_CORE_LOC_PURGE:
        w32(&w, m->u.loc_purge.tmid);
        wb(&w, m->u.loc_purge.number, LC_SIG_NUMBER_LEN);
        break;
    case LC_CORE_LOC_CANCEL:
        w32(&w, m->u.loc_cancel.tmid);
        w8(&w, m->u.loc_cancel.cause);
        break;
    case LC_CORE_CALL_ROUTE:
        w32(&w, m->u.call_route.leg_ref);
        wb(&w, m->u.call_route.caller, LC_SIG_NUMBER_LEN);
        wb(&w, m->u.call_route.called, LC_SIG_NUMBER_LEN);
        break;
    case LC_CORE_CALL_OFFER:
        w32(&w, m->u.call_offer.call_ref);
        wb(&w, m->u.call_offer.callee, LC_SIG_NUMBER_LEN);
        wb(&w, m->u.call_offer.caller, LC_SIG_NUMBER_LEN);
        break;
    case LC_CORE_CALL_ALERT:
    case LC_CORE_CALL_ANSWER:
        w32(&w, m->u.call.ref);
        break;
    case LC_CORE_CALL_RELEASE:
        w32(&w, m->u.call.ref);
        w8(&w, m->u.call.cause);
        break;
    case LC_CORE_MEDIA:
        if (m->u.media.len > LC_SIG_APP_MAX) return 0;
        w32(&w, m->u.media.ref);
        w16(&w, m->u.media.seq);
        wb(&w, m->u.media.data, m->u.media.len);
        break;
    default:
        return 0;
    }
    if (w.bad) return 0;
    out[0] = (uint8_t)((w.n - 2u) >> 8);
    out[1] = (uint8_t)(w.n - 2u);
    return w.n;
}

int lc_core_decode(const uint8_t *in, size_t len, lc_core_msg_t *m)
{
    memset(m, 0, sizeof(*m));
    if (len < 3 || len > LC_CORE_FRAME_MAX || ((size_t)in[0] << 8 | in[1]) != len - 2u) return -1;
    rd_t r = { in, len, 3, 0 };
    m->type = in[2];
    switch (m->type) {
    case LC_CORE_HELLO:
        m->u.hello.proto = r8(&r);
        m->u.hello.cell_id = r32(&r);
        m->u.hello.boot_id = r64(&r);
        rb(&r, m->u.hello.sw_version, 3);
        break;
    case LC_CORE_HELLO_ACK:
        m->u.hello_ack.mode = r8(&r);
        m->u.hello_ack.period_s = r16(&r);
        m->u.hello_ack.key_id = r16(&r);
        rnum(&r, m->u.hello_ack.echo_number);
        break;
    case LC_CORE_HELLO_NAK:
        m->u.hello_nak.reason = r8(&r);
        break;
    case LC_CORE_PING:
    case LC_CORE_PONG:
        break;
    case LC_CORE_ACT_FWD:
        m->u.act_fwd.req = r16(&r);
        m->u.act_fwd.tmid = r32(&r);
        rb(&r, m->u.act_fwd.token_id, 8);
        rb(&r, m->u.act_fwd.pkt, 32);
        rb(&r, m->u.act_fwd.tag, 8);
        break;
    case LC_CORE_ACT_RES: {
        m->u.act_res.req = r16(&r);
        m->u.act_res.tmid = r32(&r);
        uint8_t t = r8(&r);
        if (r.bad || (t != LC_SIG_ACT_ACK && t != LC_SIG_ACT_NAK) ||
            lc_sig_body_decode(t, in + r.at, len - r.at, &m->u.act_res.msg) != 0) {
            return -1;
        }
        r.at = len;
        break;
    }
    case LC_CORE_AV_REQ:
        m->u.av_req.req = r16(&r);
        m->u.av_req.tmid = r32(&r);
        m->u.av_req.count = r8(&r);
        break;
    case LC_CORE_AV_RES:
        m->u.av_res.req = r16(&r);
        m->u.av_res.tmid = r32(&r);
        m->u.av_res.status = r8(&r);
        if (m->u.av_res.status == LC_CORE_AV_OK) {
            rnum(&r, m->u.av_res.number);
        } else {
            rb(&r, m->u.av_res.number, LC_SIG_NUMBER_LEN);
        }
        m->u.av_res.count = r8(&r);
        if (m->u.av_res.count > LC_CORE_AV_MAX) return -1;
        for (uint8_t i = 0; i < m->u.av_res.count; i++) r_av(&r, &m->u.av_res.av[i]);
        break;
    case LC_CORE_RESYNC:
        m->u.resync.req = r16(&r);
        m->u.resync.tmid = r32(&r);
        rb(&r, m->u.resync.rand, 16);
        rb(&r, m->u.resync.auts, 14);
        break;
    case LC_CORE_LOC_UPDATE:
        m->u.loc_update.tmid = r32(&r);
        rnum(&r, m->u.loc_update.number);
        rb(&r, m->u.loc_update.rand, 16);
        rb(&r, m->u.loc_update.res, 8);
        break;
    case LC_CORE_LOC_PURGE:
        m->u.loc_purge.tmid = r32(&r);
        rnum(&r, m->u.loc_purge.number);
        break;
    case LC_CORE_LOC_CANCEL:
        m->u.loc_cancel.tmid = r32(&r);
        m->u.loc_cancel.cause = r8(&r);
        break;
    case LC_CORE_CALL_ROUTE:
        m->u.call_route.leg_ref = r32(&r);
        rnum(&r, m->u.call_route.caller);
        rnum(&r, m->u.call_route.called);
        break;
    case LC_CORE_CALL_OFFER:
        m->u.call_offer.call_ref = r32(&r);
        rnum(&r, m->u.call_offer.callee);
        rnum(&r, m->u.call_offer.caller);
        break;
    case LC_CORE_CALL_ALERT:
    case LC_CORE_CALL_ANSWER:
        m->u.call.ref = r32(&r);
        break;
    case LC_CORE_CALL_RELEASE:
        m->u.call.ref = r32(&r);
        m->u.call.cause = r8(&r);
        break;
    case LC_CORE_MEDIA:
        m->u.media.ref = r32(&r);
        m->u.media.seq = r16(&r);
        if (r.bad || len - r.at > LC_SIG_APP_MAX) return -1;
        m->u.media.len = (uint8_t)(len - r.at);
        rb(&r, m->u.media.data, m->u.media.len);
        break;
    default:
        return -1;
    }
    return r.bad || r.at != len ? -1 : 0;
}
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_msg 2>&1 | grep -E "error|warning"; build/tests/test_core_msg | tail -3`
Expected: no compiler output, then `3 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 1`.

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add CMakeLists.txt lc_core tests/test_core_msg.c tests/CMakeLists.txt
git commit -m "lc_core: the cell-core protocol codec (network-core spec 6)

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 2: The block table and the number policy (`lc_core_route`)

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** now (after Task 1).

Routing by the longest prefix of the full number, "am I home?", the block index inside token ids (§14.2–14.3), and the number rules the core applies (§7.11): reserved numbers and auto-assigned candidates. One core with every block at home is the same code path plan 10 uses with several.

**Files:**
- Create: `lc_core/include/lc_core_route.h`, `lc_core/lc_core_route.c`
- Modify: `lc_core/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/test_core_route.c`

**Interfaces:**
- Consumes: `lc_sig_number_valid`, `lc_sig_number_to_text`, `lc_sig_number_to_bcd`.
- Produces (`lc_core_route.h`):
  ```c
  #define LC_CORE_BLOCKS 32u
  typedef struct { char prefix[LC_SIG_NUMBER_DIGITS + 1]; uint16_t block_idx; uint16_t home_core; } lc_core_block_t;
  typedef struct { uint16_t self; lc_core_block_t b[LC_CORE_BLOCKS]; unsigned n; } lc_core_route_t;
  void lc_core_route_init(lc_core_route_t *r, uint16_t self);
  int  lc_core_route_add(lc_core_route_t *r, const char *prefix, uint16_t block_idx, uint16_t home_core);
  const lc_core_block_t *lc_core_route_find(const lc_core_route_t *r, const uint8_t number[LC_SIG_NUMBER_LEN]);
  const lc_core_block_t *lc_core_route_block(const lc_core_route_t *r, uint16_t block_idx);
  int  lc_core_route_home(const lc_core_route_t *r, const lc_core_block_t *b);
  void     lc_core_token_id(uint16_t block_idx, const uint8_t random6[6], uint8_t token_id[8]);
  uint16_t lc_core_token_block(const uint8_t token_id[8]);
  int  lc_core_number_reserved(const uint8_t number[LC_SIG_NUMBER_LEN]);
  int  lc_core_number_pick(const lc_core_block_t *b, const uint8_t random[8], uint8_t number[LC_SIG_NUMBER_LEN]);
  ```

- [ ] **Step 1: Write the failing test**

Create `tests/test_core_route.c`:
```c
/* The block table (network-core spec §14.2-14.3) and the number policy
 * (§7.11): the longest prefix wins, "am I home?", block indexes in token
 * ids, reserved numbers, auto-assigned candidates. */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "lc_core_route.h"

void setUp(void) {}
void tearDown(void) {}

static const lc_core_block_t *find(const lc_core_route_t *r, const char *number)
{
    uint8_t n[LC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, lc_sig_number_to_bcd(number, strlen(number), n), number);
    return lc_core_route_find(r, n);
}

/* The §14.2 example, seen from core 1. */
static void example(lc_core_route_t *r)
{
    lc_core_route_init(r, 1);
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(r, "8831606", 1, 1));
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(r, "8831606555", 2, 2));
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(r, "8831859", 3, 1));
}

static void test_longest_prefix_wins_and_home_is_known(void)
{
    lc_core_route_t r;
    example(&r);
    const lc_core_block_t *b = find(&r, "+883160655501234");
    TEST_ASSERT_NOT_NULL(b);
    TEST_ASSERT_EQUAL_UINT16(2, b->block_idx); /* the exchange block inside the area code */
    TEST_ASSERT_FALSE(lc_core_route_home(&r, b));
    b = find(&r, "+883160677701234");
    TEST_ASSERT_EQUAL_UINT16(1, b->block_idx);
    TEST_ASSERT_TRUE(lc_core_route_home(&r, b));
    TEST_ASSERT_EQUAL_UINT16(3, find(&r, "+883185955520000")->block_idx);
    TEST_ASSERT_NULL(find(&r, "+883121255501234")); /* no block: no route */
    TEST_ASSERT_NULL(find(&r, "+883442079460000"));
    TEST_ASSERT_FALSE(lc_core_route_home(&r, NULL));
    TEST_ASSERT_EQUAL_PTR(&r.b[2], lc_core_route_block(&r, 3));
    TEST_ASSERT_NULL(lc_core_route_block(&r, 4));
    static const uint8_t zeros[LC_SIG_NUMBER_LEN] = { 0 };
    TEST_ASSERT_NULL(lc_core_route_find(&r, zeros)); /* not a number */
}

static void test_bad_blocks_are_refused(void)
{
    lc_core_route_t r;
    example(&r);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "8831606", 9, 1));     /* the prefix again */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "8831212", 2, 1));     /* the index again */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "8831212", 0, 1));     /* index 0 */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "88316065", 9, 1));    /* NANP: NPA or NPA-NXX only */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "8841606", 9, 1));     /* not 883 */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "883-1-212", 9, 1));   /* digits only */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "883", 9, 1));         /* too short */
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(&r, "88344", 9, 1));        /* a whole country code */
    TEST_ASSERT_EQUAL_UINT16(9, find(&r, "+883442079460000")->block_idx);
    lc_core_route_init(&r, 1);
    for (unsigned i = 0; i < LC_CORE_BLOCKS; i++) {
        char p[16];
        snprintf(p, sizeof(p), "8831%03u", 200u + i);
        TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(&r, p, (uint16_t)(i + 1u), 1));
    }
    TEST_ASSERT_EQUAL_INT(-1, lc_core_route_add(&r, "8831999", 999, 1)); /* full */
}

static void test_token_ids_carry_the_block(void)
{
    static const uint8_t r6[6] = { 1, 2, 3, 4, 5, 6 };
    static const uint8_t want[8] = { 0x01, 0x02, 1, 2, 3, 4, 5, 6 };
    uint8_t id[8];
    lc_core_token_id(0x0102, r6, id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, id, 8);
    TEST_ASSERT_EQUAL_UINT16(0x0102, lc_core_token_block(id));
}

static int reserved(const char *number)
{
    uint8_t n[LC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, lc_sig_number_to_bcd(number, strlen(number), n), number);
    return lc_core_number_reserved(n);
}

static void test_reserved_numbers(void)
{
    TEST_ASSERT_TRUE(reserved("+883160655500000"));
    TEST_ASSERT_TRUE(reserved("+883160655500001"));
    TEST_ASSERT_TRUE(reserved("+883160655500100")); /* the echo service is configured, not assigned */
    TEST_ASSERT_TRUE(reserved("+883160655500911"));
    TEST_ASSERT_TRUE(reserved("+883160655500999"));
    TEST_ASSERT_TRUE(reserved("+883160655509911"));
    TEST_ASSERT_TRUE(reserved("+883160655599999"));
    TEST_ASSERT_FALSE(reserved("+883160655501000"));
    TEST_ASSERT_FALSE(reserved("+883160655501234"));
    TEST_ASSERT_FALSE(reserved("+883160655599998"));
    TEST_ASSERT_FALSE(reserved("+883442079400000")); /* no plan for other country codes yet */
}

static void test_picked_numbers_are_valid_candidates(void)
{
    lc_core_route_t r;
    example(&r);
    uint8_t rnd[8], n[LC_SIG_NUMBER_LEN];
    char text[LC_SIG_NUMBER_TEXT];
    uint32_t x = 1;
    for (unsigned i = 0; i < 5000; i++) {
        for (int k = 0; k < 8; k++) rnd[k] = (uint8_t)((x = x * 1103515245u + 12345u) >> 16);
        TEST_ASSERT_EQUAL_INT(0, lc_core_number_pick(&r.b[0], rnd, n)); /* NPA block: the NXX is picked too */
        TEST_ASSERT_TRUE(lc_sig_number_valid(n));
        TEST_ASSERT_FALSE(lc_core_number_reserved(n));
        lc_sig_number_to_text(n, text);
        TEST_ASSERT_EQUAL_INT(0, strncmp(text, "+8831606", 8));
        TEST_ASSERT_EQUAL_INT(0, lc_core_number_pick(&r.b[1], rnd, n)); /* NPA-NXX block */
        TEST_ASSERT_FALSE(lc_core_number_reserved(n));
        lc_sig_number_to_text(n, text);
        TEST_ASSERT_EQUAL_INT(0, strncmp(text, "+8831606555", 11));
    }
    lc_core_block_t uk = { "88344", 9, 1 };
    TEST_ASSERT_EQUAL_INT(-1, lc_core_number_pick(&uk, rnd, n)); /* not a NANP block */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_longest_prefix_wins_and_home_is_known);
    RUN_TEST(test_bad_blocks_are_refused);
    RUN_TEST(test_token_ids_carry_the_block);
    RUN_TEST(test_reserved_numbers);
    RUN_TEST(test_picked_numbers_are_valid_candidates);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_core_route lc_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_route 2>&1 | grep -E "error" | head -3`
Expected: `fatal error: lc_core_route.h: No such file or directory`.

- [ ] **Step 3: Implement**

Create `lc_core/include/lc_core_route.h`:
```c
/* The block table as one core sees it (network-core spec §14.2-14.3), and
 * the number policy that goes with it (§7.11, numbering-plan.md v0.2).
 *
 * A block is a prefix of the full form (883 . CC . NPA, or 883 . CC . NPA .
 * NXX) with a block index that is never reused and a home core. The longest
 * prefix wins, so an exchange block can sit inside another tenant's area
 * code. For now one core runs with every block at home; plans 10-11 add the
 * signed table, secondaries, epochs and takeovers around the same lookups. */
#ifndef LC_CORE_ROUTE_H
#define LC_CORE_ROUTE_H

#include "lc_sig.h"

#define LC_CORE_BLOCKS 32u

typedef struct {
    char     prefix[LC_SIG_NUMBER_DIGITS + 1]; /* digits only, e.g. "8831606" */
    uint16_t block_idx;                        /* 1-65535, never reused */
    uint16_t home_core;                        /* core_id */
} lc_core_block_t;

typedef struct {
    uint16_t        self; /* this core's core_id */
    lc_core_block_t b[LC_CORE_BLOCKS];
    unsigned        n;
} lc_core_route_t;

void lc_core_route_init(lc_core_route_t *r, uint16_t self);
/* 0, or -1: a prefix that is not digits starting 883 (4-15 digits; a NANP
 * prefix is NPA or NPA-NXX: 7 or 10 digits), block index 0, a prefix or
 * index already in the table, or a full table. */
int lc_core_route_add(lc_core_route_t *r, const char *prefix, uint16_t block_idx, uint16_t home_core);
/* The block with the longest prefix of number, or NULL (no route). */
const lc_core_block_t *lc_core_route_find(const lc_core_route_t *r, const uint8_t number[LC_SIG_NUMBER_LEN]);
const lc_core_block_t *lc_core_route_block(const lc_core_route_t *r, uint16_t block_idx);
/* 1 if b is a block this core is home for ("am I home?"); 0 for NULL. */
int lc_core_route_home(const lc_core_route_t *r, const lc_core_block_t *b);

/* Token ids carry their block (§14.3): the block index big-endian in bytes
 * 0-1, then 6 random bytes (the tag, keyed by the token secret, carries the
 * security). */
void     lc_core_token_id(uint16_t block_idx, const uint8_t random6[6], uint8_t token_id[8]);
uint16_t lc_core_token_block(const uint8_t token_id[8]);

/* 1 for a number no subscriber may have: a NANP subscriber part 00000,
 * 00911, 09911, 99999 or the service range 00001-00999 (service numbers such
 * as the echo service are configured, not assigned). Other country codes have
 * no reserved numbers yet. */
int lc_core_number_reserved(const uint8_t number[LC_SIG_NUMBER_LEN]);

/* A random candidate in block b (NANP blocks only): a random NXX when the
 * prefix is an NPA, then a subscriber part in 01000-99998, never 09911.
 * random: 8 random bytes. 0, or -1 when b is not a NANP block. The caller
 * checks that the number is free. */
int lc_core_number_pick(const lc_core_block_t *b, const uint8_t random[8], uint8_t number[LC_SIG_NUMBER_LEN]);

#endif
```

Create `lc_core/lc_core_route.c`:
```c
#include "lc_core_route.h"

#include <stdio.h>
#include <string.h>

void lc_core_route_init(lc_core_route_t *r, uint16_t self)
{
    memset(r, 0, sizeof(*r));
    r->self = self;
}

static int prefix_ok(const char *p)
{
    size_t n = strlen(p);
    if (n < 4 || n > LC_SIG_NUMBER_DIGITS || strncmp(p, "883", 3) != 0) return 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return 0;
    }
    return p[3] != '1' || n == 7 || n == 10;
}

int lc_core_route_add(lc_core_route_t *r, const char *prefix, uint16_t block_idx, uint16_t home_core)
{
    if (!prefix_ok(prefix) || block_idx == 0 || r->n >= LC_CORE_BLOCKS) return -1;
    for (unsigned i = 0; i < r->n; i++) {
        if (strcmp(r->b[i].prefix, prefix) == 0 || r->b[i].block_idx == block_idx) return -1;
    }
    lc_core_block_t *b = &r->b[r->n++];
    snprintf(b->prefix, sizeof(b->prefix), "%s", prefix);
    b->block_idx = block_idx;
    b->home_core = home_core;
    return 0;
}

const lc_core_block_t *lc_core_route_find(const lc_core_route_t *r, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    char text[LC_SIG_NUMBER_TEXT];
    const lc_core_block_t *best = NULL;
    if (!lc_sig_number_valid(number)) return NULL;
    lc_sig_number_to_text(number, text);
    for (unsigned i = 0; i < r->n; i++) {
        size_t n = strlen(r->b[i].prefix);
        if (strncmp(text + 1, r->b[i].prefix, n) == 0 && (best == NULL || n > strlen(best->prefix))) best = &r->b[i];
    }
    return best;
}

const lc_core_block_t *lc_core_route_block(const lc_core_route_t *r, uint16_t block_idx)
{
    for (unsigned i = 0; i < r->n; i++) {
        if (r->b[i].block_idx == block_idx) return &r->b[i];
    }
    return NULL;
}

int lc_core_route_home(const lc_core_route_t *r, const lc_core_block_t *b)
{
    return b != NULL && b->home_core == r->self;
}

void lc_core_token_id(uint16_t block_idx, const uint8_t random6[6], uint8_t token_id[8])
{
    token_id[0] = (uint8_t)(block_idx >> 8);
    token_id[1] = (uint8_t)block_idx;
    memcpy(token_id + 2, random6, 6);
}

uint16_t lc_core_token_block(const uint8_t token_id[8])
{
    return (uint16_t)((token_id[0] << 8) | token_id[1]);
}

int lc_core_number_reserved(const uint8_t number[LC_SIG_NUMBER_LEN])
{
    char text[LC_SIG_NUMBER_TEXT];
    lc_sig_number_to_text(number, text);
    if (strlen(text) != 1 + 15 || text[4] != '1') return 0; /* not NANP */
    const char *sub = text + 11;
    return (sub[0] == '0' && sub[1] == '0') /* 00000-00999: 00000 and the service range */
           || strcmp(sub, "09911") == 0 || strcmp(sub, "99999") == 0;
}

int lc_core_number_pick(const lc_core_block_t *b, const uint8_t random[8], uint8_t number[LC_SIG_NUMBER_LEN])
{
    char d[LC_SIG_NUMBER_DIGITS + 1];
    size_t n = strlen(b->prefix);
    if (n < 4 || b->prefix[3] != '1' || (n != 7 && n != 10)) return -1;
    memcpy(d, b->prefix, n);
    if (n == 7) { /* NXX: 2-9 first, not N11 */
        unsigned nxx = 200u + ((unsigned)random[0] << 8 | random[1]) % 800u;
        if (nxx % 100u == 11u) nxx++;
        for (int i = 9; i >= 7; i--, nxx /= 10u) d[i] = (char)('0' + nxx % 10u);
    }
    unsigned sub = 1000u + ((unsigned)random[2] << 16 | (unsigned)random[3] << 8 | random[4]) % 98999u;
    if (sub == 9911u) sub++;
    for (int i = 14; i >= 10; i--, sub /= 10u) d[i] = (char)('0' + sub % 10u);
    return lc_sig_number_to_bcd(d, 15, number);
}
```

In `lc_core/CMakeLists.txt`, replace:
```cmake
add_library(lc_core STATIC lc_core_msg.c)
```
with:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c)
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_route 2>&1 | grep -E "error|warning"; build/tests/test_core_route | tail -3`
Expected: no compiler output, then `5 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 2`.

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add lc_core tests/test_core_route.c tests/CMakeLists.txt
git commit -m "lc_core: block table (longest prefix, home), token block index, number policy

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 3: The storage interface and the in-memory store

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** now (after Task 2).

What the core keeps (spec §5), as records and one function per question the core asks, with begin/commit around changes that must land together. The in-memory store serves the tests and the simulation; plan 8's SQLite store implements the same interface (sealing keys at rest) and runs the same contract test.

**Files:**
- Create: `lc_core/include/lc_core_store.h`, `lc_core/include/lc_core_mem.h`, `lc_core/lc_core_mem.c`
- Modify: `lc_core/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/core_store_contract.h`, `tests/test_core_store.c`

**Interfaces:**
- Produces (`lc_core_store.h`): records `lc_core_netkey_t` (`key_id, sk, pk, period_s, created`), `lc_core_cell_t` (`cell_id, name, mode, enabled, list_id, boot_id, last_seen`), `lc_core_sub_t` (`number, state, activated, tmid, k, opc, sqn (uint64_t), created, updated`), `lc_core_token_t` (`token_id, number, secret, expiry, used_at, used_by_tmid`), `lc_core_av_issued_t` (`number, rand, xres, sqn, cell_id, issued, confirmed`), `lc_core_loc_t` (`number, cell_id, tmid, expires`), `lc_core_cdr_t`, `lc_core_audit_t`; enums `LC_CORE_SUB_ACTIVE`/`_DISABLED` and `LC_CORE_AUDIT_ACTIVATE` … `LC_CORE_AUDIT_CELL_REJECT` (the §5 audit events); and `lc_core_store_t`: `ctx`, `begin`, `commit`, `netkey_get/put`, `cell_get/put`, `sub_get`, `sub_by_tmid`, `sub_put`, `token_get/put`, `token_void`, `av_put/get`, `av_drop_cell`, `av_prune`, `loc_get/put/del`, `loc_purge_cell`, `cdr_add`, `audit_add`, each returning 0 or -1.
- Produces (`lc_core_mem.h`):
  ```c
  typedef struct { lc_core_mem_data_t d, undo; int in_txn; int fail_commits; unsigned commits; } lc_core_mem_t;
  void            lc_core_mem_init(lc_core_mem_t *m);
  lc_core_store_t lc_core_mem_store(lc_core_mem_t *m);
  const lc_core_audit_t *lc_core_mem_audit(const lc_core_mem_t *m, uint8_t event);
  ```
  `fail_commits` is the test hook: the next n commits fail and undo.
- Produces (test-only): `store_contract(const lc_core_store_t *st)` in `core_store_contract.h`, for any empty store.

- [ ] **Step 1: Write the failing test**

Create `tests/core_store_contract.h`:
```c
/* The lc_core_store_t contract (network-core spec §5), as one test any store
 * must pass: the in-memory store here, plan 8's SQLite store there. The
 * store must start empty. */
#ifndef CORE_STORE_CONTRACT_H
#define CORE_STORE_CONTRACT_H

#include <string.h>

#include "lc_core_store.h"
#include "unity.h"

static inline void contract_num(const char *text, uint8_t out[LC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT(0, lc_sig_number_to_bcd(text, strlen(text), out));
}

static inline void store_contract(const lc_core_store_t *st)
{
    void *c = st->ctx;
    uint8_t n1[LC_SIG_NUMBER_LEN], n2[LC_SIG_NUMBER_LEN];
    contract_num("+883160655501234", n1);
    contract_num("+883160655501235", n2);

    /* network keys and cells: get what was put, replace by key */
    lc_core_netkey_t k = { 1, { 1 }, { 2 }, 1800, 100 }, k2;
    TEST_ASSERT_EQUAL_INT(-1, st->netkey_get(c, 1, &k2));
    TEST_ASSERT_EQUAL_INT(0, st->netkey_put(c, &k));
    TEST_ASSERT_EQUAL_INT(0, st->netkey_get(c, 1, &k2));
    TEST_ASSERT_EQUAL_MEMORY(&k, &k2, sizeof(k));
    lc_core_cell_t cell, cell2;
    memset(&cell, 0, sizeof(cell));
    cell.cell_id = 7;
    strcpy(cell.name, "bench A");
    cell.mode = LC_SIG_MODE_PART15;
    cell.enabled = 1;
    TEST_ASSERT_EQUAL_INT(0, st->cell_put(c, &cell));
    cell.boot_id = 99;
    TEST_ASSERT_EQUAL_INT(0, st->cell_put(c, &cell));
    TEST_ASSERT_EQUAL_INT(0, st->cell_get(c, 7, &cell2));
    TEST_ASSERT_EQUAL_STRING("bench A", cell2.name);
    TEST_ASSERT_EQUAL_UINT64(99, cell2.boot_id);
    TEST_ASSERT_EQUAL_UINT8(1, cell2.enabled);
    TEST_ASSERT_EQUAL_INT(-1, st->cell_get(c, 8, &cell2));

    /* subscribers: by number; by TMID only while activated */
    lc_core_sub_t s, s2;
    memset(&s, 0, sizeof(s));
    memcpy(s.number, n1, LC_SIG_NUMBER_LEN);
    s.state = LC_CORE_SUB_ACTIVE;
    s.tmid = 0x1234u;
    s.sqn = 5;
    TEST_ASSERT_EQUAL_INT(0, st->sub_put(c, &s));
    TEST_ASSERT_EQUAL_INT(-1, st->sub_by_tmid(c, 0x1234u, &s2)); /* bound but not activated */
    s.activated = 1;
    s.sqn = (1ull << 40) + 3u; /* SQN is 48 bits */
    TEST_ASSERT_EQUAL_INT(0, st->sub_put(c, &s));
    TEST_ASSERT_EQUAL_INT(0, st->sub_by_tmid(c, 0x1234u, &s2));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(n1, s2.number, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st->sub_get(c, n1, &s2));
    TEST_ASSERT_EQUAL_UINT64((1ull << 40) + 3u, s2.sqn);
    TEST_ASSERT_EQUAL_INT(-1, st->sub_get(c, n2, &s2));

    /* tokens: voiding removes only the number's unused ones */
    lc_core_token_t t1, t2, t3, tg;
    memset(&t1, 0, sizeof(t1));
    memset(t1.token_id, 0x11, 8);
    memcpy(t1.number, n1, LC_SIG_NUMBER_LEN);
    t2 = t1;
    memset(t2.token_id, 0x22, 8);
    t2.used_at = 50;
    t3 = t1;
    memset(t3.token_id, 0x33, 8);
    memcpy(t3.number, n2, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t1));
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t2));
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t3));
    TEST_ASSERT_EQUAL_INT(0, st->token_void(c, n1));
    TEST_ASSERT_EQUAL_INT(-1, st->token_get(c, t1.token_id, &tg));
    TEST_ASSERT_EQUAL_INT(0, st->token_get(c, t2.token_id, &tg)); /* used: kept */
    TEST_ASSERT_EQUAL_UINT32(50, tg.used_at);
    TEST_ASSERT_EQUAL_INT(0, st->token_get(c, t3.token_id, &tg)); /* another number: kept */

    /* issued vectors: keyed by (number, rand); drop and prune */
    lc_core_av_issued_t a1, a2, ag;
    memset(&a1, 0, sizeof(a1));
    memcpy(a1.number, n1, LC_SIG_NUMBER_LEN);
    memset(a1.rand, 0xa1, 16);
    a1.cell_id = 7;
    a1.issued = 1000;
    a2 = a1;
    memset(a2.rand, 0xa2, 16);
    a2.issued = 2000;
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a1));
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a2));
    a2.confirmed = 1;
    TEST_ASSERT_EQUAL_INT(0, st->av_put(c, &a2)); /* replaced, not added */
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n1, a2.rand, &ag));
    TEST_ASSERT_EQUAL_UINT8(1, ag.confirmed);
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n2, a2.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_drop_cell(c, 7)); /* a1 (unconfirmed) goes, a2 stays */
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n1, a1.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n1, a2.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_prune(c, 2000)); /* issued at 2000: not before */
    TEST_ASSERT_EQUAL_INT(0, st->av_get(c, n1, a2.rand, &ag));
    TEST_ASSERT_EQUAL_INT(0, st->av_prune(c, 2001));
    TEST_ASSERT_EQUAL_INT(-1, st->av_get(c, n1, a2.rand, &ag));

    /* locations: one per number; delete; purge a cell's */
    lc_core_loc_t l1 = { { 0 }, 7, 0x1234u, 5000 }, l2 = { { 0 }, 8, 0x5678u, 5000 }, lg;
    memcpy(l1.number, n1, LC_SIG_NUMBER_LEN);
    memcpy(l2.number, n2, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l1));
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l2));
    l1.cell_id = 8;
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l1)); /* moved */
    TEST_ASSERT_EQUAL_INT(0, st->loc_get(c, n1, &lg));
    TEST_ASSERT_EQUAL_UINT32(8, lg.cell_id);
    TEST_ASSERT_EQUAL_INT(0, st->loc_del(c, n1));
    TEST_ASSERT_EQUAL_INT(-1, st->loc_get(c, n1, &lg));
    TEST_ASSERT_EQUAL_INT(0, st->loc_put(c, &l1));
    TEST_ASSERT_EQUAL_INT(0, st->loc_purge_cell(c, 8));
    TEST_ASSERT_EQUAL_INT(-1, st->loc_get(c, n1, &lg));
    TEST_ASSERT_EQUAL_INT(-1, st->loc_get(c, n2, &lg));

    /* records are appended */
    lc_core_cdr_t cdr;
    lc_core_audit_t au;
    memset(&cdr, 0, sizeof(cdr));
    memset(&au, 0, sizeof(au));
    au.event = LC_CORE_AUDIT_REGISTER;
    TEST_ASSERT_EQUAL_INT(0, st->cdr_add(c, &cdr));
    TEST_ASSERT_EQUAL_INT(0, st->audit_add(c, &au));

    /* one transaction commits as a whole */
    s.sqn = 6;
    TEST_ASSERT_EQUAL_INT(0, st->begin(c));
    TEST_ASSERT_EQUAL_INT(0, st->sub_put(c, &s));
    TEST_ASSERT_EQUAL_INT(0, st->token_put(c, &t1));
    TEST_ASSERT_EQUAL_INT(0, st->commit(c));
    TEST_ASSERT_EQUAL_INT(0, st->sub_get(c, n1, &s2));
    TEST_ASSERT_EQUAL_UINT64(6, s2.sqn);
    TEST_ASSERT_EQUAL_INT(0, st->token_get(c, t1.token_id, &tg));
}

#endif
```

Create `tests/test_core_store.c`:
```c
/* The in-memory store against the store contract, and what only the
 * in-memory store has: a failing commit undoes the transaction, and the
 * record logs keep the newest entries. */
#include "unity.h"

#include <string.h>

#include "core_store_contract.h"
#include "lc_core_mem.h"

void setUp(void) {}
void tearDown(void) {}

static lc_core_mem_t mem;

static void test_mem_store_keeps_the_contract(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    store_contract(&st);
}

static void test_failed_commit_undoes_everything_since_begin(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_sub_t s, got;
    memset(&s, 0, sizeof(s));
    contract_num("+883160655501234", s.number);
    s.sqn = 10;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    mem.fail_commits = 1;
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    s.sqn = 11;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_UINT64(10, got.sqn); /* as before the transaction */
    TEST_ASSERT_EQUAL_UINT(0, mem.commits);
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &s));
    TEST_ASSERT_EQUAL_INT(0, st.commit(st.ctx)); /* only the one commit failed */
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, s.number, &got));
    TEST_ASSERT_EQUAL_UINT64(11, got.sqn);
}

static void test_logs_keep_the_newest(void)
{
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_audit_t a;
    memset(&a, 0, sizeof(a));
    for (unsigned i = 0; i < LC_CORE_MEM_LOG + 5u; i++) {
        a.event = i == 3 ? LC_CORE_AUDIT_RESYNC : LC_CORE_AUDIT_REGISTER;
        a.ts = i;
        st.audit_add(st.ctx, &a);
    }
    TEST_ASSERT_NULL(lc_core_mem_audit(&mem, LC_CORE_AUDIT_RESYNC)); /* overwritten */
    const lc_core_audit_t *last = lc_core_mem_audit(&mem, LC_CORE_AUDIT_REGISTER);
    TEST_ASSERT_NOT_NULL(last);
    TEST_ASSERT_EQUAL_UINT32(LC_CORE_MEM_LOG + 4u, last->ts);
    TEST_ASSERT_NULL(lc_core_mem_audit(&mem, LC_CORE_AUDIT_ACTIVATE));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_mem_store_keeps_the_contract);
    RUN_TEST(test_failed_commit_undoes_everything_since_begin);
    RUN_TEST(test_logs_keep_the_newest);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_core_store lc_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_store 2>&1 | grep -E "error" | head -3`
Expected: `fatal error: lc_core_store.h: No such file or directory`.

- [ ] **Step 3: Implement**

Create `lc_core/include/lc_core_store.h`:
```c
/* What lc_core keeps (network-core spec §5), behind an interface: records
 * in the clear as lc_core uses them, one function per question it asks.
 * lc_core_mem.h is the in-memory store (tests, simulation); plan 8's SQLite
 * store seals k, opc, sk and token secrets at rest behind the same calls.
 *
 * Every function returns 0, or -1 (not found, full, or failed). A put
 * outside begin/commit is durable when it returns; between begin and commit
 * the puts are one change that commit makes durable or, failing, undoes. */
#ifndef LC_CORE_STORE_H
#define LC_CORE_STORE_H

#include "lc_sig.h"

typedef struct {
    uint16_t key_id;
    uint8_t  sk[32], pk[32]; /* X25519, for activation (QR carries key_id + pk) */
    uint16_t period_s;       /* registration period announced with this key */
    uint32_t created;
} lc_core_netkey_t;

typedef struct {
    uint32_t cell_id;
    char     name[32];
    uint8_t  mode;     /* lc_sig_mode_t */
    uint8_t  enabled;
    uint16_t list_id;  /* channel-list group (channel-list spec §8): its cells share one list; 0 none */
    uint64_t boot_id;  /* from the cell's last HELLO */
    uint32_t last_seen;
} lc_core_cell_t;

typedef enum { LC_CORE_SUB_ACTIVE = 1, LC_CORE_SUB_DISABLED = 2 } lc_core_sub_state_t;

typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN]; /* full form, the key */
    uint8_t  state;                     /* lc_core_sub_state_t */
    uint8_t  activated;
    uint32_t tmid;                      /* bound terminal, 0 = none */
    uint8_t  k[16], opc[16];
    uint64_t sqn;                       /* the last SQN issued */
    uint32_t created, updated;
} lc_core_sub_t;

typedef struct {
    uint8_t  token_id[8]; /* block index (2, big-endian) | random (6) */
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint8_t  secret[16];
    uint32_t expiry;
    uint32_t used_at;     /* 0 = unused */
    uint32_t used_by_tmid;
} lc_core_token_t;

typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint8_t  rand[16], xres[8]; /* (number, rand) is the key */
    uint64_t sqn;
    uint32_t cell_id;           /* issued to */
    uint32_t issued;
    uint8_t  confirmed;         /* a LOC_UPDATE proved it */
} lc_core_av_issued_t;

typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint32_t cell_id, tmid;
    uint32_t expires;
} lc_core_loc_t;

typedef struct {
    uint8_t  caller[LC_SIG_NUMBER_LEN], called[LC_SIG_NUMBER_LEN];
    uint32_t cell_a, cell_b; /* cell_b 0: a service (the echo service) */
    uint32_t setup, answer, end; /* unix s; answer 0 = never answered */
    uint8_t  cause;
} lc_core_cdr_t;

typedef enum {
    LC_CORE_AUDIT_ACTIVATE = 1, LC_CORE_AUDIT_ACT_FAIL, LC_CORE_AUDIT_REGISTER, LC_CORE_AUDIT_AUTH_FAIL,
    LC_CORE_AUDIT_RESYNC, LC_CORE_AUDIT_LOC_CANCEL, LC_CORE_AUDIT_TOKEN_ISSUE, LC_CORE_AUDIT_SUB_DISABLE,
    LC_CORE_AUDIT_CELL_REJECT
} lc_core_audit_event_t;

typedef struct {
    uint32_t ts;
    uint8_t  event; /* lc_core_audit_event_t */
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint32_t tmid, cell_id;
    char     detail[48];
} lc_core_audit_t;

typedef struct {
    void *ctx;
    int (*begin)(void *ctx);
    int (*commit)(void *ctx);
    int (*netkey_get)(void *ctx, uint16_t key_id, lc_core_netkey_t *out);
    int (*netkey_put)(void *ctx, const lc_core_netkey_t *k);
    int (*cell_get)(void *ctx, uint32_t cell_id, lc_core_cell_t *out);
    int (*cell_put)(void *ctx, const lc_core_cell_t *c);
    int (*sub_get)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_sub_t *out);
    int (*sub_by_tmid)(void *ctx, uint32_t tmid, lc_core_sub_t *out); /* activated and bound to tmid */
    int (*sub_put)(void *ctx, const lc_core_sub_t *s);                /* insert or replace */
    int (*token_get)(void *ctx, const uint8_t token_id[8], lc_core_token_t *out);
    int (*token_put)(void *ctx, const lc_core_token_t *t);
    int (*token_void)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN]); /* delete its unused tokens */
    int (*av_put)(void *ctx, const lc_core_av_issued_t *a);
    int (*av_get)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                  lc_core_av_issued_t *out);
    int (*av_drop_cell)(void *ctx, uint32_t cell_id);  /* the cell's unconfirmed vectors */
    int (*av_prune)(void *ctx, uint32_t issued_before);
    int (*loc_get)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out);
    int (*loc_put)(void *ctx, const lc_core_loc_t *l);
    int (*loc_del)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN]);
    int (*loc_purge_cell)(void *ctx, uint32_t cell_id);
    int (*cdr_add)(void *ctx, const lc_core_cdr_t *c);
    int (*audit_add)(void *ctx, const lc_core_audit_t *a);
} lc_core_store_t;

#endif
```

Create `lc_core/include/lc_core_mem.h`:
```c
/* The in-memory store: plain arrays behind lc_core_store_t, for the host
 * tests and the simulation. A core restarted over the same lc_core_mem_t
 * keeps everything, as it would over its database. CDRs and audit records
 * keep the newest LC_CORE_MEM_LOG of each. */
#ifndef LC_CORE_MEM_H
#define LC_CORE_MEM_H

#include "lc_core_store.h"

#define LC_CORE_MEM_KEYS  4u
#define LC_CORE_MEM_CELLS 16u
#define LC_CORE_MEM_SUBS  64u
#define LC_CORE_MEM_AVS   256u
#define LC_CORE_MEM_LOG   64u

typedef struct {
    lc_core_netkey_t    key[LC_CORE_MEM_KEYS];
    unsigned            nkey;
    lc_core_cell_t      cell[LC_CORE_MEM_CELLS];
    unsigned            ncell;
    lc_core_sub_t       sub[LC_CORE_MEM_SUBS];
    unsigned            nsub;
    lc_core_token_t     token[LC_CORE_MEM_SUBS];
    unsigned            ntoken;
    lc_core_av_issued_t av[LC_CORE_MEM_AVS];
    unsigned            nav;
    lc_core_loc_t       loc[LC_CORE_MEM_SUBS];
    unsigned            nloc;
    lc_core_cdr_t       cdr[LC_CORE_MEM_LOG];
    unsigned            ncdr;   /* ever added; the newest is cdr[(ncdr - 1) % LC_CORE_MEM_LOG] */
    lc_core_audit_t     audit[LC_CORE_MEM_LOG];
    unsigned            naudit; /* likewise */
} lc_core_mem_data_t;

typedef struct {
    lc_core_mem_data_t d;
    lc_core_mem_data_t undo;        /* d as it was at begin */
    int                in_txn;
    int                fail_commits; /* test hook: the next n commits fail (and undo) */
    unsigned           commits;      /* successful commits */
} lc_core_mem_t;

void            lc_core_mem_init(lc_core_mem_t *m);
lc_core_store_t lc_core_mem_store(lc_core_mem_t *m);

/* The newest audit record of event (NULL if none is kept): for tests. */
const lc_core_audit_t *lc_core_mem_audit(const lc_core_mem_t *m, uint8_t event);

#endif
```

Create `lc_core/lc_core_mem.c`:
```c
#include "lc_core_mem.h"

#include <string.h>

#define M(c) ((lc_core_mem_t *)(c))
#define D(c) (&M(c)->d)

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, LC_SIG_NUMBER_LEN) == 0; }

static int begin(void *c)
{
    M(c)->undo = M(c)->d;
    M(c)->in_txn = 1;
    return 0;
}

static int commit(void *c)
{
    lc_core_mem_t *m = M(c);
    m->in_txn = 0;
    if (m->fail_commits > 0) {
        m->fail_commits--;
        m->d = m->undo;
        return -1;
    }
    m->commits++;
    return 0;
}

static int netkey_get(void *c, uint16_t key_id, lc_core_netkey_t *out)
{
    for (unsigned i = 0; i < D(c)->nkey; i++) {
        if (D(c)->key[i].key_id == key_id) {
            *out = D(c)->key[i];
            return 0;
        }
    }
    return -1;
}

static int netkey_put(void *c, const lc_core_netkey_t *k)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nkey; i++) {
        if (d->key[i].key_id == k->key_id) {
            d->key[i] = *k;
            return 0;
        }
    }
    if (d->nkey >= LC_CORE_MEM_KEYS) return -1;
    d->key[d->nkey++] = *k;
    return 0;
}

static int cell_get(void *c, uint32_t cell_id, lc_core_cell_t *out)
{
    for (unsigned i = 0; i < D(c)->ncell; i++) {
        if (D(c)->cell[i].cell_id == cell_id) {
            *out = D(c)->cell[i];
            return 0;
        }
    }
    return -1;
}

static int cell_put(void *c, const lc_core_cell_t *x)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->ncell; i++) {
        if (d->cell[i].cell_id == x->cell_id) {
            d->cell[i] = *x;
            return 0;
        }
    }
    if (d->ncell >= LC_CORE_MEM_CELLS) return -1;
    d->cell[d->ncell++] = *x;
    return 0;
}

static int sub_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_sub_t *out)
{
    for (unsigned i = 0; i < D(c)->nsub; i++) {
        if (num_eq(D(c)->sub[i].number, number)) {
            *out = D(c)->sub[i];
            return 0;
        }
    }
    return -1;
}

static int sub_by_tmid(void *c, uint32_t tmid, lc_core_sub_t *out)
{
    for (unsigned i = 0; i < D(c)->nsub; i++) {
        if (D(c)->sub[i].activated && D(c)->sub[i].tmid == tmid) {
            *out = D(c)->sub[i];
            return 0;
        }
    }
    return -1;
}

static int sub_put(void *c, const lc_core_sub_t *s)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nsub; i++) {
        if (num_eq(d->sub[i].number, s->number)) {
            d->sub[i] = *s;
            return 0;
        }
    }
    if (d->nsub >= LC_CORE_MEM_SUBS) return -1;
    d->sub[d->nsub++] = *s;
    return 0;
}

static int token_get(void *c, const uint8_t token_id[8], lc_core_token_t *out)
{
    for (unsigned i = 0; i < D(c)->ntoken; i++) {
        if (memcmp(D(c)->token[i].token_id, token_id, 8) == 0) {
            *out = D(c)->token[i];
            return 0;
        }
    }
    return -1;
}

static int token_put(void *c, const lc_core_token_t *t)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->ntoken; i++) {
        if (memcmp(d->token[i].token_id, t->token_id, 8) == 0) {
            d->token[i] = *t;
            return 0;
        }
    }
    if (d->ntoken >= LC_CORE_MEM_SUBS) return -1;
    d->token[d->ntoken++] = *t;
    return 0;
}

static int token_void(void *c, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->ntoken; i++) {
        if (!(num_eq(d->token[i].number, number) && d->token[i].used_at == 0)) d->token[k++] = d->token[i];
    }
    d->ntoken = k;
    return 0;
}

static int av_find(lc_core_mem_data_t *d, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16])
{
    for (unsigned i = 0; i < d->nav; i++) {
        if (num_eq(d->av[i].number, number) && memcmp(d->av[i].rand, rand, 16) == 0) return (int)i;
    }
    return -1;
}

static int av_put(void *c, const lc_core_av_issued_t *a)
{
    lc_core_mem_data_t *d = D(c);
    int i = av_find(d, a->number, a->rand);
    if (i >= 0) {
        d->av[i] = *a;
        return 0;
    }
    if (d->nav >= LC_CORE_MEM_AVS) return -1;
    d->av[d->nav++] = *a;
    return 0;
}

static int av_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16], lc_core_av_issued_t *out)
{
    int i = av_find(D(c), number, rand);
    if (i < 0) return -1;
    *out = D(c)->av[i];
    return 0;
}

static int av_drop_cell(void *c, uint32_t cell_id)
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nav; i++) {
        if (!(d->av[i].cell_id == cell_id && !d->av[i].confirmed)) d->av[k++] = d->av[i];
    }
    d->nav = k;
    return 0;
}

static int av_prune(void *c, uint32_t issued_before)
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nav; i++) {
        if (d->av[i].issued >= issued_before) d->av[k++] = d->av[i];
    }
    d->nav = k;
    return 0;
}

static int loc_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out)
{
    for (unsigned i = 0; i < D(c)->nloc; i++) {
        if (num_eq(D(c)->loc[i].number, number)) {
            *out = D(c)->loc[i];
            return 0;
        }
    }
    return -1;
}

static int loc_put(void *c, const lc_core_loc_t *l)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nloc; i++) {
        if (num_eq(d->loc[i].number, l->number)) {
            d->loc[i] = *l;
            return 0;
        }
    }
    if (d->nloc >= LC_CORE_MEM_SUBS) return -1;
    d->loc[d->nloc++] = *l;
    return 0;
}

static int loc_del(void *c, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nloc; i++) {
        if (num_eq(d->loc[i].number, number)) {
            d->loc[i] = d->loc[--d->nloc];
            return 0;
        }
    }
    return -1;
}

static int loc_purge_cell(void *c, uint32_t cell_id)
{
    lc_core_mem_data_t *d = D(c);
    unsigned k = 0;
    for (unsigned i = 0; i < d->nloc; i++) {
        if (d->loc[i].cell_id != cell_id) d->loc[k++] = d->loc[i];
    }
    d->nloc = k;
    return 0;
}

static int cdr_add(void *c, const lc_core_cdr_t *x)
{
    lc_core_mem_data_t *d = D(c);
    d->cdr[d->ncdr++ % LC_CORE_MEM_LOG] = *x;
    return 0;
}

static int audit_add(void *c, const lc_core_audit_t *a)
{
    lc_core_mem_data_t *d = D(c);
    d->audit[d->naudit++ % LC_CORE_MEM_LOG] = *a;
    return 0;
}

void lc_core_mem_init(lc_core_mem_t *m)
{
    memset(m, 0, sizeof(*m));
}

lc_core_store_t lc_core_mem_store(lc_core_mem_t *m)
{
    lc_core_store_t s = {
        .ctx = m,
        .begin = begin,
        .commit = commit,
        .netkey_get = netkey_get,
        .netkey_put = netkey_put,
        .cell_get = cell_get,
        .cell_put = cell_put,
        .sub_get = sub_get,
        .sub_by_tmid = sub_by_tmid,
        .sub_put = sub_put,
        .token_get = token_get,
        .token_put = token_put,
        .token_void = token_void,
        .av_put = av_put,
        .av_get = av_get,
        .av_drop_cell = av_drop_cell,
        .av_prune = av_prune,
        .loc_get = loc_get,
        .loc_put = loc_put,
        .loc_del = loc_del,
        .loc_purge_cell = loc_purge_cell,
        .cdr_add = cdr_add,
        .audit_add = audit_add,
    };
    return s;
}

const lc_core_audit_t *lc_core_mem_audit(const lc_core_mem_t *m, uint8_t event)
{
    unsigned kept = m->d.naudit < LC_CORE_MEM_LOG ? m->d.naudit : LC_CORE_MEM_LOG;
    for (unsigned i = 0; i < kept; i++) {
        const lc_core_audit_t *a = &m->d.audit[(m->d.naudit - 1u - i) % LC_CORE_MEM_LOG];
        if (a->event == event) return a;
    }
    return NULL;
}
```

In `lc_core/CMakeLists.txt`, replace:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c)
```
with:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c)
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_store 2>&1 | grep -E "error|warning"; build/tests/test_core_store | tail -3`
Expected: no compiler output, then `3 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 3`.

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add lc_core tests/core_store_contract.h tests/test_core_store.c tests/CMakeLists.txt
git commit -m "lc_core: storage interface, in-memory store, and the store contract test

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 4: The core's links: HELLO, liveness, cells, the network key

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** now (after Task 3).

`lc_core_t` itself: links from the transport, the cell's HELLO (accepted with the cell's mode, the period and the echo number; refused with a reason and the link dropped), one link per cell, a new boot id purging what the cell's previous process had (§7.9), PING/PONG and the 15 s silence rule, admin for cells and the network key. A cell's `list_id` (its channel-list group) is stored here and used in Task 16. Message families come in Tasks 5, 6, 11 and 12.

**Files:**
- Create: `lc_core/include/lc_core.h`, `lc_core/lc_core_int.h`, `lc_core/lc_core.c`
- Modify: `lc_core/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/core_fixture.h`, `tests/test_core_link.c`

**Interfaces:**
- Consumes: Tasks 1–3 (`lc_core_msg_t`, `lc_core_route_t`, `lc_core_store_t`), `lc_sig_x25519_public`.
- Produces (`lc_core.h`):
  ```c
  #define LC_CORE_LINKS 16u
  #define LC_CORE_PING_US 5000000u
  #define LC_CORE_DEAD_US 15000000u
  typedef struct { uint16_t core_id; uint16_t key_id; uint8_t echo_number[LC_SIG_NUMBER_LEN]; } lc_core_cfg_t;
  typedef struct {
      void *ctx;
      int      (*send)(void *ctx, uint32_t link, const lc_core_msg_t *m);
      void     (*close)(void *ctx, uint32_t link);
      void     (*random)(void *ctx, uint8_t *out, size_t n);
      uint32_t (*unix_now)(void *ctx);
      void     (*log)(void *ctx, const char *line);
  } lc_core_io_t;
  int  lc_core_netkey_new(const lc_core_store_t *st, uint16_t key_id, uint16_t period_s, const uint8_t random32[32],
                          uint32_t unix_now);
  int  lc_core_init(lc_core_t *k, const lc_core_io_t *io, const lc_core_store_t *st, const lc_core_route_t *route,
                    const lc_core_cfg_t *cfg);
  void lc_core_link_up(lc_core_t *k, uint32_t link, uint64_t now_us);
  void lc_core_link_down(lc_core_t *k, uint32_t link, uint64_t now_us);
  void lc_core_rx(lc_core_t *k, uint32_t link, const lc_core_msg_t *m, uint64_t now_us);
  void lc_core_tick(lc_core_t *k, uint64_t now_us);
  int  lc_core_cell_add(lc_core_t *k, uint32_t cell_id, const char *name, uint8_t mode, uint16_t list_id);
  int  lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us);
  ```
- Produces (`lc_core_int.h`, inside `lc_core` only): `LC_CORE_US(s)`, `lc_core_unix(k)`, `lc_core_logf(k, fmt, ...)`, `lc_core_send(k, cell_id, m)` (0, or -1 when the cell has no link), `lc_core_linked(k, cell_id)`, `lc_core_audit(k, event, number, tmid, cell_id, detail)`.
- Produces (test-only, `core_fixture.h`): `MEM`, `ST`, `RT`, `K`, `SENT[]`/`NSENT`, `CLOSED[]`/`NCLOSED`, `NOW`, `core_world()` (block `8831606` at home, cells 1 (Part 15) and 2 (Part 97)), `core_restart()`, `hello(link, cell_id, boot_id)`, `rx(link, m)`, `sent(link, type)`, `sent_since(from, link, type)`, `advance(us)`, `number(text, out)`, `ECHO_NUM`, `UNIX0`.

- [ ] **Step 1: Write the failing test**

Create `tests/core_fixture.h`:
```c
/* A core on the in-memory store, with cells as bare message endpoints: every
 * message the core sends is recorded per link, and tests feed it messages
 * as a cell would. Block 1 (+883 1 606) is at home; cells 1 and 2 exist. */
#ifndef CORE_FIXTURE_H
#define CORE_FIXTURE_H

#include <string.h>

#include "lc_core.h"
#include "lc_core_mem.h"
#include "unity.h"

#define UNIX0    1790000000u
#define ECHO_NUM "+883160655500100"

typedef struct {
    uint32_t      link;
    lc_core_msg_t m;
} sent_t;

static lc_core_mem_t   MEM;
static lc_core_store_t ST;
static lc_core_route_t RT;
static lc_core_t       K;
static sent_t          SENT[128];
static int             NSENT;
static uint32_t        CLOSED[8];
static int             NCLOSED;
static uint64_t        NOW;
static uint32_t        RNG = 1;

static int f_send(void *c, uint32_t link, const lc_core_msg_t *m)
{
    (void)c;
    SENT[NSENT % 128].link = link;
    SENT[NSENT % 128].m = *m;
    NSENT++;
    return 0;
}
static void f_close(void *c, uint32_t link)
{
    (void)c;
    CLOSED[NCLOSED++ % 8] = link;
}
static void f_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((RNG = RNG * 1103515245u + 12345u) >> 16);
}
static uint32_t f_unix(void *c)
{
    (void)c;
    return UNIX0 + (uint32_t)(NOW / 1000000u);
}
static const lc_core_io_t CORE_IO = { NULL, f_send, f_close, f_random, f_unix, NULL };

static inline void number(const char *text, uint8_t out[LC_SIG_NUMBER_LEN])
{
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, lc_sig_number_to_bcd(text, strlen(text), out), text);
}

static inline lc_core_cfg_t core_cfg(void)
{
    lc_core_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    number(ECHO_NUM, cfg.echo_number);
    return cfg;
}

/* A fresh store with the network key, block and cells; a core on it. */
static inline void core_world(void)
{
    uint8_t r[32];
    memset(r, 0x11, 32);
    lc_core_mem_init(&MEM);
    ST = lc_core_mem_store(&MEM);
    TEST_ASSERT_EQUAL_INT(0, lc_core_netkey_new(&ST, 1, 1800, r, UNIX0));
    lc_core_route_init(&RT, 1);
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(&RT, "8831606", 1, 1));
    lc_core_cfg_t cfg = core_cfg();
    NOW = 1000000u;
    NSENT = NCLOSED = 0;
    RNG = 1;
    TEST_ASSERT_EQUAL_INT(0, lc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&K, 1, "A", LC_SIG_MODE_PART15, 0));
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&K, 2, "B", LC_SIG_MODE_PART97, 0));
}

/* The core restarts on the same store: links and calls are gone. */
static inline void core_restart(void)
{
    lc_core_cfg_t cfg = core_cfg();
    TEST_ASSERT_EQUAL_INT(0, lc_core_init(&K, &CORE_IO, &ST, &RT, &cfg));
}

static inline void rx(uint32_t link, const lc_core_msg_t *m)
{
    lc_core_rx(&K, link, m, NOW);
}

/* Link `link` connects and says HELLO as cell_id. */
static inline void hello(uint32_t link, uint32_t cell_id, uint64_t boot_id)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO;
    m.u.hello.proto = LC_CORE_PROTO;
    m.u.hello.cell_id = cell_id;
    m.u.hello.boot_id = boot_id;
    lc_core_link_up(&K, link, NOW);
    rx(link, &m);
}

/* The newest message of type sent on link (NULL if none since index from). */
static inline const lc_core_msg_t *sent_since(int from, uint32_t link, uint8_t type)
{
    for (int i = NSENT - 1; i >= from && i >= NSENT - 128; i--) {
        if (SENT[i % 128].link == link && SENT[i % 128].m.type == type) return &SENT[i % 128].m;
    }
    return NULL;
}
static inline const lc_core_msg_t *sent(uint32_t link, uint8_t type) { return sent_since(0, link, type); }

static inline void advance(uint64_t us)
{
    NOW += us;
    lc_core_tick(&K, NOW);
}

#endif
```

Create `tests/test_core_link.c`:
```c
/* The core's links (network-core spec §6, §7.9): HELLO and its refusals,
 * one link per cell, a new boot purging the cell's state, liveness, revoking
 * a cell. */
#include "unity.h"

#include "core_fixture.h"

void setUp(void) {}
void tearDown(void) {}

static void test_hello_is_acked_with_the_cell_settings(void)
{
    core_world();
    hello(10, 2, 0xB007);
    const lc_core_msg_t *a = sent(10, LC_CORE_HELLO_ACK);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_MODE_PART97, a->u.hello_ack.mode); /* per cell */
    TEST_ASSERT_EQUAL_UINT16(1800, a->u.hello_ack.period_s);
    TEST_ASSERT_EQUAL_UINT16(1, a->u.hello_ack.key_id);
    uint8_t echo[LC_SIG_NUMBER_LEN];
    number(ECHO_NUM, echo);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(echo, a->u.hello_ack.echo_number, LC_SIG_NUMBER_LEN);
    lc_core_cell_t c;
    TEST_ASSERT_EQUAL_INT(0, ST.cell_get(ST.ctx, 2, &c));
    TEST_ASSERT_EQUAL_UINT64(0xB007, c.boot_id);
    TEST_ASSERT_EQUAL_INT(0, NCLOSED);
}

static void test_hello_refusals_close_the_link_and_are_audited(void)
{
    core_world();
    hello(10, 9, 1); /* unknown cell */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_NAK_UNKNOWN_CELL, sent(10, LC_CORE_HELLO_NAK)->u.hello_nak.reason);
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
    const lc_core_audit_t *a = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_CELL_REJECT);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(9, a->cell_id);

    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_revoke(&K, 2, NOW));
    hello(11, 2, 1); /* disabled */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_NAK_DISABLED, sent(11, LC_CORE_HELLO_NAK)->u.hello_nak.reason);

    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO;
    m.u.hello.proto = 2; /* a version this core doesn't speak */
    m.u.hello.cell_id = 1;
    lc_core_link_up(&K, 12, NOW);
    rx(12, &m);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_NAK_VERSION, sent(12, LC_CORE_HELLO_NAK)->u.hello_nak.reason);
    TEST_ASSERT_EQUAL_INT(3, NCLOSED);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_cell_add(&K, 1, "again", LC_SIG_MODE_PART15, 0)); /* exists */
}

static void test_nothing_but_hello_before_hello(void)
{
    core_world();
    lc_core_link_up(&K, 10, NOW);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.tmid = 1;
    m.u.av_req.count = 1;
    rx(10, &m);
    TEST_ASSERT_EQUAL_INT(0, NSENT);
    m.type = LC_CORE_PING; /* liveness works on any link */
    rx(10, &m);
    TEST_ASSERT_NOT_NULL(sent(10, LC_CORE_PONG));
}

static void put_location(uint32_t cell, const char *num)
{
    lc_core_loc_t l;
    memset(&l, 0, sizeof(l));
    number(num, l.number);
    l.cell_id = cell;
    l.tmid = 0x1234;
    l.expires = UNIX0 + 3600u;
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

/* §7.9: a HELLO with a new boot id purges the cell's locations and unused
 * vectors; the same boot id (the link dropped, the process didn't) keeps
 * them. A second link for a cell replaces the first. */
static void test_new_boot_purges_same_boot_keeps(void)
{
    core_world();
    hello(10, 1, 111);
    put_location(1, "+883160655501234");
    put_location(2, "+883160655501235");
    lc_core_av_issued_t av;
    memset(&av, 0, sizeof(av));
    number("+883160655501234", av.number);
    av.cell_id = 1;
    TEST_ASSERT_EQUAL_INT(0, ST.av_put(ST.ctx, &av));
    lc_core_link_down(&K, 10, NOW);
    hello(11, 1, 111); /* the same process, reconnected */
    lc_core_loc_t l;
    uint8_t n1[LC_SIG_NUMBER_LEN], n2[LC_SIG_NUMBER_LEN];
    number("+883160655501234", n1);
    number("+883160655501235", n2);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, n1, &l));
    hello(12, 1, 222); /* restarted, and on a new link while the old one lingers */
    TEST_ASSERT_EQUAL_UINT32(11, CLOSED[NCLOSED - 1]); /* the old link was dropped */
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n1, &l));
    TEST_ASSERT_EQUAL_INT(-1, ST.av_get(ST.ctx, n1, av.rand, &av));
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, n2, &l)); /* another cell's: untouched */
}

static void test_ping_when_idle_and_down_when_silent(void)
{
    core_world();
    hello(10, 1, 1);
    int from = NSENT;
    advance(LC_CORE_PING_US);
    TEST_ASSERT_NOT_NULL(sent_since(from, 10, LC_CORE_PING));
    lc_core_msg_t pong;
    memset(&pong, 0, sizeof(pong));
    pong.type = LC_CORE_PONG;
    rx(10, &pong);
    advance(LC_CORE_DEAD_US - 1u);
    TEST_ASSERT_EQUAL_INT(0, NCLOSED); /* it answered: alive */
    advance(1u);
    TEST_ASSERT_EQUAL_INT(1, NCLOSED);
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
}

static void test_revoked_cell_loses_its_link(void)
{
    core_world();
    hello(10, 1, 1);
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_revoke(&K, 1, NOW));
    TEST_ASSERT_EQUAL_UINT32(10, CLOSED[0]);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_cell_revoke(&K, 7, NOW));
}

static void test_core_needs_its_network_key(void)
{
    static lc_core_mem_t mem;
    lc_core_mem_init(&mem);
    lc_core_store_t st = lc_core_mem_store(&mem);
    lc_core_route_t rt;
    lc_core_route_init(&rt, 1);
    lc_core_cfg_t cfg = core_cfg();
    static lc_core_t k;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_init(&k, &CORE_IO, &st, &rt, &cfg));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hello_is_acked_with_the_cell_settings);
    RUN_TEST(test_hello_refusals_close_the_link_and_are_audited);
    RUN_TEST(test_nothing_but_hello_before_hello);
    RUN_TEST(test_new_boot_purges_same_boot_keeps);
    RUN_TEST(test_ping_when_idle_and_down_when_silent);
    RUN_TEST(test_revoked_cell_loses_its_link);
    RUN_TEST(test_core_needs_its_network_key);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_core_link lc_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_link 2>&1 | grep -E "error" | head -3`
Expected: `fatal error: lc_core.h: No such file or directory`.

- [ ] **Step 3: Implement**

Create `lc_core/include/lc_core.h`:
```c
/* lc_core: one network core (network-core spec §4.2): the cells' links,
 * the HSS/AuC, the location registry and the switch, as a portable C11
 * library with no OS calls, like lc_sig. The caller moves whole frames
 * (lc_core_rx in, io.send out), calls lc_core_tick, and owns the store and
 * the block table. Links are the transport's handles; a link belongs to a
 * cell once its HELLO is accepted. */
#ifndef LC_CORE_H
#define LC_CORE_H

#include "lc_core_msg.h"
#include "lc_core_route.h"
#include "lc_core_store.h"

#define LC_CORE_LINKS   16u
#define LC_CORE_PING_US 5000000u  /* PING when nothing was sent on a link for this long */
#define LC_CORE_DEAD_US 15000000u /* a link that sent nothing for this long is down */

typedef struct {
    uint16_t core_id;
    uint16_t key_id;                          /* the network key pair in use: must be in the store */
    uint8_t  echo_number[LC_SIG_NUMBER_LEN];  /* the echo service, +883160655500100 */
} lc_core_cfg_t;

typedef struct {
    void *ctx;
    int      (*send)(void *ctx, uint32_t link, const lc_core_msg_t *m); /* 0 queued */
    /* the core dropped the link (refused HELLO, silence, replaced, revoked):
     * the transport closes it and need not call lc_core_link_down */
    void     (*close)(void *ctx, uint32_t link);
    void     (*random)(void *ctx, uint8_t *out, size_t n);
    uint32_t (*unix_now)(void *ctx);
    void     (*log)(void *ctx, const char *line);
} lc_core_io_t;

typedef struct {
    int      used;
    uint32_t link;
    uint32_t cell_id; /* 0 until its HELLO is accepted */
    uint64_t last_rx, last_tx;
} lc_core_link_t;

typedef struct {
    lc_core_io_t    io;
    lc_core_cfg_t   cfg;
    lc_core_store_t st;
    lc_core_route_t route;
    lc_core_link_t  links[LC_CORE_LINKS];
    uint64_t        now; /* the now_us of the call being served */
} lc_core_t;

/* A new network key pair (X25519 from random32) with its registration
 * period, straight into the store: made once, before the first lc_core_init.
 * 0 or -1. */
int  lc_core_netkey_new(const lc_core_store_t *st, uint16_t key_id, uint16_t period_s, const uint8_t random32[32],
                        uint32_t unix_now);

/* 0, or -1 when cfg->key_id is not in the store. Keeps nothing of a previous
 * run but what the store holds (a restart). */
int  lc_core_init(lc_core_t *k, const lc_core_io_t *io, const lc_core_store_t *st, const lc_core_route_t *route,
                  const lc_core_cfg_t *cfg);
void lc_core_link_up(lc_core_t *k, uint32_t link, uint64_t now_us);
void lc_core_link_down(lc_core_t *k, uint32_t link, uint64_t now_us);
void lc_core_rx(lc_core_t *k, uint32_t link, const lc_core_msg_t *m, uint64_t now_us);
void lc_core_tick(lc_core_t *k, uint64_t now_us);

/* Admin (plan 8's CLI drives these). A new cell is enabled, in channel-list
 * group list_id (0: none); 0, or -1 if it exists. Revoking disables it and
 * drops its link. */
int  lc_core_cell_add(lc_core_t *k, uint32_t cell_id, const char *name, uint8_t mode, uint16_t list_id);
int  lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us);

#endif
```

Create `lc_core/lc_core_int.h`:
```c
/* Shared between lc_core's own files; not part of its interface. */
#ifndef LC_CORE_INT_H
#define LC_CORE_INT_H

#include "lc_core.h"

#define LC_CORE_US(s) ((uint64_t)(s) * 1000000ull)

uint32_t lc_core_unix(lc_core_t *k);
void     lc_core_logf(lc_core_t *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* To the link of cell_id: 0, or -1 when the cell has no link. */
int      lc_core_send(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);
int      lc_core_linked(const lc_core_t *k, uint32_t cell_id);
void     lc_core_audit(lc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                       const char *detail);

#endif
```

Create `lc_core/lc_core.c`:
```c
#include "lc_core_int.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "lc_sig_crypto.h"

uint32_t lc_core_unix(lc_core_t *k)
{
    return k->io.unix_now(k->io.ctx);
}

void lc_core_logf(lc_core_t *k, const char *fmt, ...)
{
    char line[160];
    va_list ap;
    if (k->io.log == NULL) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    k->io.log(k->io.ctx, line);
}

void lc_core_audit(lc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                   const char *detail)
{
    lc_core_audit_t a;
    memset(&a, 0, sizeof(a));
    a.ts = lc_core_unix(k);
    a.event = event;
    if (number != NULL) memcpy(a.number, number, LC_SIG_NUMBER_LEN);
    a.tmid = tmid;
    a.cell_id = cell_id;
    snprintf(a.detail, sizeof(a.detail), "%s", detail != NULL ? detail : "");
    if (k->st.audit_add(k->st.ctx, &a) != 0) lc_core_logf(k, "audit write FAILED (event %u)", event);
}

static lc_core_link_t *link_of(lc_core_t *k, uint32_t link)
{
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        if (k->links[i].used && k->links[i].link == link) return &k->links[i];
    }
    return NULL;
}

static lc_core_link_t *link_of_cell(lc_core_t *k, uint32_t cell_id)
{
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        if (k->links[i].used && k->links[i].cell_id == cell_id && cell_id != 0) return &k->links[i];
    }
    return NULL;
}

int lc_core_linked(const lc_core_t *k, uint32_t cell_id)
{
    return link_of_cell((lc_core_t *)k, cell_id) != NULL;
}

static int send_link(lc_core_t *k, lc_core_link_t *l, const lc_core_msg_t *m)
{
    l->last_tx = k->now;
    return k->io.send(k->io.ctx, l->link, m);
}

int lc_core_send(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    lc_core_link_t *l = link_of_cell(k, cell_id);
    return l != NULL ? send_link(k, l, m) : -1;
}

/* A cell's link is gone: what depended on it goes too. */
static void cell_gone(lc_core_t *k, uint32_t cell_id, uint64_t now)
{
    (void)now;
    lc_core_logf(k, "cell %u: link down", (unsigned)cell_id);
}

/* The core drops a link itself: the transport is told to close it. */
static void drop(lc_core_t *k, lc_core_link_t *l, uint64_t now)
{
    uint32_t cell = l->cell_id, link = l->link;
    l->used = 0;
    if (cell != 0) cell_gone(k, cell, now);
    if (k->io.close != NULL) k->io.close(k->io.ctx, link);
}

int lc_core_netkey_new(const lc_core_store_t *st, uint16_t key_id, uint16_t period_s, const uint8_t random32[32],
                       uint32_t unix_now)
{
    lc_core_netkey_t key;
    memset(&key, 0, sizeof(key));
    key.key_id = key_id;
    key.period_s = period_s;
    key.created = unix_now;
    memcpy(key.sk, random32, 32);
    if (lc_sig_x25519_public(key.sk, key.pk) != 0) return -1;
    return st->netkey_put(st->ctx, &key);
}

int lc_core_init(lc_core_t *k, const lc_core_io_t *io, const lc_core_store_t *st, const lc_core_route_t *route,
                 const lc_core_cfg_t *cfg)
{
    lc_core_netkey_t key;
    memset(k, 0, sizeof(*k));
    k->io = *io;
    k->st = *st;
    k->route = *route;
    k->cfg = *cfg;
    return k->st.netkey_get(k->st.ctx, cfg->key_id, &key);
}

void lc_core_link_up(lc_core_t *k, uint32_t link, uint64_t now_us)
{
    k->now = now_us;
    if (link_of(k, link) != NULL) return;
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        if (!k->links[i].used) {
            lc_core_link_t *l = &k->links[i];
            memset(l, 0, sizeof(*l));
            l->used = 1;
            l->link = link;
            l->last_rx = l->last_tx = now_us;
            return;
        }
    }
    lc_core_logf(k, "link %u refused: no room", (unsigned)link);
    if (k->io.close != NULL) k->io.close(k->io.ctx, link);
}

void lc_core_link_down(lc_core_t *k, uint32_t link, uint64_t now_us)
{
    k->now = now_us;
    lc_core_link_t *l = link_of(k, link);
    if (l == NULL) return;
    uint32_t cell = l->cell_id;
    l->used = 0;
    if (cell != 0) cell_gone(k, cell, now_us);
}

static void on_hello(lc_core_t *k, lc_core_link_t *l, const lc_core_msg_t *m, uint64_t now)
{
    lc_core_cell_t c;
    lc_core_netkey_t key;
    lc_core_msg_t r;
    uint32_t id = m->u.hello.cell_id;
    uint8_t reason = 0;
    memset(&r, 0, sizeof(r));
    if (m->u.hello.proto != LC_CORE_PROTO) {
        reason = LC_CORE_NAK_VERSION;
    } else if (id == 0 || k->st.cell_get(k->st.ctx, id, &c) != 0) {
        reason = LC_CORE_NAK_UNKNOWN_CELL;
    } else if (!c.enabled) {
        reason = LC_CORE_NAK_DISABLED;
    } else if (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) != 0) {
        reason = LC_CORE_NAK_DISABLED; /* the core itself can't serve: no network key */
    }
    if (reason != 0) {
        char d[48];
        snprintf(d, sizeof(d), "HELLO refused (%u)", reason);
        lc_core_audit(k, LC_CORE_AUDIT_CELL_REJECT, NULL, 0, id, d);
        lc_core_logf(k, "cell %u: %s", (unsigned)id, d);
        r.type = LC_CORE_HELLO_NAK;
        r.u.hello_nak.reason = reason;
        send_link(k, l, &r);
        drop(k, l, now);
        return;
    }
    lc_core_link_t *old = link_of_cell(k, id);
    if (old != NULL && old != l) drop(k, old, now); /* one link per cell: the newest wins */
    if (l->cell_id != 0 && l->cell_id != id) cell_gone(k, l->cell_id, now);
    if (c.boot_id != m->u.hello.boot_id) {
        /* the cell process restarted: its registrations and the vectors it
         * never used went with it (network-core spec §7.9) */
        k->st.loc_purge_cell(k->st.ctx, id);
        k->st.av_drop_cell(k->st.ctx, id);
        c.boot_id = m->u.hello.boot_id;
        lc_core_logf(k, "cell %u: new boot, its locations purged", (unsigned)id);
    }
    c.last_seen = lc_core_unix(k);
    k->st.cell_put(k->st.ctx, &c);
    l->cell_id = id;
    r.type = LC_CORE_HELLO_ACK;
    r.u.hello_ack.mode = c.mode;
    r.u.hello_ack.period_s = key.period_s;
    r.u.hello_ack.key_id = k->cfg.key_id;
    memcpy(r.u.hello_ack.echo_number, k->cfg.echo_number, LC_SIG_NUMBER_LEN);
    send_link(k, l, &r);
}

void lc_core_rx(lc_core_t *k, uint32_t link, const lc_core_msg_t *m, uint64_t now_us)
{
    k->now = now_us;
    lc_core_link_t *l = link_of(k, link);
    if (l == NULL) return;
    l->last_rx = now_us;
    if (m->type == LC_CORE_HELLO) {
        on_hello(k, l, m, now_us);
        return;
    }
    if (m->type == LC_CORE_PING) {
        lc_core_msg_t r;
        memset(&r, 0, sizeof(r));
        r.type = LC_CORE_PONG;
        send_link(k, l, &r);
        return;
    }
    if (l->cell_id == 0) return; /* nothing but HELLO before HELLO */
    switch (m->type) { /* each family goes to its own file: HSS, registry, switch */
    default:
        break;
    }
}

void lc_core_tick(lc_core_t *k, uint64_t now_us)
{
    k->now = now_us;
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        lc_core_link_t *l = &k->links[i];
        if (!l->used) continue;
        if (now_us - l->last_rx >= LC_CORE_DEAD_US) {
            lc_core_logf(k, "link %u: silent for 15 s", (unsigned)l->link);
            drop(k, l, now_us);
        } else if (now_us - l->last_tx >= LC_CORE_PING_US) {
            lc_core_msg_t p;
            memset(&p, 0, sizeof(p));
            p.type = LC_CORE_PING;
            send_link(k, l, &p);
        }
    }
}

int lc_core_cell_add(lc_core_t *k, uint32_t cell_id, const char *name, uint8_t mode, uint16_t list_id)
{
    lc_core_cell_t c;
    if (cell_id == 0 || k->st.cell_get(k->st.ctx, cell_id, &c) == 0) return -1;
    memset(&c, 0, sizeof(c));
    c.cell_id = cell_id;
    snprintf(c.name, sizeof(c.name), "%s", name);
    c.mode = mode;
    c.enabled = 1;
    c.list_id = list_id;
    return k->st.cell_put(k->st.ctx, &c);
}

int lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us)
{
    lc_core_cell_t c;
    k->now = now_us;
    if (k->st.cell_get(k->st.ctx, cell_id, &c) != 0) return -1;
    c.enabled = 0;
    if (k->st.cell_put(k->st.ctx, &c) != 0) return -1;
    lc_core_link_t *l = link_of_cell(k, cell_id);
    if (l != NULL) drop(k, l, now_us);
    return 0;
}
```

In `lc_core/CMakeLists.txt`, replace:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c)
```
with:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c lc_core.c)
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_link 2>&1 | grep -E "error|warning"; build/tests/test_core_link | tail -3`
Expected: no compiler output, then `7 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 4`.

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add lc_core tests/core_fixture.h tests/test_core_link.c tests/CMakeLists.txt
git commit -m "lc_core: links, HELLO, liveness, cells, network key

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 5: Subscribers and tokens (admin), disabling, and the location helpers

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** now (after Task 4).

The HSS's admin side (spec §4.2, §7.11): the operations the plan-8 CLI will drive, `sub add` (a given number, or one picked by policy), `token issue` (the QR's contents) and `sub disable`. The registry file starts here with the two location helpers that disabling and the switch need. The three questions a cell forwards (ACT_FWD, AV_REQ, RESYNC) need `lc_sig_hss` and come in Task 11, in the same two files.

**Files:**
- Create: `lc_core/lc_core_hss.c`, `lc_core/lc_core_reg.c`
- Modify: `lc_core/include/lc_core.h`, `lc_core/lc_core_int.h`, `lc_core/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/test_core_hss.c`

**Interfaces:**
- Consumes: Task 2's route and token functions (`lc_core_route_find/home`, `lc_core_number_reserved/pick`, `lc_core_token_id`); Task 4's core; `lc_sig_qr_t` (`lc_sig_qr.h`, on firmware `main`).
- Produces (`lc_core.h`):
  ```c
  int lc_core_sub_add(lc_core_t *k, const uint8_t *number, uint8_t out[LC_SIG_NUMBER_LEN]); /* number NULL: pick one */
  int lc_core_token_issue(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t valid_s, lc_sig_qr_t *qr);
  int lc_core_sub_disable(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint64_t now_us);
  ```
- Produces (`lc_core_int.h`): `lc_core_loc_live(k, number, out)` (an expired location is deleted and not returned), `lc_core_loc_cancel(k, number, cause)` (LOC_CANCEL to the number's cell, location deleted, audited).
- Produces (test-only, `tests/test_core_hss.c`): `NUM`, `TMID`, `TMID2`, `issue(num)`, `sub_world()` (a subscriber for `NUM` with a token, cell 1 on link 10), `put_location(cell, tmid)`. Task 11 adds the activation and vector tests to this file.

- [ ] **Step 1: Write the failing test**

Create `tests/test_core_hss.c`:
```c
/* The core's HSS/AuC (network-core spec §4.2, §7.1-7.2, §7.11): subscribers
 * and tokens, disabling; activation, vectors and resync, checked the way a
 * terminal checks them (its own key derivation and MILENAGE on its own
 * keys). */
#include "unity.h"

#include "core_fixture.h"
#include "lc_core_int.h" /* lc_core_loc_live */

void setUp(void) {}
void tearDown(void) {}

#define TMID  0x76ad0488u
#define TMID2 0x11223344u

static const char *NUM = "+883160655501234";

static lc_sig_qr_t issue(const char *num)
{
    uint8_t n[LC_SIG_NUMBER_LEN];
    lc_sig_qr_t qr;
    number(num, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_token_issue(&K, n, 3600, &qr));
    return qr;
}

/* A subscriber for NUM with a token, and cell 1 on link 10. */
static lc_sig_qr_t sub_world(void)
{
    uint8_t n[LC_SIG_NUMBER_LEN], got[LC_SIG_NUMBER_LEN];
    core_world();
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, n, got));
    hello(10, 1, 1);
    return issue(NUM);
}

static void put_location(uint32_t cell, uint32_t tmid)
{
    lc_core_loc_t l;
    memset(&l, 0, sizeof(l));
    number(NUM, l.number);
    l.cell_id = cell;
    l.tmid = tmid;
    l.expires = UNIX0 + 3600u;
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

static void test_subscribers_are_added_by_policy(void)
{
    uint8_t n[LC_SIG_NUMBER_LEN], got[LC_SIG_NUMBER_LEN];
    core_world();
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(&K.route, "8831606555", 2, 2)); /* another core's exchange */
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* 606-555 is core 2's */
    number("+883160677701234", n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, n, got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(n, got, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* exists */
    number("+883160677709911", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* reserved */
    number("+883185955520000", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_add(&K, n, got)); /* no block */
    for (int i = 0; i < 20; i++) { /* auto-assigned: in block 1, never in core 2's exchange */
        TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, NULL, got));
        const lc_core_block_t *b = lc_core_route_find(&K.route, got);
        TEST_ASSERT_EQUAL_UINT16(1, b->block_idx);
        TEST_ASSERT_FALSE(lc_core_number_reserved(got));
        lc_core_sub_t s;
        TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, got, &s));
        TEST_ASSERT_EQUAL_UINT8(LC_CORE_SUB_ACTIVE, s.state);
    }
}

static void test_token_issue_fills_the_qr_and_voids_the_old_token(void)
{
    lc_sig_qr_t qr = sub_world();
    lc_core_netkey_t key;
    TEST_ASSERT_EQUAL_INT(0, ST.netkey_get(ST.ctx, 1, &key));
    TEST_ASSERT_EQUAL_UINT16(1, qr.key_id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(key.pk, qr.pkn, 32);
    TEST_ASSERT_EQUAL_UINT16(1, lc_core_token_block(qr.token_id)); /* block 1 */
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 1u + 3600u, qr.expiry);
    lc_core_token_t t;
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &t));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(qr.token_secret, t.secret, 16);
    lc_sig_qr_t qr2 = issue(NUM);
    TEST_ASSERT_EQUAL_INT(-1, ST.token_get(ST.ctx, qr.token_id, &t)); /* at most one unused token */
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr2.token_id, &t));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_TOKEN_ISSUE));
    uint8_t n[LC_SIG_NUMBER_LEN];
    number("+883160655509999", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_token_issue(&K, n, 3600, &qr2)); /* not a subscriber */
}

/* NUM bound to TMID with qr's token used, as an activation leaves it (set
 * by hand: this test is about disabling). */
static void bind_by_hand(const lc_sig_qr_t *qr)
{
    lc_core_sub_t s;
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, qr->number, &s));
    s.activated = 1;
    s.tmid = TMID;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr->token_id, &tok));
    tok.used_at = UNIX0;
    tok.used_by_tmid = TMID;
    TEST_ASSERT_EQUAL_INT(0, ST.token_put(ST.ctx, &tok));
}

static void test_disable_cancels_the_location_and_voids_tokens(void)
{
    lc_sig_qr_t qr = sub_world();
    bind_by_hand(&qr);
    put_location(1, TMID);
    lc_sig_qr_t spare = issue(NUM);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    int from = NSENT;
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, n, NOW));
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_DISABLED, c->u.loc_cancel.cause);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n, &l));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_LOC_CANCEL));
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(-1, ST.token_get(ST.ctx, spare.token_id, &tok));
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &tok)); /* the used one stays, for the record */
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_SUB_DISABLE));
    TEST_ASSERT_EQUAL_INT(-1, lc_core_token_issue(&K, n, 3600, &spare));
    number("+883160655509999", n);
    TEST_ASSERT_EQUAL_INT(-1, lc_core_sub_disable(&K, n, NOW)); /* not a subscriber */
}

/* An expired location is not live, and is gone once asked about. */
static void test_expired_location_is_not_live(void)
{
    sub_world();
    put_location(1, TMID);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, lc_core_loc_live(&K, n, &l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    NOW += 3600ull * 1000000u; /* the fixture's clock: UNIX0 + 1 + 3600 > expires */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_loc_live(&K, n, &l));
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n, &l));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_subscribers_are_added_by_policy);
    RUN_TEST(test_token_issue_fills_the_qr_and_voids_the_old_token);
    RUN_TEST(test_disable_cancels_the_location_and_voids_tokens);
    RUN_TEST(test_expired_location_is_not_live);
    return UNITY_END();
}
```

`lc_core_loc_live` is internal to `lc_core` (`lc_core/lc_core_int.h`, not under `include/`), so this test gets that directory on its include path.

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_core_hss lc_core)
target_include_directories(test_core_hss PRIVATE ${CMAKE_SOURCE_DIR}/lc_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_hss 2>&1 | grep -E "error" | head -3`
Expected: errors such as `unknown type name 'lc_sig_qr_t'` and `implicit declaration of function 'lc_core_token_issue'` (`lc_core.h` doesn't include `lc_sig_qr.h` yet).

- [ ] **Step 3: The admin declarations**

In `lc_core/include/lc_core.h`, replace:
```c
#include "lc_core_store.h"
```
with:
```c
#include "lc_core_store.h"
#include "lc_sig_qr.h"
```

In `lc_core/include/lc_core.h`, replace:
```c
int  lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us);

#endif
```
with:
```c
int  lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us);

/* Subscribers (admin). number NULL: a random free number in the first NANP
 * block this core is home for (numbering-plan.md "Assignment Modes"). 0 with
 * the number in out, or -1: not a valid number, reserved, not in a block
 * this core is home for, already a subscriber, or the store failed. */
int  lc_core_sub_add(lc_core_t *k, const uint8_t *number, uint8_t out[LC_SIG_NUMBER_LEN]);
/* A new activation token for number, valid for valid_s; the number's unused
 * tokens are voided. *qr is what its QR code carries. 0 or -1. */
int  lc_core_token_issue(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t valid_s, lc_sig_qr_t *qr);
/* The subscriber can no longer register: its tokens are voided and its cell
 * is told (LOC_CANCEL disabled). 0 or -1. */
int  lc_core_sub_disable(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint64_t now_us);

#endif
```

In `lc_core/lc_core_int.h`, replace:
```c
void     lc_core_audit(lc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                       const char *detail);
```
with:
```c
void     lc_core_audit(lc_core_t *k, uint8_t event, const uint8_t *number, uint32_t tmid, uint32_t cell_id,
                       const char *detail);

/* lc_core_reg.c: the number's location if it is live (an expired one is
 * deleted): 0 or -1. */
int      lc_core_loc_live(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out);
/* Tell the number's cell to drop it (LOC_CANCEL) and forget the location. */
void     lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause);
```

In `lc_core/CMakeLists.txt`, replace:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c lc_core.c)
```
with:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c lc_core.c lc_core_hss.c lc_core_reg.c)
```

- [ ] **Step 4: Subscribers and tokens, and the registry's first two helpers**

Create `lc_core/lc_core_hss.c`:
```c
/* The HSS/AuC (network-core spec §4.2, §7.1-7.2): subscribers and tokens,
 * activation, vectors and resync. Every change is committed before the
 * answer that depends on it leaves: a vector's SQN is on disk before the
 * terminal can see it. */
#include "lc_core_int.h"

#include <stdio.h>
#include <string.h>

static int home_number(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    return lc_core_route_home(&k->route, lc_core_route_find(&k->route, number));
}

int lc_core_sub_add(lc_core_t *k, const uint8_t *number, uint8_t out[LC_SIG_NUMBER_LEN])
{
    lc_core_sub_t s;
    uint8_t n[LC_SIG_NUMBER_LEN];
    if (number != NULL) {
        if (!lc_sig_number_valid(number) || lc_core_number_reserved(number) || !home_number(k, number) ||
            k->st.sub_get(k->st.ctx, number, &s) == 0) {
            return -1;
        }
        memcpy(n, number, LC_SIG_NUMBER_LEN);
    } else {
        const lc_core_block_t *b = NULL;
        for (unsigned i = 0; i < k->route.n && b == NULL; i++) {
            if (lc_core_route_home(&k->route, &k->route.b[i]) && k->route.b[i].prefix[3] == '1') b = &k->route.b[i];
        }
        int found = 0;
        for (int tries = 0; b != NULL && tries < 64 && !found; tries++) {
            uint8_t r[8];
            k->io.random(k->io.ctx, r, sizeof(r));
            if (lc_core_number_pick(b, r, n) != 0) return -1;
            /* a pick can land in a longer block inside this one: not ours to assign */
            found = lc_core_route_find(&k->route, n) == b && k->st.sub_get(k->st.ctx, n, &s) != 0;
        }
        if (!found) return -1;
    }
    memset(&s, 0, sizeof(s));
    memcpy(s.number, n, LC_SIG_NUMBER_LEN);
    s.state = LC_CORE_SUB_ACTIVE;
    s.created = s.updated = lc_core_unix(k);
    if (k->st.sub_put(k->st.ctx, &s) != 0) return -1;
    memcpy(out, n, LC_SIG_NUMBER_LEN);
    return 0;
}

int lc_core_token_issue(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint32_t valid_s, lc_sig_qr_t *qr)
{
    lc_core_sub_t s;
    lc_core_netkey_t key;
    lc_core_token_t t, other;
    const lc_core_block_t *b = lc_core_route_find(&k->route, number);
    if (!lc_core_route_home(&k->route, b) || k->st.sub_get(k->st.ctx, number, &s) != 0 ||
        s.state != LC_CORE_SUB_ACTIVE || k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) != 0) {
        return -1;
    }
    memset(&t, 0, sizeof(t));
    int tries = 0;
    do {
        uint8_t r6[6];
        if (++tries > 8) return -1;
        k->io.random(k->io.ctx, r6, sizeof(r6));
        lc_core_token_id(b->block_idx, r6, t.token_id);
    } while (k->st.token_get(k->st.ctx, t.token_id, &other) == 0);
    memcpy(t.number, number, LC_SIG_NUMBER_LEN);
    k->io.random(k->io.ctx, t.secret, sizeof(t.secret));
    t.expiry = lc_core_unix(k) + valid_s;
    k->st.begin(k->st.ctx);
    k->st.token_void(k->st.ctx, number); /* at most one unused token per number */
    k->st.token_put(k->st.ctx, &t);
    if (k->st.commit(k->st.ctx) != 0) return -1;
    lc_core_audit(k, LC_CORE_AUDIT_TOKEN_ISSUE, number, 0, 0, NULL);
    memset(qr, 0, sizeof(*qr));
    qr->key_id = k->cfg.key_id;
    memcpy(qr->pkn, key.pk, 32);
    memcpy(qr->token_id, t.token_id, 8);
    memcpy(qr->token_secret, t.secret, 16);
    memcpy(qr->number, number, LC_SIG_NUMBER_LEN);
    qr->expiry = t.expiry;
    return 0;
}

int lc_core_sub_disable(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint64_t now_us)
{
    lc_core_sub_t s;
    k->now = now_us;
    if (k->st.sub_get(k->st.ctx, number, &s) != 0) return -1;
    s.state = LC_CORE_SUB_DISABLED;
    s.updated = lc_core_unix(k);
    k->st.begin(k->st.ctx);
    k->st.sub_put(k->st.ctx, &s);
    k->st.token_void(k->st.ctx, number);
    if (k->st.commit(k->st.ctx) != 0) return -1;
    lc_core_loc_cancel(k, number, LC_CORE_CANCEL_DISABLED);
    lc_core_audit(k, LC_CORE_AUDIT_SUB_DISABLE, number, s.tmid, 0, NULL);
    return 0;
}
```

Create `lc_core/lc_core_reg.c`:
```c
/* The location registry (network-core spec §7.7-7.8): number -> (cell,
 * TMID, expiry), moved only by a LOC_UPDATE that proves itself with the RES
 * of a vector issued to that very cell (§8 "Location claims"). */
#include "lc_core_int.h"

#include <stdio.h>
#include <string.h>

#include "lc_sig_keys.h"

/* A cell without a link purges on its new boot, or claims the number again
 * and is refused. */
static void cancel(lc_core_t *k, uint32_t cell, uint32_t tmid, uint8_t cause)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_CANCEL;
    m.u.loc_cancel.tmid = tmid;
    m.u.loc_cancel.cause = cause;
    lc_core_send(k, cell, &m);
}

int lc_core_loc_live(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_loc_t *out)
{
    if (k->st.loc_get(k->st.ctx, number, out) != 0) return -1;
    if (out->expires > lc_core_unix(k)) return 0;
    k->st.loc_del(k->st.ctx, number);
    return -1;
}

void lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause)
{
    lc_core_loc_t l;
    if (k->st.loc_get(k->st.ctx, number, &l) != 0) return;
    cancel(k, l.cell_id, l.tmid, cause);
    k->st.loc_del(k->st.ctx, number);
    char d[48];
    snprintf(d, sizeof(d), "cause %u", cause);
    lc_core_audit(k, LC_CORE_AUDIT_LOC_CANCEL, number, l.tmid, l.cell_id, d);
}
```

- [ ] **Step 5: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_hss 2>&1 | grep -E "error|warning"; build/tests/test_core_hss | tail -3`
Expected: no compiler output, then `4 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 6: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 5`.

- [ ] **Step 7: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add lc_core tests/test_core_hss.c tests/CMakeLists.txt
git commit -m "lc_core: subscribers by policy, tokens, disabling; the registry's location helpers

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 6: The switch and the echo service

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** now (after Task 5).

CALL_ROUTE from a cell becomes CALL_OFFER to the callee's cell (or a call to the echo service); alert, answer, release and media are relayed between the two legs with their own refs; the 10 s setup timer; a cell whose link goes, or which comes back with a new boot, loses its calls at once (cause 5 to the other side); a CDR for every attempt (§7.4–7.6).

**Files:**
- Create: `lc_core/lc_core_switch.c`
- Modify: `lc_core/include/lc_core.h`, `lc_core/lc_core_int.h`, `lc_core/lc_core.c`, `lc_core/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/test_core_switch.c`

**Interfaces:**
- Consumes: Task 5's `lc_core_loc_live`, `lc_core_sub_add`, `lc_core_sub_disable`; Task 2's route; the store's `sub_get/loc_get/loc_del/cdr_add`.
- Produces (`lc_core.h`):
  ```c
  #define LC_CORE_CALLS    32u
  #define LC_CORE_SETUP_US 10000000u
  #define LC_CORE_ECHO_US  3000000u
  typedef struct { uint32_t cell; uint32_t ref; } lc_core_leg_t;          /* cell 0: the echo service */
  enum { LC_CORE_CALL_ROUTING = 1, LC_CORE_CALL_ALERTING = 2, LC_CORE_CALL_ACTIVE = 3 };
  typedef struct { int used; uint8_t state; lc_core_leg_t a, b; uint8_t caller[LC_SIG_NUMBER_LEN], called[LC_SIG_NUMBER_LEN];
                   uint64_t due; uint32_t setup, answer; } lc_core_call_t;
  /* lc_core_t gains: lc_core_call_t calls[LC_CORE_CALLS]; uint32_t next_ref; */
  ```
- Produces (`lc_core_int.h`): `lc_core_sw_rx(k, cell_id, m)`, `lc_core_sw_tick(k)`, `lc_core_sw_cell_gone(k, cell_id)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_core_switch.c`:
```c
/* The switch (network-core spec §7.4-7.6): a call between two cells, relay
 * of alert, answer, media and release, the refusals and their causes, the
 * setup timer, the echo service, a cell that goes away, and the CDRs. */
#include "unity.h"

#include "core_fixture.h"

void setUp(void) {}
void tearDown(void) {}

#define TA 0x0000aaaau
#define TB 0x0000bbbbu
#define LEG 7u

static uint8_t NA[LC_SIG_NUMBER_LEN], NB[LC_SIG_NUMBER_LEN], ECHO[LC_SIG_NUMBER_LEN];

static void subscriber(const uint8_t n[LC_SIG_NUMBER_LEN], uint32_t tmid, uint32_t cell)
{
    uint8_t got[LC_SIG_NUMBER_LEN];
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, n, got));
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, n, &s));
    s.activated = 1;
    s.tmid = tmid;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    lc_core_loc_t l = { { 0 }, cell, tmid, UNIX0 + 3600u };
    memcpy(l.number, n, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_put(ST.ctx, &l));
}

/* A on cell 1 (link 10), B on cell 2 (link 20). */
static void sw_world(void)
{
    core_world();
    number("+883160655501234", NA);
    number("+883160655501235", NB);
    number(ECHO_NUM, ECHO);
    hello(10, 1, 1); /* first: a cell's first HELLO is a new boot, which purges its locations */
    hello(20, 2, 1);
    subscriber(NA, TA, 1);
    subscriber(NB, TB, 2);
}

static void route(uint32_t link, uint32_t leg, const uint8_t caller[], const uint8_t called[])
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CALL_ROUTE;
    m.u.call_route.leg_ref = leg;
    memcpy(m.u.call_route.caller, caller, LC_SIG_NUMBER_LEN);
    memcpy(m.u.call_route.called, called, LC_SIG_NUMBER_LEN);
    rx(link, &m);
}

static void call_msg(uint32_t link, uint8_t type, uint32_t ref, uint8_t cause)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = ref;
    m.u.call.cause = cause;
    rx(link, &m);
}

static void media(uint32_t link, uint32_t ref, const char *s)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_MEDIA;
    m.u.media.ref = ref;
    m.u.media.seq = 5;
    m.u.media.len = (uint8_t)strlen(s);
    memcpy(m.u.media.data, s, m.u.media.len);
    rx(link, &m);
}

static const lc_core_cdr_t *last_cdr(void)
{
    TEST_ASSERT_TRUE(MEM.d.ncdr > 0);
    return &MEM.d.cdr[(MEM.d.ncdr - 1u) % LC_CORE_MEM_LOG];
}

/* Routes A -> B and returns the core's ref for B's leg. */
static uint32_t offered(void)
{
    int from = NSENT;
    route(10, LEG, NA, NB);
    const lc_core_msg_t *o = sent_since(from, 20, LC_CORE_CALL_OFFER);
    TEST_ASSERT_NOT_NULL(o);
    TEST_ASSERT_TRUE((o->u.call_offer.call_ref & LC_CORE_REF_CORE) != 0);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NB, o->u.call_offer.callee, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NA, o->u.call_offer.caller, LC_SIG_NUMBER_LEN);
    return o->u.call_offer.call_ref;
}

static void test_cross_cell_call_relays_both_ways(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(20, LC_CORE_CALL_ALERT, ref, 0);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ALERT)->u.call.ref);
    media(10, LEG, "EARLY"); /* no media before the answer */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_MEDIA));
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ANSWER)->u.call.ref);
    media(10, LEG, "UP");
    const lc_core_msg_t *d = sent_since(from, 20, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(ref, d->u.media.ref);
    TEST_ASSERT_EQUAL_UINT16(5, d->u.media.seq);
    TEST_ASSERT_EQUAL_MEMORY("UP", d->u.media.data, 2);
    media(20, ref, "DOWN");
    d = sent_since(from, 10, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
    TEST_ASSERT_EQUAL_MEMORY("DOWN", d->u.media.data, 4);
    call_msg(20, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_NORMAL); /* B hangs up */
    const lc_core_msg_t *r = sent_since(from, 10, LC_CORE_CALL_RELEASE);
    TEST_ASSERT_EQUAL_UINT32(LEG, r->u.call.ref);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NORMAL, r->u.call.cause);
    const lc_core_cdr_t *c = last_cdr();
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NA, c->caller, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NB, c->called, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_UINT32(1, c->cell_a);
    TEST_ASSERT_EQUAL_UINT32(2, c->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, c->answer);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NORMAL, c->cause);
    from = NSENT;
    media(10, LEG, "LATE"); /* the call is gone */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_MEDIA));
}

static void test_caller_hangs_up_and_callee_refuses(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(10, LC_CORE_CALL_RELEASE, LEG, LC_SIG_CAUSE_NORMAL); /* A gives up while it rings */
    TEST_ASSERT_EQUAL_UINT32(ref, sent_since(from, 20, LC_CORE_CALL_RELEASE)->u.call.ref);
    TEST_ASSERT_EQUAL_UINT32(0, last_cdr()->answer);

    static const uint8_t causes[] = { LC_SIG_CAUSE_BUSY, LC_SIG_CAUSE_REJECTED, LC_SIG_CAUSE_NO_ANSWER,
                                      LC_SIG_CAUSE_UNREACHABLE };
    for (unsigned i = 0; i < sizeof(causes); i++) { /* cell B's answer reaches A unchanged */
        ref = offered();
        from = NSENT;
        call_msg(20, LC_CORE_CALL_RELEASE, ref, causes[i]);
        TEST_ASSERT_EQUAL_UINT8(causes[i], sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
        TEST_ASSERT_EQUAL_UINT8(causes[i], last_cdr()->cause);
    }
}

static uint8_t refused(const uint8_t caller[], const uint8_t called[])
{
    int from = NSENT;
    route(10, LEG, caller, called);
    const lc_core_msg_t *r = sent_since(from, 10, LC_CORE_CALL_RELEASE);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT32(LEG, r->u.call.ref);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
    TEST_ASSERT_EQUAL_UINT8(r->u.call.cause, last_cdr()->cause); /* every attempt has its CDR */
    return r->u.call.cause;
}

static void test_refusals_and_their_causes(void)
{
    uint8_t n[LC_SIG_NUMBER_LEN];
    sw_world();
    number("+883160655509999", n);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, n)); /* no such subscriber */
    number("+883442079460000", n);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, n)); /* no route */
    TEST_ASSERT_EQUAL_INT(0, ST.loc_del(ST.ctx, NB));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, NB)); /* registered nowhere */
    lc_core_loc_t l = { { 0 }, 2, TB, UNIX0 + 10u };
    memcpy(l.number, NB, LC_SIG_NUMBER_LEN);
    ST.loc_put(ST.ctx, &l);
    NOW += 20000000u;
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, NB)); /* its location expired */
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, NB, &l));
    l.expires = UNIX0 + 3600u;
    ST.loc_put(ST.ctx, &l);
    lc_core_link_down(&K, 20, NOW);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, refused(NA, NB)); /* B's cell is cut off */
    hello(20, 2, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, refused(NB, NA)); /* cell 1 calling as B */
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, NB, NOW));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, refused(NA, NB)); /* disabled */
}

/* §7.4 timers: no alert or release from the callee's cell in 10 s. */
static void test_setup_times_out_after_10_s(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    advance(LC_CORE_SETUP_US - 1000000u);
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_RELEASE));
    call_msg(10, LC_CORE_PING, 0, 0); /* keep the links alive */
    call_msg(20, LC_CORE_PING, 0, 0);
    advance(1000000u);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
    const lc_core_msg_t *b = sent_since(from, 20, LC_CORE_CALL_RELEASE);
    TEST_ASSERT_EQUAL_UINT32(ref, b->u.call.ref);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, b->u.call.cause);

    ref = offered(); /* an alert stops the timer: ringing is the callee cell's 60 s */
    call_msg(20, LC_CORE_CALL_ALERT, ref, 0);
    from = NSENT;
    for (int i = 0; i < 4; i++) {
        advance(4000000u);
        call_msg(10, LC_CORE_PING, 0, 0);
        call_msg(20, LC_CORE_PING, 0, 0);
    }
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_RELEASE));
}

static void test_echo_service_rings_answers_and_echoes(void)
{
    sw_world();
    int from = NSENT;
    route(10, LEG, NA, ECHO);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ALERT)->u.call.ref);
    advance(LC_CORE_ECHO_US - 1u);
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_ANSWER));
    advance(1u);
    TEST_ASSERT_EQUAL_UINT32(LEG, sent_since(from, 10, LC_CORE_CALL_ANSWER)->u.call.ref);
    media(10, LEG, "HELLO");
    const lc_core_msg_t *d = sent_since(from, 10, LC_CORE_MEDIA);
    TEST_ASSERT_EQUAL_UINT32(LEG, d->u.media.ref);
    TEST_ASSERT_EQUAL_MEMORY("HELLO", d->u.media.data, 5);
    call_msg(10, LC_CORE_CALL_RELEASE, LEG, LC_SIG_CAUSE_NORMAL);
    TEST_ASSERT_EQUAL_UINT32(0, last_cdr()->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, last_cdr()->answer);
}

/* A cell's link goes, or it comes back from a restart: every call with a
 * leg on it ends, and the other side hears cause 5 at once. */
static void test_a_cell_going_releases_its_calls(void)
{
    sw_world();
    uint32_t ref = offered();
    call_msg(20, LC_CORE_CALL_ANSWER, ref, 0);
    int from = NSENT;
    lc_core_link_down(&K, 20, NOW);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_NET_FAILURE, last_cdr()->cause);

    hello(20, 2, 1);
    ref = offered();
    from = NSENT;
    hello(30, 1, 2); /* cell 1 restarted: a new boot on a new link */
    TEST_ASSERT_EQUAL_UINT32(ref, sent_since(from, 20, LC_CORE_CALL_RELEASE)->u.call.ref);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, NA, &l)); /* and cell 1's registrations are gone */
}

/* Review Focus 2: the callee's cell has no session for it any more (it
 * moved, or the cell restarted unnoticed): cause 4, and the stale location
 * goes, so the next call is refused at once instead of offered again. */
static void test_stale_location_is_dropped(void)
{
    sw_world();
    uint32_t ref = offered();
    int from = NSENT;
    call_msg(20, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_UNREACHABLE);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_CAUSE_UNREACHABLE, sent_since(from, 10, LC_CORE_CALL_RELEASE)->u.call.cause);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, NB, &l));
    from = NSENT;
    route(10, LEG + 1u, NA, NB);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
}

/* Review Focus 5: a CALL_ROUTE repeated for a leg already routed (a
 * duplicated frame) makes no second offer and no second call. */
static void test_repeated_route_is_ignored(void)
{
    sw_world();
    offered();
    int from = NSENT;
    route(10, LEG, NA, NB);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_CALL_RELEASE));
    unsigned used = 0;
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) used += K.calls[i].used ? 1u : 0u;
    TEST_ASSERT_EQUAL_UINT(1, used);
    route(10, LC_CORE_REF_CORE | 5u, NA, NB); /* not a ref a cell may use */
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_CALL_OFFER));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cross_cell_call_relays_both_ways);
    RUN_TEST(test_caller_hangs_up_and_callee_refuses);
    RUN_TEST(test_refusals_and_their_causes);
    RUN_TEST(test_setup_times_out_after_10_s);
    RUN_TEST(test_echo_service_rings_answers_and_echoes);
    RUN_TEST(test_a_cell_going_releases_its_calls);
    RUN_TEST(test_stale_location_is_dropped);
    RUN_TEST(test_repeated_route_is_ignored);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_core_switch lc_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_switch 2>&1 | grep -E "error" | head -3`
Expected: `'LC_CORE_SETUP_US' undeclared`, `'LC_CORE_ECHO_US' undeclared` and `'LC_CORE_CALLS' undeclared`.

- [ ] **Step 3: Implement**

In `lc_core/include/lc_core.h`, replace:
```c
#define LC_CORE_LINKS   16u
#define LC_CORE_PING_US 5000000u  /* PING when nothing was sent on a link for this long */
#define LC_CORE_DEAD_US 15000000u /* a link that sent nothing for this long is down */
```
with:
```c
#define LC_CORE_LINKS    16u
#define LC_CORE_PING_US  5000000u  /* PING when nothing was sent on a link for this long */
#define LC_CORE_DEAD_US  15000000u /* a link that sent nothing for this long is down */
#define LC_CORE_CALLS    32u
#define LC_CORE_SETUP_US 10000000u /* CALL_ROUTE to the callee's alert or release (§7.4) */
#define LC_CORE_ECHO_US  3000000u  /* the echo service rings this long, then answers */
```

In `lc_core/include/lc_core.h`, replace:
```c
typedef struct {
    lc_core_io_t    io;
```
with:
```c
/* One leg of a call: a cell and the ref the leg started with. */
typedef struct {
    uint32_t cell; /* 0: the echo service */
    uint32_t ref;
} lc_core_leg_t;

enum { LC_CORE_CALL_ROUTING = 1, LC_CORE_CALL_ALERTING = 2, LC_CORE_CALL_ACTIVE = 3 };

typedef struct {
    int           used;
    uint8_t       state;
    lc_core_leg_t a, b; /* a: the caller's leg (the cell's ref); b: the callee's (a core ref) */
    uint8_t       caller[LC_SIG_NUMBER_LEN], called[LC_SIG_NUMBER_LEN];
    uint64_t      due;           /* ROUTING: give up then; the echo service: answer then */
    uint32_t      setup, answer; /* unix s; answer 0 = not answered */
} lc_core_call_t;

typedef struct {
    lc_core_io_t    io;
```

In `lc_core/include/lc_core.h`, replace:
```c
    uint64_t        now; /* the now_us of the call being served */
} lc_core_t;
```
with:
```c
    uint64_t        now; /* the now_us of the call being served */
    lc_core_call_t  calls[LC_CORE_CALLS];
    uint32_t        next_ref;
} lc_core_t;
```

In `lc_core/lc_core_int.h`, replace:
```c
/* Tell the number's cell to drop it (LOC_CANCEL) and forget the location. */
void     lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause);
```
with:
```c
/* Tell the number's cell to drop it (LOC_CANCEL) and forget the location. */
void     lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause);

/* lc_core_switch.c: CALL_* and MEDIA from a cell, the call timers, and a
 * cell whose link went (every call with a leg on it ends, cause 5) */
void     lc_core_sw_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);
void     lc_core_sw_tick(lc_core_t *k);
void     lc_core_sw_cell_gone(lc_core_t *k, uint32_t cell_id);
```

In `lc_core/lc_core.c`, replace:
```c
/* A cell's link is gone: what depended on it goes too. */
static void cell_gone(lc_core_t *k, uint32_t cell_id, uint64_t now)
{
    (void)now;
    lc_core_logf(k, "cell %u: link down", (unsigned)cell_id);
}
```
with:
```c
/* A cell's link is gone: its calls go too (§7.9, "Done means": no
 * half-open call on the other side). Its locations stay until a new boot. */
static void cell_gone(lc_core_t *k, uint32_t cell_id, uint64_t now)
{
    (void)now;
    lc_core_logf(k, "cell %u: link down", (unsigned)cell_id);
    lc_core_sw_cell_gone(k, cell_id);
}
```

In `lc_core/lc_core.c`, replace:
```c
        k->st.loc_purge_cell(k->st.ctx, id);
        k->st.av_drop_cell(k->st.ctx, id);
```
with:
```c
        k->st.loc_purge_cell(k->st.ctx, id);
        k->st.av_drop_cell(k->st.ctx, id);
        lc_core_sw_cell_gone(k, id);
```

In `lc_core/lc_core.c`, replace:
```c
    switch (m->type) { /* each family goes to its own file: HSS, registry, switch */
    default:
        break;
    }
```
with:
```c
    switch (m->type) { /* each family goes to its own file: HSS, registry, switch */
    case LC_CORE_CALL_ROUTE:
    case LC_CORE_CALL_ALERT:
    case LC_CORE_CALL_ANSWER:
    case LC_CORE_CALL_RELEASE:
    case LC_CORE_MEDIA:
        lc_core_sw_rx(k, l->cell_id, m);
        break;
    default:
        break;
    }
```

In `lc_core/lc_core.c`, replace:
```c
            p.type = LC_CORE_PING;
            send_link(k, l, &p);
        }
    }
}
```
with:
```c
            p.type = LC_CORE_PING;
            send_link(k, l, &p);
        }
    }
    lc_core_sw_tick(k);
}
```

Create `lc_core/lc_core_switch.c`:
```c
/* The switch (network-core spec §7.4-7.6): routes a cell's CALL_ROUTE to
 * the callee's cell (or the echo service), relays alert, answer, release
 * and media between the two legs, runs the setup timer, and writes a CDR
 * for every call attempt. */
#include "lc_core_int.h"

#include <string.h>

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, LC_SIG_NUMBER_LEN) == 0; }

static void to_leg(lc_core_t *k, const lc_core_leg_t *leg, uint8_t type, uint8_t cause)
{
    if (leg->cell == 0) return; /* the echo service */
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = leg->ref;
    m.u.call.cause = cause;
    lc_core_send(k, leg->cell, &m);
}

static void cdr(lc_core_t *k, const lc_core_call_t *c, uint8_t cause)
{
    lc_core_cdr_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.caller, c->caller, LC_SIG_NUMBER_LEN);
    memcpy(r.called, c->called, LC_SIG_NUMBER_LEN);
    r.cell_a = c->a.cell;
    r.cell_b = c->b.cell;
    r.setup = c->setup;
    r.answer = c->answer;
    r.end = lc_core_unix(k);
    r.cause = cause;
    if (k->st.cdr_add(k->st.ctx, &r) != 0) lc_core_logf(k, "CDR write FAILED");
}

static void end_call(lc_core_t *k, lc_core_call_t *c, uint8_t cause)
{
    cdr(k, c, cause);
    lc_core_logf(k, "call %08x/%08x ended, cause %u", (unsigned)c->a.ref, (unsigned)c->b.ref, cause);
    c->used = 0;
}

/* The call that has leg (cell, ref); *leg is it, *other the far one. */
static lc_core_call_t *find(lc_core_t *k, uint32_t cell, uint32_t ref, lc_core_leg_t **leg, lc_core_leg_t **other)
{
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) {
        lc_core_call_t *c = &k->calls[i];
        if (!c->used) continue;
        if (c->a.cell == cell && c->a.ref == ref) {
            *leg = &c->a;
            *other = &c->b;
            return c;
        }
        if (c->b.cell == cell && c->b.ref == ref) {
            *leg = &c->b;
            *other = &c->a;
            return c;
        }
    }
    return NULL;
}

static void on_route(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    const uint8_t *called = m->u.call_route.called;
    lc_core_leg_t *leg, *other;
    lc_core_call_t *c = NULL;
    lc_core_loc_t la, lb;
    lc_core_sub_t s;
    if ((m->u.call_route.leg_ref & LC_CORE_REF_CORE) != 0 || find(k, cell, m->u.call_route.leg_ref, &leg, &other)) {
        return; /* not a cell's ref, or a leg already routed */
    }
    for (unsigned i = 0; i < LC_CORE_CALLS && c == NULL; i++) {
        if (!k->calls[i].used) c = &k->calls[i];
    }
    lc_core_call_t full;
    if (c == NULL) c = &full; /* no room: refused below, the CDR still written */
    memset(c, 0, sizeof(*c));
    c->used = c != &full;
    c->a.cell = cell;
    c->a.ref = m->u.call_route.leg_ref;
    k->next_ref = (k->next_ref + 1u) & ~LC_CORE_REF_CORE;
    c->b.ref = LC_CORE_REF_CORE | k->next_ref;
    memcpy(c->caller, m->u.call_route.caller, LC_SIG_NUMBER_LEN);
    memcpy(c->called, called, LC_SIG_NUMBER_LEN);
    c->setup = lc_core_unix(k);
    uint8_t why = 0;
    if (c == &full) {
        why = LC_SIG_CAUSE_NET_FAILURE;
    } else if (lc_core_loc_live(k, c->caller, &la) != 0 || la.cell_id != cell) {
        /* a cell calls only as a subscriber registered on it */
        lc_core_logf(k, "cell %u: CALL_ROUTE from a caller not registered there", (unsigned)cell);
        why = LC_SIG_CAUSE_NET_FAILURE;
    } else if (num_eq(called, k->cfg.echo_number)) {
        c->state = LC_CORE_CALL_ALERTING; /* the echo service rings at once */
        c->due = k->now + LC_CORE_ECHO_US;
        to_leg(k, &c->a, LC_CORE_CALL_ALERT, 0);
        return;
    } else if (!lc_core_route_home(&k->route, lc_core_route_find(&k->route, called)) ||
               k->st.sub_get(k->st.ctx, called, &s) != 0 || s.state != LC_CORE_SUB_ACTIVE || !s.activated ||
               lc_core_loc_live(k, called, &lb) != 0) {
        why = LC_SIG_CAUSE_UNREACHABLE; /* unknown, not ours, disabled, or registered nowhere */
    } else if (!lc_core_linked(k, lb.cell_id)) {
        why = LC_SIG_CAUSE_NET_FAILURE; /* the callee's cell is cut off */
    }
    if (why != 0) {
        to_leg(k, &c->a, LC_CORE_CALL_RELEASE, why);
        end_call(k, c, why);
        return;
    }
    c->b.cell = lb.cell_id;
    c->state = LC_CORE_CALL_ROUTING;
    c->due = k->now + LC_CORE_SETUP_US;
    lc_core_msg_t o;
    memset(&o, 0, sizeof(o));
    o.type = LC_CORE_CALL_OFFER;
    o.u.call_offer.call_ref = c->b.ref;
    memcpy(o.u.call_offer.callee, called, LC_SIG_NUMBER_LEN);
    memcpy(o.u.call_offer.caller, c->caller, LC_SIG_NUMBER_LEN);
    lc_core_send(k, c->b.cell, &o);
}

void lc_core_sw_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    lc_core_leg_t *leg, *other;
    lc_core_call_t *c;
    if (m->type == LC_CORE_CALL_ROUTE) {
        on_route(k, cell_id, m);
        return;
    }
    c = find(k, cell_id, m->type == LC_CORE_MEDIA ? m->u.media.ref : m->u.call.ref, &leg, &other);
    if (c == NULL) return;
    switch (m->type) {
    case LC_CORE_CALL_ALERT:
        if (leg == &c->b && c->state == LC_CORE_CALL_ROUTING) {
            c->state = LC_CORE_CALL_ALERTING;
            to_leg(k, &c->a, LC_CORE_CALL_ALERT, 0);
        }
        break;
    case LC_CORE_CALL_ANSWER:
        if (leg == &c->b && c->state != LC_CORE_CALL_ACTIVE) {
            c->state = LC_CORE_CALL_ACTIVE;
            c->answer = lc_core_unix(k);
            to_leg(k, &c->a, LC_CORE_CALL_ANSWER, 0);
        }
        break;
    case LC_CORE_CALL_RELEASE:
        if (leg == &c->b && c->state == LC_CORE_CALL_ROUTING && m->u.call.cause == LC_SIG_CAUSE_UNREACHABLE) {
            lc_core_loc_t l; /* §7.4 step 3: no such session there, so the location was stale */
            if (k->st.loc_get(k->st.ctx, c->called, &l) == 0 && l.cell_id == c->b.cell) k->st.loc_del(k->st.ctx, c->called);
        }
        to_leg(k, other, LC_CORE_CALL_RELEASE, m->u.call.cause); /* the same cause on the other leg */
        end_call(k, c, m->u.call.cause);
        break;
    case LC_CORE_MEDIA:
        if (c->state == LC_CORE_CALL_ACTIVE) {
            lc_core_msg_t d = *m;
            const lc_core_leg_t *to = other->cell != 0 ? other : leg; /* the echo service sends it back */
            d.u.media.ref = to->ref;
            lc_core_send(k, to->cell, &d);
        }
        break;
    default:
        break;
    }
}

void lc_core_sw_tick(lc_core_t *k)
{
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) {
        lc_core_call_t *c = &k->calls[i];
        if (!c->used || k->now < c->due) continue;
        if (c->state == LC_CORE_CALL_ROUTING) { /* no alert or release from the callee's cell in 10 s */
            to_leg(k, &c->a, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
            to_leg(k, &c->b, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
            end_call(k, c, LC_SIG_CAUSE_NET_FAILURE);
        } else if (c->state == LC_CORE_CALL_ALERTING && c->b.cell == 0) { /* the echo service answers */
            c->state = LC_CORE_CALL_ACTIVE;
            c->answer = lc_core_unix(k);
            to_leg(k, &c->a, LC_CORE_CALL_ANSWER, 0);
        }
    }
}

void lc_core_sw_cell_gone(lc_core_t *k, uint32_t cell_id)
{
    for (unsigned i = 0; i < LC_CORE_CALLS; i++) {
        lc_core_call_t *c = &k->calls[i];
        if (!c->used || (c->a.cell != cell_id && c->b.cell != cell_id)) continue;
        if (c->a.cell != cell_id) to_leg(k, &c->a, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
        if (c->b.cell != cell_id) to_leg(k, &c->b, LC_CORE_CALL_RELEASE, LC_SIG_CAUSE_NET_FAILURE);
        end_call(k, c, LC_SIG_CAUSE_NET_FAILURE);
    }
}
```

In `lc_core/CMakeLists.txt`, replace:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c lc_core.c lc_core_hss.c lc_core_reg.c)
```
with:
```cmake
add_library(lc_core STATIC lc_core_msg.c lc_core_route.c lc_core_mem.c lc_core.c lc_core_hss.c lc_core_reg.c
                           lc_core_switch.c)
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_switch 2>&1 | grep -E "error|warning"; build/tests/test_core_switch | tail -3`
Expected: no compiler output, then `8 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 6`.

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add lc_core tests/test_core_switch.c tests/CMakeLists.txt
git commit -m "lc_core: switch - route, offer, relay, setup timer, echo service, CDRs

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 7: The firmware's `net-core` branch, after `chan-list`, and a baseline

**Repo:** `opencell-firmware`, branch `net-core` (new, off `main`), at `/home/devin/Documents/opencell/firmware`. **Starts:** once `chan-list` is merged into firmware `main`. It can run while Tasks 1–6 are under way: the two repositories don't share a working tree.

Tasks 8–10 change `lc_sig`, `lcbench` and the host tests, and must build on `chan-list`'s `lc_sig` changes (CHAN_LIST 0x16/0x17, `LC_SIG_SVC_CONFIG`, the reliable channel's fixes, `lc_sig_net_set_chan_list`), so they start from a `main` that has them.

**Files:** none.

**Interfaces:**
- Consumes: `chan-list` merged into firmware `main`.
- Produces: `net-core` = firmware `main` with `chan-list`. The baseline test count **N**, and the counts of four targets (`test_sig_e2e`, `test_sig_local`, `test_term_sim`, `test_lcbench`) that Tasks 9–10 compare against.

- [ ] **Step 1: Check that `chan-list` has landed**

Run: `cd /home/devin/Documents/opencell/firmware && git fetch -q origin && git show origin/main:firmware/components/lc_sig/include/lc_sig_net.h | grep -c "lc_sig_net_set_chan_list"`
Expected: `1`. If it prints `0`, **stop**: Tasks 7–10 must not run before `chan-list` is in firmware `main`. Report back instead (Tasks 1–6 in the core don't wait for it).

- [ ] **Step 2: The branch**

Run: `cd /home/devin/Documents/opencell/firmware && git status --short && git switch main && git pull -q && git switch -c net-core && git branch --show-current`
Expected: `git status` prints nothing (a clean tree: if the `chan-list` work left anything, stop and ask), then `net-core`.

- [ ] **Step 3: The files Tasks 8–10 edit**

Run: `cd /home/devin/Documents/opencell/firmware && sha256sum firmware/components/lc_sig/include/lc_sig_net.h firmware/components/lc_sig/lc_sig_net.c firmware/components/lc_sig/CMakeLists.txt host-tests/test_sig_e2e.c host-tests/test_sig_local.c host-tests/test_term_sim.c tools/lcbench/lcb_net.c | awk '{print substr($1, 1, 12), $2}'`
Expected, as validated on `chan-list` at `943a093` (its fix round 3):
```
a1fe6bc13da1 firmware/components/lc_sig/include/lc_sig_net.h
355068663ac4 firmware/components/lc_sig/lc_sig_net.c
5f7bde89f8ef firmware/components/lc_sig/CMakeLists.txt
7da99709b0ef host-tests/test_sig_e2e.c
647b9f628732 host-tests/test_sig_local.c
690a70f92632 host-tests/test_term_sim.c
9eed5de06f0c tools/lcbench/lcb_net.c
```
`chan-list` still had its Tasks 9–16 to run after `943a093` (among them `lcb_net.c`, `test_term_sim.c` and `test_lcbench.c` changes), so some hashes will differ. For each file that differs, run `git diff 943a093 main -- <file>` and read what changed around the text Tasks 8–10 replace: those tasks anchor on lines `chan-list` did not touch at `943a093`, and a replacement that no longer matches is made by hand on the same code, keeping every `chan-list` line.

- [ ] **Step 4: Baseline host suite**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3); for t in test_sig_e2e test_sig_local test_term_sim test_lcbench; do host-tests/build/$t | tail -2 | head -1; done`
Expected: no compiler output, `100% tests passed, 0 tests failed out of N`, then four `… Tests 0 Failures 0 Ignored` lines. Write N and the four counts down. At `943a093`: N = 33, then `40`, `4`, `21`, `21`.

- [ ] **Step 5: The same suite under AddressSanitizer and UBSan**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build/asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null && cmake --build host-tests/build/asan -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build/asan && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N`. (The two out-of-bounds accesses the first version of this plan found in `lc_sig_number.c` were fixed when numbering v2 merged.)

No commit (nothing changed).

---

### Task 8: `lc_sig_hss`: the home side as pure functions

**Repo:** `opencell-firmware`, branch `net-core`, at `/home/devin/Documents/opencell/firmware`. **Starts:** after Task 7.

Everything `lc_sig_net` computes with a subscriber's K, OPc, SQN or the network key today (the plan-5 activation checks and KDF, MILENAGE vectors, AUTS) moves into functions of their inputs, so the core, lcbench and the tests' fake core share one implementation. `lc_sig_net` still uses its own copy until Task 9. The core's HSS (Task 11) calls these functions too, through the submodule.

**Files:**
- Create: `firmware/components/lc_sig/include/lc_sig_hss.h`, `firmware/components/lc_sig/lc_sig_hss.c`
- Modify: `firmware/components/lc_sig/CMakeLists.txt` (host library), `firmware/components/lc_sig/include/lc_sig_net.h` (`lc_sig_sub_t` moves out)
- Test: `host-tests/test_sig_hss.c`, `host-tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `lc_milenage` (`lc_sig_milenage.h`), `lc_sig_act_tag`, `lc_sig_act_nak_tag`, `lc_sig_act_keys`, `lc_sig_act_confirm`, `lc_sig_ct_equal` (`lc_sig_keys.h`), `lc_sig_sqn_get/put` (`lc_sig.h`).
- Produces (`lc_sig_hss.h`, host-only):
  ```c
  typedef struct { uint8_t rand[16], autn[16], xres[8], ck[16], ik[16]; } lc_sig_av_t;
  typedef enum { LC_SIG_AV_OK = 0, LC_SIG_AV_NOT_ACTIVATED = 1, LC_SIG_AV_BOUND_ELSEWHERE = 2, LC_SIG_AV_DISABLED = 3,
                 LC_SIG_AV_UNAVAILABLE = 4, LC_SIG_AV_AUTH_FAILED = 5 } lc_sig_av_status_t;
  int lc_sig_av_make(const uint8_t k[16], const uint8_t opc[16], const uint8_t sqn[6], const uint8_t rand[16], lc_sig_av_t *av);
  int lc_sig_av_auts(const uint8_t k[16], const uint8_t opc[16], const uint8_t rand[16], const uint8_t auts[14], uint8_t sqn_ms[6]);
  typedef struct { int known, used; uint32_t expiry; uint8_t secret[16]; uint32_t bound_tmid; uint8_t bound_k[16]; } lc_sig_act_token_t;
  typedef enum { LC_SIG_ACT_REFUSED = 0, LC_SIG_ACT_FRESH = 1, LC_SIG_ACT_AGAIN = 2 } lc_sig_act_result_t;
  int lc_sig_act_answer(const lc_sig_act_token_t *tok, const uint8_t sk[32], uint32_t unix_now, uint32_t tmid,
                        const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8],
                        const uint8_t number[LC_SIG_NUMBER_LEN], lc_sig_msg_t *out, uint8_t k[16], uint8_t opc[16]);
  int     lc_sig_flat_act(lc_sig_sub_t *subs, unsigned n, const uint8_t sk[32], uint32_t unix_now, uint32_t tmid,
                          const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8], lc_sig_msg_t *out,
                          uint32_t drop[2], unsigned *ndrop);
  uint8_t lc_sig_flat_av(lc_sig_sub_t *subs, unsigned n, uint32_t tmid, const uint8_t rand[16],
                         uint8_t number[LC_SIG_NUMBER_LEN], lc_sig_av_t *av);
  uint8_t lc_sig_flat_resync(lc_sig_sub_t *subs, unsigned n, uint32_t tmid, const uint8_t rand[16], const uint8_t auts[14],
                             const uint8_t fresh_rand[16], uint8_t number[LC_SIG_NUMBER_LEN], lc_sig_av_t *av);
  ```
- Produces: `lc_sig_sub_t` now lives in `lc_sig_hss.h`, unchanged; `lc_sig_net.h` includes it.

- [ ] **Step 1: Write the failing test**

Create `host-tests/test_sig_hss.c`:
```c
/* The home side of activation and authentication (lc_sig_hss), checked the
 * way the terminal checks it: MILENAGE on the terminal's keys for vectors and
 * AUTS, the terminal's own key derivation for ACT_ACK. */
#include "unity.h"

#include <string.h>

#include "lc_sig_crypto.h"
#include "lc_sig_hss.h"
#include "lc_sig_keys.h"
#include "lc_sig_milenage.h"
#include "lc_sig_term.h"

void setUp(void) {}
void tearDown(void) {}

#define TMID  0x76ad0488u
#define TMID2 0x11223344u
#define NOW   1790000000u

static const uint8_t K[16] = { 0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f,
                               0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc };
static const uint8_t OPC[16] = { 0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e,
                                 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf };

/* What lc_sig_term does with AUTH_REQ: 0 and the SQN if MAC-A verifies. */
static int terminal_check(const lc_sig_av_t *av, uint8_t sqn[6], lc_milenage_t *o)
{
    static const uint8_t zero[6] = { 0 }, amf[2] = { 0x80, 0x00 };
    if (lc_milenage(K, OPC, av->rand, zero, amf, o) != 0) return -1;
    for (int i = 0; i < 6; i++) sqn[i] = (uint8_t)(av->autn[i] ^ o->ak[i]);
    if (lc_milenage(K, OPC, av->rand, sqn, av->autn + 6, o) != 0) return -1;
    return lc_sig_ct_equal(o->mac_a, av->autn + 8, 8) ? 0 : -1;
}

/* What lc_sig_term sends as AUTS for its own SQN sqn_ms. */
static void terminal_auts(const uint8_t rand[16], const uint8_t sqn_ms[6], uint8_t auts[14])
{
    static const uint8_t amf0[2] = { 0, 0 };
    lc_milenage_t o;
    lc_milenage(K, OPC, rand, sqn_ms, amf0, &o);
    for (int i = 0; i < 6; i++) auts[i] = (uint8_t)(sqn_ms[i] ^ o.ak_s[i]);
    memcpy(auts + 6, o.mac_s, 8);
}

static void test_av_make_passes_the_terminal_check(void)
{
    uint8_t sqn[6], rand[16], got[6];
    lc_sig_av_t av;
    lc_milenage_t o;
    lc_sig_sqn_put(sqn, 42);
    memset(rand, 0x5a, 16);
    TEST_ASSERT_EQUAL_INT(0, lc_sig_av_make(K, OPC, sqn, rand, &av));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(rand, av.rand, 16);
    TEST_ASSERT_EQUAL_INT(0, terminal_check(&av, got, &o));
    TEST_ASSERT_EQUAL_UINT64(42, lc_sig_sqn_get(got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(o.res, av.xres, 8);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(o.ck, av.ck, 16);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(o.ik, av.ik, 16);
    av.autn[15] ^= 1; /* a forged MAC-A */
    TEST_ASSERT_EQUAL_INT(-1, terminal_check(&av, got, &o));
}

static void test_auts_gives_the_terminal_sqn_and_refuses_forgeries(void)
{
    uint8_t rand[16], ms[6], auts[14], got[6];
    memset(rand, 0x33, 16);
    lc_sig_sqn_put(ms, 500);
    terminal_auts(rand, ms, auts);
    TEST_ASSERT_EQUAL_INT(0, lc_sig_av_auts(K, OPC, rand, auts, got));
    TEST_ASSERT_EQUAL_UINT64(500, lc_sig_sqn_get(got));
    auts[13] ^= 1;
    TEST_ASSERT_EQUAL_INT(-1, lc_sig_av_auts(K, OPC, rand, auts, got));
    auts[13] ^= 1;
    rand[0] ^= 1; /* AUTS for another challenge */
    TEST_ASSERT_EQUAL_INT(-1, lc_sig_av_auts(K, OPC, rand, auts, got));
}

/* A network key pair, a terminal key pair, a token, and the ACT_REQ fields. */
static uint8_t SKN[32], PKN[32], TOK[8], SECRET[16], NUM[LC_SIG_NUMBER_LEN];
static lc_sig_ident_t ID;

static void act_world(void)
{
    uint8_t r[32];
    memset(SKN, 0x11, 32);
    lc_sig_x25519_public(SKN, PKN);
    memset(r, 0x42, 32);
    lc_sig_ident_new(&ID, r);
    memset(TOK, 0xa0, 8);
    memset(SECRET, 0xb0, 16);
    lc_sig_number_to_bcd("+883160655501234", 16, NUM);
}

static lc_sig_act_token_t fresh_token(void)
{
    lc_sig_act_token_t t;
    memset(&t, 0, sizeof(t));
    t.known = 1;
    t.expiry = NOW + 3600u;
    memcpy(t.secret, SECRET, 16);
    return t;
}

static int answer(const lc_sig_act_token_t *t, uint32_t tmid, const uint8_t pk[32], lc_sig_msg_t *out,
                  uint8_t k[16], uint8_t opc[16])
{
    uint8_t tag[8];
    lc_sig_act_tag(SECRET, tmid, pk, TOK, tag);
    return lc_sig_act_answer(t, SKN, NOW, tmid, TOK, pk, tag, NUM, out, k, opc);
}

static void test_act_fresh_ack_confirms_with_the_terminal_keys(void)
{
    act_world();
    lc_sig_act_token_t t = fresh_token();
    lc_sig_msg_t m;
    uint8_t k[16], opc[16], tk[16], topc[16], conf[8];
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_FRESH, answer(&t, TMID, ID.pk, &m, k, opc));
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, m.type);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(NUM, m.u.act_ack.number, LC_SIG_NUMBER_LEN);
    /* the terminal derives the same K and OPc from its side of the exchange */
    TEST_ASSERT_EQUAL_INT(0, lc_sig_act_keys(ID.sk, PKN, TMID, TOK, tk, topc));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tk, k, 16);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(topc, opc, 16);
    lc_sig_act_confirm(tk, TMID, TOK, conf);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(conf, m.u.act_ack.confirm, 8);
}

static void test_act_refusals(void)
{
    act_world();
    lc_sig_msg_t m;
    uint8_t k[16], opc[16], want[8];
    lc_sig_act_token_t t;

    memset(&t, 0, sizeof(t)); /* unknown: no secret, zero tag */
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_REFUSED, answer(&t, TMID, ID.pk, &m, k, opc));
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_NAK, m.type);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_UNKNOWN, m.u.act_nak.reason);
    TEST_ASSERT_EACH_EQUAL_HEX8(0, m.u.act_nak.tag, 8);

    t = fresh_token();
    t.expiry = NOW - 1u;
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_REFUSED, answer(&t, TMID, ID.pk, &m, k, opc));
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_EXPIRED, m.u.act_nak.reason);
    lc_sig_act_nak_tag(SECRET, TMID, TOK, LC_SIG_ACT_EXPIRED, want);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(want, m.u.act_nak.tag, 8);
    TEST_ASSERT_EACH_EQUAL_HEX8(0, k, 16); /* no keys leave a refusal */

    t = fresh_token();
    uint8_t tag[8];
    lc_sig_act_tag(SECRET, TMID, ID.pk, TOK, tag);
    tag[0] ^= 1; /* someone guessing without the real QR */
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_REFUSED, lc_sig_act_answer(&t, SKN, NOW, TMID, TOK, ID.pk, tag, NUM, &m, k, opc));
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_BAD_TAG, m.u.act_nak.reason);

    t = fresh_token(); /* used, and bound to another terminal */
    t.used = 1;
    t.bound_tmid = TMID2;
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_REFUSED, answer(&t, TMID, ID.pk, &m, k, opc));
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_USED, m.u.act_nak.reason);
}

/* Final review I2 (plan 5): the same terminal and key pair asking again gets
 * the same ACK; the same TMID with another key pair is refused as used. */
static void test_act_again_only_for_the_same_key_pair(void)
{
    act_world();
    lc_sig_act_token_t t = fresh_token();
    lc_sig_msg_t first, m;
    uint8_t k[16], opc[16], k2[16], opc2[16];
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_FRESH, answer(&t, TMID, ID.pk, &first, k, opc));
    t.used = 1;
    t.bound_tmid = TMID;
    memcpy(t.bound_k, k, 16);
    t.expiry = NOW - 1u; /* expiry no longer matters once used */
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_AGAIN, answer(&t, TMID, ID.pk, &m, k2, opc2));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&first, &m, sizeof(m));

    lc_sig_ident_t other;
    uint8_t r[32];
    memset(r, 0x99, 32);
    lc_sig_ident_new(&other, r);
    TEST_ASSERT_EQUAL_INT(LC_SIG_ACT_REFUSED, answer(&t, TMID, other.pk, &m, k2, opc2));
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_USED, m.u.act_nak.reason);
}

static void flat_act(lc_sig_sub_t *subs, unsigned n, uint32_t tmid, const uint8_t pk[32], lc_sig_msg_t *m,
                     uint32_t drop[2], unsigned *nd, int want)
{
    uint8_t tag[8];
    lc_sig_act_tag(SECRET, tmid, pk, TOK, tag);
    TEST_ASSERT_EQUAL_INT(want, lc_sig_flat_act(subs, n, SKN, NOW, tmid, TOK, pk, tag, m, drop, nd));
}

/* Re-activation: the subscriber's old terminal, and whatever the new TMID
 * was bound to, are dropped; the old binding of the TMID is cleared. */
static void test_flat_act_binds_and_names_the_terminals_to_drop(void)
{
    act_world();
    lc_sig_sub_t subs[2];
    lc_sig_msg_t m;
    uint32_t drop[2];
    unsigned nd;
    memset(subs, 0, sizeof(subs));
    memcpy(subs[0].number, NUM, LC_SIG_NUMBER_LEN);
    memcpy(subs[0].token_id, TOK, 8);
    memcpy(subs[0].token_secret, SECRET, 16);
    subs[0].token_expiry = NOW + 60u;
    lc_sig_number_to_bcd("+883160655501235", 16, subs[1].number); /* bound to TMID2 */
    subs[1].tmid = TMID2;
    subs[1].activated = 1;

    flat_act(subs, 2, TMID, ID.pk, &m, drop, &nd, LC_SIG_ACT_FRESH);
    TEST_ASSERT_EQUAL_UINT(0, nd); /* a first activation replaces nobody */
    TEST_ASSERT_TRUE(subs[0].activated && subs[0].token_used);
    TEST_ASSERT_EQUAL_HEX32(TMID, subs[0].tmid);
    TEST_ASSERT_EQUAL_UINT64(0, lc_sig_sqn_get(subs[0].sqn));

    flat_act(subs, 2, TMID, ID.pk, &m, drop, &nd, LC_SIG_ACT_AGAIN); /* the ACK was lost */
    TEST_ASSERT_EQUAL_UINT(0, nd);

    /* a new token for number 0, presented from TMID2 (bound to number 1) */
    memset(subs[0].token_id, 0xc0, 8);
    memcpy(TOK, subs[0].token_id, 8);
    subs[0].token_used = 0;
    flat_act(subs, 2, TMID2, ID.pk, &m, drop, &nd, LC_SIG_ACT_FRESH);
    TEST_ASSERT_EQUAL_UINT(2, nd);
    TEST_ASSERT_EQUAL_HEX32(TMID, drop[0]);  /* number 0's old terminal */
    TEST_ASSERT_EQUAL_HEX32(TMID2, drop[1]); /* TMID2's old binding (number 1) */
    TEST_ASSERT_EQUAL_HEX32(TMID2, subs[0].tmid);
    TEST_ASSERT_FALSE(subs[1].activated);
    TEST_ASSERT_EQUAL_HEX32(0, subs[1].tmid);
}

static void test_flat_av_steps_sqn_and_resync_takes_the_terminal_sqn(void)
{
    lc_sig_sub_t sub;
    lc_sig_av_t av;
    lc_milenage_t o;
    uint8_t rand[16], num[LC_SIG_NUMBER_LEN], got[6], ms[6], auts[14];
    memset(&sub, 0, sizeof(sub));
    lc_sig_number_to_bcd("+883160655501234", 16, sub.number);
    memcpy(sub.k, K, 16);
    memcpy(sub.opc, OPC, 16);
    sub.tmid = TMID;
    sub.activated = 1;
    lc_sig_sqn_put(sub.sqn, 7);
    memset(rand, 0x21, 16);

    TEST_ASSERT_EQUAL_UINT8(LC_SIG_AV_NOT_ACTIVATED, lc_sig_flat_av(&sub, 1, TMID2, rand, num, &av));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_AV_OK, lc_sig_flat_av(&sub, 1, TMID, rand, num, &av));
    TEST_ASSERT_EQUAL_UINT64(8, lc_sig_sqn_get(sub.sqn));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(sub.number, num, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, terminal_check(&av, got, &o));
    TEST_ASSERT_EQUAL_UINT64(8, lc_sig_sqn_get(got));

    lc_sig_sqn_put(ms, 900); /* the terminal is ahead: it answers with AUTS */
    terminal_auts(av.rand, ms, auts);
    uint8_t fresh[16];
    memset(fresh, 0x77, 16);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_AV_OK, lc_sig_flat_resync(&sub, 1, TMID, av.rand, auts, fresh, num, &av));
    TEST_ASSERT_EQUAL_UINT64(901, lc_sig_sqn_get(sub.sqn));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(fresh, av.rand, 16);
    TEST_ASSERT_EQUAL_INT(0, terminal_check(&av, got, &o));
    TEST_ASSERT_EQUAL_UINT64(901, lc_sig_sqn_get(got));

    auts[6] ^= 1;
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_AV_AUTH_FAILED, lc_sig_flat_resync(&sub, 1, TMID, rand, auts, fresh, num, &av));
    TEST_ASSERT_EQUAL_UINT64(901, lc_sig_sqn_get(sub.sqn)); /* untouched */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_av_make_passes_the_terminal_check);
    RUN_TEST(test_auts_gives_the_terminal_sqn_and_refuses_forgeries);
    RUN_TEST(test_act_fresh_ack_confirms_with_the_terminal_keys);
    RUN_TEST(test_act_refusals);
    RUN_TEST(test_act_again_only_for_the_same_key_pair);
    RUN_TEST(test_flat_act_binds_and_names_the_terminals_to_drop);
    RUN_TEST(test_flat_av_steps_sqn_and_resync_takes_the_terminal_sqn);
    return UNITY_END();
}
```

Append to `host-tests/CMakeLists.txt`:
```cmake
lc_test(test_sig_hss lc_sig)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build --target test_sig_hss 2>&1 | grep -E "error" | head -3`
Expected: `fatal error: lc_sig_hss.h: No such file or directory`.

- [ ] **Step 3: The header and the implementation**

Create `firmware/components/lc_sig/include/lc_sig_hss.h`:
```c
/* lc_sig_hss: the home side of activation and authentication (spec §3.2,
 * §4.3; network-core spec §4.2-4.3) as pure functions, for whoever holds the
 * keys: lc_core, and the single-process stand-ins (lcbench's HSS, the host
 * tests' fake core) through the flat-array helpers at the end. lc_sig_net
 * itself never calls them: it asks its core. Host-only, no OS calls. */
#ifndef LC_SIG_HSS_H
#define LC_SIG_HSS_H

#include "lc_sig_msg.h"

/* One authentication vector (TS 33.102 §6.3.2, AMF 8000). */
typedef struct {
    uint8_t rand[16], autn[16], xres[8], ck[16], ik[16];
} lc_sig_av_t;

/* AV answer status: lc_sig_net_av_done and the AV_RES status byte
 * (network-core spec §4.3, §6). */
typedef enum {
    LC_SIG_AV_OK = 0,
    LC_SIG_AV_NOT_ACTIVATED = 1,  /* no subscriber bound to the TMID */
    LC_SIG_AV_BOUND_ELSEWHERE = 2, /* reserved: the TMID's subscriber is bound to another terminal */
    LC_SIG_AV_DISABLED = 3,
    LC_SIG_AV_UNAVAILABLE = 4,    /* no answer possible now (store, core link): the terminal retries */
    LC_SIG_AV_AUTH_FAILED = 5     /* resync refused: AUTS did not verify */
} lc_sig_av_status_t;

/* A vector for sequence number sqn and the given RAND. 0 or -1. */
int lc_sig_av_make(const uint8_t k[16], const uint8_t opc[16], const uint8_t sqn[6], const uint8_t rand[16],
                   lc_sig_av_t *av);

/* The AUTS of AUTH_FAIL cause 2, answering a challenge with rand: 0 with the
 * terminal's SQN in sqn_ms, or -1 when MAC-S does not verify. */
int lc_sig_av_auts(const uint8_t k[16], const uint8_t opc[16], const uint8_t rand[16], const uint8_t auts[14],
                   uint8_t sqn_ms[6]);

/* An activation token as its holder sees it. */
typedef struct {
    int      known;         /* 0: no such token */
    int      used;
    uint32_t expiry;        /* unix s */
    uint8_t  secret[16];
    uint32_t bound_tmid;    /* used: the terminal its subscriber is bound to now (0 = none) */
    uint8_t  bound_k[16];   /* ...and that binding's K */
} lc_sig_act_token_t;

typedef enum { LC_SIG_ACT_REFUSED = 0, LC_SIG_ACT_FRESH = 1, LC_SIG_ACT_AGAIN = 2 } lc_sig_act_result_t;

/* Answer an ACT_REQ from tmid (spec §3.2 step 3). *out is the finished
 * ACT_ACK or ACT_NAK (an unknown token gets a zero tag). Returns
 *   LC_SIG_ACT_FRESH: bind the token's subscriber to tmid with k and opc, SQN 0;
 *   LC_SIG_ACT_AGAIN: the terminal already bound by this used token, with the
 *     same key pair, asking again (its ACT_ACK was lost): nothing changes;
 *   LC_SIG_ACT_REFUSED: an ACT_NAK (reasons 1-4); k and opc are zeroed. */
int lc_sig_act_answer(const lc_sig_act_token_t *tok, const uint8_t sk[32], uint32_t unix_now, uint32_t tmid,
                      const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8],
                      const uint8_t number[LC_SIG_NUMBER_LEN], lc_sig_msg_t *out, uint8_t k[16], uint8_t opc[16]);

/* ---- a single-process HSS over a flat array of records ---- */

/* One subscriber of lcbench's text-file HSS or of a test's fake core. */
typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint8_t  token_id[8], token_secret[16];
    uint32_t token_expiry; /* unix seconds */
    int      token_used;
    uint32_t tmid;         /* bound terminal; 0 = none */
    int      activated;
    uint8_t  k[16], opc[16], sqn[6];
} lc_sig_sub_t;

/* ACT_REQ over subs[0..n). On LC_SIG_ACT_FRESH the records changed (save
 * them) and drop[0..*ndrop) are the terminals whose sessions must be
 * dropped, as the core's LOC_CANCEL(reactivated) does: every terminal this
 * binding replaces (the subscriber's old one, and tmid itself if it was bound
 * before). */
int lc_sig_flat_act(lc_sig_sub_t *subs, unsigned n, const uint8_t sk[32], uint32_t unix_now, uint32_t tmid,
                    const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8], lc_sig_msg_t *out,
                    uint32_t drop[2], unsigned *ndrop);

/* A vector for the subscriber bound to tmid, with SQN + 1 (records changed
 * when LC_SIG_AV_OK: save them before the vector is used). */
uint8_t lc_sig_flat_av(lc_sig_sub_t *subs, unsigned n, uint32_t tmid, const uint8_t rand[16],
                       uint8_t number[LC_SIG_NUMBER_LEN], lc_sig_av_t *av);

/* AUTH_FAIL cause 2: SQN from AUTS (the challenge was rand), then a vector
 * with fresh_rand as lc_sig_flat_av. */
uint8_t lc_sig_flat_resync(lc_sig_sub_t *subs, unsigned n, uint32_t tmid, const uint8_t rand[16],
                           const uint8_t auts[14], const uint8_t fresh_rand[16], uint8_t number[LC_SIG_NUMBER_LEN],
                           lc_sig_av_t *av);

#endif
```

Create `firmware/components/lc_sig/lc_sig_hss.c`:
```c
#include "lc_sig_hss.h"

#include <string.h>

#include "lc_sig_keys.h"
#include "lc_sig_milenage.h"

static const uint8_t k_amf[2] = { 0x80, 0x00 };
static const uint8_t k_amf_resync[2] = { 0x00, 0x00 };

int lc_sig_av_make(const uint8_t k[16], const uint8_t opc[16], const uint8_t sqn[6], const uint8_t rand[16],
                   lc_sig_av_t *av)
{
    lc_milenage_t o;
    if (lc_milenage(k, opc, rand, sqn, k_amf, &o) != 0) return -1;
    memcpy(av->rand, rand, 16);
    for (int i = 0; i < 6; i++) av->autn[i] = (uint8_t)(sqn[i] ^ o.ak[i]);
    memcpy(av->autn + 6, k_amf, 2);
    memcpy(av->autn + 8, o.mac_a, 8);
    memcpy(av->xres, o.res, 8);
    memcpy(av->ck, o.ck, 16);
    memcpy(av->ik, o.ik, 16);
    return 0;
}

int lc_sig_av_auts(const uint8_t k[16], const uint8_t opc[16], const uint8_t rand[16], const uint8_t auts[14],
                   uint8_t sqn_ms[6])
{
    static const uint8_t zero[6] = { 0 };
    lc_milenage_t o;
    uint8_t ms[6];
    if (lc_milenage(k, opc, rand, zero, k_amf_resync, &o) != 0) return -1; /* AK* */
    for (int i = 0; i < 6; i++) ms[i] = (uint8_t)(auts[i] ^ o.ak_s[i]);
    if (lc_milenage(k, opc, rand, ms, k_amf_resync, &o) != 0) return -1;
    if (!lc_sig_ct_equal(o.mac_s, auts + 6, 8)) return -1;
    memcpy(sqn_ms, ms, 6);
    return 0;
}

int lc_sig_act_answer(const lc_sig_act_token_t *tok, const uint8_t sk[32], uint32_t unix_now, uint32_t tmid,
                      const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8],
                      const uint8_t number[LC_SIG_NUMBER_LEN], lc_sig_msg_t *out, uint8_t k[16], uint8_t opc[16])
{
    uint8_t reason = 0, t[8];
    memset(out, 0, sizeof(*out));
    /* A used token is refused unless it is still bound to this very terminal
     * (TMID, tag and key pair all the same): then its ACT_ACK was lost and the
     * terminal gave up, so it is answered again. */
    if (!tok->known) {
        reason = LC_SIG_ACT_UNKNOWN;
    } else if (tok->used && tok->bound_tmid != tmid) {
        reason = LC_SIG_ACT_USED;
    } else if (!tok->used && unix_now > tok->expiry) {
        reason = LC_SIG_ACT_EXPIRED;
    } else if (lc_sig_act_tag(tok->secret, tmid, pkt, token_id, t) != 0 || !lc_sig_ct_equal(t, tag, 8)) {
        reason = tok->used ? LC_SIG_ACT_USED : LC_SIG_ACT_BAD_TAG;
    }
    if (reason == 0 && lc_sig_act_keys(sk, pkt, tmid, token_id, k, opc) != 0) reason = LC_SIG_ACT_BAD_TAG;
    if (reason == 0 && tok->used && !lc_sig_ct_equal(k, tok->bound_k, 16)) reason = LC_SIG_ACT_USED; /* another key pair */
    if (reason != 0) {
        memset(k, 0, 16);
        memset(opc, 0, 16);
        out->type = LC_SIG_ACT_NAK;
        out->u.act_nak.reason = reason;
        if (tok->known) lc_sig_act_nak_tag(tok->secret, tmid, token_id, reason, out->u.act_nak.tag);
        return LC_SIG_ACT_REFUSED; /* no secret for an unknown token: zero tag (ruling in plan 5) */
    }
    out->type = LC_SIG_ACT_ACK;
    memcpy(out->u.act_ack.number, number, LC_SIG_NUMBER_LEN);
    lc_sig_act_confirm(k, tmid, token_id, out->u.act_ack.confirm);
    return tok->used ? LC_SIG_ACT_AGAIN : LC_SIG_ACT_FRESH;
}

static lc_sig_sub_t *bound(lc_sig_sub_t *subs, unsigned n, uint32_t tmid)
{
    for (unsigned i = 0; i < n; i++) {
        if (subs[i].activated && subs[i].tmid == tmid) return &subs[i];
    }
    return NULL;
}

int lc_sig_flat_act(lc_sig_sub_t *subs, unsigned n, const uint8_t sk[32], uint32_t unix_now, uint32_t tmid,
                    const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8], lc_sig_msg_t *out,
                    uint32_t drop[2], unsigned *ndrop)
{
    static const uint8_t none[LC_SIG_NUMBER_LEN] = { 0 };
    lc_sig_sub_t *sub = NULL;
    lc_sig_act_token_t tok;
    uint8_t k[16], opc[16];
    *ndrop = 0;
    memset(&tok, 0, sizeof(tok));
    for (unsigned i = 0; i < n && sub == NULL; i++) {
        if (memcmp(subs[i].token_id, token_id, 8) == 0) sub = &subs[i];
    }
    if (sub != NULL) {
        tok.known = 1;
        tok.used = sub->token_used;
        tok.expiry = sub->token_expiry;
        memcpy(tok.secret, sub->token_secret, 16);
        tok.bound_tmid = sub->activated ? sub->tmid : 0;
        memcpy(tok.bound_k, sub->k, 16);
    }
    int r = lc_sig_act_answer(&tok, sk, unix_now, tmid, token_id, pkt, tag, sub != NULL ? sub->number : none, out,
                              k, opc);
    if (r != LC_SIG_ACT_FRESH) return r;
    /* the subscriber is moving to a new terminal: the old one must not keep
     * serving calls or look registered (fix round 1, Review Focus 2) */
    if (sub->activated && sub->tmid != 0 && sub->tmid != tmid) drop[(*ndrop)++] = sub->tmid;
    /* ...and whatever tmid itself was bound to, its keys predate this activation */
    if (bound(subs, n, tmid) != NULL) drop[(*ndrop)++] = tmid;
    for (unsigned i = 0; i < n; i++) {
        if (subs[i].tmid == tmid) {
            subs[i].tmid = 0;
            subs[i].activated = 0;
        }
    }
    memcpy(sub->k, k, 16);
    memcpy(sub->opc, opc, 16);
    memset(sub->sqn, 0, 6);
    sub->tmid = tmid;
    sub->activated = 1;
    sub->token_used = 1;
    return r;
}

uint8_t lc_sig_flat_av(lc_sig_sub_t *subs, unsigned n, uint32_t tmid, const uint8_t rand[16],
                       uint8_t number[LC_SIG_NUMBER_LEN], lc_sig_av_t *av)
{
    lc_sig_sub_t *sub = bound(subs, n, tmid);
    if (sub == NULL) return LC_SIG_AV_NOT_ACTIVATED;
    uint8_t sqn[6];
    lc_sig_sqn_put(sqn, lc_sig_sqn_get(sub->sqn) + 1u);
    if (lc_sig_av_make(sub->k, sub->opc, sqn, rand, av) != 0) return LC_SIG_AV_UNAVAILABLE;
    memcpy(sub->sqn, sqn, 6);
    memcpy(number, sub->number, LC_SIG_NUMBER_LEN);
    return LC_SIG_AV_OK;
}

uint8_t lc_sig_flat_resync(lc_sig_sub_t *subs, unsigned n, uint32_t tmid, const uint8_t rand[16],
                           const uint8_t auts[14], const uint8_t fresh_rand[16], uint8_t number[LC_SIG_NUMBER_LEN],
                           lc_sig_av_t *av)
{
    lc_sig_sub_t *sub = bound(subs, n, tmid);
    uint8_t ms[6];
    if (sub == NULL) return LC_SIG_AV_NOT_ACTIVATED;
    if (lc_sig_av_auts(sub->k, sub->opc, rand, auts, ms) != 0) return LC_SIG_AV_AUTH_FAILED;
    memcpy(sub->sqn, ms, 6);
    return lc_sig_flat_av(subs, n, tmid, fresh_rand, number, av);
}
```

In `firmware/components/lc_sig/CMakeLists.txt`, replace:
```cmake
  add_library(lc_sig STATIC ${LC_SIG_SRCS} lc_sig_net.c crypto_openssl.c)
```
with:
```cmake
  add_library(lc_sig STATIC ${LC_SIG_SRCS} lc_sig_net.c lc_sig_hss.c crypto_openssl.c)
```
(host only: the firmware's `idf_component_register` list stays as it is.)

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
#include "lc_sig_chan.h"

typedef struct {
    uint8_t  number[LC_SIG_NUMBER_LEN];
    uint8_t  token_id[8], token_secret[16];
    uint32_t token_expiry; /* unix seconds */
    int      token_used;
    uint32_t tmid;         /* bound terminal; 0 = none */
    int      activated;
    uint8_t  k[16], opc[16], sqn[6];
} lc_sig_sub_t;
```
with:
```c
#include "lc_sig_chan.h"
#include "lc_sig_hss.h" /* lc_sig_sub_t */
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/firmware && cmake --build host-tests/build --target test_sig_hss 2>&1 | grep -E "error|warning"; host-tests/build/test_sig_hss | tail -3`
Expected: no compiler output, then `7 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N+1` (34 when validated on `chan-list` at `943a093`, N = 33).

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/firmware
git add firmware/components/lc_sig/include/lc_sig_hss.h firmware/components/lc_sig/lc_sig_hss.c \
        firmware/components/lc_sig/CMakeLists.txt firmware/components/lc_sig/include/lc_sig_net.h \
        host-tests/test_sig_hss.c host-tests/CMakeLists.txt
git commit -m "lc_sig: the home side of activation and AKA as pure functions (lc_sig_hss)

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 9: `lc_sig_net` asks its core (spec §4.3), and the tests move to a fake core

**Repo:** `opencell-firmware`, branch `net-core`, at `/home/devin/Documents/opencell/firmware`. **Starts:** after Task 8.

`lc_sig_net` stops holding K, OPc, SQN and the network key. Activation, vectors and resync become questions (`act_req`, `av_req`, `resync_req`) answered by `lc_sig_net_act_done` / `lc_sig_net_av_done`; a session learns its number from the vector's answer; a call to a number registered on this cell is switched here, anything else goes out as `LC_SIG_NET_MO`. The plan-5 fixes stay: an unauthenticated REG_REQ never touches a registered session until AUTH_RSP matches, and pending and confirmed vectors stay separate.

The tests that ran `lc_sig_net` with their own HSS callbacks move to `host-tests/sig_fake_core.h`, a synchronous fake core over the same flat subscriber array (spec §4.3: "`test_sig_e2e.c`, `test_sig_local.c` and `test_term_sim.c` move to a synchronous fake core"). lcbench becomes its own single-process core.

**Porting `chan-list` (its plan's "Before you start": whichever lands second ports the other's changes).** `net-core` lands second, so everything `chan-list` did to `lc_sig_net` stays: its plan's four changes (`have_list`/`list` in `lc_sig_net_t` and `lc_sig_net_set_chan_list`, `queue_chan_list` after REG_ACK, cause 4 in `lc_sig_net_service_req`) and what its fix rounds added (as of `943a093`: `cl_ver`/`cl_again` in the session, `drop_chan_list` on REG_REQ, the re-push of an expired CHAN_LIST in `lc_sig_net_tick`). The edits below are anchored on lines `chan-list` doesn't touch, so they apply around its code; none of them removes a `chan-list` line. `chan-list`'s own tests in `test_sig_e2e.c` (the CHAN_LIST pushes) run on the fake core with the rest and must still pass. If a "replace" text below is not there verbatim (`chan-list` changed after `943a093`, the commit this task was validated on), find the same code and make the same change; never drop a `chan-list` line to make a replacement fit.

**Files:**
- Create: `host-tests/sig_fake_core.h`
- Modify: `host-tests/test_sig_e2e.c`, `host-tests/test_sig_local.c`, `host-tests/test_term_sim.c`
- Modify: `firmware/components/lc_sig/include/lc_sig_net.h`, `firmware/components/lc_sig/lc_sig_net.c`, `tools/lcbench/lcb_net.c`

**Interfaces:**
- Consumes: Task 8's `lc_sig_av_t`, statuses, `lc_sig_flat_act/av/resync`; `chan-list`'s channel-list code in `lc_sig_net` (kept as it is).
- Produces (`lc_sig_net.h`):
  ```c
  typedef struct {
      void *ctx;
      void (*act_req)(void *ctx, uint32_t tmid, const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8]);
      void (*av_req)(void *ctx, uint32_t tmid);
      void (*resync_req)(void *ctx, uint32_t tmid, const uint8_t rand[16], const uint8_t auts[14]);
      void (*registered)(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                         const uint8_t res[8]);
      void (*unregistered)(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN]);
      int  (*send)(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n);
      void (*channel)(void *ctx, uint32_t tmid, int on);
      void (*call)(void *ctx, const lc_sig_net_call_ev_t *ev);
      void (*log)(void *ctx, const char *line);
  } lc_sig_net_io_t;
  typedef struct { uint8_t mode; uint16_t period_s; } lc_sig_net_cfg_t;
  #define LC_SIG_NET_ASK_US 3000000u
  int lc_sig_net_act_done(lc_sig_net_t *n, uint32_t tmid, const lc_sig_msg_t *msg, uint64_t now_us);
  int lc_sig_net_av_done(lc_sig_net_t *n, uint32_t tmid, uint8_t status, const uint8_t number[LC_SIG_NUMBER_LEN],
                         const lc_sig_av_t *av, uint64_t now_us);
  int lc_sig_net_drop(lc_sig_net_t *n, uint32_t tmid, uint8_t cause, uint64_t now_us);
  ```
  Session fields added: `act_wait`, `av_wait`, `act_at`, `av_at`, `p_number`, `number`. Removed from io: `by_token`, `by_tmid`, `by_number`, `unbind`, `save`, `random`, `unix_now`; from cfg: `key_id`, `sk`.
- Produces (`sig_fake_core.h`, test-only): `fc_t FC` with `saves`, `acts`, `avs`, `resyncs`, `hold`, `down`, `held`; `fc_init(net, subs, &nsubs, sk, unix_s, clock_fn)`; io functions `fc_act_req`, `fc_av_req`, `fc_resync_req`; `fc_answer()`.

- [ ] **Step 1: The fake core, and the tests on it**

Create `host-tests/sig_fake_core.h`:
```c
/* A synchronous fake core for lc_sig_net tests (network-core spec §4.3): an
 * HSS over the test's flat subscriber array (lc_sig_flat_*), answering
 * lc_sig_net's questions from inside the call, as a single-process core may.
 * With FC.hold set, a question waits for fc_answer() instead (an answer that
 * comes later); with FC.down set, nothing is answered (no core link).
 * A fresh activation drops the sessions it replaces, as the core's
 * LOC_CANCEL(reactivated) makes a cell do. */
#ifndef SIG_FAKE_CORE_H
#define SIG_FAKE_CORE_H

#include <string.h>

#include "lc_sig_net.h"

typedef struct {
    lc_sig_net_t *net;
    lc_sig_sub_t *subs;
    int          *nsubs;
    uint8_t       sk[32];
    uint32_t      unix_s;
    uint64_t    (*now)(void);
    uint32_t      rng;
    int           saves;              /* how often the records changed (an HSS save) */
    int           acts, avs, resyncs; /* questions asked */
    int           hold, down;
    int           held;               /* the question held: 0 none, 1 act, 2 av, 3 resync */
    uint32_t      h_tmid;
    uint8_t       h_token[8], h_pkt[32], h_tag[8], h_rand[16], h_auts[14];
} fc_t;

static fc_t FC;

static inline void fc_init(lc_sig_net_t *net, lc_sig_sub_t *subs, int *nsubs, const uint8_t sk[32],
                           uint32_t unix_s, uint64_t (*now)(void))
{
    memset(&FC, 0, sizeof(FC));
    FC.net = net;
    FC.subs = subs;
    FC.nsubs = nsubs;
    memcpy(FC.sk, sk, 32);
    FC.unix_s = unix_s;
    FC.now = now;
    FC.rng = 99;
}

static inline void fc_rand(uint8_t out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)((FC.rng = FC.rng * 1103515245u + 12345u) >> 16);
}

static inline void fc_do_act(uint32_t tmid, const uint8_t token[8], const uint8_t pkt[32], const uint8_t tag[8])
{
    lc_sig_msg_t out;
    uint32_t drop[2];
    unsigned nd = 0;
    int r = lc_sig_flat_act(FC.subs, (unsigned)*FC.nsubs, FC.sk, FC.unix_s, tmid, token, pkt, tag, &out, drop, &nd);
    if (r == LC_SIG_ACT_FRESH) FC.saves++;
    for (unsigned i = 0; i < nd; i++) lc_sig_net_drop(FC.net, drop[i], LC_SIG_CAUSE_NET_FAILURE, FC.now());
    lc_sig_net_act_done(FC.net, tmid, &out, FC.now());
}

static inline void fc_do_av(uint32_t tmid, const uint8_t *rand, const uint8_t *auts)
{
    uint8_t fresh[16], number[LC_SIG_NUMBER_LEN];
    lc_sig_av_t av;
    memset(number, 0, sizeof(number));
    memset(&av, 0, sizeof(av));
    fc_rand(fresh);
    uint8_t st = auts == NULL ? lc_sig_flat_av(FC.subs, (unsigned)*FC.nsubs, tmid, fresh, number, &av)
                              : lc_sig_flat_resync(FC.subs, (unsigned)*FC.nsubs, tmid, rand, auts, fresh, number, &av);
    if (st == LC_SIG_AV_OK) FC.saves++;
    lc_sig_net_av_done(FC.net, tmid, st, number, &av, FC.now());
}

static inline void fc_act_req(void *c, uint32_t tmid, const uint8_t token[8], const uint8_t pkt[32],
                              const uint8_t tag[8])
{
    (void)c;
    FC.acts++;
    if (FC.down) return;
    if (FC.hold) {
        FC.held = 1;
        FC.h_tmid = tmid;
        memcpy(FC.h_token, token, 8);
        memcpy(FC.h_pkt, pkt, 32);
        memcpy(FC.h_tag, tag, 8);
        return;
    }
    fc_do_act(tmid, token, pkt, tag);
}

static inline void fc_av_req(void *c, uint32_t tmid)
{
    (void)c;
    FC.avs++;
    if (FC.down) return;
    if (FC.hold) {
        FC.held = 2;
        FC.h_tmid = tmid;
        return;
    }
    fc_do_av(tmid, NULL, NULL);
}

static inline void fc_resync_req(void *c, uint32_t tmid, const uint8_t rand[16], const uint8_t auts[14])
{
    (void)c;
    FC.resyncs++;
    if (FC.down) return;
    if (FC.hold) {
        FC.held = 3;
        FC.h_tmid = tmid;
        memcpy(FC.h_rand, rand, 16);
        memcpy(FC.h_auts, auts, 14);
        return;
    }
    fc_do_av(tmid, rand, auts);
}

/* Answer the held question now. */
static inline void fc_answer(void)
{
    int h = FC.held;
    FC.held = 0;
    if (h == 1) fc_do_act(FC.h_tmid, FC.h_token, FC.h_pkt, FC.h_tag);
    if (h == 2) fc_do_av(FC.h_tmid, NULL, NULL);
    if (h == 3) fc_do_av(FC.h_tmid, FC.h_rand, FC.h_auts);
}

#endif
```

In `host-tests/test_sig_e2e.c`, replace:
```c
#include "lc_sig_term.h"

void setUp(void) {}
```
with:
```c
#include "lc_sig_term.h"
#include "sig_fake_core.h"

void setUp(void) {}
```

In `host-tests/test_sig_e2e.c`, replace:
```c
static int nsubs, saves;
static uint64_t now;
```
with:
```c
static int nsubs;
static uint64_t now;
static uint64_t clock_now(void) { return now; }
```

In `host-tests/test_sig_e2e.c`, replace:
```c
/* HSS */
static lc_sig_sub_t *by_token(void *c, const uint8_t tok[8])
{
    (void)c;
    for (int i = 0; i < nsubs; i++) if (memcmp(subs[i].token_id, tok, 8) == 0) return &subs[i];
    return NULL;
}
static lc_sig_sub_t *by_tmid(void *c, uint32_t tmid)
{
    (void)c;
    for (int i = 0; i < nsubs; i++) if (subs[i].activated && subs[i].tmid == tmid) return &subs[i];
    return NULL;
}
static lc_sig_sub_t *by_number(void *c, const uint8_t num[LC_SIG_NUMBER_LEN])
{
    (void)c;
    for (int i = 0; i < nsubs; i++) if (memcmp(subs[i].number, num, LC_SIG_NUMBER_LEN) == 0) return &subs[i];
    return NULL;
}
static void unbind(void *c, uint32_t tmid)
{
    (void)c;
    for (int i = 0; i < nsubs; i++) if (subs[i].tmid == tmid) { subs[i].tmid = 0; subs[i].activated = 0; }
}
static void hss_save(void *c) { (void)c; saves++; }
```
with:
```c
/* The HSS is the fake core's (sig_fake_core.h), over subs[0..nsubs). */
```

In `host-tests/test_sig_e2e.c`, replace:
```c
static void net_random(void *c, uint8_t *out, size_t n) { (void)c; for (size_t i = 0; i < n; i++) out[i] = (uint8_t)rnd(); }
static uint32_t net_unix(void *c) { (void)c; return unix_s; }
static const lc_sig_net_io_t net_io = { NULL, by_token, by_tmid, by_number, unbind, hss_save, net_send,
                                        net_channel, net_call, net_random, net_unix, NULL };
```
with:
```c
static const lc_sig_net_io_t net_io = { NULL, fc_act_req, fc_av_req, fc_resync_req, NULL, NULL, net_send,
                                        net_channel, net_call, NULL };
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    nsubs = saves = ncalls = nevs = 0;
```
with:
```c
    nsubs = ncalls = nevs = 0;
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    lc_sig_net_cfg_t cfg = { 1, { 0 }, mode, period_s };
    memcpy(cfg.sk, SKN, 32);
    lc_sig_net_init(&N, &net_io, &cfg);
```
with:
```c
    lc_sig_net_cfg_t cfg = { mode, period_s };
    lc_sig_net_init(&N, &net_io, &cfg);
    fc_init(&N, subs, &nsubs, SKN, unix_s, clock_now);
```

`chan-list`'s fix round 2 added `net_restart()`, which starts a second `lc_sig_net` on the same subscribers.

In `host-tests/test_sig_e2e.c`, replace:
```c
    lc_sig_net_cfg_t cfg = { 1, { 0 }, mode, 1800 };
    memcpy(cfg.sk, SKN, 32);
    lc_sig_net_init(&N, &net_io, &cfg);
```
with:
```c
    lc_sig_net_cfg_t cfg = { mode, 1800 };
    lc_sig_net_init(&N, &net_io, &cfg); /* the fake core, and its subscribers, stay */
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    for (uint32_t i = 0; i < 4; i++) {
        now += FRAME;
        lc_sig_net_rx(&N, 0xAAAA0000u + i, dummy, 1, now); /* just enough to touch a session */
```
with:
```c
    for (uint32_t i = 0; i < LC_SIG_NET_TERMS; i++) {
        now += FRAME;
        lc_sig_net_rx(&N, 0xAAAA0000u + i, dummy, 1, now); /* just enough to touch a session */
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    TEST_ASSERT_EQUAL_INT(2, saves);
```
with:
```c
    TEST_ASSERT_EQUAL_INT(2, FC.saves);
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    int saves_before = saves;
```
with:
```c
    int saves_before = FC.saves;
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    TEST_ASSERT_EQUAL_INT(saves_before, saves);               /* no extra HSS save */
```
with:
```c
    TEST_ASSERT_EQUAL_INT(saves_before, FC.saves);            /* no extra HSS save */
```

The questions and answers themselves get tests too.

In `host-tests/test_sig_e2e.c`, replace:
```c
int main(void)
{
```
with:
```c
/* Network-core spec §4.3: the core may answer later. While a question
 * stands, the terminal's retransmits don't ask it again; the answer, when it
 * comes, completes activation and then registration as before. */
static void test_core_answers_later_and_is_asked_once(void)
{
    world(LC_SIG_MODE_PART15, 1800);
    FC.hold = 1;
    activate();
    run_ms(2500); /* the terminal retransmits ACT_REQ meanwhile */
    TEST_ASSERT_EQUAL_INT(1, FC.acts);
    TEST_ASSERT_EQUAL_INT(1, FC.held);
    TEST_ASSERT_FALSE(has_event(LC_SIG_EV_ACTIVATED));
    fc_answer();
    run_ms(2500);
    TEST_ASSERT_TRUE(has_event(LC_SIG_EV_ACTIVATED));
    TEST_ASSERT_EQUAL_INT(1, FC.avs); /* registration asked for one vector, once */
    TEST_ASSERT_EQUAL_INT(2, FC.held);
    fc_answer();
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, lc_sig_term_state(&T));
    TEST_ASSERT_EQUAL_INT(1, FC.avs);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(subs[0].sqn, ID.sqn, 6);
}

/* No core (backhaul down): a terminal registering again gets no answer and
 * backs off; its old registration stands. Once the core is back, the retry
 * registers it. */
static void test_core_down_registration_waits_and_recovers(void)
{
    registered_world(LC_SIG_MODE_PART15);
    FC.down = 1;
    lc_sig_term_init(&T, &term_io, &ID, TMID, now); /* the terminal reboots: it registers again */
    run_ms(8000);
    TEST_ASSERT_TRUE(has_event(LC_SIG_EV_REG_FAILED));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&N, TMID)); /* an unanswered REG_REQ deregisters nobody */
    FC.down = 0;
    nevs = 0;
    run_ms(40000); /* the terminal retries after 30 s */
    TEST_ASSERT_TRUE(has_event(LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, lc_sig_term_state(&T));
}

/* An answer nobody asked for is refused; a refusal becomes REG_REJ. */
static void test_unasked_answers_ignored_and_refusals_rejected(void)
{
    registered_world(LC_SIG_MODE_PART15);
    lc_sig_msg_t ack;
    lc_sig_av_t av;
    memset(&ack, 0, sizeof(ack));
    memset(&av, 0, sizeof(av));
    ack.type = LC_SIG_ACT_ACK;
    TEST_ASSERT_EQUAL_INT(-1, lc_sig_net_act_done(&N, TMID, &ack, now));
    TEST_ASSERT_EQUAL_INT(-1, lc_sig_net_av_done(&N, TMID, LC_SIG_AV_OK, subs[0].number, &av, now));
    TEST_ASSERT_EQUAL_INT(-1, lc_sig_net_av_done(&N, 0x0badcafeu, LC_SIG_AV_OK, subs[0].number, &av, now));

    memset(&dlq, 0, sizeof(dlq));
    lc_sig_net_link(&N, TMID2, 1, now);
    uint8_t dummy[1] = { 0 };
    lc_sig_net_rx(&N, TMID2, dummy, 1, now); /* a session for a terminal nobody activated */
    FC.hold = 1;
    inject_forged_reg_req(1, now);           /* on TMID: asks the core */
    TEST_ASSERT_EQUAL_INT(2, FC.held);
    FC.h_tmid = TMID2;                        /* ...and the core answers for TMID2: not asked */
    fc_answer();
    TEST_ASSERT_EQUAL_INT(0, dlq.count);

    FC.hold = 0;
    subs[0].activated = 0; /* the core no longer knows TMID */
    inject_forged_reg_req(2, now);
    TEST_ASSERT_EQUAL_INT(2, FC.avs);        /* the first question still stands: not asked again */
    now += LC_SIG_NET_ASK_US;
    inject_forged_reg_req(3, now);
    TEST_ASSERT_EQUAL_INT(3, FC.avs);
    uint8_t p[LC_SIG_LINK_MAX], n;
    TEST_ASSERT_EQUAL_INT(0, qpop(&dlq, p, &n));
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_REG_REJ, p[2]);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_REG_NOT_ACTIVATED, p[5]);
    TEST_ASSERT_TRUE(lc_sig_net_registered(&N, TMID)); /* a REG_REJ deregisters nobody either */
}

/* LOC_CANCEL: the cell drops a registration; a call it holds ends with the
 * given cause, and the terminal can't call until it registers again. */
static void test_drop_ends_the_call_and_deregisters(void)
{
    registered_world(LC_SIG_MODE_PART15);
    uint32_t cid = connected_mo_call();
    nevs = 0;
    TEST_ASSERT_EQUAL_INT(0, lc_sig_net_drop(&N, TMID, LC_SIG_CAUSE_LINK_LOST, now));
    TEST_ASSERT_EQUAL_INT(-1, lc_sig_net_drop(&N, TMID2, LC_SIG_CAUSE_LINK_LOST, now));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&N, TMID));
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_LINK_LOST, ended_cause());
    TEST_ASSERT_TRUE(net_ended(cid));
    ncalls = 0;
    command("\x02+883160655500100", 17);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(0, ncalls); /* refused before the switch */
}

static int regs, unregs;
static uint8_t reg_number[LC_SIG_NUMBER_LEN], reg_res[8];
static void on_registered(void *c, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                          const uint8_t res[8])
{
    (void)c;
    (void)tmid;
    (void)rand;
    regs++;
    memcpy(reg_number, number, LC_SIG_NUMBER_LEN);
    memcpy(reg_res, res, 8);
}
static void on_unregistered(void *c, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    (void)c;
    (void)tmid;
    (void)number;
    unregs++;
}

/* The cell learns of every registration (for LOC_UPDATE: number, RAND, RES)
 * and of every one that lapses (LOC_PURGE). */
static void test_registered_and_lapsed_are_reported(void)
{
    world(LC_SIG_MODE_PART15, 60);
    N.io.registered = on_registered;
    N.io.unregistered = on_unregistered;
    regs = unregs = 0;
    activate();
    run_ms(10000);
    TEST_ASSERT_EQUAL_INT(1, regs);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(subs[0].number, reg_number, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(net_sess(TMID)->p_xres, reg_res, 8); /* the RES that matched */
    now += 121000000u; /* past 2 x 60 s with no re-registration heard */
    lc_sig_net_tick(&N, now);
    TEST_ASSERT_EQUAL_INT(1, unregs);
    TEST_ASSERT_FALSE(lc_sig_net_registered(&N, TMID));
}

int main(void)
{
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    RUN_TEST(test_reactivation_elsewhere_releases_old_terminals_call);
```
with:
```c
    RUN_TEST(test_reactivation_elsewhere_releases_old_terminals_call);
    RUN_TEST(test_core_answers_later_and_is_asked_once);
    RUN_TEST(test_core_down_registration_waits_and_recovers);
    RUN_TEST(test_unasked_answers_ignored_and_refusals_rejected);
    RUN_TEST(test_drop_ends_the_call_and_deregisters);
    RUN_TEST(test_registered_and_lapsed_are_reported);
```

In `host-tests/test_sig_local.c`, replace:
```c
#include "lc_sig_term.h"

void setUp(void) {}
```
with:
```c
#include "lc_sig_term.h"
#include "sig_fake_core.h"

void setUp(void) {}
```

In `host-tests/test_sig_local.c`, replace:
```c
static lc_sig_sub_t subs[2];
```
with:
```c
static lc_sig_sub_t subs[2];
static int nsubs = 2;
```

In `host-tests/test_sig_local.c`, replace:
```c
static uint64_t now;
static uint32_t rng = 7;
```
with:
```c
static uint64_t now;
static uint64_t clock_now(void) { return now; }
```

In `host-tests/test_sig_local.c`, replace:
```c
/* network io: a two-subscriber HSS */
static lc_sig_sub_t *h_token(void *c, const uint8_t t[8])
{
    (void)c;
    for (int i = 0; i < 2; i++) if (memcmp(subs[i].token_id, t, 8) == 0) return &subs[i];
    return NULL;
}
static lc_sig_sub_t *h_tmid(void *c, uint32_t tmid)
{
    (void)c;
    for (int i = 0; i < 2; i++) if (subs[i].activated && subs[i].tmid == tmid) return &subs[i];
    return NULL;
}
static lc_sig_sub_t *h_number(void *c, const uint8_t num[LC_SIG_NUMBER_LEN])
{
    (void)c;
    for (int i = 0; i < 2; i++) if (memcmp(subs[i].number, num, LC_SIG_NUMBER_LEN) == 0) return &subs[i];
    return NULL;
}
static int n_send
```
with:
```c
/* network io: a two-subscriber fake core */
static int n_send
```

In `host-tests/test_sig_local.c`, replace:
```c
static void n_call(void *c, const lc_sig_net_call_ev_t *e) { (void)c; calls[ncalls++ % 16] = *e; }
static void n_random(void *c, uint8_t *o, size_t n) { (void)c; for (size_t i = 0; i < n; i++) o[i] = (uint8_t)((rng = rng * 1103515245u + 12345u) >> 16); }
static uint32_t n_unix(void *c) { (void)c; return 1790000000u; }
static const lc_sig_net_io_t net_io = { NULL, h_token, h_tmid, h_number, NULL, NULL, n_send,
                                        NULL, n_call, n_random, n_unix, NULL };
```
with:
```c
/* A call the network can't switch itself goes to the far end, where no
 * number is reachable in this test: the far end releases it at once. */
static void n_call(void *c, const lc_sig_net_call_ev_t *e)
{
    (void)c;
    calls[ncalls++ % 16] = *e;
    if (e->what == LC_SIG_NET_MO) lc_sig_net_peer_release(&N, e->call_id, LC_SIG_CAUSE_UNREACHABLE, now);
}
static const lc_sig_net_io_t net_io = { NULL, fc_act_req, fc_av_req, fc_resync_req, NULL, NULL, n_send,
                                        NULL, n_call, NULL };
```

In `host-tests/test_sig_local.c`, replace:
```c
    lc_sig_net_cfg_t cfg = { 1, { 0 }, mode, 1800 };
    memcpy(cfg.sk, sk, 32);
    lc_sig_net_init(&N, &net_io, &cfg);
```
with:
```c
    lc_sig_net_cfg_t cfg = { mode, 1800 };
    lc_sig_net_init(&N, &net_io, &cfg);
    fc_init(&N, subs, &nsubs, sk, 1790000000u, clock_now);
```

In `host-tests/test_sig_local.c`, replace:
```c
    subs[1].activated = 0; /* B's subscription no longer bound: unreachable */
```
with:
```c
    lc_sig_net_drop(&N, B.tmid, LC_SIG_CAUSE_NET_FAILURE, now); /* the core cancelled B here: unreachable */
```

In `host-tests/test_term_sim.c`, replace:
```c
#include "lcb_net.h"

void setUp(void) {}
```
with:
```c
#include "lcb_net.h"
#include "sig_fake_core.h"

void setUp(void) {}
```

In `host-tests/test_term_sim.c`, replace:
```c
static lc_sig_sub_t ssub;
```
with:
```c
static lc_sig_sub_t ssub;
static int nssub = 1;
```

In `host-tests/test_term_sim.c`, replace:
```c
static lc_sig_sub_t *s_by_token(void *c, const uint8_t t[8]) { (void)c; return memcmp(ssub.token_id, t, 8) == 0 ? &ssub : NULL; }
static lc_sig_sub_t *s_by_tmid(void *c, uint32_t tmid) { (void)c; return ssub.activated && ssub.tmid == tmid ? &ssub : NULL; }
static lc_sig_sub_t *s_by_number(void *c, const uint8_t n[LC_SIG_NUMBER_LEN]) { (void)c; return memcmp(ssub.number, n, LC_SIG_NUMBER_LEN) == 0 ? &ssub : NULL; }
static void s_unbind(void *c, uint32_t tmid) { (void)c; if (ssub.tmid == tmid) { ssub.tmid = 0; ssub.activated = 0; } }
static int s_send
```
with:
```c
static int s_send
```

In `host-tests/test_term_sim.c`, replace:
```c
static void s_random(void *c, uint8_t *o, size_t n) { (void)c; for (size_t i = 0; i < n; i++) o[i] = (uint8_t)(i * 37u + 11u); }
static uint32_t s_unix(void *c) { (void)c; return 1790000000u; }
static const lc_sig_net_io_t snet_io = { NULL, s_by_token, s_by_tmid, s_by_number, s_unbind, NULL, s_send,
                                         s_channel, s_call, s_random, s_unix, NULL };
```
with:
```c
static const lc_sig_net_io_t snet_io = { NULL, fc_act_req, fc_av_req, fc_resync_req, NULL, NULL, s_send,
                                         s_channel, s_call, NULL };
```

In `host-tests/test_term_sim.c`, replace:
```c
    lc_sig_net_cfg_t cfg = { 1, { 0 }, LC_SIG_MODE_PART15, 1800 };
    memcpy(cfg.sk, skn, 32);
    lc_sig_net_init(&snet, &snet_io, &cfg);
```
with:
```c
    lc_sig_net_cfg_t cfg = { LC_SIG_MODE_PART15, 1800 };
    lc_sig_net_init(&snet, &snet_io, &cfg);
    fc_init(&snet, &ssub, &nssub, skn, 1790000000u, sim_now);
```

- [ ] **Step 2: Run them to see them fail**

Run: `cd /home/devin/Documents/opencell/firmware && cmake --build host-tests/build --target test_sig_e2e 2>&1 | grep -E "error" | head -4`
Expected: errors such as `implicit declaration of function 'lc_sig_net_drop'` and `initialization of 'lc_sig_sub_t * (*)(void *, const uint8_t *)' … from incompatible pointer type` (the io struct still has the HSS callbacks).

- [ ] **Step 3: The header**

`lc_sig_net.h` gets its new io, its smaller cfg, the session fields for the open questions and the number, and the three answer functions. Everything `chan-list` added to it (`have_list`, `list`, `lc_sig_net_set_chan_list`) stays as it is.

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
/* Network role (spec §2, §3.2, §4.3, §5): the laptop stand-in now, the Pi
 * later. Host-only. Subscribers live in the caller's HSS (callbacks); one
 * session per terminal. */
```
with:
```c
/* Network role (spec §2, §3.2, §4.3, §5): the cell's half of lc_sig, one
 * session per terminal. Host-only.
 *
 * It holds no subscriber keys (network-core spec §4.3). Activation, vectors
 * and resync are asked of the core through io (act_req, av_req, resync_req)
 * and answered later with lc_sig_net_act_done / lc_sig_net_av_done, or from
 * inside the call by a single-process core. A session learns its number from
 * the vector's answer, and calls to a number registered here are switched
 * here; every other call goes out as LC_SIG_NET_MO. */
```

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
#include "lc_sig_hss.h" /* lc_sig_sub_t */
```
with:
```c
#include "lc_sig_hss.h" /* lc_sig_av_t, lc_sig_av_status_t */
```

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
typedef struct {
    void *ctx;
    lc_sig_sub_t *(*by_token)(void *ctx, const uint8_t token_id[8]);
    lc_sig_sub_t *(*by_tmid)(void *ctx, uint32_t tmid);       /* activated and bound to tmid */
    lc_sig_sub_t *(*by_number)(void *ctx, const uint8_t number[LC_SIG_NUMBER_LEN]);
    void (*unbind)(void *ctx, uint32_t tmid);                 /* clear any subscriber bound to tmid */
    void (*save)(void *ctx);
    int  (*send)(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n); /* one DL payload: 0 queued */
    void (*channel)(void *ctx, uint32_t tmid, int on);        /* on: page and grant; off: release */
    void (*call)(void *ctx, const lc_sig_net_call_ev_t *ev);
    void (*random)(void *ctx, uint8_t *out, size_t n);
    uint32_t (*unix_now)(void *ctx);
    void (*log)(void *ctx, const char *line);
} lc_sig_net_io_t;

typedef struct {
    uint16_t key_id;
    uint8_t  sk[32];   /* network X25519 private key */
    uint8_t  mode;     /* lc_sig_mode_t */
    uint16_t period_s; /* re-registration period */
} lc_sig_net_cfg_t;

#define LC_SIG_NET_TERMS 4u
```
with:
```c
typedef struct {
    void *ctx;
    /* questions for the core: answered with lc_sig_net_act_done / _av_done */
    void (*act_req)(void *ctx, uint32_t tmid, const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8]);
    void (*av_req)(void *ctx, uint32_t tmid);
    void (*resync_req)(void *ctx, uint32_t tmid, const uint8_t rand[16], const uint8_t auts[14]);
    /* AUTH_RSP matched (the cell sends LOC_UPDATE), and a registration lapsed (LOC_PURGE) */
    void (*registered)(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                       const uint8_t res[8]);
    void (*unregistered)(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN]);
    int  (*send)(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n); /* one DL payload: 0 queued */
    void (*channel)(void *ctx, uint32_t tmid, int on);        /* on: page and grant; off: release */
    void (*call)(void *ctx, const lc_sig_net_call_ev_t *ev);
    void (*log)(void *ctx, const char *line);
} lc_sig_net_io_t;

typedef struct {
    uint8_t  mode;     /* lc_sig_mode_t */
    uint16_t period_s; /* re-registration period */
} lc_sig_net_cfg_t;

#define LC_SIG_NET_TERMS 4u
#define LC_SIG_NET_ASK_US 3000000u /* a question to the core stands this long; a later request asks again */
```

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
    uint64_t     last_sig;
    int          auth_pending;
    uint8_t      rand[16], ck[16], ik[16];                  /* the last confirmed (registered) vector */
    uint8_t      p_rand[16], p_xres[8], p_ck[16], p_ik[16]; /* pending vector: not believed until AUTH_RSP matches */
    int          registered;
```
with:
```c
    uint64_t     last_sig;
    int          act_wait, av_wait;                         /* a question to the core is open... */
    uint64_t     act_at, av_at;                             /* ...since then */
    int          auth_pending;
    uint8_t      rand[16], ck[16], ik[16];                  /* the last confirmed (registered) vector */
    uint8_t      p_rand[16], p_xres[8], p_ck[16], p_ik[16]; /* pending vector: not believed until AUTH_RSP matches */
    uint8_t      p_number[LC_SIG_NUMBER_LEN];               /* ...and the number it came with */
    int          registered;
    uint8_t      number[LC_SIG_NUMBER_LEN];                 /* registered: the subscriber's number */
```

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
void lc_sig_net_tick(lc_sig_net_t *n, uint64_t now_us);
```
with:
```c
void lc_sig_net_tick(lc_sig_net_t *n, uint64_t now_us);
/* The core's answer to act_req: msg is the finished ACT_ACK or ACT_NAK. 0, or
 * -1 when tmid has no open activation question (a late or unasked answer). */
int  lc_sig_net_act_done(lc_sig_net_t *n, uint32_t tmid, const lc_sig_msg_t *msg, uint64_t now_us);
/* The core's answer to av_req or resync_req (av and number only for
 * LC_SIG_AV_OK). 0, or -1 when tmid has no open vector question. */
int  lc_sig_net_av_done(lc_sig_net_t *n, uint32_t tmid, uint8_t status, const uint8_t number[LC_SIG_NUMBER_LEN],
                        const lc_sig_av_t *av, uint64_t now_us);
/* The core cancelled tmid's registration (LOC_CANCEL): it is no longer
 * registered, and a call it holds is released with cause. 0, or -1 if unknown. */
int  lc_sig_net_drop(lc_sig_net_t *n, uint32_t tmid, uint8_t cause, uint64_t now_us);
```

- [ ] **Step 4: `lc_sig_net.c` asks instead of computing**

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
#include "lc_sig_crypto.h"
#include "lc_sig_keys.h"
#include "lc_sig_milenage.h"

#define US(s) ((uint64_t)(s) * 1000000ull)

enum { C_NONE = 0, C_MO_PROC, C_MO_ALERT, C_MO_CONNECTING, C_MT_SETUP, C_MT_ALERT, C_ACTIVE, C_RELEASING };

static const uint8_t k_amf[2] = { 0x80, 0x00 };
static const uint8_t k_amf_resync[2] = { 0x00, 0x00 };
```
with:
```c
#include "lc_sig_crypto.h"
#include "lc_sig_keys.h"

#define US(s) ((uint64_t)(s) * 1000000ull)

enum { C_NONE = 0, C_MO_PROC, C_MO_ALERT, C_MO_CONNECTING, C_MT_SETUP, C_MT_ALERT, C_ACTIVE, C_RELEASING };
```

The next replacement covers `new_av()` and `on_act_req()`: from the comment above `new_av` down to, not including, the comment `/* A call to a local subscriber (spec §5)`.

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
/* A fresh authentication vector with SQN + 1 (spec §4.3). Written into the
 * pending fields: the session's confirmed rand/ck/ik (and "registered") stay
 * untouched until AUTH_RSP actually matches, so an unauthenticated REG_REQ
 * (forged or repeated) can never deregister a session or overwrite live
 * session keys on its own say-so (fix round 1, Review Focus 1). */
static void new_av(lc_sig_net_t *n, lc_sig_net_sess_t *s, lc_sig_sub_t *sub)
{
    lc_sig_sqn_put(sub->sqn, lc_sig_sqn_get(sub->sqn) + 1u);
    if (n->io.save != NULL) n->io.save(n->io.ctx);
    n->io.random(n->io.ctx, s->p_rand, 16);
    lc_milenage_t o;
    lc_milenage(sub->k, sub->opc, s->p_rand, sub->sqn, k_amf, &o);
    lc_sig_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_SIG_AUTH_REQ;
    memcpy(m.u.auth_req.rand, s->p_rand, 16);
    for (int i = 0; i < 6; i++) m.u.auth_req.autn[i] = (uint8_t)(sub->sqn[i] ^ o.ak[i]);
    memcpy(m.u.auth_req.autn + 6, k_amf, 2);
    memcpy(m.u.auth_req.autn + 8, o.mac_a, 8);
    memcpy(s->p_xres, o.res, 8);
    memcpy(s->p_ck, o.ck, 16);
    memcpy(s->p_ik, o.ik, 16);
    s->auth_pending = 1;
    queue(s, &m);
}

static void on_act_req(lc_sig_net_t *n, lc_sig_net_sess_t *s, const lc_sig_msg_t *m, uint64_t now)
{
    lc_sig_sub_t *sub = n->io.by_token(n->io.ctx, m->u.act_req.token_id);
    uint8_t reason = 0, tag[8];
    lc_sig_msg_t r;
    memset(&r, 0, sizeof(r));
    /* A used token is refused unless it is still bound to this very terminal
     * (TMID, tag and key pair all the same): then its ACT_ACK was lost and the
     * terminal gave up, so it is answered again. */
    if (sub == NULL) {
        reason = LC_SIG_ACT_UNKNOWN;
    } else if (sub->token_used && !(sub->activated && sub->tmid == s->tmid)) {
        reason = LC_SIG_ACT_USED;
    } else if (!sub->token_used && n->io.unix_now != NULL && n->io.unix_now(n->io.ctx) > sub->token_expiry) {
        reason = LC_SIG_ACT_EXPIRED;
    } else if (lc_sig_act_tag(sub->token_secret, s->tmid, m->u.act_req.pkt, m->u.act_req.token_id, tag) != 0 ||
               !lc_sig_ct_equal(tag, m->u.act_req.tag, 8)) {
        reason = sub->token_used ? LC_SIG_ACT_USED : LC_SIG_ACT_BAD_TAG;
    }
    int again = reason == 0 && sub->token_used;
    uint8_t k[16], opc[16];
    if (reason == 0 && lc_sig_act_keys(n->cfg.sk, m->u.act_req.pkt, s->tmid, m->u.act_req.token_id, k, opc) != 0) {
        reason = LC_SIG_ACT_BAD_TAG;
    }
    if (reason == 0 && again && !lc_sig_ct_equal(k, sub->k, 16)) reason = LC_SIG_ACT_USED; /* another key pair */
    if (reason != 0) {
        r.type = LC_SIG_ACT_NAK;
        r.u.act_nak.reason = reason;
        if (sub != NULL) { /* no secret for an unknown token: zero tag (ruling in plan 5) */
            lc_sig_act_nak_tag(sub->token_secret, s->tmid, m->u.act_req.token_id, reason, r.u.act_nak.tag);
        }
        queue(s, &r);
        char line[64];
        snprintf(line, sizeof(line), "activation %08x refused (%u)", (unsigned)s->tmid, reason);
        logs(n, line);
        return;
    }
    if (again) {
        /* The binding stands (keys, SQN and registration untouched); ACT_ACK's
         * confirm is deterministic, so just say it again. */
        if (s->call != C_NONE) call_end(n, s, LC_SIG_CAUSE_LINK_LOST, now);
        r.type = LC_SIG_ACT_ACK;
        memcpy(r.u.act_ack.number, sub->number, LC_SIG_NUMBER_LEN);
        lc_sig_act_confirm(k, s->tmid, m->u.act_req.token_id, r.u.act_ack.confirm);
        queue(s, &r);
        logs(n, "activation repeated: ACT_ACK sent again");
        return;
    }
    if (n->io.unbind != NULL) n->io.unbind(n->io.ctx, s->tmid);
    if (sub->tmid != 0 && sub->tmid != s->tmid) {
        /* the subscriber is moving to a new terminal: the old one must not
         * keep serving calls or look registered once the SIM re-activates
         * elsewhere (fix round 1, Review Focus 2) */
        lc_sig_net_sess_t *old = sess(n, sub->tmid, 0);
        if (old != NULL) {
            old->registered = 0;
            /* the old terminal is told (RELEASE); once it answers (or 5 s),
             * call_end releases a local call's other leg too */
            if (old->call != C_NONE && old->call != C_RELEASING) release_leg(n, old, LC_SIG_CAUSE_NET_FAILURE, now);
        }
    }
    /* whatever call this TMID's session still holds belongs to the terminal's
     * previous life (it rebooted, or was re-activated): end it */
    if (s->call != C_NONE) call_end(n, s, LC_SIG_CAUSE_LINK_LOST, now);
    memcpy(sub->k, k, 16);
    memcpy(sub->opc, opc, 16);
    memset(sub->sqn, 0, 6);
    sub->tmid = s->tmid;
    sub->activated = 1;
    sub->token_used = 1;
    s->registered = 0;    /* this session's own keys, if any, predate the new activation */
    s->auth_pending = 0;  /* likewise any half-finished negotiation (fix round 2, Review Focus 1c) */
    if (n->io.save != NULL) n->io.save(n->io.ctx);
    r.type = LC_SIG_ACT_ACK;
    memcpy(r.u.act_ack.number, sub->number, LC_SIG_NUMBER_LEN);
    lc_sig_act_confirm(k, s->tmid, m->u.act_req.token_id, r.u.act_ack.confirm);
    queue(s, &r);
    char line[64], num[LC_SIG_NUMBER_TEXT];
    lc_sig_number_to_text(sub->number, num);
    snprintf(line, sizeof(line), "activated %s on terminal %08x", num, (unsigned)s->tmid);
    logs(n, line);
}
```
with:
```c
/* Ask the core for a vector (network-core spec §7.2). Its answer goes into
 * the pending fields (lc_sig_net_av_done): the session's confirmed
 * rand/ck/ik (and "registered") stay untouched until AUTH_RSP actually
 * matches, so an unauthenticated REG_REQ (forged or repeated) can never
 * deregister a session or overwrite live session keys on its own say-so
 * (fix round 1, Review Focus 1). One question at a time: while it stands,
 * another REG_REQ waits for the same answer. */
static void ask_av(lc_sig_net_t *n, lc_sig_net_sess_t *s, uint64_t now)
{
    if (s->av_wait && now - s->av_at < LC_SIG_NET_ASK_US) return;
    s->av_wait = 1;
    s->av_at = now;
    n->io.av_req(n->io.ctx, s->tmid); /* may answer from inside the call */
}

/* The core runs the checks and holds the keys (network-core spec §7.1); the
 * terminal's retransmits of this same ACT_REQ never reach here (the channel
 * drops a repeat until the answer exists, then repeats the answer). */
static void on_act_req(lc_sig_net_t *n, lc_sig_net_sess_t *s, const lc_sig_msg_t *m, uint64_t now)
{
    if (s->act_wait && now - s->act_at < LC_SIG_NET_ASK_US) return;
    s->act_wait = 1;
    s->act_at = now;
    n->io.act_req(n->io.ctx, s->tmid, m->u.act_req.token_id, m->u.act_req.pkt, m->u.act_req.tag);
}

/* The registered session for number, if any. */
static lc_sig_net_sess_t *by_number(lc_sig_net_t *n, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        lc_sig_net_sess_t *s = &n->s[i];
        if (s->used && s->registered && memcmp(s->number, number, LC_SIG_NUMBER_LEN) == 0) return s;
    }
    return NULL;
}
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
static void local_setup(lc_sig_net_t *n, lc_sig_net_sess_t *a, const lc_sig_sub_t *callee, uint64_t now)
{
    lc_sig_net_sess_t *b = callee->activated ? sess(n, callee->tmid, 0) : NULL;
    const lc_sig_sub_t *caller = n->io.by_tmid(n->io.ctx, a->tmid);
    if (b == NULL || !b->registered || caller == NULL) {
        release_leg(n, a, LC_SIG_CAUSE_UNREACHABLE, now);
        return;
    }
    if (b == a || b->call != C_NONE) {
        release_leg(n, a, LC_SIG_CAUSE_BUSY, now);
        return;
    }
    b->call_id = ++n->next_call_id;
    memcpy(b->peer, caller->number, LC_SIG_NUMBER_LEN);
    lc_sig_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_SIG_SETUP_IND;
    m.u.setup_ind.call_id = b->call_id;
    memcpy(m.u.setup_ind.caller, caller->number, LC_SIG_NUMBER_LEN);
```
with:
```c
static void local_setup(lc_sig_net_t *n, lc_sig_net_sess_t *a, lc_sig_net_sess_t *b, uint64_t now)
{
    if (b == a || b->call != C_NONE) {
        release_leg(n, a, LC_SIG_CAUSE_BUSY, now);
        return;
    }
    b->call_id = ++n->next_call_id;
    memcpy(b->peer, a->number, LC_SIG_NUMBER_LEN);
    lc_sig_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_SIG_SETUP_IND;
    m.u.setup_ind.call_id = b->call_id;
    memcpy(m.u.setup_ind.caller, a->number, LC_SIG_NUMBER_LEN);
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
static void handle(lc_sig_net_t *n, lc_sig_net_sess_t *s, const lc_sig_msg_t *m, uint64_t now)
{
    lc_sig_sub_t *sub;
    switch (m->type) {
```
with:
```c
static void handle(lc_sig_net_t *n, lc_sig_net_sess_t *s, const lc_sig_msg_t *m, uint64_t now)
{
    switch (m->type) {
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        sub = n->io.by_tmid(n->io.ctx, s->tmid);
        if (sub == NULL) {
            rej(s, LC_SIG_REG_NOT_ACTIVATED);
            return;
        }
        if (s->auth_pending) {
```
with:
```c
        if (s->auth_pending) {
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
            s->auth_pending = 0;
        }
        new_av(n, s, sub);
        return;
    case LC_SIG_AUTH_RSP: {
        if (!s->auth_pending) return;
        s->auth_pending = 0;
        sub = n->io.by_tmid(n->io.ctx, s->tmid);
        if (sub == NULL || !lc_sig_ct_equal(m->u.auth_rsp.res, s->p_xres, 8)) {
```
with:
```c
            s->auth_pending = 0;
        }
        ask_av(n, s, now);
        return;
    case LC_SIG_AUTH_RSP: {
        if (!s->auth_pending) return;
        s->auth_pending = 0;
        if (!lc_sig_ct_equal(m->u.auth_rsp.res, s->p_xres, 8)) {
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        memcpy(s->ik, s->p_ik, 16);
        uint8_t ki[16], ke[16];
```
with:
```c
        memcpy(s->ik, s->p_ik, 16);
        memcpy(s->number, s->p_number, LC_SIG_NUMBER_LEN);
        uint8_t ki[16], ke[16];
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        memcpy(r.u.reg_ack.number, sub->number, LC_SIG_NUMBER_LEN);
```
with:
```c
        memcpy(r.u.reg_ack.number, s->number, LC_SIG_NUMBER_LEN);
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        lc_sig_number_to_text(sub->number, num);
        snprintf(line, sizeof(line), "registered %s (terminal %08x)", num, (unsigned)s->tmid);
        logs(n, line);
        return;
```
with:
```c
        lc_sig_number_to_text(s->number, num);
        snprintf(line, sizeof(line), "registered %s (terminal %08x)", num, (unsigned)s->tmid);
        logs(n, line);
        if (n->io.registered != NULL) n->io.registered(n->io.ctx, s->tmid, s->number, s->rand, m->u.auth_rsp.res);
        return;
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        s->auth_pending = 0;
        sub = n->io.by_tmid(n->io.ctx, s->tmid);
        if (sub == NULL || !had_vector) return;
        if (m->u.auth_fail.cause == 2) {
            static const uint8_t zero[6] = { 0 };
            lc_milenage_t o;
            uint8_t ms[6];
            lc_milenage(sub->k, sub->opc, s->p_rand, zero, k_amf_resync, &o); /* AK* */
            for (int i = 0; i < 6; i++) ms[i] = (uint8_t)(m->u.auth_fail.auts[i] ^ o.ak_s[i]);
            lc_milenage(sub->k, sub->opc, s->p_rand, ms, k_amf_resync, &o);
            if (lc_sig_ct_equal(o.mac_s, m->u.auth_fail.auts + 6, 8)) {
                memcpy(sub->sqn, ms, 6);
                logs(n, "SQN resynchronized");
                new_av(n, s, sub);
                return;
            }
        }
        rej(s, LC_SIG_REG_AUTH_FAILED);
        return;
    }
```
with:
```c
        s->auth_pending = 0;
        if (!had_vector) return;
        if (m->u.auth_fail.cause == 2) { /* the core checks AUTS and answers with a fresh vector */
            s->av_wait = 1;
            s->av_at = now;
            n->io.resync_req(n->io.ctx, s->tmid, s->p_rand, m->u.auth_fail.auts);
            return;
        }
        rej(s, LC_SIG_REG_AUTH_FAILED);
        return;
    }
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        memset(&r, 0, sizeof(r));
        sub = n->io.by_tmid(n->io.ctx, s->tmid);
        if (!s->registered || sub == NULL) {
            /* not registered, or (fix round 1, Review Focus 2) this TMID's
             * subscriber moved to another terminal since */
```
with:
```c
        memset(&r, 0, sizeof(r));
        if (!s->registered) {
            /* not registered, or (fix round 1, Review Focus 2) this TMID's
             * subscriber moved to another terminal since (lc_sig_net_drop) */
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        const lc_sig_sub_t *callee = n->io.by_number(n->io.ctx, m->u.call_setup.called);
        if (callee != NULL) {
```
with:
```c
        lc_sig_net_sess_t *callee = by_number(n, m->u.call_setup.called);
        if (callee != NULL) {
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        if (s->registered && now_us > s->reg_until) s->registered = 0;
```
with:
```c
        if (s->registered && now_us > s->reg_until) {
            s->registered = 0;
            if (n->io.unregistered != NULL) n->io.unregistered(n->io.ctx, s->tmid, s->number);
        }
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
int lc_sig_net_peer_alert(lc_sig_net_t *n, uint32_t call_id, uint64_t now_us)
{
```
with:
```c
int lc_sig_net_act_done(lc_sig_net_t *n, uint32_t tmid, const lc_sig_msg_t *msg, uint64_t now_us)
{
    lc_sig_net_sess_t *s = sess(n, tmid, 0);
    if (s == NULL || !s->act_wait || (msg->type != LC_SIG_ACT_ACK && msg->type != LC_SIG_ACT_NAK)) return -1;
    s->act_wait = 0;
    char line[64];
    if (msg->type == LC_SIG_ACT_ACK) {
        /* any half-finished negotiation used the keys before this activation
         * (fix round 2, Review Focus 1c), and whatever call this TMID's
         * session still holds belongs to the terminal's previous life (it
         * rebooted, or was re-activated): end it */
        s->auth_pending = 0;
        s->av_wait = 0;
        if (s->call != C_NONE) call_end(n, s, LC_SIG_CAUSE_LINK_LOST, now_us);
        char num[LC_SIG_NUMBER_TEXT];
        lc_sig_number_to_text(msg->u.act_ack.number, num);
        snprintf(line, sizeof(line), "activated %s on terminal %08x", num, (unsigned)tmid);
    } else {
        snprintf(line, sizeof(line), "activation %08x refused (%u)", (unsigned)tmid, msg->u.act_nak.reason);
    }
    logs(n, line);
    queue(s, msg);
    flush(n, s, now_us);
    channel(n, s, now_us);
    return 0;
}

int lc_sig_net_av_done(lc_sig_net_t *n, uint32_t tmid, uint8_t status, const uint8_t number[LC_SIG_NUMBER_LEN],
                       const lc_sig_av_t *av, uint64_t now_us)
{
    lc_sig_net_sess_t *s = sess(n, tmid, 0);
    if (s == NULL || !s->av_wait) return -1;
    s->av_wait = 0;
    if (status == LC_SIG_AV_UNAVAILABLE) return 0; /* no answer: the terminal times out and backs off */
    if (status != LC_SIG_AV_OK) {
        rej(s, status == LC_SIG_AV_AUTH_FAILED ? LC_SIG_REG_AUTH_FAILED : LC_SIG_REG_NOT_ACTIVATED);
    } else {
        memcpy(s->p_rand, av->rand, 16);
        memcpy(s->p_xres, av->xres, 8);
        memcpy(s->p_ck, av->ck, 16);
        memcpy(s->p_ik, av->ik, 16);
        memcpy(s->p_number, number, LC_SIG_NUMBER_LEN);
        lc_sig_msg_t m;
        memset(&m, 0, sizeof(m));
        m.type = LC_SIG_AUTH_REQ;
        memcpy(m.u.auth_req.rand, av->rand, 16);
        memcpy(m.u.auth_req.autn, av->autn, 16);
        s->auth_pending = 1;
        queue(s, &m);
    }
    flush(n, s, now_us);
    channel(n, s, now_us);
    return 0;
}

int lc_sig_net_drop(lc_sig_net_t *n, uint32_t tmid, uint8_t cause, uint64_t now_us)
{
    lc_sig_net_sess_t *s = sess(n, tmid, 0);
    if (s == NULL) return -1;
    s->registered = 0;
    s->auth_pending = 0;
    s->av_wait = 0;
    /* the terminal is told (RELEASE); once it answers (or 5 s), call_end
     * releases a local call's other leg too */
    if (s->call != C_NONE && s->call != C_RELEASING) release_leg(n, s, cause, now_us);
    return 0;
}

int lc_sig_net_peer_alert(lc_sig_net_t *n, uint32_t call_id, uint64_t now_us)
{
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
    lc_sig_sub_t *sub = n->io.by_number(n->io.ctx, callee);
    if (sub == NULL || !sub->activated) return -1;
    lc_sig_net_sess_t *s = sess(n, sub->tmid, 0);
    if (s == NULL || !s->registered || s->call != C_NONE) return -1;
```
with:
```c
    lc_sig_net_sess_t *s = by_number(n, callee);
    if (s == NULL || s->call != C_NONE) return -1;
```

Run: `cd /home/devin/Documents/opencell/firmware && grep -nE "by_tmid|by_token|io\.save|io\.random|unix_now|cfg\.sk|lc_milenage" firmware/components/lc_sig/lc_sig_net.c`
Expected: nothing.

- [ ] **Step 5: lcbench as its own single-process core**

In `tools/lcbench/lcb_net.c`, replace:
```c
static lc_sig_sub_t *io_by_token(void *c, const uint8_t t[8]) { return lcb_hss_by_token(((lcb_net_t *)c)->hss, t); }
static lc_sig_sub_t *io_by_tmid(void *c, uint32_t tmid) { return lcb_hss_by_tmid(((lcb_net_t *)c)->hss, tmid); }
static lc_sig_sub_t *io_by_number(void *c, const uint8_t num[LC_SIG_NUMBER_LEN])
{
    return lcb_hss_by_number(((lcb_net_t *)c)->hss, num);
}
static void io_unbind(void *c, uint32_t tmid) { lcb_hss_unbind(((lcb_net_t *)c)->hss, tmid); }

static void io_save(void *c)
{
    lcb_net_t *n = c;
    if (n->hss_path != NULL && lcb_hss_save(n->hss, n->hss_path) != 0) say(n, "HSS save FAILED: %s", n->hss_path);
}
```
with:
```c
static void save(lcb_net_t *n)
{
    if (n->hss_path != NULL && lcb_hss_save(n->hss, n->hss_path) != 0) say(n, "HSS save FAILED: %s", n->hss_path);
}

/* lcbench is its own single-process core (network-core spec §4.3): the HSS
 * answers lc_sig_net's questions at once, and is saved before any answer
 * leaves (so a vector's SQN is on disk before the terminal can use it). */
static void io_act_req(void *c, uint32_t tmid, const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8])
{
    lcb_net_t *n = c;
    lc_sig_msg_t out;
    uint32_t drop[2];
    unsigned nd = 0;
    uint64_t now = n->now_us();
    if (lc_sig_flat_act(n->hss->subs, n->hss->n, n->hss->sk, (uint32_t)time(NULL), tmid, token_id, pkt, tag, &out,
                        drop, &nd) == LC_SIG_ACT_FRESH) {
        save(n);
    }
    for (unsigned i = 0; i < nd; i++) lc_sig_net_drop(&n->net, drop[i], LC_SIG_CAUSE_NET_FAILURE, now);
    lc_sig_net_act_done(&n->net, tmid, &out, now);
}

static void answer_av(lcb_net_t *n, uint32_t tmid, const uint8_t *rand, const uint8_t *auts)
{
    uint8_t fresh[16], number[LC_SIG_NUMBER_LEN];
    lc_sig_av_t av;
    memset(number, 0, sizeof(number));
    memset(&av, 0, sizeof(av));
    n->random(fresh, 16);
    uint8_t st = auts == NULL ? lc_sig_flat_av(n->hss->subs, n->hss->n, tmid, fresh, number, &av)
                              : lc_sig_flat_resync(n->hss->subs, n->hss->n, tmid, rand, auts, fresh, number, &av);
    if (st == LC_SIG_AV_OK) save(n);
    if (auts != NULL) say(n, "%08x: %s", tmid, st == LC_SIG_AV_OK ? "SQN resynchronized" : "resync refused");
    lc_sig_net_av_done(&n->net, tmid, st, number, &av, n->now_us());
}

static void io_av_req(void *c, uint32_t tmid) { answer_av(c, tmid, NULL, NULL); }
static void io_resync_req(void *c, uint32_t tmid, const uint8_t rand[16], const uint8_t auts[14])
{
    answer_av(c, tmid, rand, auts);
}
```

In `tools/lcbench/lcb_net.c`, replace:
```c
    if (e->what == LC_SIG_NET_MO) {
        say(n, "call %u: %08x dials %s; peer rings, answers in 3 s", e->call_id, e->tmid, num);
```
with:
```c
    if (e->what == LC_SIG_NET_MO && lcb_hss_by_number(n->hss, e->number) != NULL) {
        /* a subscriber of this HSS that isn't registered here: not the far end */
        say(n, "call %u: %08x dials %s: not registered", e->call_id, e->tmid, num);
        lc_sig_net_peer_release(&n->net, e->call_id, LC_SIG_CAUSE_UNREACHABLE, n->now_us());
    } else if (e->what == LC_SIG_NET_MO) {
        say(n, "call %u: %08x dials %s; peer rings, answers in 3 s", e->call_id, e->tmid, num);
```

In `tools/lcbench/lcb_net.c`, replace:
```c
static void io_random(void *c, uint8_t *out, size_t len) { ((lcb_net_t *)c)->random(out, len); }
static uint32_t io_unix(void *c) { (void)c; return (uint32_t)time(NULL); }
static void io_log(void *c, const char *line) { say((lcb_net_t *)c, "%s", line); }
```
with:
```c
static void io_log(void *c, const char *line) { say((lcb_net_t *)c, "%s", line); }
```

In `tools/lcbench/lcb_net.c`, replace:
```c
    const lc_sig_net_io_t io = { n, io_by_token, io_by_tmid, io_by_number, io_unbind, io_save, io_send,
                                 io_channel, io_call, io_random, io_unix, io_log };
    lc_sig_net_cfg_t cfg = { hss->key_id, { 0 }, hss->mode, hss->period_s };
    memcpy(cfg.sk, hss->sk, 32);
    lc_sig_net_init(&n->net, &io, &cfg);
    memset(cfg.sk, 0, 32);
```
with:
```c
    const lc_sig_net_io_t io = { n, io_act_req, io_av_req, io_resync_req, NULL, NULL, io_send,
                                 io_channel, io_call, io_log };
    const lc_sig_net_cfg_t cfg = { hss->mode, hss->period_s };
    lc_sig_net_init(&n->net, &io, &cfg);
```

- [ ] **Step 6: Run them to see them pass**

Run: `cd /home/devin/Documents/opencell/firmware && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; for t in test_sig_e2e test_sig_local test_term_sim test_lcbench; do host-tests/build/$t | tail -2 | head -1; done`
Expected: no compiler output, then four `… Tests 0 Failures 0 Ignored` lines: `test_sig_e2e` with 5 more tests than Task 7 counted, and `test_sig_local`, `test_term_sim` and `test_lcbench` with exactly Task 7's counts (nothing of theirs was added or removed). Validated on `chan-list` at `943a093`: `45`, `4`, `21`, `21`.

- [ ] **Step 7: The whole suite, and lcbench on its own**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N+1` (34 when validated).

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S tools/lcbench -B tools/lcbench/build -G Ninja >/dev/null && cmake --build tools/lcbench/build 2>&1 | grep -E "error|warning"; ls tools/lcbench/build/lcbench`
Expected: no compiler output, then `tools/lcbench/build/lcbench`.

- [ ] **Step 8: Commit**

```bash
cd /home/devin/Documents/opencell/firmware
git add firmware/components/lc_sig/include/lc_sig_net.h firmware/components/lc_sig/lc_sig_net.c tools/lcbench/lcb_net.c \
        host-tests/sig_fake_core.h host-tests/test_sig_e2e.c host-tests/test_sig_local.c host-tests/test_term_sim.c
git commit -m "lc_sig_net: ask the core for activation, vectors and resync (network-core spec 4.3)

The library no longer holds K, OPc, SQN or the network key. Tests run on a
synchronous fake core; lcbench answers from its own HSS.

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 10: `lc_sig_net` for a cell that talks to a core: ALERTING, call_in's answer, 32 sessions

**Repo:** `opencell-firmware`, branch `net-core`, at `/home/devin/Documents/opencell/firmware`. **Starts:** after Task 9.

A cell relays an incoming leg's alert to the core, answers an offer with busy or unreachable, and finds a caller's number, so `lc_sig_net` reports those; and it serves at least plan 4's 32 terminals.

**Files:**
- Modify: `firmware/components/lc_sig/include/lc_sig_net.h`, `firmware/components/lc_sig/lc_sig_net.c`, `firmware/components/lc_sig/CMakeLists.txt`
- Test: `host-tests/test_sig_e2e.c`

**Interfaces:**
- Consumes: Task 9's `lc_sig_net`.
- Produces:
  ```c
  LC_SIG_NET_ALERTING = 5                        /* lc_sig_net_what_t: an incoming leg's terminal rings */
  #define LC_SIG_NET_IN_UNREACHABLE (-1)         /* lc_sig_net_call_in */
  #define LC_SIG_NET_IN_BUSY        (-2)
  #define LC_SIG_NET_TERMS 32u                   /* unless defined before: CMake cache variable LC_SIG_NET_TERMS */
  int lc_sig_net_number(const lc_sig_net_t *n, uint32_t tmid, uint8_t out[LC_SIG_NUMBER_LEN]); /* 0 / -1 */
  ```

- [ ] **Step 1: Write the failing tests**

In `host-tests/test_sig_e2e.c`, replace:
```c
int main(void)
{
```
with:
```c
/* An incoming leg's terminal rings: the switch hears ALERTING. call_in says
 * why it could not set a call up. */
static void test_alerting_event_and_call_in_codes(void)
{
    registered_world(LC_SIG_MODE_PART15);
    uint8_t caller[LC_SIG_NUMBER_LEN], got[LC_SIG_NUMBER_LEN], nobody[LC_SIG_NUMBER_LEN];
    uint32_t cid, cid2;
    lc_sig_number_to_bcd("+883160655500100", 16, caller);
    lc_sig_number_to_bcd("+883160655509999", 16, nobody);
    TEST_ASSERT_EQUAL_INT(0, lc_sig_net_number(&N, TMID, got));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(subs[0].number, got, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(-1, lc_sig_net_number(&N, TMID2, got));
    TEST_ASSERT_EQUAL_INT(LC_SIG_NET_IN_UNREACHABLE, lc_sig_net_call_in(&N, nobody, caller, now, &cid));
    TEST_ASSERT_EQUAL_INT(0, lc_sig_net_call_in(&N, subs[0].number, caller, now, &cid));
    TEST_ASSERT_EQUAL_INT(LC_SIG_NET_IN_BUSY, lc_sig_net_call_in(&N, subs[0].number, caller, now, &cid2));
    run_ms(2000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_RINGING_IN, lc_sig_term_state(&T));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_NET_ALERTING, calls[ncalls - 1].what);
    TEST_ASSERT_EQUAL_UINT32(cid, calls[ncalls - 1].call_id);
    TEST_ASSERT_EQUAL_UINT32(0, calls[ncalls - 1].peer_tmid);
}

/* Network-core spec §4.1: sessions for at least plan 4's RHU_MAX_TERMS (32)
 * terminals, a build-time setting. */
static void test_sessions_for_32_terminals(void)
{
    world(LC_SIG_MODE_PART15, 1800);
    TEST_ASSERT_TRUE(LC_SIG_NET_TERMS >= 32u);
    uint8_t dummy[1] = { 0 };
    for (uint32_t i = 0; i < 32u; i++) lc_sig_net_rx(&N, 0xBBBB0000u + i, dummy, 1, now);
    unsigned used = 0;
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) used += N.s[i].used ? 1u : 0u;
    TEST_ASSERT_EQUAL_UINT(32, used);
}

int main(void)
{
```

In `host-tests/test_sig_e2e.c`, replace:
```c
    RUN_TEST(test_registered_and_lapsed_are_reported);
```
with:
```c
    RUN_TEST(test_registered_and_lapsed_are_reported);
    RUN_TEST(test_alerting_event_and_call_in_codes);
    RUN_TEST(test_sessions_for_32_terminals);
```

- [ ] **Step 2: Run them to see them fail**

Run: `cd /home/devin/Documents/opencell/firmware && cmake --build host-tests/build --target test_sig_e2e 2>&1 | grep -E "error" | head -4`
Expected: errors including `implicit declaration of function 'lc_sig_net_number'`, `'LC_SIG_NET_IN_UNREACHABLE' undeclared`, `'LC_SIG_NET_IN_BUSY' undeclared` and `'LC_SIG_NET_ALERTING' undeclared`.

- [ ] **Step 3: Implement**

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
/* MO: a call to the far end (the caller answers it with lc_sig_net_peer_*). LOCAL: a call to
 * another local subscriber, which the network switches itself (two legs, relayed). */
typedef enum { LC_SIG_NET_MO = 1, LC_SIG_NET_ANSWERED = 2, LC_SIG_NET_ENDED = 3, LC_SIG_NET_LOCAL = 4 } lc_sig_net_what_t;
```
with:
```c
/* MO: a call to the far end (the caller answers it with lc_sig_net_peer_*). LOCAL: a call to
 * another local subscriber, which the network switches itself (two legs, relayed).
 * ALERTING / ANSWERED: an incoming leg's terminal rings / answers. */
typedef enum {
    LC_SIG_NET_MO = 1, LC_SIG_NET_ANSWERED = 2, LC_SIG_NET_ENDED = 3, LC_SIG_NET_LOCAL = 4, LC_SIG_NET_ALERTING = 5
} lc_sig_net_what_t;

/* lc_sig_net_call_in: why no call was set up */
#define LC_SIG_NET_IN_UNREACHABLE (-1) /* no registered session has that number */
#define LC_SIG_NET_IN_BUSY        (-2) /* it has a call */
```

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
#define LC_SIG_NET_TERMS 4u
```
with:
```c
#ifndef LC_SIG_NET_TERMS
#define LC_SIG_NET_TERMS 32u /* sessions; build-time (CMake LC_SIG_NET_TERMS), at least plan 4's RHU_MAX_TERMS */
#endif
```

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
int  lc_sig_net_call_in(lc_sig_net_t *n, const uint8_t callee[LC_SIG_NUMBER_LEN],
                        const uint8_t caller[LC_SIG_NUMBER_LEN], uint64_t now_us, uint32_t *call_id);
```
with:
```c
/* An incoming call for callee: 0 (SETUP_IND sent, *call_id set),
 * LC_SIG_NET_IN_UNREACHABLE or LC_SIG_NET_IN_BUSY. */
int  lc_sig_net_call_in(lc_sig_net_t *n, const uint8_t callee[LC_SIG_NUMBER_LEN],
                        const uint8_t caller[LC_SIG_NUMBER_LEN], uint64_t now_us, uint32_t *call_id);
```

In `firmware/components/lc_sig/include/lc_sig_net.h`, replace:
```c
int  lc_sig_net_registered(const lc_sig_net_t *n, uint32_t tmid);
```
with:
```c
int  lc_sig_net_registered(const lc_sig_net_t *n, uint32_t tmid);
/* The number tmid registered with: 0, or -1 when it isn't registered. */
int  lc_sig_net_number(const lc_sig_net_t *n, uint32_t tmid, uint8_t out[LC_SIG_NUMBER_LEN]);
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
        if (s->call == C_MT_SETUP && m->u.call.call_id == s->call_id) {
            s->call = C_MT_ALERT;
```
with:
```c
        if (s->call == C_MT_SETUP && m->u.call.call_id == s->call_id) {
            s->call = C_MT_ALERT;
            call_ev(n, s, LC_SIG_NET_ALERTING, 0);
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
    lc_sig_net_sess_t *s = by_number(n, callee);
    if (s == NULL || s->call != C_NONE) return -1;
```
with:
```c
    lc_sig_net_sess_t *s = by_number(n, callee);
    if (s == NULL) return LC_SIG_NET_IN_UNREACHABLE;
    if (s->call != C_NONE) return LC_SIG_NET_IN_BUSY;
```

In `firmware/components/lc_sig/lc_sig_net.c`, replace:
```c
int lc_sig_net_local_peer(const lc_sig_net_t *n, uint32_t tmid, uint32_t *peer_tmid)
{
```
with:
```c
int lc_sig_net_number(const lc_sig_net_t *n, uint32_t tmid, uint8_t out[LC_SIG_NUMBER_LEN])
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (n->s[i].used && n->s[i].tmid == tmid && n->s[i].registered) {
            memcpy(out, n->s[i].number, LC_SIG_NUMBER_LEN);
            return 0;
        }
    }
    return -1;
}

int lc_sig_net_local_peer(const lc_sig_net_t *n, uint32_t tmid, uint32_t *peer_tmid)
{
```

In `firmware/components/lc_sig/CMakeLists.txt`, replace:
```cmake
  find_package(OpenSSL REQUIRED)
  add_library(lc_sig STATIC ${LC_SIG_SRCS} lc_sig_net.c lc_sig_hss.c crypto_openssl.c)
  target_include_directories(lc_sig PUBLIC include)
```
with:
```cmake
  find_package(OpenSSL REQUIRED)
  set(LC_SIG_NET_TERMS 32 CACHE STRING "lc_sig_net sessions (terminals) per cell")
  add_library(lc_sig STATIC ${LC_SIG_SRCS} lc_sig_net.c lc_sig_hss.c crypto_openssl.c)
  target_include_directories(lc_sig PUBLIC include)
  target_compile_definitions(lc_sig PUBLIC LC_SIG_NET_TERMS=${LC_SIG_NET_TERMS}u)
```

`lcb_net.c` already treats any non-zero `lc_sig_net_call_in` as "refused"; nothing else calls it.

- [ ] **Step 4: Run them to see them pass**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build --target test_sig_e2e 2>&1 | grep -E "error|warning"; host-tests/build/test_sig_e2e | tail -3`
Expected: no compiler output, then `… Tests 0 Failures 0 Ignored` with 2 more tests than after Task 9 (47 when validated), and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N+1` (34 when validated).

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/firmware
git add firmware/components/lc_sig host-tests/test_sig_e2e.c
git commit -m "lc_sig_net: ALERTING event, call_in says busy or unreachable, 32 sessions (build-time)

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

- [ ] **Step 7: Push `net-core`, for the core's submodule**

The core pins its submodule to this commit (Task 11), so it must be on `origin`. Pushing the branch is not merging it: `net-core` goes into firmware `main` only when the controller says so.

```bash
cd /home/devin/Documents/opencell/firmware
git push -u origin net-core
git rev-parse --short HEAD
```

Expected: the push succeeds, then the short hash of Task 10's commit. Task 11 needs it.

---

### Task 11: The core's submodule on `net-core`; activation, vectors and resync

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 10 (its commit pushed) and Task 6.

The submodule moves to firmware `net-core` (Tasks 8–10 on top of `chan-list`), and the codec's AV type becomes `lc_sig_av_t` itself. Then the rest of the HSS (spec §4.2, §7.1–7.2): the three questions a cell forwards. Every change commits before the answer that depends on it leaves; a fresh activation cancels the number's old location (and the TMID's previous subscriber's) before ACT_RES goes out.

**Files:**
- Modify: `third_party/opencell-firmware` (the submodule's commit), `lc_core/include/lc_core_msg.h`, `lc_core/lc_core_int.h`, `lc_core/lc_core.c`, `lc_core/lc_core_hss.c` (append)
- Test: `tests/test_core_hss.c`

**Interfaces:**
- Consumes: Task 8's `lc_sig_act_answer`, `lc_sig_act_token_t`, `lc_sig_av_make`, `lc_sig_av_auts`, `lc_sig_av_t`, `lc_sig_av_status_t` (through the submodule); Task 5's subscribers, tokens and `lc_core_loc_cancel`; Task 2's `lc_core_token_block`.
- Produces (`lc_core_msg.h`): `typedef lc_sig_av_t lc_core_av_t;` and a compile-time check that `LC_CORE_AV_*` equal `LC_SIG_AV_*`.
- Produces (`lc_core_int.h`): `lc_core_hss_rx(k, cell_id, m)`.
- On the wire: ACT_FWD → ACT_RES (after any LOC_CANCEL); AV_REQ and RESYNC → AV_RES with status, number and `count` vectors (1–4; RESYNC: 1).

- [ ] **Step 1: The submodule on `net-core`**

```bash
cd /home/devin/Documents/opencell/core
git -C third_party/opencell-firmware fetch -q origin
git -C third_party/opencell-firmware checkout -q <net-core hash from Task 10 Step 7>
git -C third_party/opencell-firmware log --oneline -1
```

Run: `cd /home/devin/Documents/opencell/core && grep -ohE "lc_sig_av_make|lc_sig_act_answer|lc_sig_net_act_done|LC_SIG_NET_ALERTING|lc_sig_net_set_chan_list" third_party/opencell-firmware/firmware/components/lc_sig/include/lc_sig_hss.h third_party/opencell-firmware/firmware/components/lc_sig/include/lc_sig_net.h | sort -u | wc -l; rm -rf build && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `5` (Tasks 8–10 and `chan-list` are in), then no compiler output, then `100% tests passed, 0 tests failed out of 6`: nothing of Tasks 1–6 depends on what changed. (`rm -rf build`: `lc_sig` now has `lc_sig_hss.c` and the `LC_SIG_NET_TERMS` cache variable.)

- [ ] **Step 2: Write the failing tests**

In `tests/test_core_hss.c`, replace:
```c
#include "core_fixture.h"
#include "lc_core_int.h" /* lc_core_loc_live */
```
with:
```c
#include "core_fixture.h"
#include "lc_core_int.h" /* lc_core_loc_live */
#include "lc_sig_keys.h"
#include "lc_sig_milenage.h"
#include "lc_sig_term.h"
```

In `tests/test_core_hss.c`, replace:
```c
static lc_sig_qr_t issue(const char *num)
```
with:
```c
/* A terminal: its identity, the QR it scanned, and the K/OPc it derives. */
typedef struct {
    lc_sig_ident_t id;
    lc_sig_qr_t    qr;
    uint32_t       tmid;
    uint8_t        k[16], opc[16];
} term_t;

static void term(term_t *t, uint32_t tmid, uint8_t seed, const lc_sig_qr_t *qr)
{
    uint8_t r[32];
    memset(t, 0, sizeof(*t));
    memset(r, seed, 32);
    lc_sig_ident_new(&t->id, r);
    t->qr = *qr;
    t->tmid = tmid;
    lc_sig_act_keys(t->id.sk, qr->pkn, tmid, qr->token_id, t->k, t->opc);
}

/* ACT_FWD from cell_link for t, as the cell forwards its ACT_REQ. */
static const lc_core_msg_t *activate(uint32_t link, const term_t *t)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_ACT_FWD;
    m.u.act_fwd.req = 9;
    m.u.act_fwd.tmid = t->tmid;
    memcpy(m.u.act_fwd.token_id, t->qr.token_id, 8);
    memcpy(m.u.act_fwd.pkt, t->id.pk, 32);
    lc_sig_act_tag(t->qr.token_secret, t->tmid, t->id.pk, t->qr.token_id, m.u.act_fwd.tag);
    int from = NSENT;
    rx(link, &m);
    return sent_since(from, link, LC_CORE_ACT_RES);
}

static const lc_core_msg_t *ask_avs(uint32_t link, uint32_t tmid, uint8_t count)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.req = 3;
    m.u.av_req.tmid = tmid;
    m.u.av_req.count = count;
    int from = NSENT;
    rx(link, &m);
    return sent_since(from, link, LC_CORE_AV_RES);
}

/* What lc_sig_term does with AUTH_REQ: the SQN if MAC-A verifies, else -1. */
static int64_t terminal_sqn(const term_t *t, const lc_core_av_t *av)
{
    static const uint8_t zero[6] = { 0 }, amf[2] = { 0x80, 0x00 };
    lc_milenage_t o;
    uint8_t sqn[6];
    lc_milenage(t->k, t->opc, av->rand, zero, amf, &o);
    for (int i = 0; i < 6; i++) sqn[i] = (uint8_t)(av->autn[i] ^ o.ak[i]);
    lc_milenage(t->k, t->opc, av->rand, sqn, av->autn + 6, &o);
    if (!lc_sig_ct_equal(o.mac_a, av->autn + 8, 8) || memcmp(o.res, av->xres, 8) != 0) return -1;
    return (int64_t)lc_sig_sqn_get(sqn);
}

static lc_sig_qr_t issue(const char *num)
```

In `tests/test_core_hss.c`, replace:
```c
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_subscribers_are_added_by_policy);
    RUN_TEST(test_token_issue_fills_the_qr_and_voids_the_old_token);
    RUN_TEST(test_disable_cancels_the_location_and_voids_tokens);
    RUN_TEST(test_expired_location_is_not_live);
    return UNITY_END();
}
```
with:
```c
static void test_activation_binds_and_confirms(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    const lc_core_msg_t *r = activate(10, &t);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT16(9, r->u.act_res.req);
    TEST_ASSERT_EQUAL_HEX32(TMID, r->u.act_res.tmid);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
    uint8_t conf[8];
    lc_sig_act_confirm(t.k, TMID, qr.token_id, conf); /* what the terminal expects */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(conf, r->u.act_res.msg.u.act_ack.confirm, 8);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(qr.number, r->u.act_res.msg.u.act_ack.number, LC_SIG_NUMBER_LEN);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(t.k, s.k, 16);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(t.opc, s.opc, 16);
    TEST_ASSERT_EQUAL_UINT64(0, s.sqn);
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &tok));
    TEST_ASSERT_NOT_EQUAL(0, tok.used_at);
    TEST_ASSERT_EQUAL_HEX32(TMID, tok.used_by_tmid);
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_ACTIVATE));

    unsigned commits = MEM.commits;
    r = activate(10, &t); /* its ACT_ACK was lost: the same answer, nothing changes */
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(conf, r->u.act_res.msg.u.act_ack.confirm, 8);
    TEST_ASSERT_EQUAL_UINT(commits, MEM.commits);
}

/* Review Focus 4: the store fails in the middle of an activation: no answer
 * (the terminal times out), the token is not consumed, and the same QR works
 * on the next attempt. */
static void test_failed_activation_commit_leaves_the_token_usable(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    MEM.fail_commits = 1;
    TEST_ASSERT_NULL(activate(10, &t));
    lc_core_token_t tok;
    TEST_ASSERT_EQUAL_INT(0, ST.token_get(ST.ctx, qr.token_id, &tok));
    TEST_ASSERT_EQUAL_UINT32(0, tok.used_at);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(-1, ST.sub_by_tmid(ST.ctx, TMID, &s));
    const lc_core_msg_t *r = activate(10, &t);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
}

static uint8_t nak(uint32_t link, const term_t *t)
{
    const lc_core_msg_t *r = activate(link, t);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_NAK, r->u.act_res.msg.type);
    return r->u.act_res.msg.u.act_nak.reason;
}

static void test_activation_refusals(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;

    lc_sig_qr_t bad = qr;
    bad.token_secret[0] ^= 1; /* someone without the real QR */
    term(&t, TMID, 0x42, &bad);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_BAD_TAG, nak(10, &t));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_ACT_FAIL));

    bad = qr;
    bad.token_id[7] ^= 1; /* no such token */
    term(&t, TMID, 0x42, &bad);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_UNKNOWN, nak(10, &t));
    bad = qr;
    bad.token_id[1] = 2; /* a block this core is not home for */
    term(&t, TMID, 0x42, &bad);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_UNKNOWN, nak(10, &t));

    term(&t, TMID, 0x42, &qr);
    NOW += 3601000000ull; /* past the token's expiry */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_EXPIRED, nak(10, &t));

    qr = issue(NUM);
    term(&t, TMID, 0x42, &qr);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, activate(10, &t)->u.act_res.msg.type);
    term_t other;
    term(&other, TMID2, 0x99, &qr); /* the used QR, on another terminal */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_USED, nak(10, &other));
    term(&other, TMID, 0x99, &qr); /* the same TMID, another key pair */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_USED, nak(10, &other));

    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    qr = issue(NUM);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, n, NOW));
    term(&t, TMID2, 0x77, &qr); /* a disabled subscriber's token: void */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ACT_UNKNOWN, nak(10, &t));
}

/* §7.1 step 4: re-activating on a new terminal cancels the old one's
 * location, at its cell, before ACT_RES goes out. */
static void test_reactivation_cancels_the_old_location_first(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    hello(20, 2, 1);
    put_location(2, TMID); /* registered on cell 2 */
    qr = issue(NUM);
    term(&t, TMID2, 0x55, &qr);
    int from = NSENT;
    const lc_core_msg_t *r = activate(10, &t);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_ACT_ACK, r->u.act_res.msg.type);
    const lc_core_msg_t *c = sent_since(from, 20, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, c->u.loc_cancel.cause);
    lc_core_loc_t l;
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(-1, ST.loc_get(ST.ctx, n, &l));
    TEST_ASSERT_EQUAL_INT(-1, ST.sub_by_tmid(ST.ctx, TMID, &(lc_core_sub_t){ 0 }));
}

static void test_vectors_rise_and_are_committed_first(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    const lc_core_msg_t *r = ask_avs(10, TMID, 2);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(2, r->u.av_res.count);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(qr.number, r->u.av_res.number, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT64(1, terminal_sqn(&t, &r->u.av_res.av[0]));
    TEST_ASSERT_EQUAL_INT64(2, terminal_sqn(&t, &r->u.av_res.av[1]));
    lc_core_av_issued_t a;
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, qr.number, r->u.av_res.av[1].rand, &a));
    TEST_ASSERT_EQUAL_UINT32(1, a.cell_id);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(r->u.av_res.av[1].xres, a.xres, 8);

    MEM.fail_commits = 1; /* the store can't commit: no vector may leave */
    r = ask_avs(10, TMID, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_UNAVAILABLE, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(0, r->u.av_res.count);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(2, s.sqn);

    core_restart(); /* SQN persists: the next vector continues from it */
    hello(11, 1, 1);
    r = ask_avs(11, TMID, 9); /* at most LC_CORE_AV_MAX */
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_MAX, r->u.av_res.count);
    TEST_ASSERT_EQUAL_INT64(3, terminal_sqn(&t, &r->u.av_res.av[0]));
    TEST_ASSERT_EQUAL_INT64(6, terminal_sqn(&t, &r->u.av_res.av[3]));

    r = ask_avs(11, TMID2, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_NOT_ACTIVATED, r->u.av_res.status);
    uint8_t n[LC_SIG_NUMBER_LEN];
    number(NUM, n);
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_disable(&K, n, NOW));
    r = ask_avs(11, TMID, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_DISABLED, r->u.av_res.status);
}

static void test_resync_takes_the_terminal_sqn(void)
{
    lc_sig_qr_t qr = sub_world();
    term_t t;
    term(&t, TMID, 0x42, &qr);
    activate(10, &t);
    const lc_core_msg_t *r = ask_avs(10, TMID, 1);
    lc_core_av_t av = r->u.av_res.av[0];
    /* the terminal is at SQN 500: it answers AUTH_FAIL(2) with AUTS */
    static const uint8_t amf0[2] = { 0, 0 };
    lc_milenage_t o;
    uint8_t ms[6];
    lc_sig_sqn_put(ms, 500);
    lc_milenage(t.k, t.opc, av.rand, ms, amf0, &o);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_RESYNC;
    m.u.resync.tmid = TMID;
    memcpy(m.u.resync.rand, av.rand, 16);
    for (int i = 0; i < 6; i++) m.u.resync.auts[i] = (uint8_t)(ms[i] ^ o.ak_s[i]);
    memcpy(m.u.resync.auts + 6, o.mac_s, 8);
    int from = NSENT;
    rx(10, &m);
    r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    TEST_ASSERT_EQUAL_UINT8(1, r->u.av_res.count);
    TEST_ASSERT_EQUAL_INT64(501, terminal_sqn(&t, &r->u.av_res.av[0]));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_RESYNC));

    m.u.resync.auts[13] ^= 1; /* forged */
    from = NSENT;
    rx(10, &m);
    r = sent_since(from, 10, LC_CORE_AV_RES);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_AUTH_FAILED, r->u.av_res.status);
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL));
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_by_tmid(ST.ctx, TMID, &s));
    TEST_ASSERT_EQUAL_UINT64(501, s.sqn);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_subscribers_are_added_by_policy);
    RUN_TEST(test_token_issue_fills_the_qr_and_voids_the_old_token);
    RUN_TEST(test_disable_cancels_the_location_and_voids_tokens);
    RUN_TEST(test_expired_location_is_not_live);
    RUN_TEST(test_activation_binds_and_confirms);
    RUN_TEST(test_failed_activation_commit_leaves_the_token_usable);
    RUN_TEST(test_activation_refusals);
    RUN_TEST(test_reactivation_cancels_the_old_location_first);
    RUN_TEST(test_vectors_rise_and_are_committed_first);
    RUN_TEST(test_resync_takes_the_terminal_sqn);
    return UNITY_END();
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `cd /home/devin/Documents/opencell/core && cmake --build build --target test_core_hss 2>&1 | grep -E "error|warning"; build/tests/test_core_hss >/dev/null 2>&1; echo "exit $?"`
Expected: no compiler output (the tests send frames the core already decodes), then `exit 139` (and the shell's `Segmentation fault` line): the core ignores ACT_FWD, so `activate()` finds no ACT_RES and a test reads through the NULL.

- [ ] **Step 4: The codec's vector is `lc_sig_av_t`**

In `lc_core/include/lc_core_msg.h`, replace:
```c
#include "lc_sig_msg.h" /* lc_sig_msg_t, lc_sig_body_encode/decode */
```
with:
```c
#include "lc_sig_hss.h" /* lc_sig_av_t, lc_sig_av_status_t */
#include "lc_sig_msg.h" /* lc_sig_msg_t, lc_sig_body_encode/decode */
```

In `lc_core/include/lc_core_msg.h`, replace:
```c
/* One authentication vector as AV_RES carries it (TS 33.102 §6.3.2). The
 * layout of lc_sig_av_t (lc_sig_hss.h), which it becomes once lc_sig has it. */
typedef struct {
    uint8_t rand[16], autn[16], xres[8], ck[16], ik[16];
} lc_core_av_t;

/* AV_RES status (§6; network-core spec §4.3). The values of lc_sig_hss.h's
 * lc_sig_av_status_t, which lc_sig_net_av_done takes. */
```
with:
```c
/* One authentication vector as AV_RES carries it (TS 33.102 §6.3.2): the
 * HSS makes it with lc_sig_av_make, and a cell hands it to
 * lc_sig_net_av_done as it is. */
typedef lc_sig_av_t lc_core_av_t;

/* AV_RES status (§6; network-core spec §4.3): the values of lc_sig_hss.h's
 * lc_sig_av_status_t, which lc_sig_net_av_done takes (checked below). */
```

In `lc_core/include/lc_core_msg.h`, replace:
```c
    LC_CORE_AV_AUTH_FAILED = 5      /* resync refused: AUTS did not verify */
} lc_core_av_status_t;
```
with:
```c
    LC_CORE_AV_AUTH_FAILED = 5      /* resync refused: AUTS did not verify */
} lc_core_av_status_t;

_Static_assert((int)LC_CORE_AV_OK == (int)LC_SIG_AV_OK &&
                   (int)LC_CORE_AV_NOT_ACTIVATED == (int)LC_SIG_AV_NOT_ACTIVATED &&
                   (int)LC_CORE_AV_BOUND_ELSEWHERE == (int)LC_SIG_AV_BOUND_ELSEWHERE &&
                   (int)LC_CORE_AV_DISABLED == (int)LC_SIG_AV_DISABLED &&
                   (int)LC_CORE_AV_UNAVAILABLE == (int)LC_SIG_AV_UNAVAILABLE &&
                   (int)LC_CORE_AV_AUTH_FAILED == (int)LC_SIG_AV_AUTH_FAILED,
               "AV_RES status values are lc_sig_net_av_done's");
```

- [ ] **Step 5: The questions**

In `lc_core/lc_core_int.h`, replace:
```c
/* lc_core_reg.c: the number's location if it is live (an expired one is
```
with:
```c
/* lc_core_hss.c: ACT_FWD, AV_REQ, RESYNC from a cell */
void     lc_core_hss_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);

/* lc_core_reg.c: the number's location if it is live (an expired one is
```

In `lc_core/lc_core.c`, replace:
```c
    switch (m->type) { /* each family goes to its own file: HSS, registry, switch */
    case LC_CORE_CALL_ROUTE:
```
with:
```c
    switch (m->type) { /* each family goes to its own file: HSS, registry, switch */
    case LC_CORE_ACT_FWD:
    case LC_CORE_AV_REQ:
    case LC_CORE_RESYNC:
        lc_core_hss_rx(k, l->cell_id, m);
        break;
    case LC_CORE_CALL_ROUTE:
```

In `lc_core/lc_core_hss.c`, replace:
```c
#include <stdio.h>
#include <string.h>

static int home_number
```
with:
```c
#include <stdio.h>
#include <string.h>

#include "lc_sig_hss.h"

static int home_number
```

Append to `lc_core/lc_core_hss.c`:
```c

static int num_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, LC_SIG_NUMBER_LEN) == 0; }

/* §7.1: the plan-5 checks, then bind, all in one commit; then the old
 * terminals are cut off (LOC_CANCEL before ACT_RES, so a cell drops its old
 * session before it hears the answer). */
static void on_act_fwd(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    static const uint8_t none[LC_SIG_NUMBER_LEN] = { 0 };
    const uint8_t *tid = m->u.act_fwd.token_id;
    uint32_t tmid = m->u.act_fwd.tmid;
    lc_core_token_t tok;
    lc_core_sub_t sub, other;
    lc_core_netkey_t key;
    lc_sig_act_token_t t;
    lc_core_msg_t r;
    uint8_t kk[16], opc[16];
    memset(&t, 0, sizeof(t));
    memset(&r, 0, sizeof(r));
    if (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) != 0) {
        lc_core_logf(k, "activation: no network key %u", k->cfg.key_id);
        return;
    }
    /* the token id's block says which core holds it (§14.3): one core, so
     * a token of a block this core isn't home for is unknown here */
    int known = lc_core_route_home(&k->route, lc_core_route_block(&k->route, lc_core_token_block(tid))) &&
                k->st.token_get(k->st.ctx, tid, &tok) == 0 && k->st.sub_get(k->st.ctx, tok.number, &sub) == 0 &&
                sub.state == LC_CORE_SUB_ACTIVE;
    if (known) {
        t.known = 1;
        t.used = tok.used_at != 0;
        t.expiry = tok.expiry;
        memcpy(t.secret, tok.secret, 16);
        t.bound_tmid = sub.activated ? sub.tmid : 0;
        memcpy(t.bound_k, sub.k, 16);
    }
    r.type = LC_CORE_ACT_RES;
    r.u.act_res.req = m->u.act_fwd.req;
    r.u.act_res.tmid = tmid;
    int res = lc_sig_act_answer(&t, key.sk, lc_core_unix(k), tmid, tid, m->u.act_fwd.pkt, m->u.act_fwd.tag,
                                known ? sub.number : none, &r.u.act_res.msg, kk, opc);
    if (res == LC_SIG_ACT_REFUSED) {
        char d[48];
        snprintf(d, sizeof(d), "reason %u", r.u.act_res.msg.u.act_nak.reason);
        lc_core_audit(k, LC_CORE_AUDIT_ACT_FAIL, known ? sub.number : NULL, tmid, cell, d);
    } else if (res == LC_SIG_ACT_FRESH) {
        int had_other = k->st.sub_by_tmid(k->st.ctx, tmid, &other) == 0 && !num_eq(other.number, sub.number);
        k->st.begin(k->st.ctx);
        if (had_other) { /* the terminal's previous subscriber loses it */
            other.activated = 0;
            other.tmid = 0;
            other.updated = lc_core_unix(k);
            k->st.sub_put(k->st.ctx, &other);
        }
        memcpy(sub.k, kk, 16);
        memcpy(sub.opc, opc, 16);
        sub.sqn = 0;
        sub.tmid = tmid;
        sub.activated = 1;
        sub.updated = lc_core_unix(k);
        k->st.sub_put(k->st.ctx, &sub);
        tok.used_at = lc_core_unix(k);
        tok.used_by_tmid = tmid;
        k->st.token_put(k->st.ctx, &tok);
        if (k->st.commit(k->st.ctx) != 0) {
            lc_core_logf(k, "activation of %08x: store FAILED, no answer", (unsigned)tmid);
            return; /* the terminal retries */
        }
        if (had_other) lc_core_loc_cancel(k, other.number, LC_CORE_CANCEL_REACTIVATED);
        lc_core_loc_cancel(k, sub.number, LC_CORE_CANCEL_REACTIVATED); /* wherever it was registered */
        lc_core_audit(k, LC_CORE_AUDIT_ACTIVATE, sub.number, tmid, cell, NULL);
    }
    memset(kk, 0, sizeof(kk));
    memset(opc, 0, sizeof(opc));
    lc_core_send(k, cell, &r);
}

/* 0 (and the subscriber) when tmid may have vectors, else the status. */
static uint8_t av_status(lc_core_t *k, uint32_t tmid, lc_core_sub_t *sub)
{
    if (k->st.sub_by_tmid(k->st.ctx, tmid, sub) != 0) return LC_CORE_AV_NOT_ACTIVATED;
    if (sub->state != LC_CORE_SUB_ACTIVE) return LC_CORE_AV_DISABLED;
    if (!home_number(k, sub->number)) return LC_CORE_AV_UNAVAILABLE;
    return LC_CORE_AV_OK;
}

/* §7.2: count vectors with rising SQN, committed (SQN and av_issued) before
 * AV_RES leaves; for RESYNC, SQN from AUTS first (TS 33.102 §6.3.5). */
static void answer_av(lc_core_t *k, uint32_t cell, uint16_t req, uint32_t tmid, unsigned count, const uint8_t *rand,
                      const uint8_t *auts)
{
    lc_core_msg_t r;
    lc_core_sub_t sub;
    memset(&r, 0, sizeof(r));
    r.type = LC_CORE_AV_RES;
    r.u.av_res.req = req;
    r.u.av_res.tmid = tmid;
    uint8_t st = av_status(k, tmid, &sub);
    int resynced = 0;
    if (st == LC_CORE_AV_OK && auts != NULL) {
        uint8_t ms[6];
        if (lc_sig_av_auts(sub.k, sub.opc, rand, auts, ms) != 0) {
            st = LC_CORE_AV_AUTH_FAILED;
            lc_core_audit(k, LC_CORE_AUDIT_AUTH_FAIL, sub.number, tmid, cell, "AUTS did not verify");
        } else {
            sub.sqn = lc_sig_sqn_get(ms);
            resynced = 1;
        }
    }
    if (st == LC_CORE_AV_OK) {
        count = count < 1 ? 1 : count > LC_CORE_AV_MAX ? LC_CORE_AV_MAX : count;
        k->st.begin(k->st.ctx);
        for (unsigned i = 0; i < count; i++) {
            lc_core_av_issued_t a;
            uint8_t sqn[6], rnd[16];
            sub.sqn++;
            lc_sig_sqn_put(sqn, sub.sqn);
            k->io.random(k->io.ctx, rnd, sizeof(rnd));
            lc_sig_av_make(sub.k, sub.opc, sqn, rnd, &r.u.av_res.av[i]);
            memset(&a, 0, sizeof(a));
            memcpy(a.number, sub.number, LC_SIG_NUMBER_LEN);
            memcpy(a.rand, rnd, 16);
            memcpy(a.xres, r.u.av_res.av[i].xres, 8);
            a.sqn = sub.sqn;
            a.cell_id = cell;
            a.issued = lc_core_unix(k);
            k->st.av_put(k->st.ctx, &a);
        }
        sub.updated = lc_core_unix(k);
        k->st.sub_put(k->st.ctx, &sub);
        if (k->st.commit(k->st.ctx) != 0) {
            lc_core_logf(k, "vectors for %08x: store FAILED", (unsigned)tmid);
            st = LC_CORE_AV_UNAVAILABLE;
            memset(r.u.av_res.av, 0, sizeof(r.u.av_res.av));
        } else {
            memcpy(r.u.av_res.number, sub.number, LC_SIG_NUMBER_LEN);
            r.u.av_res.count = (uint8_t)count;
            if (resynced) lc_core_audit(k, LC_CORE_AUDIT_RESYNC, sub.number, tmid, cell, NULL);
        }
    }
    r.u.av_res.status = st;
    lc_core_send(k, cell, &r);
}

void lc_core_hss_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    switch (m->type) {
    case LC_CORE_ACT_FWD:
        on_act_fwd(k, cell_id, m);
        break;
    case LC_CORE_AV_REQ:
        answer_av(k, cell_id, m->u.av_req.req, m->u.av_req.tmid, m->u.av_req.count, NULL, NULL);
        break;
    case LC_CORE_RESYNC:
        answer_av(k, cell_id, m->u.resync.req, m->u.resync.tmid, 1, m->u.resync.rand, m->u.resync.auts);
        break;
    default:
        break;
    }
}
```

- [ ] **Step 6: Run them to see them pass**

Run: `cd /home/devin/Documents/opencell/core && cmake --build build --target test_core_hss 2>&1 | grep -E "error|warning"; build/tests/test_core_hss | tail -3; build/tests/test_core_msg | tail -1`
Expected: no compiler output, then `10 Tests 0 Failures 0 Ignored` and `OK`, then `OK` (the codec's tests pass on the typedef unchanged).

- [ ] **Step 7: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 6`.

- [ ] **Step 8: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add third_party/opencell-firmware lc_core tests/test_core_hss.c
git commit -m "lc_core: HSS/AuC questions - activation, vectors committed first, resync; firmware net-core <hash>

The submodule moves to firmware net-core (lc_sig_hss, async lc_sig_net);
AV_RES carries lc_sig_av_t.

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 12: The location registry

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 11.

LOC_UPDATE moves a location only with the RES of a vector issued to that same cell (§7.7, §8), and tells the cell a moved terminal left (§7.8); a proven claim for a binding the core has since cancelled is cancelled back; LOC_PURGE from the location's own cell; issued vectors pruned after a day.

**Files:**
- Modify: `lc_core/lc_core_reg.c` (append), `lc_core/include/lc_core.h`, `lc_core/lc_core_int.h`, `lc_core/lc_core.c`, `tests/CMakeLists.txt`
- Test: `tests/test_core_reg.c`

**Interfaces:**
- Consumes: Task 5's `lc_core_loc_*`, Task 11's vectors (AV_REQ), the store's `av_get/av_put/loc_*`.
- Produces (`lc_core_int.h`): `lc_core_reg_rx(k, cell_id, m)` (LOC_UPDATE, LOC_PURGE), `lc_core_reg_tick(k)` (prunes `av_issued` older than 86400 s; `lc_core_tick` calls it hourly, and on its first call).
- Produces (`lc_core_t`): field `prune_at`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_core_reg.c`:
```c
/* The location registry (network-core spec §7.7-7.8, §8): a location moves
 * only on a LOC_UPDATE carrying the RES of a vector issued to that cell;
 * the cell left behind is told; stale claims are cancelled; purges and
 * pruning. */
#include "unity.h"

#include "core_fixture.h"
#include "lc_sig_keys.h"

void setUp(void) {}
void tearDown(void) {}

#define TMID  0x76ad0488u
#define TMID2 0x11223344u

static uint8_t N1[LC_SIG_NUMBER_LEN];

/* NUM activated on TMID (by hand: this test is about locations), cells 1
 * and 2 on links 10 and 20. */
static void reg_world(void)
{
    core_world();
    number("+883160655501234", N1);
    uint8_t got[LC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&K, N1, got));
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, N1, &s));
    s.activated = 1;
    s.tmid = TMID;
    memset(s.k, 0x4b, 16);
    memset(s.opc, 0x0c, 16);
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    hello(10, 1, 1);
    hello(20, 2, 1);
}

/* A vector for TMID issued to the cell on link; returns it. */
static lc_core_av_t vector_for(uint32_t link)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.tmid = TMID;
    m.u.av_req.count = 1;
    int from = NSENT;
    rx(link, &m);
    const lc_core_msg_t *r = sent_since(from, link, LC_CORE_AV_RES);
    TEST_ASSERT_NOT_NULL(r);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_AV_OK, r->u.av_res.status);
    return r->u.av_res.av[0];
}

static void loc_update(uint32_t link, uint32_t tmid, const lc_core_av_t *av)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_UPDATE;
    m.u.loc_update.tmid = tmid;
    memcpy(m.u.loc_update.number, N1, LC_SIG_NUMBER_LEN);
    memcpy(m.u.loc_update.rand, av->rand, 16);
    memcpy(m.u.loc_update.res, av->xres, 8);
    rx(link, &m);
}

static int where(lc_core_loc_t *l) { return ST.loc_get(ST.ctx, N1, l); }

static void test_proven_update_sets_the_location(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_HEX32(TMID, l.tmid);
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 1u + 3600u, l.expires); /* 2 x period_s */
    lc_core_av_issued_t a;
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, N1, av.rand, &a));
    TEST_ASSERT_EQUAL_UINT8(1, a.confirmed);
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&MEM, LC_CORE_AUDIT_REGISTER));

    NOW += 600000000u; /* re-sent after a reconnect: still proves itself, and refreshes */
    loc_update(10, TMID, &av);
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(UNIX0 + 601u + 3600u, l.expires);
}

/* §7.8: the terminal registers on cell 2; cell 1 is told to drop it. */
static void test_move_cancels_at_the_old_cell(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    av = vector_for(20);
    int from = NSENT;
    loc_update(20, TMID, &av);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(2, l.cell_id);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_HEX32(TMID, c->u.loc_cancel.tmid);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_MOVED, c->u.loc_cancel.cause);
    TEST_ASSERT_NULL(sent_since(from, 20, LC_CORE_LOC_CANCEL));
}

/* §8: a rogue cell can't pull a subscriber to itself: not with another
 * cell's vector, not with a wrong RES, not with a RAND never issued. */
static void test_rogue_claims_are_refused_and_audited(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    int from = NSENT;
    loc_update(20, TMID, &av); /* cell 1's vector, claimed by cell 2 */
    lc_core_av_t wrong = vector_for(20);
    wrong.xres[0] ^= 1;
    loc_update(20, TMID, &wrong);
    lc_core_av_t never = wrong;
    memset(never.rand, 0x5a, 16);
    loc_update(20, TMID, &never);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id); /* unmoved */
    TEST_ASSERT_NULL(sent_since(from, 10, LC_CORE_LOC_CANCEL));
    const lc_core_audit_t *a = lc_core_mem_audit(&MEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(2, a->cell_id);
}

/* A proven claim for a binding the core has since cancelled: the claiming
 * cell is told to drop it. */
static void test_stale_claims_are_cancelled_back(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_get(ST.ctx, N1, &s));
    s.tmid = TMID2; /* re-activated on another terminal meanwhile */
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    int from = NSENT;
    loc_update(10, TMID, &av);
    const lc_core_msg_t *c = sent_since(from, 10, LC_CORE_LOC_CANCEL);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_REACTIVATED, c->u.loc_cancel.cause);
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(-1, where(&l));

    s.tmid = TMID;
    s.state = LC_CORE_SUB_DISABLED;
    TEST_ASSERT_EQUAL_INT(0, ST.sub_put(ST.ctx, &s));
    from = NSENT;
    loc_update(10, TMID, &av);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_CANCEL_DISABLED, sent_since(from, 10, LC_CORE_LOC_CANCEL)->u.loc_cancel.cause);
}

static void test_purge_only_from_the_location_cell(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    loc_update(10, TMID, &av);
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_PURGE;
    m.u.loc_purge.tmid = TMID;
    memcpy(m.u.loc_purge.number, N1, LC_SIG_NUMBER_LEN);
    rx(20, &m); /* not cell 2's to purge */
    lc_core_loc_t l;
    TEST_ASSERT_EQUAL_INT(0, where(&l));
    rx(10, &m);
    TEST_ASSERT_EQUAL_INT(-1, where(&l));
}

static void test_issued_vectors_are_pruned_after_a_day(void)
{
    reg_world();
    lc_core_av_t av = vector_for(10);
    lc_core_av_issued_t a;
    advance(1000000u); /* the first tick prunes nothing young */
    TEST_ASSERT_EQUAL_INT(0, ST.av_get(ST.ctx, N1, av.rand, &a));
    NOW += 86400ull * 1000000u;
    advance(3600ull * 1000000u); /* the hourly prune */
    TEST_ASSERT_EQUAL_INT(-1, ST.av_get(ST.ctx, N1, av.rand, &a));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_proven_update_sets_the_location);
    RUN_TEST(test_move_cancels_at_the_old_cell);
    RUN_TEST(test_rogue_claims_are_refused_and_audited);
    RUN_TEST(test_stale_claims_are_cancelled_back);
    RUN_TEST(test_purge_only_from_the_location_cell);
    RUN_TEST(test_issued_vectors_are_pruned_after_a_day);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_core_reg lc_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_core_reg 2>&1 | grep -E "error|warning"; build/tests/test_core_reg | tail -3`
Expected: it builds (nothing new is declared: the test uses the fixture and the store), and fails: `6 Tests 6 Failures 0 Ignored` and `FAIL` (the core ignores LOC_UPDATE and LOC_PURGE, and never prunes).

- [ ] **Step 3: Implement**

In `lc_core/include/lc_core.h`, replace:
```c
    uint64_t        now; /* the now_us of the call being served */
    lc_core_call_t  calls[LC_CORE_CALLS];
```
with:
```c
    uint64_t        now;      /* the now_us of the call being served */
    uint64_t        prune_at; /* next pruning of issued vectors */
    lc_core_call_t  calls[LC_CORE_CALLS];
```

In `lc_core/lc_core_int.h`, replace:
```c
/* Tell the number's cell to drop it (LOC_CANCEL) and forget the location. */
void     lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause);
```
with:
```c
/* Tell the number's cell to drop it (LOC_CANCEL) and forget the location. */
void     lc_core_loc_cancel(lc_core_t *k, const uint8_t number[LC_SIG_NUMBER_LEN], uint8_t cause);
/* LOC_UPDATE and LOC_PURGE from a cell */
void     lc_core_reg_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m);
/* Issued vectors older than a day go (network-core spec §5 av_issued). */
void     lc_core_reg_tick(lc_core_t *k);
```

In `lc_core/lc_core.c`, replace:
```c
        lc_core_hss_rx(k, l->cell_id, m);
        break;
    case LC_CORE_CALL_ROUTE:
```
with:
```c
        lc_core_hss_rx(k, l->cell_id, m);
        break;
    case LC_CORE_LOC_UPDATE:
    case LC_CORE_LOC_PURGE:
        lc_core_reg_rx(k, l->cell_id, m);
        break;
    case LC_CORE_CALL_ROUTE:
```

In `lc_core/lc_core.c`, replace:
```c
            p.type = LC_CORE_PING;
            send_link(k, l, &p);
        }
    }
    lc_core_sw_tick(k);
}
```
with:
```c
            p.type = LC_CORE_PING;
            send_link(k, l, &p);
        }
    }
    if (now_us >= k->prune_at) {
        k->prune_at = now_us + LC_CORE_US(3600);
        lc_core_reg_tick(k);
    }
    lc_core_sw_tick(k);
}
```

Append to `lc_core/lc_core_reg.c`:
```c

static void on_loc_update(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    const uint8_t *num = m->u.loc_update.number;
    uint32_t tmid = m->u.loc_update.tmid;
    lc_core_av_issued_t a;
    lc_core_sub_t s;
    lc_core_loc_t old, l;
    lc_core_netkey_t key;
    if (k->st.av_get(k->st.ctx, num, m->u.loc_update.rand, &a) != 0 || a.cell_id != cell ||
        !lc_sig_ct_equal(m->u.loc_update.res, a.xres, 8)) {
        lc_core_audit(k, LC_CORE_AUDIT_AUTH_FAIL, num, tmid, cell, "LOC_UPDATE: no vector of this cell's matches");
        lc_core_logf(k, "cell %u: location claim for %08x refused", (unsigned)cell, (unsigned)tmid);
        return;
    }
    int known = k->st.sub_get(k->st.ctx, num, &s) == 0;
    if (!known || !s.activated || s.tmid != tmid || s.state != LC_CORE_SUB_ACTIVE) {
        /* a proven registration the core has since cancelled (re-activated
         * or disabled while the cell was cut off): the cell drops it now */
        int off = known && s.state == LC_CORE_SUB_DISABLED;
        cancel(k, cell, tmid, off ? LC_CORE_CANCEL_DISABLED : LC_CORE_CANCEL_REACTIVATED);
        return;
    }
    int moved = k->st.loc_get(k->st.ctx, num, &old) == 0 && (old.cell_id != cell || old.tmid != tmid);
    memset(&l, 0, sizeof(l));
    memcpy(l.number, num, LC_SIG_NUMBER_LEN);
    l.cell_id = cell;
    l.tmid = tmid;
    l.expires = lc_core_unix(k) + 2u * (k->st.netkey_get(k->st.ctx, k->cfg.key_id, &key) == 0 ? key.period_s : 1800u);
    a.confirmed = 1;
    k->st.begin(k->st.ctx);
    k->st.av_put(k->st.ctx, &a);
    k->st.loc_put(k->st.ctx, &l);
    if (k->st.commit(k->st.ctx) != 0) {
        lc_core_logf(k, "location of %08x: store FAILED", (unsigned)tmid);
        return;
    }
    if (moved) { /* §7.8: the cell it left drops it */
        cancel(k, old.cell_id, old.tmid, LC_CORE_CANCEL_MOVED);
        lc_core_audit(k, LC_CORE_AUDIT_LOC_CANCEL, num, old.tmid, old.cell_id, "moved");
    }
    lc_core_audit(k, LC_CORE_AUDIT_REGISTER, num, tmid, cell, NULL);
}

static void on_loc_purge(lc_core_t *k, uint32_t cell, const lc_core_msg_t *m)
{
    lc_core_loc_t l;
    if (k->st.loc_get(k->st.ctx, m->u.loc_purge.number, &l) == 0 && l.cell_id == cell && l.tmid == m->u.loc_purge.tmid) {
        k->st.loc_del(k->st.ctx, m->u.loc_purge.number);
    }
}

void lc_core_reg_rx(lc_core_t *k, uint32_t cell_id, const lc_core_msg_t *m)
{
    if (m->type == LC_CORE_LOC_UPDATE) on_loc_update(k, cell_id, m);
    if (m->type == LC_CORE_LOC_PURGE) on_loc_purge(k, cell_id, m);
}

void lc_core_reg_tick(lc_core_t *k)
{
    uint32_t now = lc_core_unix(k);
    if (now > 86400u) k->st.av_prune(k->st.ctx, now - 86400u);
}
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake --build build --target test_core_reg 2>&1 | grep -E "error|warning"; build/tests/test_core_reg | tail -3`
Expected: no compiler output, then `6 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 7`.

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add lc_core tests/test_core_reg.c tests/CMakeLists.txt
git commit -m "lc_core: location registry - proven LOC_UPDATE only, moved/stale cancels, purge, pruning

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 13: `lc_cell`, and the simulation that runs it against the core

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 12.

A cell's network side (spec §4.1): `lc_sig_net` for the terminals it hears, with its questions answered over the cell↔core protocol; LOC_UPDATE on every registration (again for all of them after each HELLO_ACK); LOC_PURGE when one lapses; LOC_CANCEL → `lc_sig_net_drop`; CALL_ROUTE for calls it can't switch itself, CALL_OFFER → `lc_sig_net_call_in`; app data between two local legs or to the core as MEDIA; every cross-cell leg released (cause 5) the moment the core link drops. While the link is not up, activation gets no answer and a vector question waits for HELLO_ACK (Review Focus 1).

The simulation (spec §9.2) is `tests/net_sim.h`: three cells, five terminals, one core. Its transport carries every message encoded and decoded (so the codec runs end to end) with 20 ms each way.

**Files:**
- Create: `lc_cell/CMakeLists.txt`, `lc_cell/include/lc_cell.h`, `lc_cell/lc_cell.c`
- Modify: `tests/CMakeLists.txt`
- Test: `tests/net_sim.h`, `tests/test_net_sim.c`

**Interfaces:**
- Consumes: `lc_sig_net` (firmware Tasks 9–10, through the submodule), `lc_core_msg_t` (Tasks 1, 11); in the simulation, all of `lc_core` (Tasks 1–6, 11–12) and `lc_sig_term` (with `chan-list`'s changes, which the simulation doesn't exercise until Task 16).
- Produces (`lc_cell.h`):
  ```c
  #define LC_CELL_PING_US 5000000u
  #define LC_CELL_DEAD_US 15000000u
  typedef struct {
      void *ctx;
      int  (*core_send)(void *ctx, const lc_core_msg_t *m);
      void (*core_close)(void *ctx);
      int  (*radio_send)(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n);
      void (*radio_channel)(void *ctx, uint32_t tmid, int on);
      void (*log)(void *ctx, const char *line);
  } lc_cell_io_t;
  typedef struct { uint32_t cell_id; uint64_t boot_id; uint8_t sw_version[3]; uint8_t mode; uint16_t period_s; } lc_cell_cfg_t;
  void lc_cell_init(lc_cell_t *c, const lc_cell_io_t *io, const lc_cell_cfg_t *cfg);
  void lc_cell_ul(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
  void lc_cell_upper(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
  void lc_cell_radio_link(lc_cell_t *c, uint32_t tmid, int granted, uint64_t now_us);
  void lc_cell_core_up(lc_cell_t *c, uint64_t now_us);
  void lc_cell_core_down(lc_cell_t *c, uint64_t now_us);
  void lc_cell_core_rx(lc_cell_t *c, const lc_core_msg_t *m, uint64_t now_us);
  void lc_cell_tick(lc_cell_t *c, uint64_t now_us);
  ```
  `lc_cell_t` holds `net` (its `lc_sig_net_t`), `linked`, `ready`, `echo_number`, the leg table and the registrations.
- Produces (test-only, `net_sim.h`): `CELL[3]`, `TERM[5]` (terminal i's subscriber is `+88316065550123i`, TMID `0x7600000i`), `CORE`, `SMEM`/`SST`, `now`; `sim_world()`, `frame()`, `run_ms(ms)`, `sim_connect(i)`, `sim_disconnect(i)`, `sim_cell_start(i)` (a new boot id), `sim_core_start()`, `activate_on(i, cell)`, `registered_on(i, cell)`, `dial(i, text)`, `press(i, cmd)`, `talk(i, text)`, `event(t, code)`, `ended(i)` (the last ENDED cause, -1 if none), `state(i)`, `located(i)` (cell id at the core, 0 if none), `forget_events()`, `wire_push(...)`, `last_loc_update[cell]`; `CELL[i].mute` and `CELL[i].up` as test hooks.

- [ ] **Step 1: Write the failing test**

Create `tests/net_sim.h`:
```c
/* The multi-cell simulation (network-core spec §9.2): SIM_CELLS cells
 * (lc_cell: lc_sig_net and the core client), SIM_TERMS lc_sig_term
 * terminals on fake radio links (one UL and one DL payload per 120 ms frame,
 * always granted, as test_sig_local.c), and one lc_core on the in-memory
 * store. Cells and core talk through an in-memory transport that carries
 * encoded frames (lc_core_encode/decode) with a one-way delay; tests can
 * disconnect a cell, mute it, restart it, or restart the core. */
#ifndef NET_SIM_H
#define NET_SIM_H

#include <stdio.h>
#include <string.h>

#include "lc_cell.h"
#include "lc_core.h"
#include "lc_core_mem.h"
#include "lc_sig_crypto.h"
#include "lc_sig_term.h"
#include "unity.h"

#define SIM_CELLS    3
#define SIM_TERMS    5
#define SIM_FRAME    120000u
#define SIM_DELAY_US 20000u /* cell <-> core, one way */
#define SIM_WIRE     512
#define SIM_ECHO     "+883160655500100"

typedef struct {
    uint8_t p[32][LC_SIG_LINK_MAX], n[32];
    int     head, count;
} sim_q_t;

typedef struct {
    uint32_t       tmid;
    uint8_t        number[LC_SIG_NUMBER_LEN]; /* its subscriber */
    lc_sig_ident_t id;
    lc_sig_term_t  t;
    int            cell; /* the cell it is attached to; -1: none */
    sim_q_t        ul, dl;
    uint8_t        ev[64][16];
    int            nev;
    uint8_t        app[LC_SIG_APP_MAX], app_n; /* the last app data it received */
} sim_term_t;

typedef struct {
    lc_cell_t c;
    int       up;    /* the process runs: its beacon is on the air */
    uint32_t  link;  /* its link to the core; 0: none */
    int       mute;  /* test hook: its frames to the core are lost */
    uint32_t  boots;
} sim_cell_t;

typedef struct {
    uint64_t at;
    int      to_core;
    int      cell;
    uint32_t link;
    uint8_t  f[LC_CORE_FRAME_MAX];
    size_t   n;
} sim_frame_t;

static sim_cell_t      CELL[SIM_CELLS];
static sim_term_t      TERM[SIM_TERMS];
static sim_frame_t     WIRE[SIM_WIRE];
static int             NWIRE;
static lc_core_mem_t   SMEM;
static lc_core_store_t SST;
static lc_core_route_t SRT;
static lc_core_t       CORE;
static uint64_t        now;
static uint32_t        next_link;
static lc_core_msg_t   last_loc_update[SIM_CELLS]; /* what each cell last claimed (the rogue-cell test replays it) */

static inline int sim_qpush(sim_q_t *q, const uint8_t *p, uint8_t n)
{
    if (q->count == 32) return -1;
    int i = (q->head + q->count++) % 32;
    memcpy(q->p[i], p, n);
    q->n[i] = n;
    return 0;
}

static inline int sim_qpop(sim_q_t *q, uint8_t *p, uint8_t *n)
{
    if (q->count == 0) return -1;
    memcpy(p, q->p[q->head], q->n[q->head]);
    *n = q->n[q->head];
    q->head = (q->head + 1) % 32;
    q->count--;
    return 0;
}

static inline int cell_of_link(uint32_t link)
{
    for (int i = 0; i < SIM_CELLS; i++) {
        if (CELL[i].link == link && link != 0) return i;
    }
    return -1;
}

static inline void wire_push(int to_core, int cell, uint32_t link, const lc_core_msg_t *m)
{
    TEST_ASSERT_TRUE_MESSAGE(NWIRE < SIM_WIRE, "wire full");
    sim_frame_t *w = &WIRE[NWIRE++];
    w->at = now + SIM_DELAY_US;
    w->to_core = to_core;
    w->cell = cell;
    w->link = link;
    w->n = lc_core_encode(m, w->f, sizeof(w->f));
    TEST_ASSERT_TRUE_MESSAGE(w->n > 0, "encode");
}

static inline void wire_forget(uint32_t link)
{
    int k = 0;
    for (int i = 0; i < NWIRE; i++) {
        if (WIRE[i].link != link) WIRE[k++] = WIRE[i];
    }
    NWIRE = k;
}

/* ---- the core's transport ---- */

static int k_send(void *c, uint32_t link, const lc_core_msg_t *m)
{
    (void)c;
    int i = cell_of_link(link);
    if (i < 0) return -1;
    wire_push(0, i, link, m);
    return 0;
}

static void k_close(void *c, uint32_t link) /* the core dropped it: the cell sees its connection close */
{
    (void)c;
    int i = cell_of_link(link);
    if (i < 0) return;
    CELL[i].link = 0;
    wire_forget(link);
    lc_cell_core_down(&CELL[i].c, now);
}

static uint32_t sim_rng = 5;
static void k_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((sim_rng = sim_rng * 1103515245u + 12345u) >> 16);
}
static uint32_t k_unix(void *c)
{
    (void)c;
    return 1790000000u + (uint32_t)(now / 1000000u);
}
static const lc_core_io_t SIM_CORE_IO = { NULL, k_send, k_close, k_random, k_unix, NULL };

/* ---- a cell's transport and radio ---- */

static int c_send(void *ctx, const lc_core_msg_t *m)
{
    sim_cell_t *s = ctx;
    int i = (int)(s - CELL);
    if (s->link == 0) return -1;
    if (m->type == LC_CORE_LOC_UPDATE) last_loc_update[i] = *m;
    if (!s->mute) wire_push(1, i, s->link, m);
    return 0;
}

static void c_close(void *ctx) /* the cell dropped it: the core sees the connection close */
{
    sim_cell_t *s = ctx;
    if (s->link == 0) return;
    lc_core_link_down(&CORE, s->link, now);
    wire_forget(s->link);
    s->link = 0;
}

static int c_radio(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    sim_cell_t *s = ctx;
    for (int i = 0; i < SIM_TERMS; i++) {
        if (TERM[i].tmid == tmid && TERM[i].cell == (int)(s - CELL)) return sim_qpush(&TERM[i].dl, p, n);
    }
    return 0; /* sent; nobody here to hear it */
}

static const lc_cell_io_t SIM_CELL_IO_TEMPLATE = { NULL, c_send, c_close, c_radio, NULL, NULL };

/* ---- terminals ---- */

static int t_send(void *c, const uint8_t *p, uint8_t n) { return sim_qpush(&((sim_term_t *)c)->ul, p, n); }
static int t_svc(void *c, uint8_t cause)
{
    sim_term_t *t = c;
    uint8_t p = (uint8_t)(LC_SIG_KIND_SVC | cause);
    if (t->cell >= 0 && CELL[t->cell].up) lc_cell_upper(&CELL[t->cell].c, t->tmid, &p, 1, now);
    return 0;
}
static void t_event(void *c, const uint8_t *e, uint8_t n)
{
    sim_term_t *t = c;
    memcpy(t->ev[t->nev % 64], e, n);
    t->nev++;
}

/* ---- the world ---- */

static inline void sim_connect(int i)
{
    CELL[i].link = ++next_link;
    lc_core_link_up(&CORE, CELL[i].link, now);
    lc_cell_core_up(&CELL[i].c, now);
}

static inline void sim_disconnect(int i)
{
    if (CELL[i].link == 0) return;
    lc_core_link_down(&CORE, CELL[i].link, now);
    wire_forget(CELL[i].link);
    CELL[i].link = 0;
    lc_cell_core_down(&CELL[i].c, now);
}

static inline void sim_cell_start(int i)
{
    lc_cell_io_t io = SIM_CELL_IO_TEMPLATE;
    io.ctx = &CELL[i];
    lc_cell_cfg_t cfg = { (uint32_t)(i + 1), 0, { 0, 7, 0 }, LC_SIG_MODE_PART15, 1800 };
    cfg.boot_id = 0xB0070000ull + (uint64_t)(i + 1) * 0x100u + ++CELL[i].boots; /* a new boot id every start */
    lc_cell_init(&CELL[i].c, &io, &cfg);
    CELL[i].up = 1;
}

static inline void sim_core_start(void)
{
    lc_core_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    lc_sig_number_to_bcd(SIM_ECHO, strlen(SIM_ECHO), cfg.echo_number);
    TEST_ASSERT_EQUAL_INT(0, lc_core_init(&CORE, &SIM_CORE_IO, &SST, &SRT, &cfg));
}

static sim_frame_t DUE[SIM_WIRE];

/* Every frame whose time has come, in the order sent; a frame of a
 * connection that has closed since is lost. */
static inline void deliver(void)
{
    int nd = 0, k = 0;
    for (int i = 0; i < NWIRE; i++) {
        if (WIRE[i].at <= now) {
            DUE[nd++] = WIRE[i];
        } else {
            WIRE[k++] = WIRE[i];
        }
    }
    NWIRE = k;
    for (int i = 0; i < nd; i++) {
        lc_core_msg_t m;
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, lc_core_decode(DUE[i].f, DUE[i].n, &m), "decode");
        if (CELL[DUE[i].cell].link != DUE[i].link) continue;
        if (DUE[i].to_core) {
            lc_core_rx(&CORE, DUE[i].link, &m, now);
        } else {
            lc_cell_core_rx(&CELL[DUE[i].cell].c, &m, now);
        }
    }
}

/* One 120 ms frame: the wire, every terminal's link state and timers, the
 * cells, the core, then one UL and one DL payload per attached terminal. */
static inline void frame(void)
{
    uint8_t p[LC_SIG_LINK_MAX], n;
    now += SIM_FRAME;
    deliver();
    for (int i = 0; i < SIM_TERMS; i++) {
        sim_term_t *t = &TERM[i];
        int on = t->cell >= 0 && CELL[t->cell].up;
        lc_sig_term_link(&t->t, on, on, now);
        if (on) lc_cell_radio_link(&CELL[t->cell].c, t->tmid, 1, now);
        lc_sig_term_tick(&t->t, now);
    }
    for (int i = 0; i < SIM_CELLS; i++) {
        if (CELL[i].up) lc_cell_tick(&CELL[i].c, now);
    }
    lc_core_tick(&CORE, now);
    for (int i = 0; i < SIM_TERMS; i++) {
        sim_term_t *t = &TERM[i];
        if (t->cell < 0 || !CELL[t->cell].up) continue;
        lc_cell_t *c = &CELL[t->cell].c;
        if (sim_qpop(&t->ul, p, &n) == 0) {
            lc_cell_ul(c, t->tmid, p, n, now);
        } else {
            lc_cell_ul(c, t->tmid, NULL, 0, now); /* its UL slot was heard, empty */
        }
        if (sim_qpop(&t->dl, p, &n) == 0) {
            if ((p[0] & 0xF0u) == LC_SIG_KIND_SIG) {
                lc_sig_term_rx(&t->t, p, n, now);
            } else if (p[0] == LC_SIG_KIND_DATA) {
                lc_sig_term_data_in(&t->t, p, n, t->app, &t->app_n);
            }
        }
    }
}

static inline void run_ms(uint32_t ms)
{
    for (uint32_t t = 0; t < ms; t += SIM_FRAME / 1000u) frame();
}

/* Terminal i's subscriber is +883 1 606 555 0123<i>; nobody is activated. */
static inline void sim_world(void)
{
    uint8_t r[32];
    memset(CELL, 0, sizeof(CELL));
    memset(TERM, 0, sizeof(TERM));
    memset(last_loc_update, 0, sizeof(last_loc_update));
    NWIRE = 0;
    now = 0;
    next_link = 0;
    sim_rng = 5;
    lc_core_mem_init(&SMEM);
    SST = lc_core_mem_store(&SMEM);
    memset(r, 0x11, 32);
    TEST_ASSERT_EQUAL_INT(0, lc_core_netkey_new(&SST, 1, 1800, r, 1790000000u));
    lc_core_route_init(&SRT, 1);
    TEST_ASSERT_EQUAL_INT(0, lc_core_route_add(&SRT, "8831606", 1, 1));
    sim_core_start();
    for (int i = 0; i < SIM_CELLS; i++) {
        char name[] = "cell ?";
        name[5] = (char)('1' + i);
        TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&CORE, (uint32_t)(i + 1), name, LC_SIG_MODE_PART15, 0));
        sim_cell_start(i);
        sim_connect(i);
    }
    for (int i = 0; i < SIM_TERMS; i++) {
        sim_term_t *t = &TERM[i];
        char num[] = "+88316065550123?";
        uint8_t got[LC_SIG_NUMBER_LEN];
        num[15] = (char)('0' + i);
        TEST_ASSERT_EQUAL_INT(0, lc_sig_number_to_bcd(num, strlen(num), t->number));
        TEST_ASSERT_EQUAL_INT(0, lc_core_sub_add(&CORE, t->number, got));
        t->tmid = 0x76000000u + (uint32_t)i;
        t->cell = -1;
        memset(r, 0x40 + i, 32);
        lc_sig_ident_new(&t->id, r);
        const lc_sig_term_io_t io = { t, t_send, t_svc, NULL, t_event };
        lc_sig_term_init(&t->t, &io, &t->id, t->tmid, now);
    }
    run_ms(500); /* HELLO, HELLO_ACK */
    for (int i = 0; i < SIM_CELLS; i++) TEST_ASSERT_TRUE(CELL[i].c.ready);
}

static inline const uint8_t *event(const sim_term_t *t, uint8_t code)
{
    for (int i = t->nev - 1; i >= 0 && i >= t->nev - 64; i--) {
        if (t->ev[i % 64][0] == code) return t->ev[i % 64];
    }
    return NULL;
}

static inline uint8_t state(int i) { return lc_sig_term_state(&TERM[i].t); }

static inline void command(int i, const uint8_t *cmd, size_t n)
{
    TEST_ASSERT_EQUAL_UINT8(0, lc_sig_term_command(&TERM[i].t, cmd, n, now));
}

/* A fresh QR from the core, scanned on terminal i (attached to cell). */
static inline void activate_on(int i, int cell)
{
    lc_sig_qr_t qr;
    uint8_t cmd[1 + LC_SIG_QR_TEXT + 1];
    TERM[i].cell = cell;
    TEST_ASSERT_EQUAL_INT(0, lc_core_token_issue(&CORE, TERM[i].number, 3600, &qr));
    cmd[0] = LC_SIG_CMD_ACTIVATE;
    size_t n = lc_sig_qr_format(&qr, (char *)cmd + 1, sizeof(cmd) - 1);
    command(i, cmd, 1 + n);
}

/* Terminal i activated and registered on cell. */
static inline void registered_on(int i, int cell)
{
    activate_on(i, cell);
    run_ms(8000);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(LC_SIG_ST_REGISTERED, state(i), "registered");
}

static inline void dial(int i, const char *number)
{
    uint8_t cmd[1 + 24];
    size_t n = strlen(number);
    cmd[0] = LC_SIG_CMD_DIAL;
    memcpy(cmd + 1, number, n);
    command(i, cmd, 1 + n);
}

static inline void press(int i, uint8_t cmd) { command(i, &cmd, 1); }

/* App data from terminal i, as its app would send it. */
static inline void talk(int i, const char *s)
{
    uint8_t out[LC_SIG_LINK_MAX], on;
    TEST_ASSERT_EQUAL_INT(0, lc_sig_term_data_out(&TERM[i].t, (const uint8_t *)s, (uint8_t)strlen(s), out, &on));
    sim_qpush(&TERM[i].ul, out, on);
}

/* The cause of terminal i's last ENDED, or -1. */
static inline int ended(int i)
{
    const uint8_t *e = event(&TERM[i], LC_SIG_EV_ENDED);
    return e != NULL ? e[5] : -1;
}

static inline void forget_events(void)
{
    for (int i = 0; i < SIM_TERMS; i++) TERM[i].nev = 0;
}

/* The core's view: the cell (1-based id) number i is located on, 0 if none. */
static inline uint32_t located(int i)
{
    lc_core_loc_t l;
    return SST.loc_get(SST.ctx, TERM[i].number, &l) == 0 ? l.cell_id : 0;
}

#endif
```

Create `tests/test_net_sim.c`:
```c
/* The multi-cell simulation (network-core spec §9.2): lc_sig_term terminals
 * on three cells (lc_cell) and one core (lc_core), over net_sim.h. Activation
 * and registration through the core; calls across cells and within one, the
 * refusals and their causes, the echo service; idle moves, re-activation
 * elsewhere, cell and core restarts, a backhaul outage, resync, and a rogue
 * cell. */
#include "unity.h"

#include "net_sim.h"

void setUp(void) {}
void tearDown(void) {}

static void test_activation_and_registration_through_the_core(void)
{
    sim_world();
    activate_on(0, 0);
    run_ms(8000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_ACTIVATED));
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(1, located(0)); /* cell 1 told the core (LOC_UPDATE) */
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    TEST_ASSERT_EQUAL_UINT64(lc_sig_sqn_get(TERM[0].id.sqn), s.sqn); /* terminal and HSS agree */
}

/* Review Focus 1: a terminal registers while its cell's core link is still
 * coming up (after a cell or core restart). The question waits for
 * HELLO_ACK and registration completes, instead of timing out and backing
 * off for 30 s. */
static void test_registration_while_the_core_link_comes_up(void)
{
    sim_world();
    registered_on(0, 0);
    sim_disconnect(0);
    const lc_sig_term_io_t io = TERM[0].t.io;
    lc_sig_term_init(&TERM[0].t, &io, &TERM[0].id, TERM[0].tmid, now); /* reboot: it registers again */
    forget_events();
    run_ms(1000); /* its REG_REQ reaches a cell without a core */
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    sim_connect(0);
    run_ms(2000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_REG_FAILED));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_activation_and_registration_through_the_core);
    RUN_TEST(test_registration_while_the_core_link_comes_up);
    return UNITY_END();
}
```

In `CMakeLists.txt`, replace:
```cmake
add_subdirectory(lc_core)
```
with:
```cmake
add_subdirectory(lc_core)
add_subdirectory(lc_cell)
```

Append to `tests/CMakeLists.txt`:
```cmake
lc_test(test_net_sim lc_cell)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build 2>&1 | grep -m1 "add_subdirectory given source"`
Expected: `add_subdirectory given source "lc_cell" which is not an existing directory.`: no `lc_cell` yet.

- [ ] **Step 3: Implement**

Create `lc_cell/CMakeLists.txt`:
```cmake
# lc_cell: a cell's network side as a portable C11 library (network-core
# spec §4.1). oc-cell (plan 8) adds the radio backend and the transport.
add_library(lc_cell STATIC lc_cell.c)
target_include_directories(lc_cell PUBLIC include)
target_link_libraries(lc_cell PUBLIC lc_core lc_sig)
```

Create `lc_cell/include/lc_cell.h`:
```c
/* lc_cell: a cell's network side (network-core spec §4.1): lc_sig_net for
 * the terminals the cell hears, and the core client that answers
 * lc_sig_net's questions over the cell <-> core protocol (§6-7). It keeps
 * the leg table (lc_sig_net call id <-> the leg's ref), forwards app data
 * between two local legs or to the core as MEDIA, re-sends LOC_UPDATE for
 * every live registration after each HELLO_ACK, and releases every
 * cross-cell leg (cause 5) when the link to the core drops. Portable C11
 * with no OS calls: oc-cell (plan 8) adds the radio backend and the
 * transport; the multi-cell simulation drives it directly. */
#ifndef LC_CELL_H
#define LC_CELL_H

#include "lc_core_msg.h"
#include "lc_sig_net.h"

#define LC_CELL_PING_US 5000000u  /* PING when nothing was sent to the core for this long */
#define LC_CELL_DEAD_US 15000000u /* the core link is down after this long without a frame */

typedef struct {
    void *ctx;
    int  (*core_send)(void *ctx, const lc_core_msg_t *m); /* 0 queued; -1 no link */
    void (*core_close)(void *ctx);                        /* the link went silent: the transport drops it */
    int  (*radio_send)(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n); /* one DL payload: 0 queued */
    void (*radio_channel)(void *ctx, uint32_t tmid, int on);                   /* page and grant / release */
    void (*log)(void *ctx, const char *line);
} lc_cell_io_t;

typedef struct {
    uint32_t cell_id;
    uint64_t boot_id;       /* random at every process start */
    uint8_t  sw_version[3];
    uint8_t  mode;          /* lc_sig_mode_t until HELLO_ACK says otherwise */
    uint16_t period_s;
} lc_cell_cfg_t;

typedef struct {
    int      used;
    uint32_t call_id; /* lc_sig_net's */
    uint32_t ref;     /* on the wire: the call id (a call from here), or the core's call ref (a call to here) */
    uint32_t tmid;
    uint16_t seq;     /* MEDIA sent on this leg */
} lc_cell_leg_t;

typedef struct {
    int      used;
    uint32_t tmid;
    uint8_t  number[LC_SIG_NUMBER_LEN], rand[16], res[8]; /* for LOC_UPDATE, again after a reconnect */
} lc_cell_reg_t;

typedef struct {
    lc_cell_io_t  io;
    lc_cell_cfg_t cfg;
    lc_sig_net_t  net;
    int           linked; /* the transport is up */
    int           ready;  /* ...and the core accepted HELLO */
    uint64_t      now, last_rx, last_tx;
    uint16_t      req;
    uint8_t       echo_number[LC_SIG_NUMBER_LEN];
    lc_cell_leg_t legs[LC_SIG_NET_TERMS];
    lc_cell_reg_t regs[LC_SIG_NET_TERMS];
} lc_cell_t;

void lc_cell_init(lc_cell_t *c, const lc_cell_io_t *io, const lc_cell_cfg_t *cfg);
/* radio side: one UL payload, one RACH UPPER payload, a terminal's grant */
void lc_cell_ul(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
void lc_cell_upper(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us);
void lc_cell_radio_link(lc_cell_t *c, uint32_t tmid, int granted, uint64_t now_us);
/* core side: the transport connected (HELLO goes out), dropped, or brought a frame */
void lc_cell_core_up(lc_cell_t *c, uint64_t now_us);
void lc_cell_core_down(lc_cell_t *c, uint64_t now_us);
void lc_cell_core_rx(lc_cell_t *c, const lc_core_msg_t *m, uint64_t now_us);
void lc_cell_tick(lc_cell_t *c, uint64_t now_us);

#endif
```

Create `lc_cell/lc_cell.c`:
```c
#include "lc_cell.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void logf_(lc_cell_t *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void logf_(lc_cell_t *c, const char *fmt, ...)
{
    char line[160];
    va_list ap;
    if (c->io.log == NULL) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    c->io.log(c->io.ctx, line);
}

static int to_core(lc_cell_t *c, lc_core_msg_t *m)
{
    if (!c->linked) return -1;
    c->last_tx = c->now;
    return c->io.core_send(c->io.ctx, m);
}

/* ---- the leg table and the registrations ---- */

static lc_cell_leg_t *leg_by_call(lc_cell_t *c, uint32_t call_id)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->legs[i].used && c->legs[i].call_id == call_id) return &c->legs[i];
    }
    return NULL;
}

static lc_cell_leg_t *leg_by_ref(lc_cell_t *c, uint32_t ref)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->legs[i].used && c->legs[i].ref == ref) return &c->legs[i];
    }
    return NULL;
}

static lc_cell_leg_t *leg_by_tmid(lc_cell_t *c, uint32_t tmid)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->legs[i].used && c->legs[i].tmid == tmid) return &c->legs[i];
    }
    return NULL;
}

static lc_cell_leg_t *leg_new(lc_cell_t *c, uint32_t call_id, uint32_t ref, uint32_t tmid)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (!c->legs[i].used) {
            lc_cell_leg_t *l = &c->legs[i];
            memset(l, 0, sizeof(*l));
            l->used = 1;
            l->call_id = call_id;
            l->ref = ref;
            l->tmid = tmid;
            return l;
        }
    }
    return NULL;
}

static lc_cell_reg_t *reg_of(lc_cell_t *c, uint32_t tmid, int create)
{
    lc_cell_reg_t *free_slot = NULL;
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->regs[i].used && c->regs[i].tmid == tmid) return &c->regs[i];
        if (!c->regs[i].used && free_slot == NULL) free_slot = &c->regs[i];
    }
    if (!create || free_slot == NULL) return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = 1;
    free_slot->tmid = tmid;
    return free_slot;
}

static void loc_update(lc_cell_t *c, const lc_cell_reg_t *r)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_UPDATE;
    m.u.loc_update.tmid = r->tmid;
    memcpy(m.u.loc_update.number, r->number, LC_SIG_NUMBER_LEN);
    memcpy(m.u.loc_update.rand, r->rand, 16);
    memcpy(m.u.loc_update.res, r->res, 8);
    to_core(c, &m);
}

static void call_msg(lc_cell_t *c, uint8_t type, uint32_t ref, uint8_t cause)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = type;
    m.u.call.ref = ref;
    m.u.call.cause = cause;
    to_core(c, &m);
}

/* ---- lc_sig_net's io: the questions go to the core ---- */

static void n_act_req(void *ctx, uint32_t tmid, const uint8_t token_id[8], const uint8_t pkt[32], const uint8_t tag[8])
{
    lc_cell_t *c = ctx;
    if (!c->ready) return; /* activation always needs the core: the terminal times out */
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_ACT_FWD;
    m.u.act_fwd.req = ++c->req;
    m.u.act_fwd.tmid = tmid;
    memcpy(m.u.act_fwd.token_id, token_id, 8);
    memcpy(m.u.act_fwd.pkt, pkt, 32);
    memcpy(m.u.act_fwd.tag, tag, 8);
    to_core(c, &m);
}

static void ask_av(lc_cell_t *c, uint32_t tmid)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_AV_REQ;
    m.u.av_req.req = ++c->req;
    m.u.av_req.tmid = tmid;
    m.u.av_req.count = 1; /* no vector cache yet (plan 9) */
    to_core(c, &m);
}

static void n_av_req(void *ctx, uint32_t tmid)
{
    lc_cell_t *c = ctx;
    if (c->ready) ask_av(c, tmid); /* else asked when the core accepts HELLO, if still wanted */
}

static void n_resync_req(void *ctx, uint32_t tmid, const uint8_t rand[16], const uint8_t auts[14])
{
    lc_cell_t *c = ctx;
    if (!c->ready) {
        lc_sig_net_av_done(&c->net, tmid, LC_SIG_AV_UNAVAILABLE, NULL, NULL, c->now);
        return;
    }
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_RESYNC;
    m.u.resync.req = ++c->req;
    m.u.resync.tmid = tmid;
    memcpy(m.u.resync.rand, rand, 16);
    memcpy(m.u.resync.auts, auts, 14);
    to_core(c, &m);
}

static void n_registered(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN], const uint8_t rand[16],
                         const uint8_t res[8])
{
    lc_cell_t *c = ctx;
    lc_cell_reg_t *r = reg_of(c, tmid, 1);
    if (r == NULL) return;
    memcpy(r->number, number, LC_SIG_NUMBER_LEN);
    memcpy(r->rand, rand, 16);
    memcpy(r->res, res, 8);
    if (c->ready) loc_update(c, r); /* otherwise after the next HELLO_ACK */
}

static void n_unregistered(void *ctx, uint32_t tmid, const uint8_t number[LC_SIG_NUMBER_LEN])
{
    lc_cell_t *c = ctx;
    lc_cell_reg_t *r = reg_of(c, tmid, 0);
    if (r != NULL) r->used = 0;
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_LOC_PURGE;
    m.u.loc_purge.tmid = tmid;
    memcpy(m.u.loc_purge.number, number, LC_SIG_NUMBER_LEN);
    if (c->ready) to_core(c, &m);
}

static int n_send(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    lc_cell_t *c = ctx;
    return c->io.radio_send(c->io.ctx, tmid, p, n);
}

static void n_channel(void *ctx, uint32_t tmid, int on)
{
    lc_cell_t *c = ctx;
    if (c->io.radio_channel != NULL) c->io.radio_channel(c->io.ctx, tmid, on);
}

static void n_call(void *ctx, const lc_sig_net_call_ev_t *e)
{
    lc_cell_t *c = ctx;
    lc_cell_leg_t *l = leg_by_call(c, e->call_id);
    switch (e->what) {
    case LC_SIG_NET_MO: { /* not a number registered here: the core routes it (§7.4) */
        lc_core_msg_t m;
        memset(&m, 0, sizeof(m));
        m.type = LC_CORE_CALL_ROUTE;
        m.u.call_route.leg_ref = e->call_id;
        memcpy(m.u.call_route.called, e->number, LC_SIG_NUMBER_LEN);
        if (!c->ready || lc_sig_net_number(&c->net, e->tmid, m.u.call_route.caller) != 0 ||
            leg_new(c, e->call_id, e->call_id, e->tmid) == NULL) {
            lc_sig_net_peer_release(&c->net, e->call_id, LC_SIG_CAUSE_NET_FAILURE, c->now);
            return;
        }
        to_core(c, &m);
        return;
    }
    case LC_SIG_NET_ALERTING:
        if (l != NULL) call_msg(c, LC_CORE_CALL_ALERT, l->ref, 0);
        return;
    case LC_SIG_NET_ANSWERED:
        if (l != NULL) call_msg(c, LC_CORE_CALL_ANSWER, l->ref, 0);
        return;
    case LC_SIG_NET_ENDED:
        if (l != NULL) {
            l->used = 0;
            call_msg(c, LC_CORE_CALL_RELEASE, l->ref, e->cause); /* the same cause on the other leg */
        }
        return;
    default: /* LOCAL: switched here, nothing for the core */
        return;
    }
}

static void n_log(void *ctx, const char *line)
{
    lc_cell_t *c = ctx;
    logf_(c, "%s", line);
}

void lc_cell_init(lc_cell_t *c, const lc_cell_io_t *io, const lc_cell_cfg_t *cfg)
{
    memset(c, 0, sizeof(*c));
    c->io = *io;
    c->cfg = *cfg;
    const lc_sig_net_io_t nio = { c,      n_act_req, n_av_req, n_resync_req, n_registered, n_unregistered,
                                  n_send, n_channel, n_call,   n_log };
    const lc_sig_net_cfg_t ncfg = { cfg->mode, cfg->period_s };
    lc_sig_net_init(&c->net, &nio, &ncfg);
}

/* ---- radio side ---- */

void lc_cell_ul(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us)
{
    c->now = now_us;
    lc_sig_net_heard(&c->net, tmid, now_us);
    if (n > 0 && (p[0] & 0xF0u) == LC_SIG_KIND_SIG) {
        lc_sig_net_rx(&c->net, tmid, p, n, now_us);
        return;
    }
    if (n == 0 || p[0] != LC_SIG_KIND_DATA) return;
    uint8_t d[LC_SIG_APP_MAX], dn, out[LC_SIG_LINK_MAX], on;
    uint32_t to = 0;
    if (lc_sig_net_local_peer(&c->net, tmid, &to)) { /* a local call: straight to the other leg */
        if (lc_sig_net_data_in(&c->net, tmid, p, n, d, &dn) == 0 && lc_sig_net_data_out(&c->net, to, d, dn, out, &on) == 0) {
            c->io.radio_send(c->io.ctx, to, out, on);
        }
        return;
    }
    lc_cell_leg_t *l = leg_by_tmid(c, tmid);
    if (l == NULL || lc_sig_net_data_in(&c->net, tmid, p, n, d, &dn) != 0) return;
    lc_core_msg_t m; /* to the far leg, in the clear inside the core link (§7.4 step 6) */
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_MEDIA;
    m.u.media.ref = l->ref;
    m.u.media.seq = l->seq++;
    m.u.media.len = dn;
    memcpy(m.u.media.data, d, dn);
    to_core(c, &m);
}

void lc_cell_upper(lc_cell_t *c, uint32_t tmid, const uint8_t *p, uint8_t n, uint64_t now_us)
{
    c->now = now_us;
    if (n == 1 && (p[0] & 0xF0u) == LC_SIG_KIND_SVC) lc_sig_net_service_req(&c->net, tmid, p[0] & 0x0Fu, now_us);
}

void lc_cell_radio_link(lc_cell_t *c, uint32_t tmid, int granted, uint64_t now_us)
{
    c->now = now_us;
    lc_sig_net_link(&c->net, tmid, granted, now_us);
}

/* ---- core side ---- */

void lc_cell_core_up(lc_cell_t *c, uint64_t now_us)
{
    c->now = c->last_rx = c->last_tx = now_us;
    c->linked = 1;
    c->ready = 0;
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_HELLO;
    m.u.hello.proto = LC_CORE_PROTO;
    m.u.hello.cell_id = c->cfg.cell_id;
    m.u.hello.boot_id = c->cfg.boot_id;
    memcpy(m.u.hello.sw_version, c->cfg.sw_version, 3);
    to_core(c, &m);
}

/* §7.4 timers: with no core, every cross-cell leg ends at once (cause 5);
 * local calls and registrations go on. */
void lc_cell_core_down(lc_cell_t *c, uint64_t now_us)
{
    c->now = now_us;
    c->linked = 0;
    c->ready = 0;
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (!c->legs[i].used) continue;
        c->legs[i].used = 0;
        lc_sig_net_peer_release(&c->net, c->legs[i].call_id, LC_SIG_CAUSE_NET_FAILURE, now_us);
    }
}

static uint32_t tmid_of_call(const lc_cell_t *c, uint32_t call_id)
{
    for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) {
        if (c->net.s[i].used && c->net.s[i].call_id == call_id) return c->net.s[i].tmid;
    }
    return 0;
}

static void on_offer(lc_cell_t *c, const lc_core_msg_t *m)
{
    uint32_t cid = 0;
    uint32_t ref = m->u.call_offer.call_ref;
    int r = lc_sig_net_call_in(&c->net, m->u.call_offer.callee, m->u.call_offer.caller, c->now, &cid);
    if (r == 0 && leg_new(c, cid, ref, tmid_of_call(c, cid)) == NULL) { /* no room for the leg */
        lc_sig_net_peer_release(&c->net, cid, LC_SIG_CAUSE_NET_FAILURE, c->now);
        r = LC_SIG_NET_IN_UNREACHABLE;
    }
    if (r == LC_SIG_NET_IN_BUSY) call_msg(c, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_BUSY);
    if (r == LC_SIG_NET_IN_UNREACHABLE) call_msg(c, LC_CORE_CALL_RELEASE, ref, LC_SIG_CAUSE_UNREACHABLE);
}

void lc_cell_core_rx(lc_cell_t *c, const lc_core_msg_t *m, uint64_t now_us)
{
    lc_cell_leg_t *l;
    c->now = c->last_rx = now_us;
    switch (m->type) {
    case LC_CORE_HELLO_ACK:
        c->ready = 1;
        c->net.cfg.mode = m->u.hello_ack.mode;
        c->net.cfg.period_s = m->u.hello_ack.period_s;
        memcpy(c->echo_number, m->u.hello_ack.echo_number, LC_SIG_NUMBER_LEN);
        for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) { /* the core may have lost them (§7.10, §14.6) */
            if (c->regs[i].used && lc_sig_net_registered(&c->net, c->regs[i].tmid)) loc_update(c, &c->regs[i]);
        }
        for (unsigned i = 0; i < LC_SIG_NET_TERMS; i++) { /* registrations that waited for the core */
            const lc_sig_net_sess_t *s = &c->net.s[i];
            if (s->used && s->av_wait && now_us - s->av_at < LC_SIG_NET_ASK_US) ask_av(c, s->tmid);
        }
        logf_(c, "core: HELLO accepted");
        break;
    case LC_CORE_HELLO_NAK:
        logf_(c, "core: HELLO refused (%u)", m->u.hello_nak.reason);
        c->ready = 0;
        if (c->io.core_close != NULL) c->io.core_close(c->io.ctx);
        lc_cell_core_down(c, now_us);
        break;
    case LC_CORE_PING: {
        lc_core_msg_t p;
        memset(&p, 0, sizeof(p));
        p.type = LC_CORE_PONG;
        to_core(c, &p);
        break;
    }
    case LC_CORE_ACT_RES:
        lc_sig_net_act_done(&c->net, m->u.act_res.tmid, &m->u.act_res.msg, now_us);
        break;
    case LC_CORE_AV_RES: {
        uint8_t st = m->u.av_res.status == LC_SIG_AV_OK && m->u.av_res.count == 0 ? LC_SIG_AV_UNAVAILABLE
                                                                                   : m->u.av_res.status;
        lc_sig_net_av_done(&c->net, m->u.av_res.tmid, st, m->u.av_res.number, &m->u.av_res.av[0], now_us);
        break;
    }
    case LC_CORE_LOC_CANCEL: {
        lc_cell_reg_t *r = reg_of(c, m->u.loc_cancel.tmid, 0);
        if (r != NULL) r->used = 0;
        /* moved: as a lost link would (no handover); otherwise the network cut it */
        uint8_t cause = m->u.loc_cancel.cause == LC_CORE_CANCEL_MOVED ? LC_SIG_CAUSE_LINK_LOST : LC_SIG_CAUSE_NET_FAILURE;
        lc_sig_net_drop(&c->net, m->u.loc_cancel.tmid, cause, now_us);
        break;
    }
    case LC_CORE_CALL_OFFER:
        on_offer(c, m);
        break;
    case LC_CORE_CALL_ALERT:
        if ((l = leg_by_ref(c, m->u.call.ref)) != NULL) lc_sig_net_peer_alert(&c->net, l->call_id, now_us);
        break;
    case LC_CORE_CALL_ANSWER:
        if ((l = leg_by_ref(c, m->u.call.ref)) != NULL) lc_sig_net_peer_answer(&c->net, l->call_id, now_us);
        break;
    case LC_CORE_CALL_RELEASE:
        if ((l = leg_by_ref(c, m->u.call.ref)) != NULL) {
            l->used = 0; /* the core knows: its ENDED goes nowhere */
            lc_sig_net_peer_release(&c->net, l->call_id, m->u.call.cause, now_us);
        }
        break;
    case LC_CORE_MEDIA:
        if ((l = leg_by_ref(c, m->u.media.ref)) != NULL) {
            uint8_t out[LC_SIG_LINK_MAX], on;
            if (lc_sig_net_data_out(&c->net, l->tmid, m->u.media.data, m->u.media.len, out, &on) == 0) {
                c->io.radio_send(c->io.ctx, l->tmid, out, on);
            }
        }
        break;
    default:
        break;
    }
}

void lc_cell_tick(lc_cell_t *c, uint64_t now_us)
{
    c->now = now_us;
    lc_sig_net_tick(&c->net, now_us);
    if (!c->linked) return;
    if (now_us - c->last_rx >= LC_CELL_DEAD_US) {
        logf_(c, "core: silent for 15 s, link dropped");
        if (c->io.core_close != NULL) c->io.core_close(c->io.ctx);
        lc_cell_core_down(c, now_us);
    } else if (now_us - c->last_tx >= LC_CELL_PING_US) {
        lc_core_msg_t p;
        memset(&p, 0, sizeof(p));
        p.type = LC_CORE_PING;
        to_core(c, &p);
    }
}
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_net_sim 2>&1 | grep -E "error|warning"; build/tests/test_net_sim | tail -3`
Expected: no compiler output, then `2 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 8`.

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add CMakeLists.txt lc_cell tests/net_sim.h tests/test_net_sim.c tests/CMakeLists.txt
git commit -m "lc_cell: a cell's network side; multi-cell simulation with activation and registration

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 14: The simulation: calls

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 13.

Spec §9.2's call scenarios with real terminals on three cells: a cross-cell call with ringing, answer, app data both ways and hang-up from each side; a same-cell call that never involves the core; reject, busy, unreachable (unknown number, registered nowhere) and no answer (60 s); both terminals dialling each other at once (Review Focus 3); the echo service.

**Files:**
- Modify: `tests/test_net_sim.c`

**Interfaces:**
- Consumes: Task 13's `net_sim.h`. Produces nothing new.

- [ ] **Step 1: Write the tests**

In `tests/test_net_sim.c`, replace:
```c
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_activation_and_registration_through_the_core);
    RUN_TEST(test_registration_while_the_core_link_comes_up);
    return UNITY_END();
}
```
with:
```c
/* T0 on cell 1 calls T1 on cell 2: ring, answer, app data both ways,
 * hang-up by the caller; then again, hung up by the callee. */
static void test_cross_cell_call(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    const uint8_t *in = event(&TERM[1], LC_SIG_EV_INCOMING);
    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM[0].number, in + 5, LC_SIG_NUMBER_LEN); /* caller id across cells */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_RINGING_OUT, state(0));
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
    talk(0, "HELLO FROM CELL 1");
    run_ms(1000);
    TEST_ASSERT_EQUAL_UINT8(17, TERM[1].app_n);
    TEST_ASSERT_EQUAL_MEMORY("HELLO FROM CELL 1", TERM[1].app, 17);
    talk(1, "HI");
    run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("HI", TERM[0].app, 2);
    press(0, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NORMAL, ended(1));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));

    forget_events();
    dial(0, "+883-1-606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    press(1, LC_SIG_CMD_HANGUP); /* the callee hangs up this time */
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NORMAL, ended(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    const lc_core_cdr_t *c = &SMEM.d.cdr[(SMEM.d.ncdr - 1u) % LC_CORE_MEM_LOG];
    TEST_ASSERT_EQUAL_UINT32(1, c->cell_a);
    TEST_ASSERT_EQUAL_UINT32(2, c->cell_b);
    TEST_ASSERT_NOT_EQUAL(0, c->answer);
}

/* Two terminals on one cell: switched there, as in plan 5; the core sees
 * no call. */
static void test_same_cell_call_stays_local(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(2, 0);
    unsigned cdrs = SMEM.d.ncdr;
    dial(0, "606-555-01232");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[2], LC_SIG_EV_INCOMING));
    press(2, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    talk(2, "LOCAL");
    run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("LOCAL", TERM[0].app, 5);
    press(0, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NORMAL, ended(2));
    TEST_ASSERT_EQUAL_UINT(cdrs, SMEM.d.ncdr);
}

static void test_reject_busy_unreachable_no_answer(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    registered_on(2, 1);

    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_REJECT);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_REJECTED, ended(0));

    forget_events(); /* T1 is in a local call with T2 on cell 2: busy */
    dial(2, "606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
    dial(0, "606-555-01231");
    run_ms(4000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_BUSY, ended(0));
    press(2, LC_SIG_CMD_HANGUP);
    run_ms(3000);

    forget_events();
    dial(0, "606-555-01239"); /* no such subscriber */
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_UNREACHABLE, ended(0));
    forget_events();
    dial(0, "606-555-01233"); /* a subscriber registered nowhere */
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_UNREACHABLE, ended(0));

    forget_events();
    dial(0, "606-555-01231");
    run_ms(65000); /* the callee's cell gives up after 60 s of ringing */
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NO_ANSWER, ended(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));
}

/* Review Focus 3: T0 and T1, on different cells, dial each other at the
 * same moment: each offer finds the callee busy placing its own call, and
 * both calls end busy; nobody is left ringing. */
static void test_both_dial_each_other_at_once(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    forget_events();
    dial(0, "606-555-01231");
    dial(1, "606-555-01230");
    run_ms(5000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_BUSY, ended(0));
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_BUSY, ended(1));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
}

static void test_echo_service(void)
{
    sim_world();
    registered_on(0, 2);
    forget_events();
    dial(0, "606-555-0100");
    run_ms(2000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_RINGING_OUT, state(0));
    run_ms(3000); /* it answers after 3 s */
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    talk(0, "ECHO?");
    run_ms(1000);
    TEST_ASSERT_EQUAL_MEMORY("ECHO?", TERM[0].app, 5);
    press(0, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_activation_and_registration_through_the_core);
    RUN_TEST(test_registration_while_the_core_link_comes_up);
    RUN_TEST(test_cross_cell_call);
    RUN_TEST(test_same_cell_call_stays_local);
    RUN_TEST(test_reject_busy_unreachable_no_answer);
    RUN_TEST(test_both_dial_each_other_at_once);
    RUN_TEST(test_echo_service);
    return UNITY_END();
}
```

- [ ] **Step 2: Run them**

Run: `cd /home/devin/Documents/opencell/core && cmake --build build --target test_net_sim 2>&1 | grep -E "error|warning"; build/tests/test_net_sim | tail -3`
Expected: no compiler output, then `7 Tests 0 Failures 0 Ignored` and `OK`. These tests exercise code Tasks 1–13 (and firmware Tasks 8–10) already wrote, so they pass at once. If one fails, it has found a defect in that code: go back to the owning task's file (the failing assertion's message names the state), fix it there, and re-run that task's tests too. A defect in `lc_sig` is fixed on firmware `net-core`, pushed, and the submodule bumped (Task 11 Step 1's commands with the new hash).

- [ ] **Step 3: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 8`.

- [ ] **Step 4: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add tests/test_net_sim.c
git commit -m "net sim: calls across and within cells, refusals, glare, echo service

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 15: The simulation: moves, restarts, outages, resync, a rogue cell

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 14.

The rest of §9.2 and the spec's "Done means": a terminal moving between cells while idle; re-activation on a new terminal while the old one is registered elsewhere; a cell restart and a core restart mid-call (no half-open call, everyone registered again within one re-attach); a backhaul outage at a cell; the HSS behind the terminal (resync through the core); a rogue cell replaying a location claim; a callee cell that never answers (the core's 10 s timer).

**Files:**
- Modify: `tests/test_net_sim.c`

**Interfaces:**
- Consumes: Task 13's `net_sim.h`. Produces nothing new.

- [ ] **Step 1: Write the tests**

In `tests/test_net_sim.c`, replace:
```c
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_activation_and_registration_through_the_core);
    RUN_TEST(test_registration_while_the_core_link_comes_up);
    RUN_TEST(test_cross_cell_call);
    RUN_TEST(test_same_cell_call_stays_local);
    RUN_TEST(test_reject_busy_unreachable_no_answer);
    RUN_TEST(test_both_dial_each_other_at_once);
    RUN_TEST(test_echo_service);
    return UNITY_END();
}
```
with:
```c
/* T0 and T1 in a call across cells 1 and 2. */
static void in_a_cross_cell_call(void)
{
    registered_on(0, 0);
    registered_on(1, 1);
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
}

/* §7.8: T0 leaves cell 1 while idle and attaches to cell 2; it registers
 * there by itself, cell 1 is told to drop it, and a call to T0 rings on
 * cell 2. */
static void test_idle_move_between_cells(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(2, 2);
    TERM[0].cell = -1; /* out of cell 1's coverage */
    run_ms(2000);
    TERM[0].cell = 1;  /* cell 2's beacon */
    forget_events();
    run_ms(8000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_UINT32(2, located(0));
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid)); /* LOC_CANCEL(moved) */
    TEST_ASSERT_TRUE(lc_sig_net_registered(&CELL[1].c.net, TERM[0].tmid));
    dial(2, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* §7.1 step 4: the operator re-issues T0's number and another terminal
 * (T3, on cell 2) activates it while T0 is registered on cell 1: cell 1
 * drops T0, T0 can no longer call, and calls to the number reach T3. */
static void test_reactivation_on_a_new_terminal_elsewhere(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 2);
    memcpy(TERM[3].number, TERM[0].number, LC_SIG_NUMBER_LEN); /* T3 scans a new code for T0's number */
    registered_on(3, 1);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TERM[0].number, TERM[3].id.number, LC_SIG_NUMBER_LEN);
    TEST_ASSERT_FALSE(lc_sig_net_registered(&CELL[0].c.net, TERM[0].tmid));
    TEST_ASSERT_EQUAL_UINT32(2, located(0));
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_UNREACHABLE, ended(0)); /* refused by its own cell */
    TEST_ASSERT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
    dial(1, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* §7.9 and "Done means": cell 2's process dies mid-call. The core sees its
 * link close and releases T0's leg at once (cause 5). When cell 2 is back
 * (a new boot), T1 registers again on re-attach and calls work again. */
static void test_cell_restart_mid_call(void)
{
    sim_world();
    in_a_cross_cell_call();
    sim_disconnect(1);
    CELL[1].up = 0; /* its beacon stops */
    run_ms(2000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));
    TEST_ASSERT_EQUAL_UINT32(2, located(1)); /* the core keeps it until the cell's new boot */
    run_ms(8000);
    sim_cell_start(1);
    sim_connect(1);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(0, located(1)); /* HELLO with a new boot id purged cell 2 */
    run_ms(10000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(1));
    TEST_ASSERT_EQUAL_UINT32(2, located(1));
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
}

/* §7.10: the core restarts mid-call. Both cells lose their link and release
 * their legs (cause 5); the core comes back on its store, the cells
 * reconnect with their boot ids, and a new call connects without anyone
 * registering again. */
static void test_core_restart_mid_call(void)
{
    sim_world();
    in_a_cross_cell_call();
    for (int i = 0; i < SIM_CELLS; i++) sim_disconnect(i);
    run_ms(2000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(1));
    sim_core_start(); /* the same store: SQN, bindings, locations */
    for (int i = 0; i < SIM_CELLS; i++) sim_connect(i);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    TEST_ASSERT_EQUAL_UINT32(2, located(1));
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
    TEST_ASSERT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    press(1, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(0));
}

/* §7.10: cell 2's backhaul is down. Its registered terminals still call
 * each other; calls into or out of the cell get cause 5; activation there
 * fails. Once the link is back, cross-cell calls work again. */
static void test_backhaul_outage_at_a_cell(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    registered_on(2, 1);
    sim_disconnect(1);
    forget_events();
    dial(1, "606-555-01232");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[2], LC_SIG_EV_INCOMING)); /* local: no core needed */
    press(2, LC_SIG_CMD_ANSWER);
    run_ms(3000);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_IN_CALL, state(1));
    press(1, LC_SIG_CMD_HANGUP);
    run_ms(3000);
    forget_events();
    dial(1, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(1));
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    activate_on(3, 1);
    run_ms(8000);
    TEST_ASSERT_NOT_NULL(event(&TERM[3], LC_SIG_EV_ACT_FAILED));
    sim_connect(1);
    run_ms(1000);
    forget_events();
    dial(0, "606-555-01231");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[1], LC_SIG_EV_INCOMING));
}

/* The HSS is behind the terminal (a vector it already used, or a core
 * restored from an old copy): AUTH_FAIL(2) goes through the core as RESYNC
 * and the terminal registers without help. */
static void test_resync_through_the_core(void)
{
    sim_world();
    registered_on(0, 0);
    lc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    s.sqn = 0;
    TEST_ASSERT_EQUAL_INT(0, SST.sub_put(SST.ctx, &s));
    lc_sig_sqn_put(TERM[0].id.sqn, 5000);
    const lc_sig_term_io_t io = TERM[0].t.io;
    lc_sig_term_init(&TERM[0].t, &io, &TERM[0].id, TERM[0].tmid, now); /* reboot: it registers again */
    forget_events();
    run_ms(10000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_REGISTERED));
    TEST_ASSERT_EQUAL_INT(0, SST.sub_get(SST.ctx, TERM[0].number, &s));
    TEST_ASSERT_EQUAL_UINT64(5001, s.sqn);
    TEST_ASSERT_EQUAL_UINT64(5001, lc_sig_sqn_get(TERM[0].id.sqn));
    TEST_ASSERT_NOT_NULL(lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_RESYNC));
}

/* §8: cell 3 replays cell 1's location claim for T0 (RAND and RES heard
 * on the way): refused, audited, and T0's calls still ring on cell 1. */
static void test_rogue_cell_cannot_pull_a_subscriber(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    TEST_ASSERT_EQUAL_UINT8(LC_CORE_LOC_UPDATE, last_loc_update[0].type);
    wire_push(1, 2, CELL[2].link, &last_loc_update[0]);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT32(1, located(0));
    const lc_core_audit_t *a = lc_core_mem_audit(&SMEM, LC_CORE_AUDIT_AUTH_FAIL);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_EQUAL_UINT32(3, a->cell_id);
    forget_events();
    dial(1, "606-555-01230");
    run_ms(3000);
    TEST_ASSERT_NOT_NULL(event(&TERM[0], LC_SIG_EV_INCOMING));
}

/* §7.4 timers: the callee's cell never answers the offer (its frames to the
 * core are lost): the core gives up after 10 s, cause 5, on both legs. */
static void test_silent_callee_cell_times_out(void)
{
    sim_world();
    registered_on(0, 0);
    registered_on(1, 1);
    CELL[1].mute = 1;
    forget_events();
    dial(0, "606-555-01231");
    run_ms(9000);
    TEST_ASSERT_EQUAL_INT(-1, ended(0));
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(0));
    TEST_ASSERT_EQUAL_INT(LC_SIG_CAUSE_NET_FAILURE, ended(1)); /* its ringing leg released too */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_activation_and_registration_through_the_core);
    RUN_TEST(test_registration_while_the_core_link_comes_up);
    RUN_TEST(test_cross_cell_call);
    RUN_TEST(test_same_cell_call_stays_local);
    RUN_TEST(test_reject_busy_unreachable_no_answer);
    RUN_TEST(test_both_dial_each_other_at_once);
    RUN_TEST(test_echo_service);
    RUN_TEST(test_idle_move_between_cells);
    RUN_TEST(test_reactivation_on_a_new_terminal_elsewhere);
    RUN_TEST(test_cell_restart_mid_call);
    RUN_TEST(test_core_restart_mid_call);
    RUN_TEST(test_backhaul_outage_at_a_cell);
    RUN_TEST(test_resync_through_the_core);
    RUN_TEST(test_rogue_cell_cannot_pull_a_subscriber);
    RUN_TEST(test_silent_callee_cell_times_out);
    return UNITY_END();
}
```

- [ ] **Step 2: Run them**

Run: `cd /home/devin/Documents/opencell/core && cmake --build build --target test_net_sim 2>&1 | grep -E "error|warning"; build/tests/test_net_sim | tail -3`
Expected: no compiler output, then `15 Tests 0 Failures 0 Ignored` and `OK`. As in Task 14, a failure here is a defect in Tasks 1–13 or firmware Tasks 8–10: fix it in the owning file (and repository).

- [ ] **Step 3: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 8`.

- [ ] **Step 4: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add tests/test_net_sim.c
git commit -m "net sim: idle move, re-activation elsewhere, cell and core restarts, outage, resync, rogue cell

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 16: The channel list: one per group of cells, from the core to the terminals

**Repo:** `opencell-core`, branch `lc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 15.

The channel-list spec (§8) makes the core own a channel list per list group and send it to the group's cells "at HELLO and on change, either in HELLO_ACK or a new K→C `CELL_CFG`"; the cell serves `CHAN_LIST` (which `lc_sig_net` already pushes after every REG_ACK and on a config service request, cause 4). This task takes the `CELL_CFG` branch: a new cell↔core type `0x06` whose body is exactly a `CHAN_LIST` body as `lc_sig` encodes it. The core stores one list per group (`list_id`, the cell record's field since Task 3), numbers its versions itself, sends it after each HELLO_ACK and to every linked cell of the group when it changes; `lc_cell` hands it to `lc_sig_net_set_chan_list`. Left for network core 2 (with `oc-cell`, the SQLite store and the admin CLI): the operator's anchors (`cell.sync_ch`, `cell.sync_fixed`), the unique-anchor-per-group check, and putting `lc_cell_list_ver() & 3` into the beacon's `cfg_ver`.

**Files:**
- Modify: `lc_core/include/lc_core_msg.h`, `lc_core/lc_core_msg.c`, `lc_core/include/lc_core_store.h`, `lc_core/include/lc_core_mem.h`, `lc_core/lc_core_mem.c`, `lc_core/include/lc_core.h`, `lc_core/lc_core.c`, `lc_cell/include/lc_cell.h`, `lc_cell/lc_cell.c`, `tests/net_sim.h`
- Test: `tests/test_core_msg.c`, `tests/core_store_contract.h`, `tests/test_core_link.c`, `tests/test_net_sim.c`

**Interfaces:**
- Consumes: `chan-list`'s `lc_sig_chan_list_t`, `LC_SIG_CHAN_MAX`, `LC_SIG_CHAN_FIXED`, `LC_SIG_CHAN_LIST` body coding, `LC_SIG_SVC_CONFIG`, `lc_sig_net_set_chan_list`, `lc_sig_term_chan_list` (through the submodule); Task 4's links; Task 13's `lc_cell` and `net_sim.h`.
- Produces (`lc_core_msg.h`): `LC_CORE_CELL_CFG` (0x06, K→C), body member `cell_cfg` (`{ lc_sig_chan_list_t list; }`).
- Produces (`lc_core_store.h`): `lc_core_store_t.list_get(ctx, list_id, out)`, `.list_put(ctx, list_id, list)` (plan 8's SQLite store implements them too; the contract test covers them).
- Produces (`lc_core.h`): `int lc_core_chan_list_set(lc_core_t *k, uint16_t list_id, const lc_sig_chan_list_t *list, uint64_t now_us);` (the new version, or -1).
- Produces (`lc_cell.h`): `uint8_t lc_cell_list_ver(const lc_cell_t *c);` (0: no list).

- [ ] **Step 1: Write the failing tests**

In `tests/test_core_msg.c`, replace:
```c
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_golden_bytes);
    RUN_TEST(test_every_type_round_trips);
    RUN_TEST(test_what_does_not_decode);
    return UNITY_END();
}
```
with:
```c
/* CELL_CFG carries a CHAN_LIST body exactly as lc_sig encodes it:
 * ver, count, then count x { freq_hz (big-endian, as in lc_sig), flags }. */
static void test_cell_cfg(void)
{
    lc_core_msg_t m, back;
    uint8_t buf[LC_CORE_FRAME_MAX];
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CELL_CFG;
    m.u.cell_cfg.list.ver = 1;
    m.u.cell_cfg.list.count = 2;
    m.u.cell_cfg.list.freq_hz[0] = 917250000u;
    m.u.cell_cfg.list.freq_hz[1] = 922250000u;
    m.u.cell_cfg.list.flags[1] = LC_SIG_CHAN_FIXED;
    static const uint8_t cfg[] = { 0x00, 0x0D, 0x06, 0x01, 0x02, 0x36, 0xAC, 0x1F, 0xD0, 0x00,
                                   0x36, 0xF8, 0x6B, 0x10, 0x01 };
    golden(&m, cfg, sizeof(cfg));

    memset(&m, 0, sizeof(m)); /* no entries: the group's list was emptied */
    m.type = LC_CORE_CELL_CFG;
    m.u.cell_cfg.list.ver = 9;
    static const uint8_t empty[] = { 0x00, 0x03, 0x06, 0x09, 0x00 };
    golden(&m, empty, sizeof(empty));

    m.u.cell_cfg.list.count = LC_SIG_CHAN_MAX + 1u;
    TEST_ASSERT_EQUAL_size_t(0, lc_core_encode(&m, buf, sizeof(buf)));
    static const uint8_t cut[] = { 0x00, 0x07, 0x06, 0x01, 0x01, 0x36, 0xAC, 0x1F, 0xD0 }; /* no flags byte */
    TEST_ASSERT_EQUAL_INT(-1, lc_core_decode(cut, sizeof(cut), &back));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_golden_bytes);
    RUN_TEST(test_every_type_round_trips);
    RUN_TEST(test_what_does_not_decode);
    RUN_TEST(test_cell_cfg);
    return UNITY_END();
}
```

In `tests/core_store_contract.h`, replace:
```c
    TEST_ASSERT_EQUAL_INT(-1, st->cell_get(c, 8, &cell2));
```
with:
```c
    TEST_ASSERT_EQUAL_INT(-1, st->cell_get(c, 8, &cell2));

    /* channel lists: one per list group, replaced by group */
    lc_sig_chan_list_t cl, cl2;
    memset(&cl, 0, sizeof(cl));
    cl.ver = 1;
    cl.count = 1;
    cl.freq_hz[0] = 917250000u;
    TEST_ASSERT_EQUAL_INT(-1, st->list_get(c, 3, &cl2));
    TEST_ASSERT_EQUAL_INT(0, st->list_put(c, 3, &cl));
    cl.ver = 2;
    cl.flags[0] = LC_SIG_CHAN_FIXED;
    TEST_ASSERT_EQUAL_INT(0, st->list_put(c, 3, &cl));
    TEST_ASSERT_EQUAL_INT(0, st->list_get(c, 3, &cl2));
    TEST_ASSERT_EQUAL_MEMORY(&cl, &cl2, sizeof(cl));
    TEST_ASSERT_EQUAL_INT(-1, st->list_get(c, 4, &cl2));
```

In `tests/test_core_link.c`, replace:
```c
int main(void)
{
    UNITY_BEGIN();
```
with:
```c
/* Channel-list spec §8: a group's list goes to its cells in CELL_CFG, after
 * HELLO_ACK and whenever it changes; the core numbers the versions and keeps
 * the list across a restart. */
static void test_channel_list_goes_to_the_group(void)
{
    core_world();
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&K, 3, "C", LC_SIG_MODE_PART15, 5));
    TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&K, 4, "D", LC_SIG_MODE_PART15, 5));
    lc_sig_chan_list_t l;
    memset(&l, 0, sizeof(l));
    l.ver = 77; /* the core numbers versions itself */
    l.count = 1;
    l.freq_hz[0] = 917250000u;
    hello(10, 1, 1); /* group 0: none */
    hello(30, 3, 1); /* group 5, before it has a list */
    TEST_ASSERT_NULL(sent(30, LC_CORE_CELL_CFG));
    TEST_ASSERT_EQUAL_INT(1, lc_core_chan_list_set(&K, 5, &l, NOW));
    const lc_core_msg_t *c = sent(30, LC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.count);
    TEST_ASSERT_EQUAL_UINT32(917250000u, c->u.cell_cfg.list.freq_hz[0]);
    TEST_ASSERT_NULL(sent(10, LC_CORE_CELL_CFG));

    int from = NSENT;
    hello(40, 4, 1); /* a cell of the group comes up: HELLO_ACK, then the list */
    TEST_ASSERT_NOT_NULL(sent_since(from, 40, LC_CORE_HELLO_ACK));
    c = sent_since(from, 40, LC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(1, c->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_INT(2, lc_core_chan_list_set(&K, 5, &l, NOW)); /* a change reaches both */
    TEST_ASSERT_EQUAL_UINT8(2, sent(30, LC_CORE_CELL_CFG)->u.cell_cfg.list.ver);
    TEST_ASSERT_EQUAL_UINT8(2, sent(40, LC_CORE_CELL_CFG)->u.cell_cfg.list.ver);

    core_restart(); /* the list is in the store */
    from = NSENT;
    hello(31, 3, 1);
    c = sent_since(from, 31, LC_CORE_CELL_CFG);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT8(2, c->u.cell_cfg.list.ver);

    l.count = LC_SIG_CHAN_MAX + 1u;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_chan_list_set(&K, 5, &l, NOW));
    l.count = 1;
    TEST_ASSERT_EQUAL_INT(-1, lc_core_chan_list_set(&K, 0, &l, NOW)); /* 0: no group */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_channel_list_goes_to_the_group);
```

In `tests/net_sim.h`, replace:
```c
        TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&CORE, (uint32_t)(i + 1), name, LC_SIG_MODE_PART15, 0));
```
with:
```c
        /* cells 1 and 2 share channel-list group 1; cell 3 is group 2 */
        TEST_ASSERT_EQUAL_INT(0, lc_core_cell_add(&CORE, (uint32_t)(i + 1), name, LC_SIG_MODE_PART15,
                                                  (uint16_t)(i < 2 ? 1 : 2)));
```

In `tests/test_net_sim.c`, replace:
```c
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_activation_and_registration_through_the_core);
```
with:
```c
/* Channel-list spec §7-8: the core's list for group 1 reaches cells 1 and 2
 * (CELL_CFG), and each pushes it to its terminals after REG_ACK. A change
 * reaches the cells at once and a terminal when it asks (a config service
 * request: its beacon's cfg_ver changed); a restarted cell gets the list at
 * HELLO. Cell 3 (group 2, no list) pushes nothing. */
static void test_channel_list_from_the_core(void)
{
    sim_world();
    lc_sig_chan_list_t l, got;
    memset(&l, 0, sizeof(l));
    l.count = 2;
    l.freq_hz[0] = 917250000u;
    l.freq_hz[1] = 922250000u;
    l.flags[1] = LC_SIG_CHAN_FIXED;
    TEST_ASSERT_EQUAL_INT(1, lc_core_chan_list_set(&CORE, 1, &l, now));
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT8(1, lc_cell_list_ver(&CELL[0].c));
    TEST_ASSERT_EQUAL_UINT8(1, lc_cell_list_ver(&CELL[1].c));
    TEST_ASSERT_EQUAL_UINT8(0, lc_cell_list_ver(&CELL[2].c));

    registered_on(0, 0);
    registered_on(1, 2);
    TEST_ASSERT_EQUAL_INT(1, lc_sig_term_chan_list(&TERM[0].t, &got)); /* pushed after REG_ACK */
    TEST_ASSERT_EQUAL_UINT8(1, got.ver);
    TEST_ASSERT_EQUAL_UINT8(2, got.count);
    TEST_ASSERT_EQUAL_UINT32(922250000u, got.freq_hz[1]);
    TEST_ASSERT_EQUAL_HEX8(LC_SIG_CHAN_FIXED, got.flags[1]);
    TEST_ASSERT_EQUAL_INT(0, lc_sig_term_chan_list(&TERM[1].t, &got)); /* cell 3 has none */

    l.count = 1; /* the operator changes group 1's list */
    TEST_ASSERT_EQUAL_INT(2, lc_core_chan_list_set(&CORE, 1, &l, now));
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT8(2, lc_cell_list_ver(&CELL[0].c));
    uint8_t svc = (uint8_t)(LC_SIG_KIND_SVC | LC_SIG_SVC_CONFIG); /* T0 saw cfg_ver 2 in the beacon */
    lc_cell_upper(&CELL[0].c, TERM[0].tmid, &svc, 1, now);
    run_ms(3000);
    TEST_ASSERT_EQUAL_INT(1, lc_sig_term_chan_list(&TERM[0].t, &got));
    TEST_ASSERT_EQUAL_UINT8(2, got.ver);
    TEST_ASSERT_EQUAL_UINT8(1, got.count);
    TEST_ASSERT_EQUAL_UINT8(LC_SIG_ST_REGISTERED, state(0));

    sim_disconnect(1); /* cell 2 restarts: HELLO brings the list back */
    sim_cell_start(1);
    TEST_ASSERT_EQUAL_UINT8(0, lc_cell_list_ver(&CELL[1].c));
    sim_connect(1);
    run_ms(500);
    TEST_ASSERT_EQUAL_UINT8(2, lc_cell_list_ver(&CELL[1].c));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_channel_list_from_the_core);
    RUN_TEST(test_activation_and_registration_through_the_core);
```

- [ ] **Step 2: Run them to see them fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 -- -k 2>&1 | grep -oE "(LC_CORE_CELL_CFG. undeclared|no member named .list_get|function .lc_core_chan_list_set|function .lc_cell_list_ver)" | sort -u`
Expected: four lines (the compiler's quotes around the names): `function ‘lc_cell_list_ver`, `function ‘lc_core_chan_list_set`, `LC_CORE_CELL_CFG’ undeclared`, `no member named ‘list_get`.

- [ ] **Step 3: `CELL_CFG` in the codec**

In `lc_core/include/lc_core_msg.h`, replace:
```c
 * Types not listed here are free. */
```
with:
```c
 * CELL_CFG (K->C) carries the cell's channel list (channel-list spec §8) as
 * a CHAN_LIST body exactly as lc_sig encodes it (lc_sig_body_encode: its
 * frequencies are big-endian, as everywhere in lc_sig).
 *
 * Types not listed here are free. */
```

In `lc_core/include/lc_core_msg.h`, replace:
```c
    LC_CORE_HELLO = 0x01, LC_CORE_HELLO_ACK = 0x02, LC_CORE_HELLO_NAK = 0x03, LC_CORE_PING = 0x04, LC_CORE_PONG = 0x05,
```
with:
```c
    LC_CORE_HELLO = 0x01, LC_CORE_HELLO_ACK = 0x02, LC_CORE_HELLO_NAK = 0x03, LC_CORE_PING = 0x04, LC_CORE_PONG = 0x05,
    LC_CORE_CELL_CFG = 0x06,
```

In `lc_core/include/lc_core_msg.h`, replace:
```c
        struct { uint8_t reason; } hello_nak;
```
with:
```c
        struct { uint8_t reason; } hello_nak;
        struct { lc_sig_chan_list_t list; } cell_cfg; /* list.count 0: no entries */
```

In `lc_core/lc_core_msg.c`, replace:
```c
    case LC_CORE_PING:
    case LC_CORE_PONG:
        break;
    case LC_CORE_ACT_FWD:
        w16(&w, m->u.act_fwd.req);
```
with:
```c
    case LC_CORE_PING:
    case LC_CORE_PONG:
        break;
    case LC_CORE_CELL_CFG: {
        lc_sig_msg_t cl;
        memset(&cl, 0, sizeof(cl));
        cl.type = LC_SIG_CHAN_LIST;
        cl.u.chan_list = m->u.cell_cfg.list;
        sn = lc_sig_body_encode(&cl, sig, sizeof(sig));
        if (sn == 0) return 0;
        wb(&w, sig, sn);
        break;
    }
    case LC_CORE_ACT_FWD:
        w16(&w, m->u.act_fwd.req);
```

In `lc_core/lc_core_msg.c`, replace:
```c
    case LC_CORE_PING:
    case LC_CORE_PONG:
        break;
    case LC_CORE_ACT_FWD:
        m->u.act_fwd.req = r16(&r);
```
with:
```c
    case LC_CORE_PING:
    case LC_CORE_PONG:
        break;
    case LC_CORE_CELL_CFG: {
        lc_sig_msg_t cl;
        if (lc_sig_body_decode(LC_SIG_CHAN_LIST, in + r.at, len - r.at, &cl) != 0) return -1;
        m->u.cell_cfg.list = cl.u.chan_list;
        r.at = len;
        break;
    }
    case LC_CORE_ACT_FWD:
        m->u.act_fwd.req = r16(&r);
```

- [ ] **Step 4: The lists in the store**

In `lc_core/include/lc_core_store.h`, replace:
```c
    int (*cell_put)(void *ctx, const lc_core_cell_t *c);
```
with:
```c
    int (*cell_put)(void *ctx, const lc_core_cell_t *c);
    /* channel lists, one per list group (channel-list spec §8; list_id 1-65535) */
    int (*list_get)(void *ctx, uint16_t list_id, lc_sig_chan_list_t *out);
    int (*list_put)(void *ctx, uint16_t list_id, const lc_sig_chan_list_t *l); /* insert or replace */
```

In `lc_core/include/lc_core_mem.h`, replace:
```c
#define LC_CORE_MEM_LOG   64u
```
with:
```c
#define LC_CORE_MEM_LOG   64u
#define LC_CORE_MEM_LISTS 8u
```

In `lc_core/include/lc_core_mem.h`, replace:
```c
    lc_core_cell_t      cell[LC_CORE_MEM_CELLS];
    unsigned            ncell;
```
with:
```c
    lc_core_cell_t      cell[LC_CORE_MEM_CELLS];
    unsigned            ncell;
    uint16_t            list_id[LC_CORE_MEM_LISTS];
    lc_sig_chan_list_t  list[LC_CORE_MEM_LISTS];
    unsigned            nlist;
```

In `lc_core/lc_core_mem.c`, replace:
```c
static int sub_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_sub_t *out)
```
with:
```c
static int list_get(void *c, uint16_t list_id, lc_sig_chan_list_t *out)
{
    for (unsigned i = 0; i < D(c)->nlist; i++) {
        if (D(c)->list_id[i] == list_id) {
            *out = D(c)->list[i];
            return 0;
        }
    }
    return -1;
}

static int list_put(void *c, uint16_t list_id, const lc_sig_chan_list_t *l)
{
    lc_core_mem_data_t *d = D(c);
    for (unsigned i = 0; i < d->nlist; i++) {
        if (d->list_id[i] == list_id) {
            d->list[i] = *l;
            return 0;
        }
    }
    if (d->nlist >= LC_CORE_MEM_LISTS) return -1;
    d->list_id[d->nlist] = list_id;
    d->list[d->nlist++] = *l;
    return 0;
}

static int sub_get(void *c, const uint8_t number[LC_SIG_NUMBER_LEN], lc_core_sub_t *out)
```

In `lc_core/lc_core_mem.c`, replace:
```c
        .cell_put = cell_put,
```
with:
```c
        .cell_put = cell_put,
        .list_get = list_get,
        .list_put = list_put,
```

- [ ] **Step 5: The core sends a group's list**

In `lc_core/include/lc_core.h`, replace:
```c
int  lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us);
```
with:
```c
int  lc_core_cell_revoke(lc_core_t *k, uint32_t cell_id, uint64_t now_us);
/* The channel list of list group list_id (channel-list spec §8): stored, and
 * sent in CELL_CFG to every linked cell of the group now and to each after
 * its HELLO_ACK. The core numbers the versions (list->ver is ignored): 1, 2,
 * ... 255, then 1 again. The new version, or -1: list_id 0, more than
 * LC_SIG_CHAN_MAX entries, or the store failed. The operator's anchors and
 * the unique-anchor check per group come with network core 2. */
int  lc_core_chan_list_set(lc_core_t *k, uint16_t list_id, const lc_sig_chan_list_t *list, uint64_t now_us);
```

In `lc_core/lc_core.c`, replace:
```c
static void on_hello(lc_core_t *k, lc_core_link_t *l, const lc_core_msg_t *m, uint64_t now)
```
with:
```c
/* CELL_CFG with list group list_id's channel list, if the group has one. */
static void send_list(lc_core_t *k, lc_core_link_t *l, uint16_t list_id)
{
    lc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = LC_CORE_CELL_CFG;
    if (list_id == 0 || k->st.list_get(k->st.ctx, list_id, &m.u.cell_cfg.list) != 0) return;
    send_link(k, l, &m);
}

static void on_hello(lc_core_t *k, lc_core_link_t *l, const lc_core_msg_t *m, uint64_t now)
```

In `lc_core/lc_core.c`, replace:
```c
    memcpy(r.u.hello_ack.echo_number, k->cfg.echo_number, LC_SIG_NUMBER_LEN);
    send_link(k, l, &r);
}
```
with:
```c
    memcpy(r.u.hello_ack.echo_number, k->cfg.echo_number, LC_SIG_NUMBER_LEN);
    send_link(k, l, &r);
    send_list(k, l, c.list_id);
}
```

Append to `lc_core/lc_core.c`:
```c

int lc_core_chan_list_set(lc_core_t *k, uint16_t list_id, const lc_sig_chan_list_t *list, uint64_t now_us)
{
    lc_sig_chan_list_t l, old;
    k->now = now_us;
    if (list_id == 0 || list->count > LC_SIG_CHAN_MAX) return -1;
    memset(&l, 0, sizeof(l));
    l.count = list->count;
    memcpy(l.freq_hz, list->freq_hz, sizeof(l.freq_hz[0]) * l.count);
    memcpy(l.flags, list->flags, l.count);
    l.ver = k->st.list_get(k->st.ctx, list_id, &old) == 0 && old.ver != 255u ? (uint8_t)(old.ver + 1u) : 1u;
    if (k->st.list_put(k->st.ctx, list_id, &l) != 0) return -1;
    for (unsigned i = 0; i < LC_CORE_LINKS; i++) {
        lc_core_link_t *ln = &k->links[i];
        lc_core_cell_t c;
        if (ln->used && ln->cell_id != 0 && k->st.cell_get(k->st.ctx, ln->cell_id, &c) == 0 && c.list_id == list_id) {
            send_list(k, ln, list_id);
        }
    }
    lc_core_logf(k, "channel list %u: version %u, %u entries", (unsigned)list_id, (unsigned)l.ver, (unsigned)l.count);
    return l.ver;
}
```

- [ ] **Step 6: The cell serves it**

In `lc_cell/include/lc_cell.h`, replace:
```c
void lc_cell_tick(lc_cell_t *c, uint64_t now_us);
```
with:
```c
void lc_cell_tick(lc_cell_t *c, uint64_t now_us);
/* The version of the channel list this cell serves (0: none yet). Its beacon
 * carries it as cfg_ver (ver & 3, channel-list spec §7): oc-cell's to set. */
uint8_t lc_cell_list_ver(const lc_cell_t *c);
```

In `lc_cell/lc_cell.c`, replace:
```c
    case LC_CORE_HELLO_NAK:
```
with:
```c
    case LC_CORE_CELL_CFG: /* the core's list for this cell's group: pushed to terminals from now on */
        lc_sig_net_set_chan_list(&c->net, &m->u.cell_cfg.list);
        logf_(c, "core: channel list v%u, %u entries", m->u.cell_cfg.list.ver, m->u.cell_cfg.list.count);
        break;
    case LC_CORE_HELLO_NAK:
```

Append to `lc_cell/lc_cell.c`:
```c

uint8_t lc_cell_list_ver(const lc_cell_t *c)
{
    return c->net.have_list ? c->net.list.ver : 0;
}
```

- [ ] **Step 7: Run them to see them pass**

Run: `cd /home/devin/Documents/opencell/core && cmake --build build -j8 2>&1 | grep -E "error|warning"; for t in test_core_msg test_core_store test_core_link test_net_sim; do build/tests/$t | tail -2 | head -1; done`
Expected: no compiler output, then `4 Tests 0 Failures 0 Ignored`, `3 Tests 0 Failures 0 Ignored`, `8 Tests 0 Failures 0 Ignored`, `16 Tests 0 Failures 0 Ignored`.

- [ ] **Step 8: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 8`.

- [ ] **Step 9: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add lc_core lc_cell tests/test_core_msg.c tests/core_store_contract.h tests/test_core_link.c tests/net_sim.h tests/test_net_sim.c
git commit -m "Channel list per group of cells: CELL_CFG from the core, CHAN_LIST from the cell (channel-list spec 8)

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 17: Final checks, both repositories

**Repo:** `opencell-core` (`lc-core`) and `opencell-firmware` (`net-core`). **Starts:** after Task 16.

**Files:** none, unless Step 6 moves the submodule (a check that finds something sends you back to the task that owns the file, in its repository).

- [ ] **Step 1: The core's suite, clean**

Run: `cd /home/devin/Documents/opencell/core && rm -rf build && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: no compiler output, then `100% tests passed, 0 tests failed out of 8`.

- [ ] **Step 2: The core under AddressSanitizer and UBSan, optimized**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build/asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null && cmake --build build/asan -j8 2>&1 | grep -E "error|warning"; (cd build/asan && ctest | tail -3)`
Expected: no compiler output (with `-O1`, GCC's `-Wformat-truncation` looks harder: nothing here may trip it), then `100% tests passed, 0 tests failed out of 8`.

- [ ] **Step 3: The firmware's suite, clean and under the sanitizers**

Run: `cd /home/devin/Documents/opencell/firmware && git branch --show-current && rm -rf host-tests/build && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3); cmake -S host-tests -B host-tests/build/asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null && cmake --build host-tests/build/asan -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build/asan && ctest | tail -3)`
Expected: `net-core`, no compiler output, then `100% tests passed, 0 tests failed out of N+1` twice (34 when validated).

- [ ] **Step 4: No keys or HSS left in `lc_sig_net`; no `lc_sig` in the core repository**

Run: `cd /home/devin/Documents/opencell/firmware && grep -nE "by_token|by_tmid\b|by_number\)|io\.save|io\.unix_now|cfg\.sk|lc_milenage|lc_sig_act_keys" firmware/components/lc_sig/lc_sig_net.c firmware/components/lc_sig/include/lc_sig_net.h tools/lcbench/lcb_net.c; grep -nE "by_token|by_tmid\b|by_number\)|io\.save|io\.unix_now|cfg\.sk" host-tests/test_sig_e2e.c host-tests/test_sig_local.c host-tests/test_term_sim.c`
Expected: nothing. (The tests may call `lc_milenage` and `lc_sig_act_keys`: that is the terminal's side of a check, which `chan-list`'s tests do too.)

Run: `cd /home/devin/Documents/opencell/core && git ls-files | grep -E "(^|/)lc_sig[^/]*\.[ch]$"; git submodule status`
Expected: no file from the first command (the core's code is `lc_core*` and `lc_cell*`; `lc_sig` is only in the submodule), then one line that starts with a space (the submodule is at the commit the superproject records; `+` would mean it isn't), with the firmware commit Task 11 pinned and `third_party/opencell-firmware`.

- [ ] **Step 5: lcbench on its own, and the firmware for the ESP32-S3**

Run: `cd /home/devin/Documents/opencell/firmware && rm -rf tools/lcbench/build && cmake -S tools/lcbench -B tools/lcbench/build -G Ninja >/dev/null && cmake --build tools/lcbench/build 2>&1 | grep -E "error|warning"; ls tools/lcbench/build/lcbench`
Expected: no compiler output, then `tools/lcbench/build/lcbench`.

Run: `bash -c 'source ~/.espressif/tools/activate_idf_v6.0.1.sh >/dev/null 2>&1; idf.py -C /home/devin/Documents/opencell/firmware/firmware -DLC_BENCH_LOW_POWER=1 build 2>&1 | grep -E "error:|warning:|Project build complete" | grep -v "God mode"'`
Expected: `Project build complete. To flash, run:` and no `error:` or `warning:` lines. (The firmware uses none of `lc_sig_net` or `lc_sig_hss`; this proves the shared `lc_sig` headers still build for the ESP32-S3. Nothing is flashed.)

- [ ] **Step 6: Where the submodule ends**

Run: `cd /home/devin/Documents/opencell/firmware && git fetch -q origin && git merge-base --is-ancestor net-core origin/main && echo merged || echo "not merged"`
Expected: `not merged` unless someone merged `net-core` into firmware `main` meanwhile. If `merged`: point the core's submodule at `origin/main` (Task 11 Step 1's three commands with `origin/main` as the commit), rerun Step 1, and commit (`git add third_party/opencell-firmware`, message `Submodule: firmware main <hash> (net-core merged)`, with the two trailer lines). If `not merged`: nothing to do; the core stays pinned to `net-core`'s pushed head.

- [ ] **Step 7: Report**

Report: the commit lists of `lc-core` (Tasks 0–6, 11–16) and `net-core` (Tasks 8–10), the final counts (core 8 tests with `test_net_sim` 16; firmware N+1), the firmware commit the submodule pins, and anything a check sent back to an earlier task. Merging `net-core` into firmware `main` (it changes `lc_sig`, which the terminal firmware and lcbench build) and `lc-core` into core `main` is the controller's call: don't merge.
