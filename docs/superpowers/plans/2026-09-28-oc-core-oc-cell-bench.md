# Network core 2: `oc-core` and `oc-cell` on the bench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the network core as two real programs on the Pi `opencell-bs1`: `oc-core` (the SQLite HSS with sealed keys, the registry, the switch, an admin socket) and `oc-cell` (`oc_cell` on board A over USB), replacing `ocbench net` and `ocbench mkqr`, and pass the plan-5 done list over the air with T and T2 (network-core spec §9.5a).

**Architecture:**
- Three repositories. **`opencell-core`** (branch `oc-core`) gets `oc/`: `oc_util` (journald logging, `key = value` config files, the §6 framing over Unix sockets), `oc_store` (the SQLite store behind `oc_core_store_t`, AES-256-GCM sealing, migrations, the admin commands, the import of ocbench's HSS) and the `oc-core` program (daemon and admin client), plus the deploy script. **`opencell-pi`** (branch `oc-cell`) gets `oc-cell`: `ocr` (the radio backend on `ocb_cell`, one board), `ocs` (simulated terminals, for the process tests) and the program. **`opencell-firmware`** (branch `oc-bench`) gets the TIME-label fix (`ocb_time`, issue #2) and, at the end, loses `ocbench net`, `ocbench mkqr`, `ocb_net` and `ocb_hss`.
- `oc-core` is one thread: a `poll()` loop over the cell socket, the admin socket and each cell's link, feeding `oc_core` (plan 1) its frames and `tick(now)`, with SQLite on the same thread. `oc-core admin …` sends its words to the running daemon, which runs them through the same `oc_core`, so a disable sends its `LOC_CANCEL` at once; `--offline` runs them on a stopped core's database.
- `oc-cell` is one thread too: the board's USB port, the core link (reconnecting with backoff) and, for tests, a control FIFO. `ocr` builds every frame's SCHEDULE with `ocb_cell` and `ocb_merge` as `ocbench net --one-board` did, learns the board's frame from its STATUS (internal PPS on the Pi bench), labels it with `ocb_time`, and makes the beacon follow the core (mode → PART97 flag, channel list → `cfg_ver`).
- `opencell-pi` has **one submodule, `third_party/opencell-core`**, and reaches the firmware through the core's own submodule (`third_party/opencell-core/third_party/opencell-firmware`): see "Decisions" for why this, not two submodules.

**Tech Stack:** C11 (`-Wall -Wextra -Werror`), SQLite 3 (Debian 13: 3.46), OpenSSL 3 (EVP AES-256-GCM, and `oc_sig`'s host crypto), Unity host tests, CMake ≥ 3.21, bash for the process tests and the deploy script, systemd units, Debian 13 on the laptop (amd64) and the Pi 4 (arm64).

**Spec:** `docs/superpowers/specs/2026-09-27-network-core-design.md` (approved 2026-09-27), §11 row "8: `oc-core` and `oc-cell` on the bench", with **§17 (decisions for plans 8–9, 2026-09-28), which binds this plan**. Read §3–§9, §16 and §17 before Task 1. This plan is **network core 2**; network core 1 is `docs/superpowers/plans/2026-09-27-net-core-1-lc-core.md` ("plan 1" below), whose `oc_core`, `oc_cell`, async `oc_sig_net` and `CELL_CFG` it runs. Known bug fixed here: opencell-firmware issue #2 (TIME labels refused with the internal PPS). The specs are in the docs repository (`/home/devin/Documents/opencell/docs`).

**Validated while writing** (by script: every file directive of this plan applied in order to scratch clones, every `Run:` command run and compared with its Expected, the `git rm` lines run; other git, ssh, sudo, systemctl, esptool and BLE commands skipped, and the commits and pin moves they stand for done by hand):
- The starting point: firmware `net-core` at `3c9581f` (plan 1 Tasks 7–10, real) and core `lc-core` at `38ba859` (plan 1 Tasks 0–6 and 11 with its fix round, real), plus plan 1's Task 12–16 text applied to the core (it applied cleanly; one line's spacing in `oc_core_mem.h` differs from the real Task 3). Baselines there: firmware 34 tests, core 8.
- Tasks 1–10, 12 and 13, in order, on those clones: every Expected matched. The firmware suite (35) and the core (14) and Pi (3) suites pass plain and under ASan/UBSan; the process test (Task 9) passed three runs in a row, about 12 s each. Task 10's own tag step was run by hand: both real repositories deployed locally with nested submodules and the tests off.
- Not validated: Task 0 (git checks; its greps were dry-run against the clones) and Task 11 (the bench, on hardware). Plan 1's real Tasks 12–16 may differ from its text: Task 0 Step 1 checks the names this plan uses, and Task 4 says what to do if the store contract grew.

**Revised 2026-09-28 with the controller's note:** plan 1's store contract now dooms a transaction on any failed write (core `38ba859`); SQLite can roll a transaction back by itself (`SQLITE_FULL`, `SQLITE_IOERR`, `SQLITE_NOMEM`, `SQLITE_BUSY`), after which later statements would run in autocommit. Task 4's store keeps its own doomed flag and checks `sqlite3_get_autocommit`, with two fault-injection tests; `store_contract()` runs against the SQLite store; the sealing and every key buffer use `oc_sig_wipe` as the core does.

**Rulings made while writing (the controller should confirm):**
1. **Subscribers move by import, not by new QR codes.** `oc-core admin --offline import-ocb-hss FILE` copies ocbench's network key pair and every subscriber (TMID, K, OPc, SQN) from `~/.config/opencell/hss-bench.txt`, so T and T2 keep their identities and register without the phone, and T2's restored NVS matches. The user does nothing for T and T2. Unused tokens are not carried over (their ids have no block index, spec §14.3): `+883160655509999` becomes a subscriber without a code (`admin sub issue` gives it one).
2. **The cell socket is `/run/opencell/core.sock`, mode 0660, group `oc-cell`**, not owner-only (§6 "owner-only"): `oc-core` and `oc-cell` run as two system users so the cell's process can't read the database or the master key. The admin socket is 0660 group `oc-admin` (§17.1).
3. **Channel-list anchors stay in `oc-cell.conf` for now.** Plan 1 left "the operator's anchors (`cell.sync_ch`, `cell.sync_fixed`), the unique-anchor-per-group check" to network core 2. With one cell they can't collide, and the §6 protocol has no field to send an anchor to a cell; the check needs two cells, which is plan 9's bench (§9.5b). Plan 8 does the part a single cell needs: the core's list version reaches the beacon's `cfg_ver`, and `fixed_sync` is refused unless the core's mode for the cell is part97.
4. **Deploys build from tags `vX.Y.Z` on the feature branches** (`v0.1.0` on `oc-core` and `oc-cell` for the bench), before the controller merges them; merging with a merge commit keeps the tagged commits in `main`'s history.
5. **`ocb_net` and `ocb_hss` are deleted** (Task 12, after the bench passes), with `ocbench net` and `ocbench mkqr`. `test_term_sim`'s channel-list air-path tests that ran over `ocb_net` move onto the bare `oc_sig_net` and the fake core, every assertion kept; only the stand-in's own far-end test goes (the echo service is the core's now, covered by `test_ocr`, `test_net_sim` and the process tests). The HSS and `--chan-list` parser tests go with their code (`oc_chan_parse` has its own). `ocbench cell` (gaining `--mode`), `link`, `cw`, `guard`, `duplex`, `config`, `flash` and `status` stay.


> **Amendments after validation (controller, 2026-09-28).**
> 1. **Network-core spec §19 (plan 1 Task 12b)** changes the store and the codec after this plan was validated against core `38ba859`:
>    - `oc_core_loc_t` gains `sqn`;
>    - the store interface gains `av_del_number`;
>    - `AV_RES` vectors carry HXRES (16 B) in place of XRES.
>
>    Task 4's SQLite schema v1 and store must add the `location.sqn` and `location.rand` columns (LOC_CANCEL carries the proving RAND since the Task 13 review) and `av_del_number`, and pass the updated `core_store_contract.h`. Task 0's pre-flight re-runs Tasks 1–10 against plan 1's final tips before starting, and fixes what moved.
> 2. **SQLite store, fail-closed (§19 review):** `av_newest_confirmed` and `loc_get` must distinguish "none" from a store error. On an error, `on_loc_update` refuses the claim (no location change, no cancel) instead of skipping the SQN floor. Index `av_issued (number, confirmed, sqn)` for `SELECT MAX(sqn) … WHERE number=? AND confirmed=1 AND cell_id<>?`.
> 3. **Plan 1 merged 2026-09-29** (firmware main `d668bb6`, core main `ee6297a`): the store contract header (`oc_core_store.h`) now defines a failing `begin` that dooms the transaction, the core as the only writer, and `OC_CORE_STORE_NONE` vs FAILED lookups. The SQLite store implements them all, plus `sub_by_tmid` returning NONE/FAILED (activation must `goto done` on FAILED — final re-review). Task 0 starts from these mains.
> 4. **`sub enable`**: the portal spec (§7) lists `sub.enable`. It stays out of this plan and comes with the portal's core admin API (portal plan P4).

> **Amended 2026-09-29 by the oc rename** (`docs/superpowers/plans/2026-09-29-oc-rename.md`, run after plan 1 merged). This text was rewritten by `tools/rename/lc2oc.py --pre ocb=ocr --pre oc_cell=occ`: every `lc_*`, `LC_*`, `lcb_*` and `lcbench` name is now `oc_*`, `OC_*`, `ocb_*` and `ocbench`, as in the code. Two of this plan's own names changed so they don't collide with the renamed code: the Pi's radio backend `ocb` is **`ocr`** (`ocb_*` is ocbench's prefix now), and the `oc-cell` program's modules `oc_cell_cfg`, `oc_cell_board`, `oc_cell_main`, `oc_cell_lib`, `OC_CELL_*` are **`occ_cfg`, `occ_board`, `occ_main`, `occ_lib`, `OCC_*`** (`oc_cell_*` is the library, plan 1's `lc_cell`). Branches start from the renamed `main`s; `oc-bench` was rebuilt on the renamed firmware with Task 1's commit carried over (oc rename Task 9). Boards flashed with a pre-rename image keep their data in NVS `lc*`; the first boot of the renamed firmware moves it to `oc*` (oc rename Task 4). <!-- lc2oc: keep -->

## Before you start: sequencing

| Task | Repo, branch | Starts | What |
|---|---|---|---|
| 0 | all three | **after plan 1 Task 17** (both plan-1 branches pushed) | pre-flight, branches, baselines |
| 1 | `opencell-firmware`, `oc-bench` (rebuilt on the renamed firmware by the oc rename, Task 9) | done | `ocb_time`: TIME labels with the internal PPS (#2); push |
| 2 | `opencell-core`, `oc-core` (new, off `main`) | after 1 | submodule on `oc-bench`; build options; `oc_util` (log, config, framing, sockets) |
| 3 | `opencell-core`, `oc-core` | after 2 | `oc_seal`: AES-256-GCM, the master key file |
| 4 | `opencell-core`, `oc-core` | after 3 | `oc_sql`: the SQLite store, migrations, backup, lock |
| 5 | `opencell-core`, `oc-core` | after 4 | the admin commands, the channel-list text, the HSS import |
| 6 | `opencell-core`, `oc-core` | after 5 | the `oc-core` program, its unit, its process test; push |
| 7 | `opencell-pi`, `oc-cell` (new, off `main`) | after 6 | the submodule, the build, `ocr` (the radio backend) |
| 8 | `opencell-pi`, `oc-cell` | after 7 | the `oc-cell` program: config, serial port, core client, `ocs`, unit |
| 9 | `opencell-pi`, `oc-cell` | after 8 | process tests (§9.4): two cells, a core, kills and restarts; push |
| 10 | `opencell-core`, `oc-core` | after 6 (may run beside 7–9) | the deploy script (§17.4); push |
| 11 | the bench: laptop + `opencell-bs1` | after 9 and 10 | Pi setup, deploy `v0.1.0`, import, T2 restored, §9.5a over the air |
| 12 | `opencell-firmware`, `oc-bench` | after 11 | retire `ocbench net`/`mkqr`, `ocb_net`, `ocb_hss`; push |
| 13 | all three | after 12 | pins on the final tips, suites, sanitizers, READMEs; push |

Plan 1 must be finished first for everything from Task 2 on: Tasks 4–9 and 13 use `oc_cell` (plan 1 Task 13), `CELL_CFG` and `oc_cell_list_ver` (Task 16), the store contract of its Task 11 fix round, the async `oc_sig_net` (firmware Task 9) and `oc_sig_net_number`, `OC_SIG_NET_ALERTING` (Task 10). Task 1 needs only plan 1's firmware Tasks 7–10, which are pushed (`net-core` `3c9581f`): it may start now, doing Task 0's firmware lines (Steps 3 and 4 for the firmware) first. Task 10 needs only Task 6 and can run while Tasks 7–9 do.

**Files other work touches.** `tools/ocbench/ocbench.c` (Task 1 and 12) is also where any bench fix lands; if a "replace" text is not there verbatim, find the same code and make the same change; never drop another branch's line to make a replacement fit.

## Global Constraints

- **Where to work:** firmware in `/home/devin/Documents/opencell/firmware` on `oc-bench`; core in `/home/devin/Documents/opencell/core` on `oc-core`; Pi in `/home/devin/Documents/opencell/pi` on `oc-cell`. Each task names its repository in its **Repo:** line; check with `git -C <repo> branch --show-current` before the first edit. Never commit to any `main`; merging is the controller's decision.
- **Submodules, not copies:** the core uses `oc_sig` through `third_party/opencell-firmware`; the Pi repository uses the core (and through it the firmware) through `third_party/opencell-core`. A change to either is made in its own repository, pushed, and reached by moving the pin (`git -C third_party/… checkout <commit>` then `git add third_party/…`).
- **Commits:** one per task, at the task's last step. Every commit message ends with exactly these two lines, with your own model name in the first:

  ```
  Co-Authored-By: <your model name> <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL
  ```
- **Language and warnings:** C11 with `-Wall -Wextra -Werror` everywhere; fix what the compiler reports, never silence it. Linux-only files start with `#define _GNU_SOURCE`.
- **Portable libraries stay portable:** `oc_core` and `oc_cell` make no OS calls. Everything Linux (files, sockets, SQLite, clocks, signals) lives in `oc/` (core) and `oc-cell/` (Pi).
- **Framing (spec §6):** "`len (2, BE) ‖ type (1) ‖ body`, at most 512 B, little-endian fields like oc_link; numbers are 8 BCD bytes, full form." "Single site: a Unix stream socket (`/run/opencell/core.sock`, owner-only)" — here 0660 group `oc-cell` (ruling 2). "Connections always go out from the cell."
- **Liveness (spec §6):** "PING every 5 s. The link counts as down after 15 s without traffic." (`oc_core` and `oc_cell` run it; the programs only move frames.)
- **Data model (spec §5):** "SQLite, WAL, `synchronous=FULL`". Numbers stored "Always the full form" as text `+883160655501234`. "SQN, numbers and TMIDs are stored in the clear."
- **Keys at rest (spec §5):** "`k`, `opc`, `sk` and token `secret` are sealed with AES-256-GCM under a 32-byte master key. The GCM nonce is random (12 B, stored with the ciphertext), and the AAD is `table ‖ column ‖ primary key ‖ key_version`." "The master key is not in the database. It comes from a systemd credential file (`LoadCredential=`, root-only, 0400), or from `--key-file` on the bench."
- **Admin (spec §17.1):** "`oc-core admin …` talks to the **running daemon over a local Unix socket** (`/run/opencell/admin.sock`). Access is root or the `oc-admin` group, mode 0660, and every admin command is written to `audit`." "`oc-core admin --offline --db …` opens the database directly, only while the daemon is stopped (first setup, recovery); it refuses if the daemon's lock is held."
- **Daemon (spec §17.5):** "One thread: a `poll()` loop that feeds `oc_core` its messages and `tick(now)`, with SQLite on the same thread (WAL, `synchronous=FULL`, small transactions)."
- **Logs (spec §17.8):** "journald, plus `oc-core admin status` (links, cells, calls, and later replication lag). There are no metrics endpoints until a need appears."
- **Schema (spec §17.9):** "`PRAGMA user_version`, with ordered migrations in the binary. Before migrating, the daemon takes an automatic `.backup` next to the database."
- **Deploy (spec §17.4, §17.11):** "It takes a tagged revision (`vX.Y.Z`; only tags are deployed), sends it over SSH or Tailscale, builds on the target (… Debian 13 arm64 on the Pi), installs to `/usr/local` with a systemd unit, and keeps the previous build for `rollback`. No packages for now." "A `vX.Y.Z` tag per repository."
- **Numbers:** the echo service is "`+883160655500100`"; the bench block is `8831606` (block index 1); T is `+883160655501234` (TMID `76ad0488`), T2 `+883160655501235` (TMID `76ae2064`).
- **Bench rules:** stop a program with `pkill -x <name>` or `systemctl stop`, never `pkill -f`/`pgrep -f`; one process per serial port (oc-cell holds its board's port exclusively, `TIOCEXCL`).
- **Host test commands:**
  - firmware, one target: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build --target NAME 2>&1 | grep -E "error|warning"; host-tests/build/NAME | tail -3`
  - firmware, whole suite: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3)`
  - core, one target: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target NAME 2>&1 | grep -E "error|warning"; build/tests/NAME | tail -3`
  - core, whole suite: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
  - Pi, one target / whole suite: the core commands with `/home/devin/Documents/opencell/pi`.
  - under ASan/UBSan: the whole-suite command with `-B build/asan` (or `host-tests/build/asan`) and `-DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"` on the configure line.

## Review Focus

1. **The core goes away and comes back while cells run** (`systemctl restart oc-core`, a crash, the bench's power strip). Expected: every cell reconnects by itself (1 s, doubling to 30 s), keeps its boot id so the core keeps its locations, and a call across the core ends at once with cause 5 instead of hanging. Pinned by `test_proc_cells.sh` "the core is killed and restarted" (Task 9).
2. **Two programs open the same serial port** (a second `oc-cell`, or `ocbench`/`oc_console.py` while `oc-cell` runs). Expected: the second is refused with "in use by another process" and the running cell is not disturbed; two readers of one USB port silently split its frames. Pinned by `test_occ_cfg` `test_the_board_port_is_exclusive` (Task 8, on a pseudo-terminal).
3. **The master key is wrong or readable by others** (a copied file, a `chmod` slip, the wrong credential). Expected: `oc-core` refuses to start, naming the problem, instead of starting and failing at the first activation or leaking the key. Pinned by `test_oc_sql` `test_a_wrong_master_key_is_refused_at_open` and `test_oc_core_proc.sh` (Tasks 4, 6).
4. **The board resets under a running `oc-cell`** (USB glitch, brown-out, someone presses RST). Expected: `oc-cell` sees STATUS frame 0, labels the board again and resumes the schedule without a restart, whatever the new PPS phase. Pinned by `test_ocr` `test_internal_pps_labels_then_schedules` (Task 7) and `test_ocb_time` `test_a_rebooted_board_is_labelled_again` (Task 1).
5. **The HSS import meets a file it can't fully take** (a hand-edited line, a TMID already bound, a key id the config doesn't use, the daemon running). Expected: nothing is written and the reason names the line or subscriber, so the import can be fixed and run again. Pinned by `test_oc_admin` `test_import_is_all_or_nothing` (Task 5).

## Decisions where the spec is silent

**Repositories and build**
- **`opencell-pi` has one submodule, `opencell-core`, and uses its nested `opencell-firmware`.** `oc_cell` (in the core) is compiled against `oc_sig_net_t` (in the firmware), and `OC_SIG_NET_TERMS` must agree between them; two independent pins could name a core and a firmware never built together. One pin names a pair the core's own suite tested. The price: a firmware-only fix reaches the Pi in two steps (move the core's pin, then the Pi's). §17.10's "opencell-firmware as a submodule … and opencell-core as a submodule" holds in substance: the firmware is there, one level down.
- The core's CMake option is `OC_CORE_TESTS` and the Pi's `OC_PI_TESTS`, each defaulting to "top-level project", so the core built inside the Pi repository (or by the deploy script, with the option off) never fetches Unity or builds its tests. `cmake_minimum_required` rises to 3.21 for `PROJECT_IS_TOP_LEVEL` (Debian 13 has 3.31).
- The Pi repository adds the core with `EXCLUDE_FROM_ALL`: `oc-cell` builds only what it links; `oc-core` is built there only for the process tests.
- Programs report `OC_VERSION`: the deploy script passes the tag (`-DOC_VERSION=v0.1.0`); a developer build says what `git describe` says. `oc-cell`'s HELLO carries it as `sw_version` (x.y.z; 0.0.0 when it isn't a tag).

**`oc-core`**
- **Config** `/etc/opencell/oc-core.conf`: `core_id`, `key_id`, `echo`, `block = PREFIX INDEX` (one line per block), `db`, `cell_socket`, `cell_group`, `admin_socket`, `admin_group`. An unknown key is an error (a typo must not be ignored). Defaults: db `/var/lib/opencell/core/core.db`, sockets under `/run/opencell/`, no groups (0600).
- **The master key** is a file of exactly 32 raw bytes, refused if group or others may read it; the daemon takes `--key-file` or `$CREDENTIALS_DIRECTORY/master.key`. The database keeps a sealed check value (`meta.key_check`), so a wrong key is refused at open.
- **Sealing:** blob = `version (1) ‖ nonce (12) ‖ ciphertext ‖ tag (16)`; AAD = `table ‖ 0 ‖ column ‖ 0 ‖ primary key ‖ version`, the primary key being the number's 8 BCD bytes (subscriber), the token id (token), the key id big-endian (network), and nothing (meta). Version 1 is the only master key version for now.
- **Transactions:** `oc_core` calls `begin`, its puts, then `commit` without checking each put. The SQL store therefore remembers a failed put (or a failed `BEGIN`) and makes `commit` roll everything back and fail, so half a change is never durable. Outside `begin`/`commit` each put is its own durable transaction.
- **Token uniqueness:** "At most one unused token per number (partial unique index)" is enforced by the index; `token_put` is an upsert on `token_id` only, so a second unused token is refused, never silently replacing the first.
- **One process per database:** `PATH.lock` (flock) is held by the daemon and by `--offline`; the second is refused. `--offline` run as root reads the key, then becomes the owner of the database's directory, so files it creates stay the daemon's.
- **The admin socket protocol:** one command per connection; the client writes its words, each ending with a NUL, and shuts its side; the daemon answers `<status>\n` and the output (status 0 done, 1 refused, 2 usage). The daemon reads the peer's uid (`SO_PEERCRED`) for the audit record: `ADMIN`, detail `u<uid> [(refused)] <words>` (48 bytes, truncated). `OC_CORE_AUDIT_ADMIN` is added to `oc_core_store.h`.
- **Admin commands:** `status`; `net init [--period S]`; `cell add ID NAME [--mode part15|part97] [--list N]`, `cell mode ID part15|part97` (the daemon drops the cell's link so it reconnects and takes the mode from HELLO_ACK), `cell revoke ID`, `cell list`; `sub add [NUMBER]`, `sub issue NUMBER [--valid-h H]` (the client draws the QR with `qrencode` when a person is looking), `sub disable NUMBER`, `sub list`; `loc`; `cdr [N]`; `audit [N]`; `list set ID MHZ[:fixed],…|none`, `list show`; `import-ocb-hss FILE` (offline only). No `sub enable`: a disabled number stays disabled (the spec lists add, issue, disable, list).
- **Logs:** every line on stderr as `<N>text` (journald priorities); `oc_core`'s own lines at info.

**`oc-cell`**
- **Config** `/etc/opencell/oc-cell.conf` (see `occ_cfg.h`): `cell_id`, `core`, `radio = board|sim`, `board`, `board_role = bench|bs`, `board_reset`, `cell_seed`, `tier`, `dl_band`, `ul_band`, `mode`, `sync_ch`, `fixed_sync`, `attach_idle`, `period`, and for `radio = sim` `sim_term`, `sim_state`, `sim_control`.
- **At start** it sends the board a CONFIG (role, 915, radio 0, seed) and waits 1.5 s for its ACK: no ACK means no bs-radio on that port (a terminal ignores link frames), and `oc-cell` exits. `board_reset = 1` (default) pulses RTS first, so every start begins with a fresh board and a fresh PPS phase.
- **Clocks:** the board's frames and TIME labels use the host's realtime clock (chrony); `oc_cell` and `oc_sig_net` run on `CLOCK_MONOTONIC`.
- **Core client:** connect at start; on a drop, reconnect after 1 s, doubling to 30 s, back to 1 s once a HELLO is accepted. The boot id is random per process start.
- **Beacon from the core:** the mode `oc_cell` holds (from HELLO_ACK) sets PART97; with `fixed_sync` in a part15 cell the cell goes off air and logs why. `oc_cell_list_ver() & 3` is `cfg_ver`.
- **`attach_idle = 0`** (as `ocbench net` ran): an attaching terminal gets legs; `oc_sig_net`'s `channel(off)` releases them.

**Deferred (plan 9 and later)**
- TLS/mTLS for the cell and core links, certificates and the CA script, `cell.cert_fpr` checks, per-cell rate limits, the AV cache (2 per terminal), the two-cell bench (§9.5b), the `oc-core-1` VM and its port forward, backups to `oc-core-2`, the core's anchors per cell and their uniqueness check (ruling 3).

**Not in this plan:** TLS/mTLS (§6 multi-site), certificates (§17.6), the VM (§16), backups (§17.7), OCSS and several cores (plans 10–11), `rhu_bs` (plan 4), the web portal, voice.

## File Structure

| File | Repo | Responsibility | Task |
|---|---|---|---|
| `tools/ocbench/ocb_time.h`, `ocb_time.c` | firmware | When to send a board its TIME label, and which second (#2) | 1 |
| `host-tests/test_ocb_time.c` | firmware | `ocb_time` against `oc_clock` at every PPS phase | 1 |
| `tools/ocbench/ocbench.c`, `tools/ocbench/CMakeLists.txt`, `host-tests/CMakeLists.txt` | firmware | ocbench uses `ocb_time` (1); loses `net`/`mkqr` (12) | 1, 12 |
| `tools/ocbench/ocb_net.[ch]`, `ocb_hss.[ch]`, parts of `host-tests/test_ocbench.c`, `test_term_sim.c` | firmware | deleted | 12 |
| `CMakeLists.txt`, `tests/CMakeLists.txt`, `.gitmodules` pin | core | `OC_CORE_TESTS`, `oc/`, new tests | 2–6 |
| `oc/include/oc_log.h`, `oc_log.c` | core | `<N>`-prefixed log lines for journald | 2 |
| `oc/include/oc_kv.h`, `oc_kv.c` | core | `key = value` config files | 2 |
| `oc/include/oc_conn.h`, `oc_conn.c` | core | §6 framing on a non-blocking socket; Unix listen/connect; backoff | 2 |
| `oc/include/oc_seal.h`, `oc_seal.c` | core | AES-256-GCM sealing; the master key file | 3 |
| `oc/include/oc_sql.h`, `oc_sql.c` | core | The SQLite store, schema v1, migrations, backup, lock, key check | 4 |
| `oc/include/oc_admin.h`, `oc_admin.c`, `oc_import.c` | core | Admin commands, channel-list text, ocbench HSS import | 5 |
| `oc_core/include/oc_core_store.h` | core | `OC_CORE_AUDIT_ADMIN` | 5 |
| `oc/oc_core_main.c`, `oc/CMakeLists.txt` | core | The `oc-core` program (daemon, admin client, `--offline`) | 2–6 |
| `dist/systemd/oc-core.service`, `dist/oc-core.conf.example` | core | The unit and a commented config | 6 |
| `tests/test_oc_conn.c`, `test_oc_seal.c`, `test_oc_sql.c`, `test_oc_admin.c`, `tool_oc_hello.c`, `test_oc_core_proc.sh` | core | The tests of 2–6 | 2–6 |
| `tools/deploy/oc-deploy`, `tests/test_oc_deploy.sh` | core | Deploy a tag to a host, rollback (§17.4) | 10 |
| `.gitmodules`, `third_party/opencell-core` | pi | The core (and, nested, the firmware) at a pinned commit | 7, 13 |
| `CMakeLists.txt`, `oc-cell/CMakeLists.txt`, `tests/CMakeLists.txt`, `.gitignore` | pi | The build | 7–9 |
| `oc-cell/ocr.h`, `ocr.c` | pi | The radio backend: `ocb_cell` + `oc_cell`, one W12 | 7 |
| `oc-cell/occ_cfg.h`, `occ_cfg.c` | pi | `oc-cell.conf` | 8 |
| `oc-cell/ocs.h`, `ocs.c` | pi | Simulated terminals (`radio = sim`) | 8 |
| `oc-cell/occ_board.h`, `occ_board.c` | pi | The board's serial port: exclusive open, reset, frames | 8 |
| `oc-cell/occ_main.c` | pi | The `oc-cell` program | 8 |
| `dist/systemd/oc-cell.service`, `dist/oc-cell.conf.example` | pi | The unit and a commented config | 8 |
| `tests/test_ocr.c`, `test_occ_cfg.c`, `test_proc_cells.sh` | pi | The tests of 7–9 | 7–9 |
| `docs/bench/network-core-bench.md` | pi | The bench record (§9.5a) | 11 |
| `README.md` | core, pi | What is there now | 13 |

---

### Task 0: Pre-flight: plan 1 is done; the three branches

**Repos:** all three. **Starts:** after plan 1 Task 17.

Plan 1 (network core 1) builds everything this plan runs: `oc_cell`, `CELL_CFG`, the async `oc_sig_net`. This task checks that its final branches are pushed and have the names this plan uses, makes this plan's three branches, and writes down the test counts later tasks compare against.

**Files:** none.

**Interfaces:**
- Consumes (from plan 1, exact names used by Tasks 4–9): `oc_cell_init`, `oc_cell_ul`, `oc_cell_upper`, `oc_cell_radio_link`, `oc_cell_core_up/down/rx`, `oc_cell_tick`, `oc_cell_list_ver`, `oc_cell_t.ready`, `oc_cell_t.net` (`oc_sig_net_t`, whose `cfg.mode` HELLO_ACK sets); `oc_core_init`, `oc_core_link_up/down`, `oc_core_rx`, `oc_core_tick`, `oc_core_netkey_new`, `oc_core_cell_add`, `oc_core_cell_revoke`, `oc_core_sub_add`, `oc_core_token_issue`, `oc_core_sub_disable`, `oc_core_chan_list_set`, `oc_core_t.links[]`/`.calls[]`; `oc_core_store_t` with `list_get`/`list_put`; `store_contract()` in `tests/core_store_contract.h`; `oc_sig_net_number`, `OC_SIG_NET_IN_BUSY`, `OC_SIG_NET_ALERTING`.
- Produces: branches `oc-bench` (firmware), `oc-core` (core), `oc-cell` (Pi); the baseline counts **N_fw** (firmware suite) and **N_core** (core suite).

- [ ] **Step 1: Plan 1 is pushed and complete**

Run: `cd /home/devin/Documents/opencell/firmware && git fetch -q && git grep -c 'OC_SIG_NET_ALERTING\|OC_SIG_NET_IN_BUSY\|int oc_sig_net_number' origin/main -- firmware/components/oc_sig/include/oc_sig_net.h`
Expected: `origin/main:firmware/components/oc_sig/include/oc_sig_net.h:3` (or more).

Run: `cd /home/devin/Documents/opencell/core && git fetch -q && for s in oc_cell_list_ver oc_cell_radio_link oc_core_chan_list_set 'list_get' ; do printf '%s ' "$s"; git grep -c "$s" origin/main -- oc_cell/include/oc_cell.h oc_core/include/oc_core.h oc_core/include/oc_core_store.h | awk -F: '{n+=$NF} END {print n}'; done; git ls-tree origin/main tests/ | grep -c 'net_sim.h\|core_store_contract.h'`
Expected: four lines each ending in a number ≥ 1 (`oc_cell_list_ver 1`, `oc_cell_radio_link 1`, `oc_core_chan_list_set 1`, `list_get 1`), then `2`.

If either check fails, plan 1 is not finished: stop and report. If a name exists under a different spelling (plan 1's reviews may have renamed something), stop and report the difference: every later task's code uses the names in the **Interfaces** block above.

- [ ] **Step 2: Has plan 1 been merged?**

Run: `cd /home/devin/Documents/opencell/firmware && git fetch -q && git ls-tree -d --name-only origin/main firmware/components/oc_sig; cd ../core && git fetch -q && git ls-tree -d --name-only origin/main oc_core`
Expected: `firmware/components/oc_sig`, then `oc_core`: plan 1 and the oc rename are in both `main`s. If either line is missing, stop: this plan starts after the oc rename.

- [ ] **Step 3: The branches**

```bash
cd /home/devin/Documents/opencell/firmware && git status --short && git switch oc-bench   # rebuilt by the oc rename (its Task 9)
cd /home/devin/Documents/opencell/core && git status --short && git switch -c oc-core origin/main
git submodule update --init
cd /home/devin/Documents/opencell/pi && git status --short && git switch -c oc-cell origin/main
```

Each `git status --short` must print nothing first (a clean tree). The firmware tree may still be on `net-core` with plan 1's work committed; if `git status` shows changes there, stop and report.

- [ ] **Step 4: Baselines**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3)`
Expected: no compiler output, `100% tests passed, 0 tests failed out of N_fw`. Write N_fw down (34 when validated).

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: no compiler output, `100% tests passed, 0 tests failed out of N_core`. Write N_core down (8 when validated).

- [ ] **Step 5: The Pi's build tools**

Run: `ssh opencell@opencell-bs1 'dpkg-query -W -f="\${Package} \${Status}\n" cmake gcc git libssl-dev libsqlite3-dev sqlite3 qrencode python3-venv 2>&1 | sed "s/ install ok installed//"'`
Expected: one line per package; `libssl-dev`, `libsqlite3-dev`, `sqlite3` and `qrencode` were missing on 2026-09-28 (Task 11 installs them). Nothing to commit.

---

### Task 1: TIME labels with the internal PPS (`ocb_time`, opencell-firmware#2)

**Repo:** `opencell-firmware`, branch `oc-bench`, at `/home/devin/Documents/opencell/firmware`. **Starts:** after Task 0.

With `--internal` (a board in the bench role, internal 1 Hz PPS), `ocbench` sends each TIME label about 0.1 s after the host second, but the board accepts a label only within `OC_TIME_LABEL_MAX_US` (900 ms) of its own PPS edge. When the edge falls 0.1–0.2 s after the host second, every label is refused as `late`, the board never gets a timebase, and the cell sends nothing (issue #2, bench 2026-09-28). The Pi bench runs exactly this way: the L76K HAT's PPS is not wired to board A.

The fix, `ocb_time`, is shared by ocbench and `oc-cell` (Task 7): with the internal PPS a label goes out only while the board has no timebase (its STATUS frame is 0) — any second will do, since the board counts on by itself once labelled — a `late` answer is retried 300 ms later (after the edge that was under 100 ms away), and once a label is accepted nothing more is sent until STATUS shows the frame, so no later label can disagree with the board's count (three disagreeing labels would re-anchor it, `oc_clock.h`). With GPS PPS nothing changes: one label per host second, 0.1–0.8 s into it.

**Files:**
- Create: `tools/ocbench/ocb_time.h`, `tools/ocbench/ocb_time.c`, `host-tests/test_ocb_time.c`
- Modify: `tools/ocbench/CMakeLists.txt`, `host-tests/CMakeLists.txt`, `tools/ocbench/ocbench.c`

**Interfaces:**
- Consumes: `oc_clock_on_pps`, `oc_clock_on_time`, `oc_clock_frame_at`, `OC_TIME_LABEL_MAX_US` (`oc_clock.h`); `OC_ACK_OK`, `OC_ACK_ERR_LATE` (`oc_link.h`).
- Produces (`ocb_time.h`, in the `ocbench_core` library):
  ```c
  typedef struct { int internal; uint32_t last_s; int pending; uint8_t seq; uint64_t sent_us, next_us;
                   uint32_t sent, accepted, late; } ocb_time_t;
  void     ocb_time_init(ocb_time_t *t, int internal);
  uint32_t ocb_time_due(ocb_time_t *t, uint64_t now_us, int board_has_time); /* the second to send now, or 0 */
  void     ocb_time_sent(ocb_time_t *t, uint8_t seq, uint64_t now_us);
  void     ocb_time_ack(ocb_time_t *t, uint8_t seq, uint8_t status, uint64_t now_us);
  ```
  `OCB_TIME_RETRY_US` 300000, `OCB_TIME_ACK_US` 500000, `OCB_TIME_HOLD_US` 3000000, `OCB_TIME_REFUSED_US` 1000000.

- [ ] **Step 1: Write the failing test**

The test runs the board's real `oc_clock` against `ocb_time` at every PPS phase in 10 ms steps, and shows the old rule failing at 150 ms.

Create `host-tests/test_ocb_time.c`:
```c
/* ocb_time against the board's own oc_clock (opencell-firmware#2): a W12
 * with its internal 1 Hz PPS gets a timebase within a few seconds whatever
 * the phase of its edge against the host second, and never takes a label
 * that disagrees with its count. */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "oc_clock.h"
#include "oc_link.h"
#include "ocb_time.h"

void setUp(void) {}
void tearDown(void) {}

#define LAT_US   4000u /* USB, one way */
#define HOST0_US 1790000000000000ull

typedef struct {
    oc_clock_t c;
    uint64_t   phase_us; /* its edges fall this far after each host second */
    uint64_t   next_edge;
} board_t;

typedef struct {
    uint64_t at; /* host time it arrives */
    uint32_t s;
    uint8_t  seq;
} label_t;

/* Board time is host time here (no crystal error: the phase is what
 * matters). Runs the host loop every 5 ms for ms, the way ocbench and
 * oc-cell do: STATUS once a second, labels as ocb_time says. Returns the
 * host time the board's clock became usable, or 0. */
static uint64_t run(board_t *b, ocb_time_t *t, uint64_t start, uint32_t ms, uint32_t *refused)
{
    label_t inflight[8];
    int n = 0;
    uint8_t seq = 0;
    uint32_t f;
    int has_time = oc_clock_frame_at(&b->c, start, &f) == 0; /* what the host learned from the last STATUS */
    uint64_t got = 0;
    for (uint64_t now = start; now < start + (uint64_t)ms * 1000u; now += 5000u) {
        while (b->next_edge <= now) {
            oc_clock_on_pps(&b->c, b->next_edge);
            b->next_edge += 1000000u;
        }
        for (int i = 0; i < n; i++) { /* labels arriving at the board; their ACKs come back at once */
            if (inflight[i].at > now) continue;
            int ok = oc_clock_on_time(&b->c, inflight[i].s, inflight[i].at) == 0;
            if (!ok && refused != NULL) (*refused)++;
            ocb_time_ack(t, inflight[i].seq, ok ? OC_ACK_OK : OC_ACK_ERR_LATE, now + LAT_US);
            inflight[i--] = inflight[--n];
        }
        if ((now - start) % 1000000u == 250000u) has_time = oc_clock_frame_at(&b->c, now, &f) == 0; /* STATUS */
        if (got == 0 && oc_clock_frame_at(&b->c, now, &f) == 0) got = now;
        uint32_t s = ocb_time_due(t, now, has_time);
        if (s != 0 && n < 8) {
            ocb_time_sent(t, seq, now);
            inflight[n++] = (label_t){ now + LAT_US, s, seq++ };
        }
    }
    return got;
}

static void board_init(board_t *b, uint64_t start, uint32_t phase_ms)
{
    oc_clock_init(&b->c, 5000000u);
    b->phase_us = (uint64_t)phase_ms * 1000u;
    b->next_edge = start - start % 1000000u + b->phase_us;
    if (b->next_edge < start) b->next_edge += 1000000u;
}

/* The bug: labels 0.1 s after the host second, edges 0.1-0.2 s after it. */
static void test_the_old_rule_never_labels_a_late_edge(void)
{
    board_t b;
    ocb_time_t t;
    uint32_t refused = 0;
    board_init(&b, HOST0_US, 150);
    ocb_time_init(&t, 0); /* the GPS rule, which ocbench used for --internal too */
    TEST_ASSERT_EQUAL_UINT64(0, run(&b, &t, HOST0_US, 10000, &refused));
    TEST_ASSERT_TRUE(refused >= 9);
}

static void test_every_edge_phase_gets_a_timebase_within_3_s(void)
{
    for (uint32_t phase = 0; phase < 1000; phase += 10) {
        board_t b;
        ocb_time_t t;
        board_init(&b, HOST0_US, phase);
        ocb_time_init(&t, 1);
        uint64_t got = run(&b, &t, HOST0_US, 6000, NULL);
        char msg[48];
        snprintf(msg, sizeof(msg), "edge phase %u ms", phase);
        TEST_ASSERT_TRUE_MESSAGE(got != 0, msg);
        /* 3 edges to lock, then at most one refusal and a 300 ms retry */
        TEST_ASSERT_TRUE_MESSAGE(got - HOST0_US <= 3600000u, msg);
        TEST_ASSERT_TRUE_MESSAGE(t.accepted == 1, msg);
    }
}

/* Once the board counts on its own, nothing more is sent: no second label
 * can disagree with its count (three would re-anchor it, oc_clock.h). */
static void test_no_label_once_the_board_has_time(void)
{
    board_t b;
    ocb_time_t t;
    board_init(&b, HOST0_US, 150);
    ocb_time_init(&t, 1);
    TEST_ASSERT_TRUE(run(&b, &t, HOST0_US, 5000, NULL) != 0);
    uint32_t sent = t.sent;
    uint32_t anchor = b.c.anchor_unix_s;
    run(&b, &t, HOST0_US + 5000000u, 20000, NULL);
    TEST_ASSERT_EQUAL_UINT32(sent, t.sent);
    TEST_ASSERT_EQUAL_UINT32(anchor + 20u, b.c.anchor_unix_s); /* counted on by itself, 20 edges */
}

/* A board that reboots (STATUS frame 0 again) is labelled again. */
static void test_a_rebooted_board_is_labelled_again(void)
{
    board_t b;
    ocb_time_t t;
    board_init(&b, HOST0_US, 420);
    ocb_time_init(&t, 1);
    TEST_ASSERT_TRUE(run(&b, &t, HOST0_US, 5000, NULL) != 0);
    board_init(&b, HOST0_US + 5000000u, 870); /* a new boot: a new phase, no time */
    TEST_ASSERT_TRUE(run(&b, &t, HOST0_US + 5000000u, 6000, NULL) != 0);
    TEST_ASSERT_EQUAL_UINT32(2, t.accepted);
}

static void test_a_lost_ack_is_sent_again(void)
{
    ocb_time_t t;
    ocb_time_init(&t, 1);
    uint64_t now = HOST0_US + 300000u;
    uint32_t s = ocb_time_due(&t, now, 0);
    TEST_ASSERT_EQUAL_UINT32((uint32_t)(now / 1000000u), s);
    ocb_time_sent(&t, 7, now);
    TEST_ASSERT_EQUAL_UINT32(0, ocb_time_due(&t, now + 100000u, 0)); /* waiting for its ACK */
    ocb_time_ack(&t, 8, OC_ACK_OK, now + 100000u);                  /* someone else's ACK */
    TEST_ASSERT_EQUAL_UINT32(0, ocb_time_due(&t, now + 200000u, 0));
    TEST_ASSERT_TRUE(ocb_time_due(&t, now + OCB_TIME_ACK_US, 0) != 0);
}

/* GPS PPS: one label per host second, 0.1-0.8 s into it, as before. */
static void test_gps_labels_once_a_second(void)
{
    ocb_time_t t;
    ocb_time_init(&t, 0);
    TEST_ASSERT_EQUAL_UINT32(0, ocb_time_due(&t, HOST0_US + 50000u, 1));
    TEST_ASSERT_EQUAL_UINT32((uint32_t)(HOST0_US / 1000000u), ocb_time_due(&t, HOST0_US + 150000u, 1));
    TEST_ASSERT_EQUAL_UINT32(0, ocb_time_due(&t, HOST0_US + 200000u, 1));
    TEST_ASSERT_EQUAL_UINT32(0, ocb_time_due(&t, HOST0_US + 900000u, 1));
    TEST_ASSERT_EQUAL_UINT32((uint32_t)(HOST0_US / 1000000u) + 1u, ocb_time_due(&t, HOST0_US + 1300000u, 1));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_the_old_rule_never_labels_a_late_edge);
    RUN_TEST(test_every_edge_phase_gets_a_timebase_within_3_s);
    RUN_TEST(test_no_label_once_the_board_has_time);
    RUN_TEST(test_a_rebooted_board_is_labelled_again);
    RUN_TEST(test_a_lost_ack_is_sent_again);
    RUN_TEST(test_gps_labels_once_a_second);
    return UNITY_END();
}
```

In `host-tests/CMakeLists.txt`, replace:
```cmake
oc_test(test_ocbench ocbench_core)
```
with:
```cmake
oc_test(test_ocbench ocbench_core)
oc_test(test_ocb_time ocbench_core)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build --target test_ocb_time 2>&1 | grep -oE "ocb_time.h: No such file or directory" | head -1`
Expected: `ocb_time.h: No such file or directory`.

- [ ] **Step 3: Implement**

Create `tools/ocbench/ocb_time.h`:
```c
/* ocb_time: when to send a W12 its TIME label, and which second to put in it.
 *
 * GPS PPS on the board (role bs): the edge is the true second, so the label
 * is the host second, sent once per second 0.1-0.8 s after it.
 *
 * Internal PPS (role bench, --internal): the edge falls wherever the board's
 * boot put it, and the board accepts a label only within
 * OC_TIME_LABEL_MAX_US (900 ms) after its latest edge (oc_clock_on_time).
 * Sending at a fixed point of the host second is refused for ever when the
 * edge lands just after it (opencell-firmware#2). So in this mode a label
 * goes out only while the board has no timebase (its STATUS frame is 0):
 * any second will do, since the board then counts on by itself. A label
 * refused as late means the next edge is under 100 ms away: the same label
 * is tried again 300 ms later, after that edge. Once one is accepted,
 * nothing more is sent until the board shows its frame (or 3 s pass), so a
 * second label can never disagree with the board's count.
 *
 * I/O-free: the caller sends the message and feeds back its ACK. */
#ifndef OCB_TIME_H
#define OCB_TIME_H

#include <stdint.h>

#define OCB_TIME_RETRY_US   300000u  /* after a "late" ACK */
#define OCB_TIME_ACK_US     500000u  /* no ACK by then: lost, send again */
#define OCB_TIME_HOLD_US    3000000u /* after an accepted label: wait this long for STATUS to show a frame */
#define OCB_TIME_REFUSED_US 1000000u /* any other refusal (the board is not configured yet) */

typedef struct {
    int      internal;
    uint32_t last_s;  /* GPS: the host second last labelled */
    int      pending; /* internal: a label is out, its ACK not in */
    uint8_t  seq;
    uint64_t sent_us;
    uint64_t next_us; /* internal: nothing before this */
    uint32_t sent, accepted, late; /* counters */
} ocb_time_t;

void ocb_time_init(ocb_time_t *t, int internal);
/* The unix second to send in a TIME label now, or 0: nothing to send.
 * board_has_time: the board's latest STATUS carried a frame number. */
uint32_t ocb_time_due(ocb_time_t *t, uint64_t now_us, int board_has_time);
/* The label ocb_time_due gave was sent with this seq. */
void ocb_time_sent(ocb_time_t *t, uint8_t seq, uint64_t now_us);
/* An ACK came in (any seq: those not of the pending label are ignored).
 * status is an oc_ack_status_t. */
void ocb_time_ack(ocb_time_t *t, uint8_t seq, uint8_t status, uint64_t now_us);

#endif
```

Create `tools/ocbench/ocb_time.c`:
```c
#include "ocb_time.h"

#include <string.h>

#include "oc_link.h"

void ocb_time_init(ocb_time_t *t, int internal)
{
    memset(t, 0, sizeof(*t));
    t->internal = internal;
}

uint32_t ocb_time_due(ocb_time_t *t, uint64_t now_us, int board_has_time)
{
    uint32_t s = (uint32_t)(now_us / 1000000u);
    if (!t->internal) {
        uint32_t into = (uint32_t)(now_us % 1000000u);
        if (s == t->last_s || into <= 100000u || into >= 800000u) return 0;
        t->last_s = s;
        return s;
    }
    if (board_has_time) {
        t->pending = 0;
        t->next_us = 0;
        return 0;
    }
    if (t->pending && now_us - t->sent_us >= OCB_TIME_ACK_US) {
        t->pending = 0; /* the ACK was lost: try again now */
        t->next_us = 0;
    }
    if (t->pending || now_us < t->next_us) return 0;
    return s;
}

void ocb_time_sent(ocb_time_t *t, uint8_t seq, uint64_t now_us)
{
    t->sent++;
    if (!t->internal) return;
    t->pending = 1;
    t->seq = seq;
    t->sent_us = now_us;
}

void ocb_time_ack(ocb_time_t *t, uint8_t seq, uint8_t status, uint64_t now_us)
{
    if (!t->internal || !t->pending || seq != t->seq) return;
    t->pending = 0;
    if (status == OC_ACK_OK) {
        t->accepted++;
        t->next_us = now_us + OCB_TIME_HOLD_US;
    } else if (status == OC_ACK_ERR_LATE) {
        t->late++;
        t->next_us = now_us + OCB_TIME_RETRY_US;
    } else {
        t->next_us = now_us + OCB_TIME_REFUSED_US;
    }
}
```

In `tools/ocbench/CMakeLists.txt`, replace:
```cmake
add_library(ocbench_core STATIC ocbench_core.c ocb_cell.c ocb_hss.c ocb_net.c ocb_merge.c)
```
with:
```cmake
add_library(ocbench_core STATIC ocbench_core.c ocb_cell.c ocb_hss.c ocb_net.c ocb_merge.c ocb_time.c)
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build --target test_ocb_time 2>&1 | grep -E "error|warning"; host-tests/build/test_ocb_time | tail -3`
Expected: no compiler output, then `6 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: ocbench labels its boards with `ocb_time`**

Every ocbench command that labels boards (`link`, `cw`, `guard`, `cell`, `net`, `duplex`) goes through one function.

In `tools/ocbench/ocbench.c`, replace:
```c
 * With --internal (boards configured as "bench", internal 1 Hz PPS), each
 * board's frame numbering is learned from its STATUS messages. */
```
with:
```c
 * With --internal (boards configured as "bench", internal 1 Hz PPS), each
 * board's frame numbering is learned from its STATUS messages, and a board
 * gets TIME labels only until it has a timebase (ocb_time.h). */
```

In `tools/ocbench/ocbench.c`, replace:
```c
#include "ocb_net.h"
```
with:
```c
#include "ocb_net.h"
#include "ocb_time.h"
```

In `tools/ocbench/ocbench.c`, replace:
```c
    uint64_t    status_at_us;
    int         have_status;
```
with:
```c
    uint64_t    status_at_us;
    int         have_status;
    int         has_time;         /* its latest fresh STATUS carried a frame (it has a timebase) */
    ocb_time_t  time;             /* its TIME labels */
```

In `tools/ocbench/ocbench.c`, replace:
```c
                if (m.type == OC_MSG_STATUS && m.u.status.frame_number != 0 &&
                    now_us() - b->opened_us > 1500000u) {
                    b->status_frame = m.u.status.frame_number;
                    b->status_at_us = now_us();
                    b->have_status = 1;
                } else if (m.type == OC_MSG_ACK && m.u.ack.status != OC_ACK_OK) {
                    b->acks_err++;
                    b->ack_err_by[b->sent_type[m.u.ack.acked_seq] & 15][m.u.ack.status & 7]++;
                }
```
with:
```c
                if (m.type == OC_MSG_STATUS && now_us() - b->opened_us > 1500000u) {
                    b->has_time = m.u.status.frame_number != 0;
                    if (b->has_time) {
                        b->status_frame = m.u.status.frame_number;
                        b->status_at_us = now_us();
                        b->have_status = 1;
                    }
                } else if (m.type == OC_MSG_ACK) {
                    if (b->sent_type[m.u.ack.acked_seq] == OC_MSG_TIME) {
                        ocb_time_ack(&b->time, m.u.ack.acked_seq, m.u.ack.status, now_us());
                    }
                    if (m.u.ack.status != OC_ACK_OK) {
                        b->acks_err++;
                        b->ack_err_by[b->sent_type[m.u.ack.acked_seq] & 15][m.u.ack.status & 7]++;
                    }
                }
```

In `tools/ocbench/ocbench.c`, replace:
```c
static void send_time(board_t *b, uint32_t unix_s)
{
    oc_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_MSG_TIME;
    m.u.time.unix_s = unix_s;
    send_msg(b, &m);
}
```
with:
```c
/* Each board's TIME label when ocb_time says it is due: once a second with
 * GPS PPS; with --internal only until the board has a timebase, a "late"
 * tried again 300 ms on (opencell-firmware#2). */
static void send_labels(board_t **bs, int n, uint64_t t)
{
    for (int i = 0; i < n; i++) {
        uint32_t s = ocb_time_due(&bs[i]->time, t, bs[i]->has_time);
        if (s == 0) continue;
        oc_msg_t m;
        memset(&m, 0, sizeof(m));
        m.type = OC_MSG_TIME;
        m.u.time.unix_s = s;
        int seq = send_msg(bs[i], &m);
        if (seq >= 0) ocb_time_sent(&bs[i]->time, (uint8_t)seq, t);
    }
}
```

In `tools/ocbench/ocbench.c`, replace:
```c
    uint32_t last_time_s = 0;
    uint32_t sent_frames = 0;
```
with:
```c
    uint32_t sent_frames = 0;
    for (int i = 0; i < nb; i++) ocb_time_init(&bs[i]->time, internal);
```

In `tools/ocbench/ocbench.c`, replace:
```c
        uint64_t t = now_us();
        uint32_t s = (uint32_t)(t / 1000000u);
        if (s != last_time_s && t % 1000000u > 100000u && t % 1000000u < 800000u) {
            last_time_s = s;
            for (int i = 0; i < nb; i++) {
                send_time(bs[i], s);
            }
        }
        if (sent_frames >= frames) {
```
with:
```c
        uint64_t t = now_us();
        send_labels(bs, nb, t);
        if (sent_frames >= frames) {
```

In `tools/ocbench/ocbench.c`, replace:
```c
    uint32_t last_time_s = 0, last_host_frame = 0, last_print_s = 0;
```
with:
```c
    uint32_t last_host_frame = 0, last_print_s = 0;
    for (int i = 0; i < nb; i++) ocb_time_init(&bs[i]->time, internal);
```

In `tools/ocbench/ocbench.c`, replace:
```c
        if (net) {
            ocb_net_tick(&lnet, t);
        }
        uint32_t s = (uint32_t)(t / 1000000u);
        if (s != last_time_s && t % 1000000u > 100000u && t % 1000000u < 800000u) {
            last_time_s = s;
            for (int i = 0; i < nb; i++) {
                send_time(bs[i], s);
            }
        }
```
with:
```c
        if (net) {
            ocb_net_tick(&lnet, t);
        }
        uint32_t s = (uint32_t)(t / 1000000u);
        send_labels(bs, nb, t);
```

In `tools/ocbench/ocbench.c`, replace:
```c
    uint32_t last_time_s = 0, sent = 0, next = 0, t_minus_a = 0;
```
with:
```c
    uint32_t sent = 0, next = 0, t_minus_a = 0;
    ocb_time_init(&a.time, internal);
    ocb_time_init(&t.time, internal);
```

In `tools/ocbench/ocbench.c`, replace:
```c
        uint64_t now = now_us();
        uint32_t s = (uint32_t)(now / 1000000u);
        if (s != last_time_s && now % 1000000u > 100000u && now % 1000000u < 800000u) {
            last_time_s = s;
            send_time(&a, s);
            send_time(&t, s);
        }
```
with:
```c
        uint64_t now = now_us();
        send_labels(bs, 2, now);
```

- [ ] **Step 6: ocbench builds, and the whole suite passes**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S tools/ocbench -B tools/ocbench/build -G Ninja >/dev/null && cmake --build tools/ocbench/build 2>&1 | grep -E "error|warning"; ls tools/ocbench/build/ocbench`
Expected: no compiler output, then `tools/ocbench/build/ocbench`.

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_fw+1` (35 when validated).

- [ ] **Step 7: Commit and push**

```bash
cd /home/devin/Documents/opencell/firmware
git add tools/ocbench/ocb_time.h tools/ocbench/ocb_time.c tools/ocbench/ocbench.c tools/ocbench/CMakeLists.txt \
        host-tests/test_ocb_time.c host-tests/CMakeLists.txt
git commit -m "ocbench: TIME labels with the internal PPS only until the board has a timebase, retried on late (fixes #2)

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push -u origin oc-bench
```

(Close issue #2 with a comment naming the commit after Task 11 has seen board A take its labels on the Pi.)

---

### Task 2: The core's Linux utilities: logging, config files, framed connections

**Repo:** `opencell-core`, branch `oc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 1 (its commit is pushed).

Both daemons need the same three small things: log lines journald understands, `key = value` config files, and the §6 framing on a non-blocking stream socket (with the Unix-socket helpers and the reconnect backoff). They go into `oc_util`, which `oc-cell` links through the submodule. This task also moves the firmware pin to `oc-bench` (for `ocb_time`) and makes the build safe to include from another project: the tests become an option, `OC_CORE_TESTS`, on only when the core is the top-level project.

**Files:**
- Modify: `third_party/opencell-firmware` (the pin), `CMakeLists.txt`, `tests/CMakeLists.txt`
- Create: `oc/CMakeLists.txt`, `oc/include/oc_log.h`, `oc/oc_log.c`, `oc/include/oc_kv.h`, `oc/oc_kv.c`, `oc/include/oc_conn.h`, `oc/oc_conn.c`
- Test: `tests/test_oc_conn.c`

**Interfaces:**
- Consumes: `oc_core_encode`, `oc_core_decode`, `OC_CORE_FRAME_MAX`, `oc_core_msg_t` (`oc_core_msg.h`, plan 1).
- Produces (library `oc_util`, include dir `oc/include`):
  ```c
  void oc_log(int prio, const char *fmt, ...);   /* OC_LOG_ERR 3, WARNING 4, NOTICE 5, INFO 6, DEBUG 7 */
  void oc_log_line(void *ctx, const char *line); /* an oc_* library's io.log */
  typedef struct { char key[64][32], val[64][160]; unsigned line[64], n; char err[256]; } oc_kv_t; /* OC_KV_MAX 64, OC_KV_KEY 32, OC_KV_VAL 160 */
  int oc_kv_load(oc_kv_t *kv, const char *path);
  int oc_kv_parse(oc_kv_t *kv, const char *text, const char *name);
  const char *oc_kv_get(const oc_kv_t *kv, const char *key);
  const char *oc_kv_nth(const oc_kv_t *kv, const char *key, unsigned i);
  int oc_kv_num(oc_kv_t *kv, const char *key, long long lo, long long hi, long long def, long long *out);
  int oc_kv_known(oc_kv_t *kv, const char *const *keys);
  typedef struct { int fd; uint8_t rx[2048]; size_t rn; uint8_t tx[16384]; size_t tn; uint32_t bad; } oc_conn_t;
  typedef void (*oc_conn_rx_fn)(void *ctx, const oc_core_msg_t *m);
  void oc_conn_init(oc_conn_t *c, int fd);
  int  oc_conn_read(oc_conn_t *c, oc_conn_rx_fn cb, void *ctx);
  int  oc_conn_send(oc_conn_t *c, const oc_core_msg_t *m);
  int  oc_conn_flush(oc_conn_t *c);
  void oc_conn_close(oc_conn_t *c);
  int  oc_unix_listen(const char *path, unsigned mode, const char *group);
  int  oc_unix_connect(const char *path);
  uint32_t oc_backoff_next(uint32_t prev_ms);
  ```
- Produces (CMake): option `OC_CORE_TESTS` (default: top-level project); `cmake_minimum_required(VERSION 3.21)`; the directory `oc/`.

- [ ] **Step 1: The firmware pin on `oc-bench`**

```bash
cd /home/devin/Documents/opencell/core
git -C third_party/opencell-firmware fetch -q origin
git -C third_party/opencell-firmware checkout -q origin/oc-bench
```

Run: `cd /home/devin/Documents/opencell/core && ls third_party/opencell-firmware/tools/ocbench/ocb_time.h && rm -rf build && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `third_party/opencell-firmware/tools/ocbench/ocb_time.h`, no compiler output, `100% tests passed, 0 tests failed out of N_core` (8 when validated): nothing the core uses changed.

- [ ] **Step 2: Write the failing test**

Create `tests/test_oc_conn.c`:
```c
#define _GNU_SOURCE
/* oc_conn: frames over a socket pair, as the daemons use them, and the
 * Unix-socket helpers; oc_kv: the configuration files. */
#include "unity.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oc_conn.h"
#include "oc_kv.h"

void setUp(void) {}
void tearDown(void) {}

static oc_core_msg_t got[64];
static int ngot;
static oc_conn_t *close_on_rx;

static void on_rx(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    got[ngot++ % 64] = *m;
    if (close_on_rx != NULL) oc_conn_close(close_on_rx);
}

static void pair(oc_conn_t *a, int *raw)
{
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    oc_conn_init(a, sv[0]);
    *raw = sv[1];
    ngot = 0;
    close_on_rx = NULL;
}

static oc_core_msg_t ping(void)
{
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_PING;
    return m;
}

static void test_frames_cross_both_ways(void)
{
    oc_conn_t a, b;
    int raw;
    pair(&a, &raw);
    oc_conn_init(&b, raw);
    oc_core_msg_t h;
    memset(&h, 0, sizeof(h));
    h.type = OC_CORE_HELLO;
    h.u.hello.proto = OC_CORE_PROTO;
    h.u.hello.cell_id = 7;
    h.u.hello.boot_id = 0x1122334455667788ull;
    TEST_ASSERT_EQUAL_INT(0, oc_conn_send(&a, &h));
    oc_core_msg_t p = ping();
    TEST_ASSERT_EQUAL_INT(0, oc_conn_send(&a, &p));
    TEST_ASSERT_EQUAL_INT(0, oc_conn_read(&b, on_rx, NULL));
    TEST_ASSERT_EQUAL_INT(2, ngot);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_HELLO, got[0].type);
    TEST_ASSERT_EQUAL_UINT32(7, got[0].u.hello.cell_id);
    TEST_ASSERT_EQUAL_UINT64(0x1122334455667788ull, got[0].u.hello.boot_id);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_PING, got[1].type);
    oc_conn_close(&a);
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&b, on_rx, NULL)); /* the peer closed */
    oc_conn_close(&b);
    oc_conn_close(&b); /* twice is fine */
}

/* A frame split across reads is whole when its last byte arrives. */
static void test_a_frame_in_pieces(void)
{
    oc_conn_t a;
    int raw;
    uint8_t f[OC_CORE_FRAME_MAX];
    pair(&a, &raw);
    oc_core_msg_t p = ping();
    size_t n = oc_core_encode(&p, f, sizeof(f));
    TEST_ASSERT_EQUAL_INT(3, (int)n);
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_EQUAL_INT(1, (int)write(raw, f + i, 1));
        TEST_ASSERT_EQUAL_INT(0, oc_conn_read(&a, on_rx, NULL));
        TEST_ASSERT_EQUAL_INT(i + 1 == n ? 1 : 0, ngot);
    }
    oc_conn_close(&a);
    close(raw);
}

/* An unknown type is dropped and counted; the link stays up. */
static void test_an_undecodable_frame_is_dropped(void)
{
    oc_conn_t a;
    int raw;
    pair(&a, &raw);
    const uint8_t junk[] = { 0x00, 0x03, 0x7F, 0x01, 0x02, 0x00, 0x01, OC_CORE_PING };
    TEST_ASSERT_EQUAL_INT((int)sizeof(junk), (int)write(raw, junk, sizeof(junk)));
    TEST_ASSERT_EQUAL_INT(0, oc_conn_read(&a, on_rx, NULL));
    TEST_ASSERT_EQUAL_UINT32(1, a.bad);
    TEST_ASSERT_EQUAL_INT(1, ngot);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_PING, got[0].type);
    oc_conn_close(&a);
    close(raw);
}

/* A length no frame can have breaks the stream. */
static void test_an_impossible_length_breaks_the_link(void)
{
    oc_conn_t a;
    int raw;
    pair(&a, &raw);
    const uint8_t zero[] = { 0x00, 0x00 };
    TEST_ASSERT_EQUAL_INT(2, (int)write(raw, zero, 2));
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&a, on_rx, NULL));
    oc_conn_close(&a);
    close(raw);
    pair(&a, &raw);
    const uint8_t big[] = { 0x01, 0xFF, 0x04 }; /* 511 + 2 > 512 */
    TEST_ASSERT_EQUAL_INT(3, (int)write(raw, big, 3));
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&a, on_rx, NULL));
    oc_conn_close(&a);
    close(raw);
}

/* The callback may close the connection (the core drops a link); reading
 * stops there. */
static void test_rx_callback_may_close(void)
{
    oc_conn_t a;
    int raw;
    pair(&a, &raw);
    const uint8_t two[] = { 0x00, 0x01, OC_CORE_PING, 0x00, 0x01, OC_CORE_PING };
    TEST_ASSERT_EQUAL_INT(6, (int)write(raw, two, 6));
    close_on_rx = &a;
    TEST_ASSERT_EQUAL_INT(-1, oc_conn_read(&a, on_rx, NULL));
    TEST_ASSERT_EQUAL_INT(1, ngot);
    TEST_ASSERT_EQUAL_INT(-1, a.fd);
    close(raw);
}

/* A peer that reads nothing fills the queue: send then fails, so the
 * caller drops the link instead of blocking the daemon. */
static void test_a_full_queue_refuses(void)
{
    oc_conn_t a;
    int raw, rc = 0;
    pair(&a, &raw);
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_MEDIA;
    m.u.media.len = OC_SIG_APP_MAX;
    for (int i = 0; i < 100000 && rc == 0; i++) rc = oc_conn_send(&a, &m);
    TEST_ASSERT_EQUAL_INT(-1, rc);
    TEST_ASSERT_TRUE(a.tn > OC_CONN_TX - 40u);
    oc_conn_close(&a);
    close(raw);
}

static void test_unix_listen_and_connect(void)
{
    char path[] = "/tmp/oc_conn_test_XXXXXX";
    int tmp = mkstemp(path);
    TEST_ASSERT_TRUE(tmp >= 0);
    close(tmp);
    errno = 0;
    TEST_ASSERT_EQUAL_INT(-1, oc_unix_listen(path, 0600, NULL)); /* a regular file is not removed */
    TEST_ASSERT_EQUAL_INT(EEXIST, errno);
    unlink(path);
    int l = oc_unix_listen(path, 0600, NULL);
    TEST_ASSERT_TRUE(l >= 0);
    struct stat st;
    TEST_ASSERT_EQUAL_INT(0, stat(path, &st));
    TEST_ASSERT_EQUAL_UINT(0600, st.st_mode & 0777);
    int c = oc_unix_connect(path);
    TEST_ASSERT_TRUE(c >= 0);
    int s = accept(l, NULL, NULL);
    TEST_ASSERT_TRUE(s >= 0);
    close(s);
    close(c);
    close(l);
    l = oc_unix_listen(path, 0660, NULL); /* the stale socket is replaced */
    TEST_ASSERT_TRUE(l >= 0);
    close(l);
    unlink(path);
    TEST_ASSERT_EQUAL_INT(-1, oc_unix_connect(path));
    TEST_ASSERT_EQUAL_INT(ENOENT, errno);
}

static void test_backoff(void)
{
    uint32_t d = oc_backoff_next(0);
    TEST_ASSERT_EQUAL_UINT32(1000, d);
    d = oc_backoff_next(d);
    TEST_ASSERT_EQUAL_UINT32(2000, d);
    for (int i = 0; i < 10; i++) d = oc_backoff_next(d);
    TEST_ASSERT_EQUAL_UINT32(30000, d);
}

static void test_kv(void)
{
    oc_kv_t kv;
    long long v;
    static const char *const known[] = { "cell_id", "block", "name", NULL };
    TEST_ASSERT_EQUAL_INT(0, oc_kv_parse(&kv,
                                         "# comment\n cell_id = 0x2A \n\nblock = 8831606 1\nblock=8831859 2 # two\n"
                                         "name = bench A\n",
                                         "t"));
    TEST_ASSERT_EQUAL_UINT(4, kv.n);
    TEST_ASSERT_EQUAL_INT(0, oc_kv_num(&kv, "cell_id", 1, 100, 0, &v));
    TEST_ASSERT_EQUAL_INT64(42, v);
    TEST_ASSERT_EQUAL_STRING("8831859 2", oc_kv_nth(&kv, "block", 1));
    TEST_ASSERT_NULL(oc_kv_nth(&kv, "block", 2));
    TEST_ASSERT_EQUAL_STRING("bench A", oc_kv_get(&kv, "name"));
    TEST_ASSERT_EQUAL_INT(0, oc_kv_num(&kv, "missing", 0, 5, 3, &v));
    TEST_ASSERT_EQUAL_INT64(3, v);
    TEST_ASSERT_EQUAL_INT(-1, oc_kv_num(&kv, "cell_id", 1, 10, 0, &v));
    TEST_ASSERT_EQUAL_STRING("cell_id = '0x2A': a number 1-10", kv.err);
    TEST_ASSERT_EQUAL_INT(1, oc_kv_known(&kv, known));
    TEST_ASSERT_EQUAL_INT(0, oc_kv_parse(&kv, "cel_id = 1\n", "t"));
    TEST_ASSERT_EQUAL_INT(0, oc_kv_known(&kv, known));
    TEST_ASSERT_EQUAL_STRING("line 1: unknown key 'cel_id'", kv.err);
    TEST_ASSERT_EQUAL_INT(-1, oc_kv_parse(&kv, "a = 1\nnonsense\n", "f.conf"));
    TEST_ASSERT_EQUAL_STRING("f.conf:2: expected key = value", kv.err);
    TEST_ASSERT_EQUAL_INT(-1, oc_kv_load(&kv, "/nonexistent/oc.conf"));
    TEST_ASSERT_EQUAL_STRING("/nonexistent/oc.conf: No such file or directory", kv.err);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_frames_cross_both_ways);
    RUN_TEST(test_a_frame_in_pieces);
    RUN_TEST(test_an_undecodable_frame_is_dropped);
    RUN_TEST(test_an_impossible_length_breaks_the_link);
    RUN_TEST(test_rx_callback_may_close);
    RUN_TEST(test_a_full_queue_refuses);
    RUN_TEST(test_unix_listen_and_connect);
    RUN_TEST(test_backoff);
    RUN_TEST(test_kv);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
oc_test(test_oc_conn oc_util)
```

- [ ] **Step 3: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_conn 2>&1 | grep -oE "oc_conn.h: No such file or directory" | head -1`
Expected: `oc_conn.h: No such file or directory`.

- [ ] **Step 4: Implement**

In `CMakeLists.txt`, replace:
```cmake
# The OpenCell network core (network-core spec §4.2). Host-only for now: the
# portable libraries oc_core and oc_cell, and their tests. oc_sig comes from
```
with:
```cmake
# The OpenCell network core (network-core spec §4.2): the portable libraries
# oc_core and oc_cell, the Linux programs around them (oc/: oc-core, and the
# pieces oc-cell shares), and their tests. oc_sig comes from
```

In `CMakeLists.txt`, replace:
```cmake
cmake_minimum_required(VERSION 3.16)
```
with:
```cmake
cmake_minimum_required(VERSION 3.21)
```

In `CMakeLists.txt`, replace:
```cmake
add_compile_options(-Wall -Wextra -Werror)
```
with:
```cmake
add_compile_options(-Wall -Wextra -Werror)
# The tests fetch Unity from GitHub: off when this project is a submodule
# (opencell-pi) or a deploy build (-DOC_CORE_TESTS=OFF).
option(OC_CORE_TESTS "Build the core's host tests" ${PROJECT_IS_TOP_LEVEL})
```

In `CMakeLists.txt`, replace:
```cmake
add_subdirectory(oc_cell)

enable_testing()
add_subdirectory(tests)
```
with:
```cmake
add_subdirectory(oc_cell)
add_subdirectory(oc)

if(OC_CORE_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
```

Create `oc/CMakeLists.txt`:
```cmake
# The Linux side of the core (network core 2): oc_util (logging, config
# files, framed connections: oc-cell uses it too), oc_store (the SQLite
# store with sealed keys and the admin commands) and the oc-core program.
add_library(oc_util STATIC oc_log.c oc_kv.c oc_conn.c)
target_include_directories(oc_util PUBLIC include)
target_link_libraries(oc_util PUBLIC oc_core)
```

Create `oc/include/oc_log.h`:
```c
/* Logging for the OpenCell daemons: one line per call on stderr, with the
 * syslog priority as a "<N>" prefix, which journald reads (SyslogLevelPrefix,
 * on by default) and strips. Run by hand, the prefix shows as is. */
#ifndef OC_LOG_H
#define OC_LOG_H

#define OC_LOG_ERR     3
#define OC_LOG_WARNING 4
#define OC_LOG_NOTICE  5
#define OC_LOG_INFO    6
#define OC_LOG_DEBUG   7

void oc_log(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* An oc_* library's log line (its io.log callback): info. */
void oc_log_line(void *ctx, const char *line);

#endif
```

Create `oc/oc_log.c`:
```c
#define _GNU_SOURCE
#include "oc_log.h"

#include <stdarg.h>
#include <stdio.h>

void oc_log(int prio, const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    fprintf(stderr, "<%d>%s\n", prio, line);
    fflush(stderr);
}

void oc_log_line(void *ctx, const char *line)
{
    (void)ctx;
    oc_log(OC_LOG_INFO, "%s", line);
}
```

Create `oc/include/oc_kv.h`:
```c
/* key = value configuration files (oc-core.conf, oc-cell.conf): one pair
 * per line, '#' starts a comment, blank lines are skipped, spaces around
 * the key and the value are dropped. A key may repeat (block = ...);
 * oc_kv_get returns the first, oc_kv_nth the others. */
#ifndef OC_KV_H
#define OC_KV_H

#include <stddef.h>
#include <stdint.h>

#define OC_KV_MAX 64u
#define OC_KV_KEY 32u
#define OC_KV_VAL 160u

typedef struct {
    char     key[OC_KV_MAX][OC_KV_KEY];
    char     val[OC_KV_MAX][OC_KV_VAL];
    unsigned line[OC_KV_MAX];
    unsigned n;
    char     err[256]; /* why a call failed: "FILE:LINE: reason" or "KEY = 'VALUE': reason" */
} oc_kv_t;

/* 0, or -1 (unreadable file, a line without '=', a key or value too long,
 * more than OC_KV_MAX pairs): kv->err says which. */
int         oc_kv_load(oc_kv_t *kv, const char *path);
/* The same from text; name stands in for the file name in kv->err. */
int         oc_kv_parse(oc_kv_t *kv, const char *text, const char *name);
const char *oc_kv_get(const oc_kv_t *kv, const char *key);             /* NULL: not set */
const char *oc_kv_nth(const oc_kv_t *kv, const char *key, unsigned i); /* the i-th (0-based), or NULL */
/* A whole number (decimal, or 0x hex) in lo..hi, or def when not set. 0, or
 * -1 (set but not such a number: kv->err names the key). */
int         oc_kv_num(oc_kv_t *kv, const char *key, long long lo, long long hi, long long def, long long *out);
/* 1 if every key is in the NULL-terminated list; else 0, with kv->err
 * naming the first unknown key (a typo must not be ignored). */
int         oc_kv_known(oc_kv_t *kv, const char *const *keys);

#endif
```

Create `oc/oc_kv.c`:
```c
#define _GNU_SOURCE
#include "oc_kv.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

int oc_kv_parse(oc_kv_t *kv, const char *text, const char *name)
{
    memset(kv, 0, sizeof(*kv));
    unsigned ln = 0;
    const char *p = text;
    while (*p != '\0') {
        char line[512];
        const char *nl = strchr(p, '\n');
        size_t len = nl != NULL ? (size_t)(nl - p) : strlen(p);
        ln++;
        if (len >= sizeof(line)) {
            snprintf(kv->err, sizeof(kv->err), "%s:%u: line too long", name, ln);
            return -1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        p += len + (nl != NULL ? 1u : 0u);
        char *hash = strchr(line, '#');
        if (hash != NULL) *hash = '\0';
        char *s = trim(line);
        if (*s == '\0') continue;
        char *eq = strchr(s, '=');
        if (eq == NULL) {
            snprintf(kv->err, sizeof(kv->err), "%s:%u: expected key = value", name, ln);
            return -1;
        }
        *eq = '\0';
        char *k = trim(s), *v = trim(eq + 1);
        if (*k == '\0' || strlen(k) >= OC_KV_KEY || strlen(v) >= OC_KV_VAL || kv->n >= OC_KV_MAX) {
            snprintf(kv->err, sizeof(kv->err), "%s:%u: empty or long key, long value, or too many lines", name,
                     ln);
            return -1;
        }
        strcpy(kv->key[kv->n], k);
        strcpy(kv->val[kv->n], v);
        kv->line[kv->n++] = ln;
    }
    return 0;
}

int oc_kv_load(oc_kv_t *kv, const char *path)
{
    static char text[OC_KV_MAX * 256];
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        memset(kv, 0, sizeof(*kv));
        snprintf(kv->err, sizeof(kv->err), "%s: %s", path, strerror(errno));
        return -1;
    }
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    int big = !feof(f);
    fclose(f);
    if (big) {
        memset(kv, 0, sizeof(*kv));
        snprintf(kv->err, sizeof(kv->err), "%s: file too long", path);
        return -1;
    }
    text[n] = '\0';
    return oc_kv_parse(kv, text, path);
}

const char *oc_kv_nth(const oc_kv_t *kv, const char *key, unsigned i)
{
    for (unsigned k = 0; k < kv->n; k++) {
        if (strcmp(kv->key[k], key) == 0 && i-- == 0) return kv->val[k];
    }
    return NULL;
}

const char *oc_kv_get(const oc_kv_t *kv, const char *key) { return oc_kv_nth(kv, key, 0); }

int oc_kv_num(oc_kv_t *kv, const char *key, long long lo, long long hi, long long def, long long *out)
{
    const char *v = oc_kv_get(kv, key);
    if (v == NULL) {
        *out = def;
        return 0;
    }
    char *end;
    errno = 0;
    long long x = strtoll(v, &end, 0);
    if (errno != 0 || end == v || *end != '\0' || x < lo || x > hi) {
        snprintf(kv->err, sizeof(kv->err), "%s = '%s': a number %lld-%lld", key, v, lo, hi);
        return -1;
    }
    *out = x;
    return 0;
}

int oc_kv_known(oc_kv_t *kv, const char *const *keys)
{
    for (unsigned k = 0; k < kv->n; k++) {
        int ok = 0;
        for (const char *const *p = keys; *p != NULL && !ok; p++) ok = strcmp(*p, kv->key[k]) == 0;
        if (!ok) {
            snprintf(kv->err, sizeof(kv->err), "line %u: unknown key '%s'", kv->line[k], kv->key[k]);
            return 0;
        }
    }
    return 1;
}
```

Create `oc/include/oc_conn.h`:
```c
/* The cell <-> core protocol over a stream socket (network-core spec §6):
 * frames of oc_core_msg.h ("len (2, BE) | type (1) | body", at most
 * OC_CORE_FRAME_MAX bytes) read and written on a non-blocking fd, plus the
 * Unix-socket helpers both daemons use. Linux only; plan 9 adds TLS under
 * the same calls.
 *
 * A frame whose length is impossible (0, or more than OC_CORE_FRAME_MAX in
 * all) breaks the stream: oc_conn_read fails and the caller closes. A frame
 * of a good length that does not decode (a type this build does not know, a
 * bad number) is dropped and counted in bad, and the link stays up. */
#ifndef OC_CONN_H
#define OC_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "oc_core_msg.h"

#define OC_CONN_RX 2048u
#define OC_CONN_TX 16384u /* about 30 s of one call's MEDIA each way: a peer that reads nothing for longer is dropped */

typedef struct {
    int      fd; /* -1: closed */
    uint8_t  rx[OC_CONN_RX];
    size_t   rn;
    uint8_t  tx[OC_CONN_TX];
    size_t   tn;
    uint32_t bad; /* frames dropped because they did not decode */
} oc_conn_t;

typedef void (*oc_conn_rx_fn)(void *ctx, const oc_core_msg_t *m);

/* Takes fd (made non-blocking and close-on-exec). */
void oc_conn_init(oc_conn_t *c, int fd);
/* Reads what the socket has and hands every whole frame to cb, in order. cb
 * may close the connection; reading then stops. 0, or -1: the peer closed,
 * a read error, a broken frame length, or the connection was closed. */
int  oc_conn_read(oc_conn_t *c, oc_conn_rx_fn cb, void *ctx);
/* Queues one message and writes what the socket takes now. 0, or -1: not
 * encodable, the queue is full (the peer stopped reading), a write error,
 * or the connection is closed. */
int  oc_conn_send(oc_conn_t *c, const oc_core_msg_t *m);
/* Writes what is queued (on POLLOUT). 0 or -1 (a write error). */
int  oc_conn_flush(oc_conn_t *c);
/* Closes the fd; safe to call twice. */
void oc_conn_close(oc_conn_t *c);

/* A listening Unix stream socket at path: a stale socket there is removed
 * (any other kind of file is left alone and the call fails), the socket is
 * given mode and, if group is not NULL, that group. Non-blocking,
 * close-on-exec. The fd, or -1 with errno set. */
int      oc_unix_listen(const char *path, unsigned mode, const char *group);
/* A connected, non-blocking client socket, or -1 with errno set. */
int      oc_unix_connect(const char *path);
/* The next reconnect delay: 1 s, then doubling up to 30 s. */
uint32_t oc_backoff_next(uint32_t prev_ms);

#endif
```

Create `oc/oc_conn.c`:
```c
#define _GNU_SOURCE
#include "oc_conn.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

void oc_conn_init(oc_conn_t *c, int fd)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    if (fd >= 0) nonblock(fd);
}

void oc_conn_close(oc_conn_t *c)
{
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->rn = c->tn = 0;
}

int oc_conn_read(oc_conn_t *c, oc_conn_rx_fn cb, void *ctx)
{
    if (c->fd < 0) return -1;
    for (;;) {
        ssize_t r = recv(c->fd, c->rx + c->rn, sizeof(c->rx) - c->rn, 0);
        if (r == 0) return -1; /* the peer closed */
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            return -1;
        }
        c->rn += (size_t)r;
        size_t off = 0;
        while (c->rn - off >= 2) {
            size_t len = ((size_t)c->rx[off] << 8) | c->rx[off + 1];
            if (len == 0 || len + 2u > OC_CORE_FRAME_MAX) return -1; /* the stream is broken */
            if (c->rn - off < len + 2u) break;
            oc_core_msg_t m;
            if (oc_core_decode(c->rx + off, len + 2u, &m) == 0) {
                cb(ctx, &m);
                if (c->fd < 0) return -1; /* cb closed it */
            } else {
                c->bad++;
            }
            off += len + 2u;
        }
        memmove(c->rx, c->rx + off, c->rn - off);
        c->rn -= off;
    }
}

int oc_conn_flush(oc_conn_t *c)
{
    if (c->fd < 0) return -1;
    while (c->tn > 0) {
        ssize_t w = send(c->fd, c->tx, c->tn, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            return -1;
        }
        memmove(c->tx, c->tx + w, c->tn - (size_t)w);
        c->tn -= (size_t)w;
    }
    return 0;
}

int oc_conn_send(oc_conn_t *c, const oc_core_msg_t *m)
{
    uint8_t f[OC_CORE_FRAME_MAX];
    if (c->fd < 0) return -1;
    size_t n = oc_core_encode(m, f, sizeof(f));
    if (n == 0 || c->tn + n > sizeof(c->tx)) return -1;
    memcpy(c->tx + c->tn, f, n);
    c->tn += n;
    return oc_conn_flush(c);
}

static int unix_addr(const char *path, struct sockaddr_un *a)
{
    memset(a, 0, sizeof(*a));
    a->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(a->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(a->sun_path, path);
    return 0;
}

int oc_unix_listen(const char *path, unsigned mode, const char *group)
{
    struct sockaddr_un a;
    struct stat st;
    int e;
    if (unix_addr(path, &a) != 0) return -1;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            errno = EEXIST; /* not ours to remove */
            return -1;
        }
        unlink(path);
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    mode_t old = umask(0177); /* never reachable by others, even for a moment */
    int r = bind(fd, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (r != 0 || chmod(path, (mode_t)mode) != 0) goto fail;
    if (group != NULL) {
        struct group *g = getgrnam(group);
        if (g == NULL) {
            errno = ENOENT;
            goto fail;
        }
        if (chown(path, (uid_t)-1, g->gr_gid) != 0) goto fail;
    }
    if (listen(fd, 16) != 0) goto fail;
    nonblock(fd);
    return fd;
fail:
    e = errno;
    close(fd);
    unlink(path);
    errno = e;
    return -1;
}

int oc_unix_connect(const char *path)
{
    struct sockaddr_un a;
    if (unix_addr(path, &a) != 0) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    nonblock(fd);
    return fd;
}

uint32_t oc_backoff_next(uint32_t prev_ms)
{
    if (prev_ms < 1000u) return 1000u;
    return prev_ms >= 15000u ? 30000u : prev_ms * 2u;
}
```

- [ ] **Step 5: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_conn 2>&1 | grep -E "error|warning"; build/tests/test_oc_conn | tail -3`
Expected: no compiler output, then `9 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 6: The whole suite, and the core as a subproject**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_core+1` (9 when validated).

Run: `cd /home/devin/Documents/opencell/core && rm -rf build/notests && cmake -S . -B build/notests -DOC_CORE_TESTS=OFF >/dev/null && cmake --build build/notests -j8 2>&1 | grep -E "error|warning"; ls -d build/notests/_deps build/notests/tests 2>&1 | sed 's/.*cannot access //'`
Expected: no compiler output, then `'build/notests/_deps': No such file or directory` and `'build/notests/tests': No such file or directory` (no Unity fetched, no tests built).

- [ ] **Step 7: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add third_party/opencell-firmware CMakeLists.txt tests/CMakeLists.txt tests/test_oc_conn.c oc
git commit -m "oc_util: journald logging, key = value config files, the cell-core framing on Unix sockets; firmware pin on oc-bench

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 3: Keys at rest: AES-256-GCM sealing and the master key file (`oc_seal`)

**Repo:** `opencell-core`, branch `oc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 2.

Spec §5: K, OPc, SKn and token secrets are sealed with AES-256-GCM under a 32-byte master key kept outside the database; the AAD binds each blob to its table, column, row and key version, so a blob copied elsewhere does not open (§9.1 "AES-GCM seal/open, including a wrong AAD"). The master key file is checked before it is used: exactly 32 bytes, unreadable by group and others (§5: "root-only, 0400").

**Files:**
- Create: `oc/include/oc_seal.h`, `oc/oc_seal.c`
- Modify: `oc/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/test_oc_seal.c`

**Interfaces:**
- Consumes: OpenSSL 3 EVP (`EVP_aes_256_gcm`); `oc_sig_wipe` (`oc_sig_keys.h`, the firmware's `net-core`: a wipe the compiler may not drop, as `oc_core` uses for key material).
- Produces (library `oc_store`):
  ```c
  #define OC_SEAL_VERSION  1u
  #define OC_SEAL_OVERHEAD 29u /* version 1 + nonce 12 + tag 16 */
  #define OC_SEAL_PT_MAX   64u
  int oc_seal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
              const uint8_t *pt, size_t n, const uint8_t nonce[12], uint8_t *out);
  int oc_unseal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
                const uint8_t *in, size_t in_n, uint8_t *pt);
  int oc_key_load(const char *path, uint8_t key[32], char *err, size_t cap);
  ```

- [ ] **Step 1: Write the failing test**

Create `tests/test_oc_seal.c`:
```c
#define _GNU_SOURCE
/* oc_seal (network-core spec §5, §9.1 "AES-GCM seal/open, including a wrong
 * AAD") and the master key file. */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oc_seal.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t KEY[32] = { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const uint8_t NONCE[12] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB };
static const uint8_t PK[8] = { 0x88, 0x31, 0x60, 0x65, 0x55, 0x01, 0x23, 0x4F };

static void test_seal_opens_with_the_same_row(void)
{
    uint8_t k[16], blob[16 + OC_SEAL_OVERHEAD], back[16];
    memset(k, 0x5A, 16);
    TEST_ASSERT_EQUAL_INT(0, oc_seal(KEY, "subscriber", "k", PK, 8, k, 16, NONCE, blob));
    TEST_ASSERT_EQUAL_UINT8(OC_SEAL_VERSION, blob[0]);
    TEST_ASSERT_EQUAL_MEMORY(NONCE, blob + 1, 12);
    TEST_ASSERT_TRUE(memcmp(blob + 13, k, 16) != 0); /* not in the clear */
    TEST_ASSERT_EQUAL_INT(0, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_MEMORY(k, back, 16);
}

/* A blob moved to another column, row or table, or opened with another key,
 * or changed in one bit, does not open. */
static void test_seal_refuses_anything_else(void)
{
    uint8_t k[16], blob[16 + OC_SEAL_OVERHEAD], back[16], pk2[8], key2[32];
    memset(k, 0x5A, 16);
    memcpy(pk2, PK, 8);
    pk2[7] ^= 0x10;
    memcpy(key2, KEY, 32);
    key2[0] ^= 1;
    TEST_ASSERT_EQUAL_INT(0, oc_seal(KEY, "subscriber", "k", PK, 8, k, 16, NONCE, blob));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "opc", PK, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "k", pk2, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "token", "k", PK, 8, blob, sizeof(blob), back));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(key2, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
    for (size_t i = 0; i < sizeof(blob); i++) {
        blob[i] ^= 0x01;
        TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
        blob[i] ^= 0x01;
    }
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob) - 1, back));
    TEST_ASSERT_EQUAL_INT(0, oc_unseal(KEY, "subscriber", "k", PK, 8, blob, sizeof(blob), back));
}

/* The AAD's fields are separated, so "ab"+"c" is not "a"+"bc". */
static void test_aad_fields_do_not_run_together(void)
{
    uint8_t s[8] = { 7 }, blob[8 + OC_SEAL_OVERHEAD], back[8];
    TEST_ASSERT_EQUAL_INT(0, oc_seal(KEY, "ab", "c", PK, 8, s, 8, NONCE, blob));
    TEST_ASSERT_EQUAL_INT(-1, oc_unseal(KEY, "a", "bc", PK, 8, blob, sizeof(blob), back));
}

static void write_key(const char *path, size_t n, mode_t mode)
{
    unlink(path); /* the last one may be read-only */
    FILE *f = fopen(path, "w");
    TEST_ASSERT_NOT_NULL(f);
    for (size_t i = 0; i < n; i++) fputc((int)(i + 1), f);
    fclose(f);
    TEST_ASSERT_EQUAL_INT(0, chmod(path, mode));
}

static void test_key_file_rules(void)
{
    char path[] = "/tmp/oc_seal_key_XXXXXX", err[160];
    uint8_t k[32];
    int fd = mkstemp(path);
    TEST_ASSERT_TRUE(fd >= 0);
    close(fd);
    write_key(path, 32, 0400);
    TEST_ASSERT_EQUAL_INT(0, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_EQUAL_MEMORY(KEY, k, 32);
    write_key(path, 32, 0640);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "readable by group or others (mode 640)"));
    write_key(path, 31, 0600);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "exactly 32 bytes"));
    unlink(path);
    TEST_ASSERT_EQUAL_INT(-1, oc_key_load(path, k, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL(strstr(err, "No such file"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_seal_opens_with_the_same_row);
    RUN_TEST(test_seal_refuses_anything_else);
    RUN_TEST(test_aad_fields_do_not_run_together);
    RUN_TEST(test_key_file_rules);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
oc_test(test_oc_seal oc_store)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_seal 2>&1 | grep -oE "oc_seal.h: No such file or directory" | head -1`
Expected: `oc_seal.h: No such file or directory`.

- [ ] **Step 3: Implement**

Append to `oc/CMakeLists.txt`:
```cmake

find_package(OpenSSL REQUIRED)
add_library(oc_store STATIC oc_seal.c)
target_include_directories(oc_store PUBLIC include)
target_link_libraries(oc_store PUBLIC oc_core oc_util OpenSSL::Crypto)
```

Create `oc/include/oc_seal.h`:
```c
/* Keys at rest (network-core spec §5): K, OPc, the network SKn and token
 * secrets are sealed with AES-256-GCM under a 32-byte master key that is not
 * in the database. A sealed blob is
 *   version (1) | nonce (12, random) | ciphertext | tag (16)
 * and its AAD is table | 0 | column | 0 | primary key | version, so a blob
 * copied to another row, column or table does not open. version is the
 * master key's version (OC_SEAL_VERSION): a later key rotation re-seals
 * under a new one. */
#ifndef OC_SEAL_H
#define OC_SEAL_H

#include <stddef.h>
#include <stdint.h>

#define OC_SEAL_VERSION  1u
#define OC_SEAL_OVERHEAD 29u /* version + nonce + tag */
#define OC_SEAL_PT_MAX   64u /* the largest secret sealed here (SKn is 32) */

/* out gets n + OC_SEAL_OVERHEAD bytes. 0, or -1 (n > OC_SEAL_PT_MAX, crypto
 * failure). */
int oc_seal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
            const uint8_t *pt, size_t n, const uint8_t nonce[12], uint8_t *out);
/* pt gets in_n - OC_SEAL_OVERHEAD bytes. 0, or -1: a wrong key, a blob from
 * another row/column/table, a changed byte, an unknown version, or a
 * length that is not n + OC_SEAL_OVERHEAD for some n <= OC_SEAL_PT_MAX. */
int oc_unseal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
              const uint8_t *in, size_t in_n, uint8_t *pt);
/* The master key from path: a regular file of exactly 32 bytes that neither
 * group nor others may read (a systemd credential, or --key-file on the
 * bench). 0, or -1 with the reason in err. */
int oc_key_load(const char *path, uint8_t key[32], char *err, size_t cap);

#endif
```

Create `oc/oc_seal.c`:
```c
#define _GNU_SOURCE
#include "oc_seal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "oc_sig_keys.h" /* oc_sig_wipe: a memset the compiler may not drop */

#define AAD_MAX 128u

static size_t aad(uint8_t out[AAD_MAX], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
                  uint8_t version)
{
    size_t t = strlen(table) + 1u, c = strlen(column) + 1u;
    if (t + c + pk_n + 1u > AAD_MAX) return 0;
    memcpy(out, table, t);
    memcpy(out + t, column, c);
    memcpy(out + t + c, pk, pk_n);
    out[t + c + pk_n] = version;
    return t + c + pk_n + 1u;
}

/* One GCM pass: enc 1 seals (tag out), 0 opens (tag in, checked). */
static int gcm(int enc, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *a, size_t an,
               const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16])
{
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int len = 0, ok = x != NULL;
    ok = ok && EVP_CipherInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1;
    ok = ok && EVP_CipherInit_ex(x, NULL, NULL, key, nonce, enc) == 1;
    ok = ok && EVP_CipherUpdate(x, NULL, &len, a, (int)an) == 1;
    ok = ok && EVP_CipherUpdate(x, out, &len, in, (int)n) == 1;
    if (!enc) ok = ok && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
    ok = ok && EVP_CipherFinal_ex(x, out + len, &len) == 1;
    if (enc) ok = ok && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(x);
    return ok ? 0 : -1;
}

int oc_seal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
            const uint8_t *pt, size_t n, const uint8_t nonce[12], uint8_t *out)
{
    uint8_t a[AAD_MAX];
    size_t an = aad(a, table, column, pk, pk_n, OC_SEAL_VERSION);
    if (an == 0 || n > OC_SEAL_PT_MAX) return -1;
    out[0] = OC_SEAL_VERSION;
    memcpy(out + 1, nonce, 12);
    return gcm(1, key, nonce, a, an, pt, n, out + 13, out + 13 + n);
}

int oc_unseal(const uint8_t key[32], const char *table, const char *column, const uint8_t *pk, size_t pk_n,
              const uint8_t *in, size_t in_n, uint8_t *pt)
{
    uint8_t a[AAD_MAX], tag[16], buf[OC_SEAL_PT_MAX];
    if (in_n < OC_SEAL_OVERHEAD || in_n - OC_SEAL_OVERHEAD > OC_SEAL_PT_MAX || in[0] != OC_SEAL_VERSION) return -1;
    size_t n = in_n - OC_SEAL_OVERHEAD;
    size_t an = aad(a, table, column, pk, pk_n, in[0]);
    if (an == 0) return -1;
    memcpy(tag, in + 13 + n, 16);
    if (gcm(0, key, in + 1, a, an, in + 13, n, buf, tag) != 0) {
        oc_sig_wipe(buf, sizeof(buf));
        return -1; /* nothing of a blob that failed its tag reaches the caller */
    }
    memcpy(pt, buf, n);
    oc_sig_wipe(buf, sizeof(buf));
    return 0;
}

int oc_key_load(const char *path, uint8_t key[32], char *err, size_t cap)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        return -1;
    }
    int bad = fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != 32;
    if (bad) {
        snprintf(err, cap, "%s: the master key must be a file of exactly 32 bytes", path);
    } else if ((st.st_mode & 077) != 0) {
        snprintf(err, cap, "%s: readable by group or others (mode %03o): chmod 0400 it", path,
                 (unsigned)(st.st_mode & 0777));
        bad = 1;
    } else if (read(fd, key, 32) != 32) {
        snprintf(err, cap, "%s: short read", path);
        bad = 1;
    }
    close(fd);
    return bad ? -1 : 0;
}
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_seal 2>&1 | grep -E "error|warning"; build/tests/test_oc_seal | tail -3`
Expected: no compiler output, then `4 Tests 0 Failures 0 Ignored` and `OK`.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_core+2` (10 when validated).

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add oc/CMakeLists.txt oc/include/oc_seal.h oc/oc_seal.c tests/CMakeLists.txt tests/test_oc_seal.c
git commit -m "oc_seal: AES-256-GCM sealing bound to table, column, row and key version; the master key file

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 4: The SQLite store (`oc_sql`): schema v1, sealed keys, migrations, backup, lock

**Repo:** `opencell-core`, branch `oc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 3.

`oc_core_store_t` over SQLite (spec §5): WAL, `synchronous=FULL`, numbers as full-form text, keys sealed. The schema is versioned with `PRAGMA user_version`; migrations run in order, each in its own transaction, after an automatic backup next to the database (§17.9). Opening takes a lock so the daemon and `--offline` never run together (§17.1), and checks the master key against a sealed value in the database. The store passes plan 1's `store_contract()` (its channel lists too), and a restarted core keeps issuing SQN above what it issued (§9.1).

A detail that matters: `oc_core` calls `begin`, its puts, then `commit` without checking each put, and plan 1's store contract (`oc_core_store.h`, fix round of Task 11) says a failed write dooms the transaction: `commit` then returns -1 and undoes everything. SQLite adds a trap: on `SQLITE_FULL`, `SQLITE_IOERR`, `SQLITE_NOMEM` or `SQLITE_BUSY` it may roll the transaction back by itself, after which later statements run in autocommit and each becomes durable. The store keeps its own doomed flag and also treats a transaction SQLite dropped (`sqlite3_get_autocommit`) as doomed; two tests inject exactly these faults (a `ROLLBACK` behind the store's back, and a page limit that fills the database mid-transaction).

**Files:**
- Create: `oc/include/oc_sql.h`, `oc/oc_sql.c`
- Modify: `oc/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/test_oc_sql.c`

**Interfaces:**
- Consumes: `oc_core_store_t` (plan 1 Task 3, with `list_get`/`list_put` from Task 16, and the doomed-transaction rule of its Task 11 fix round), `store_contract()` (`tests/core_store_contract.h`), `oc_seal`/`oc_unseal` (Task 3), `oc_sig_number_to_text`/`_to_bcd`, `oc_sig_wipe`.
- Produces (library `oc_store`):
  ```c
  #define OC_SQL_VERSION 1
  typedef struct oc_sql oc_sql_t;
  typedef struct { const char *path; const uint8_t *master_key; void (*random)(uint8_t *out, size_t n);
                   const char *const *migrations; unsigned nmigrations; } oc_sql_cfg_t;
  oc_sql_t       *oc_sql_open(const oc_sql_cfg_t *cfg, char *err, size_t cap);
  void            oc_sql_close(oc_sql_t *s);
  oc_core_store_t oc_sql_store(oc_sql_t *s);
  sqlite3        *oc_sql_db(oc_sql_t *s);
  int             oc_sql_version(oc_sql_t *s);
  const char     *oc_sql_backup(oc_sql_t *s);
  unsigned        oc_sql_unseal_failures(oc_sql_t *s);
  const char     *oc_sql_migration(unsigned i);
  ```
  Tables (schema v1): `meta`, `network`, `cell`, `subscriber`, `token`, `av_issued`, `location`, `chan_list`, `cdr`, `audit`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_oc_sql.c`:
```c
#define _GNU_SOURCE
/* The SQLite store (network-core spec §5, §9.1, §17 decision 9): the store
 * contract, keys sealed at rest, the master-key check, the lock, the
 * schema migrations and their backup, and transactions that fail whole. */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core_store_contract.h"
#include "oc_core.h"
#include "oc_sql.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t KEY[32] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                                 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                                 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F };
static uint32_t rng = 7;
static void rnd(uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((rng = rng * 1103515245u + 12345u) >> 16);
}

static char dir[64], db[96];

static oc_sql_t *open_db(const char *path, const uint8_t *key, const char *const *mig, unsigned n, char *err)
{
    oc_sql_cfg_t cfg = { path, key, rnd, mig, n };
    return oc_sql_open(&cfg, err, 256);
}

static void fresh_dir(void)
{
    strcpy(dir, "/tmp/oc_sql_test_XXXXXX");
    TEST_ASSERT_NOT_NULL(mkdtemp(dir));
    snprintf(db, sizeof(db), "%s/core.db", dir);
}

static void rm_dir(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    TEST_ASSERT_EQUAL_INT(0, system(cmd));
}

static void test_sql_store_keeps_the_contract(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    store_contract(&st);
    TEST_ASSERT_EQUAL_INT(OC_SQL_VERSION, oc_sql_version(s));
    oc_sql_close(s);
}

static oc_core_sub_t a_sub(void)
{
    oc_core_sub_t x;
    memset(&x, 0, sizeof(x));
    contract_num("+883160655501234", x.number);
    x.state = OC_CORE_SUB_ACTIVE;
    x.activated = 1;
    x.tmid = 0x76AD0488u;
    memset(x.k, 0xC1, 16);
    memset(x.opc, 0xC2, 16);
    x.sqn = 41;
    return x;
}

/* K and OPc are never in the file in the clear, and come back after a
 * restart; a file-level search for their bytes finds nothing. */
static void test_keys_are_sealed_on_disk_and_survive_a_restart(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(s), "SELECT k_enc FROM subscriber", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    TEST_ASSERT_EQUAL_INT(16 + 29, sqlite3_column_bytes(q, 0));
    TEST_ASSERT_TRUE(memcmp((const uint8_t *)sqlite3_column_blob(q, 0) + 13, x.k, 16) != 0);
    sqlite3_finalize(q);
    oc_sql_close(s);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat %s %s-wal 2>/dev/null | grep -c -P '\\xC1{16}' >/dev/null", db, db);
    TEST_ASSERT_NOT_EQUAL_INT(0, system(cmd)); /* grep found no 16 x 0xC1 */
    struct stat sb;
    TEST_ASSERT_EQUAL_INT(0, stat(db, &sb));
    TEST_ASSERT_EQUAL_UINT(0600, sb.st_mode & 0777);

    s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    st = oc_sql_store(s);
    TEST_ASSERT_EQUAL_INT(0, st.sub_by_tmid(st.ctx, 0x76AD0488u, &y));
    TEST_ASSERT_EQUAL_MEMORY(x.k, y.k, 16);
    TEST_ASSERT_EQUAL_MEMORY(x.opc, y.opc, 16);
    TEST_ASSERT_EQUAL_UINT64(41, y.sqn);
    oc_sql_close(s);
    rm_dir();
}

static void test_a_wrong_master_key_is_refused_at_open(void)
{
    char err[256];
    uint8_t other[32];
    memcpy(other, KEY, 32);
    other[31] ^= 0x80;
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_sql_close(s);
    TEST_ASSERT_NULL(open_db(db, other, NULL, 0, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "the master key does not open this database"));
    rm_dir();
}

/* One process at a time: the running daemon, or one admin --offline. */
static void test_the_lock_keeps_a_second_process_out(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_NULL(open_db(db, KEY, NULL, 0, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "is in use (oc-core is running"));
    oc_sql_close(s);
    s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_sql_close(s);
    rm_dir();
}

/* §17 decision 9: a newer build migrates after a backup that still opens
 * at the old version; an older build refuses a newer database. */
static void test_migration_backs_up_first(void)
{
    char err[256];
    const char *v1[] = { oc_sql_migration(0) };
    const char *v2[] = { oc_sql_migration(0), "ALTER TABLE cell ADD COLUMN note TEXT" };
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_STRING("", oc_sql_backup(s)); /* a new database: nothing to keep */
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    oc_sql_close(s);

    s = open_db(db, KEY, v2, 2, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(2, oc_sql_version(s));
    char backup[600];
    snprintf(backup, sizeof(backup), "%s", oc_sql_backup(s));
    TEST_ASSERT_NOT_NULL(strstr(backup, "core.db.v1."));
    oc_sql_close(s);

    s = open_db(backup, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(1, oc_sql_version(s));
    st = oc_sql_store(s);
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, x.number, &y));
    oc_sql_close(s);

    TEST_ASSERT_NULL(open_db(db, KEY, v1, 1, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "schema v2 is newer than this oc-core (v1)"));
    rm_dir();
}

/* A migration that fails leaves the database as it was. */
static void test_a_failed_migration_changes_nothing(void)
{
    char err[256];
    const char *v1[] = { oc_sql_migration(0) };
    const char *bad[] = { oc_sql_migration(0), "CREATE TABLE ok(x); CREATE TABLE cell(x)" };
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_sql_close(s);
    TEST_ASSERT_NULL(open_db(db, KEY, bad, 2, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "migration to v2 failed"));
    s = open_db(db, KEY, v1, 1, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_INT(1, oc_sql_version(s));
    TEST_ASSERT_EQUAL_INT(SQLITE_ERROR, sqlite3_exec(oc_sql_db(s), "SELECT * FROM ok", NULL, NULL, NULL));
    oc_sql_close(s);
    rm_dir();
}

/* oc_core commits without checking each put: a put that fails inside the
 * transaction must make the whole change fail. */
static void test_a_failed_put_fails_the_whole_transaction(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    oc_core_token_t t1, t2;
    memset(&t1, 0, sizeof(t1));
    memcpy(t1.number, x.number, OC_SIG_NUMBER_LEN);
    memset(t1.token_id, 1, 8);
    t2 = t1;
    memset(t2.token_id, 2, 8);
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(-1, st.begin(st.ctx)); /* no nesting */
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    TEST_ASSERT_EQUAL_INT(0, st.token_put(st.ctx, &t1));
    TEST_ASSERT_EQUAL_INT(-1, st.token_put(st.ctx, &t2)); /* a second unused token for the number */
    TEST_ASSERT_EQUAL_INT(-1, st.loc_del(st.ctx, x.number)); /* nothing more is written */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(-1, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x)); /* the store works on */
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx)); /* commit without begin */
    oc_sql_close(s);
}

/* SQLite may roll a transaction back by itself (SQLITE_FULL, SQLITE_IOERR,
 * SQLITE_NOMEM, SQLITE_BUSY); the statements after it would then run in
 * autocommit, each durable. The store notices, writes nothing more, and the
 * commit fails. */
static void test_a_transaction_sqlite_dropped_writes_nothing_more(void)
{
    char err[256];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    oc_core_sub_t x = a_sub(), y;
    oc_core_loc_t l = { { 0 }, 1, x.tmid, 5000 }, lg;
    memcpy(l.number, x.number, OC_SIG_NUMBER_LEN);
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    /* what SQLite does after an SQLITE_FULL or SQLITE_IOERR */
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), "ROLLBACK", NULL, NULL, NULL));
    TEST_ASSERT_EQUAL_INT(-1, st.loc_put(st.ctx, &l));
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(-1, st.sub_get(st.ctx, x.number, &y));
    TEST_ASSERT_EQUAL_INT(-1, st.loc_get(st.ctx, x.number, &lg)); /* not written in autocommit */
    TEST_ASSERT_EQUAL_INT(0, st.loc_put(st.ctx, &l));             /* outside a transaction: works */
    oc_sql_close(s);
}

/* The database fills up in the middle of a transaction (SQLITE_FULL, here
 * by a page limit): that put fails, every later write is refused, and none
 * of the transaction is left. */
static void test_a_full_database_undoes_the_transaction(void)
{
    char err[256], sql[64];
    oc_sql_t *s = open_db(":memory:", KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    oc_core_store_t st = oc_sql_store(s);
    sqlite3_stmt *q;
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(s), "PRAGMA page_count", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    snprintf(sql, sizeof(sql), "PRAGMA max_page_count = %d", sqlite3_column_int(q, 0) + 2);
    sqlite3_finalize(q);
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_exec(oc_sql_db(s), sql, NULL, NULL, NULL));
    oc_core_sub_t x = a_sub();
    oc_core_audit_t au;
    memset(&au, 0, sizeof(au));
    int failed_at = -1;
    TEST_ASSERT_EQUAL_INT(0, st.begin(st.ctx));
    for (int i = 0; i < 5000 && failed_at < 0; i++) {
        char t[32];
        snprintf(t, sizeof(t), "+88316065551%04d", i);
        contract_num(t, x.number);
        if (st.sub_put(st.ctx, &x) != 0) failed_at = i;
    }
    TEST_ASSERT_TRUE_MESSAGE(failed_at > 0, "the page limit was never reached");
    TEST_ASSERT_EQUAL_INT(-1, st.audit_add(st.ctx, &au)); /* doomed: nothing more */
    TEST_ASSERT_EQUAL_INT(-1, st.commit(st.ctx));
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_prepare_v2(oc_sql_db(s), "SELECT count(*) FROM subscriber", -1, &q, NULL));
    TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(q));
    TEST_ASSERT_EQUAL_INT(0, sqlite3_column_int(q, 0));
    sqlite3_finalize(q);
    oc_sql_close(s);
}

/* The core over this store: a vector's SQN is on disk when AV_RES leaves,
 * and a restarted core carries on above it (§9.1 "SQN monotonic across
 * restarts"). */
static oc_core_msg_t last;
static int k_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    (void)link;
    last = *m;
    return 0;
}
static uint32_t k_unix(void *c)
{
    (void)c;
    return 1790000000u;
}
static void k_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    rnd(out, n);
}

static uint64_t ask_one_vector(oc_sql_t *s, int first)
{
    static oc_core_t k;
    oc_core_route_t rt;
    oc_core_cfg_t cfg;
    const oc_core_io_t io = { NULL, k_send, NULL, k_random, k_unix, NULL };
    oc_core_store_t st = oc_sql_store(s);
    oc_core_route_init(&rt, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&rt, "8831606", 1, 1));
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    contract_num("+883160655500100", cfg.echo_number);
    if (first) {
        uint8_t r[32];
        rnd(r, 32);
        TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&st, 1, 1800, r, 1790000000u));
    }
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&k, &io, &st, &rt, &cfg));
    if (first) {
        TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&k, 1, "bench", OC_SIG_MODE_PART15, 0));
        oc_core_sub_t x = a_sub();
        TEST_ASSERT_EQUAL_INT(0, st.sub_put(st.ctx, &x));
    }
    oc_core_msg_t m;
    memset(&m, 0, sizeof(m));
    oc_core_link_up(&k, 5, 1000);
    m.type = OC_CORE_HELLO;
    m.u.hello.proto = OC_CORE_PROTO;
    m.u.hello.cell_id = 1;
    m.u.hello.boot_id = 99;
    oc_core_rx(&k, 5, &m, 1000);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_HELLO_ACK, last.type);
    memset(&m, 0, sizeof(m));
    m.type = OC_CORE_AV_REQ;
    m.u.av_req.tmid = 0x76AD0488u;
    m.u.av_req.count = 1;
    oc_core_rx(&k, 5, &m, 2000);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_AV_RES, last.type);
    TEST_ASSERT_EQUAL_UINT8(OC_CORE_AV_OK, last.u.av_res.status);
    oc_core_sub_t y;
    TEST_ASSERT_EQUAL_INT(0, st.sub_get(st.ctx, last.u.av_res.number, &y));
    return y.sqn;
}

static void test_sqn_rises_across_a_core_restart(void)
{
    char err[256];
    fresh_dir();
    oc_sql_t *s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_UINT64(42, ask_one_vector(s, 1));
    oc_sql_close(s);
    s = open_db(db, KEY, NULL, 0, err);
    TEST_ASSERT_NOT_NULL_MESSAGE(s, err);
    TEST_ASSERT_EQUAL_UINT64(43, ask_one_vector(s, 0));
    oc_sql_close(s);
    rm_dir();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sql_store_keeps_the_contract);
    RUN_TEST(test_keys_are_sealed_on_disk_and_survive_a_restart);
    RUN_TEST(test_a_wrong_master_key_is_refused_at_open);
    RUN_TEST(test_the_lock_keeps_a_second_process_out);
    RUN_TEST(test_migration_backs_up_first);
    RUN_TEST(test_a_failed_migration_changes_nothing);
    RUN_TEST(test_a_failed_put_fails_the_whole_transaction);
    RUN_TEST(test_a_transaction_sqlite_dropped_writes_nothing_more);
    RUN_TEST(test_a_full_database_undoes_the_transaction);
    RUN_TEST(test_sqn_rises_across_a_core_restart);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
oc_test(test_oc_sql oc_store)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_sql 2>&1 | grep -oE "oc_sql.h: No such file or directory" | head -1`
Expected: `oc_sql.h: No such file or directory`.

- [ ] **Step 3: Implement**

In `oc/CMakeLists.txt`, replace:
```cmake
find_package(OpenSSL REQUIRED)
add_library(oc_store STATIC oc_seal.c)
target_include_directories(oc_store PUBLIC include)
target_link_libraries(oc_store PUBLIC oc_core oc_util OpenSSL::Crypto)
```
with:
```cmake
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
add_library(oc_store STATIC oc_seal.c oc_sql.c)
target_include_directories(oc_store PUBLIC include)
target_link_libraries(oc_store PUBLIC oc_core oc_util SQLite::SQLite3 OpenSSL::Crypto)
```

Create `oc/include/oc_sql.h`:
```c
/* The core's database (network-core spec §5, §17 decisions 5 and 9): SQLite
 * in WAL mode with synchronous=FULL, behind oc_core_store_t. K, OPc, the
 * network SKn and token secrets are sealed (oc_seal.h); numbers are stored
 * in the full form as text ("+883160655501234"), TMIDs and SQN in the clear.
 *
 * Opening takes the database's lock (PATH.lock, flock): one process at a
 * time, the running oc-core or an `oc-core admin --offline`. It checks the
 * master key against a sealed value kept in the database, so a wrong key is
 * refused at start and not at the first activation. The schema is versioned
 * with PRAGMA user_version; migrations are applied in order, each in its
 * own transaction, after an automatic backup of the database next to it
 * (PATH.v<old>.<unix time>.bak), which holds sealed keys only.
 *
 * Transactions (oc_core_store.h): a write that fails between begin and
 * commit dooms the transaction: nothing more is written and the commit
 * fails and rolls everything back, so oc_core, which commits without
 * looking at each put, never makes half a change durable. A transaction
 * SQLite rolled back by itself (SQLITE_FULL, SQLITE_IOERR, SQLITE_NOMEM,
 * SQLITE_BUSY) counts as failed: the writes after it would otherwise run in
 * autocommit and each become durable. A delete that deletes nothing is not
 * a failure. */
#ifndef OC_SQL_H
#define OC_SQL_H

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#include "oc_core_store.h"

#define OC_SQL_VERSION 1 /* the schema this build writes */

typedef struct oc_sql oc_sql_t;

typedef struct {
    const char    *path;       /* ":memory:" (tests): no lock, no backup */
    const uint8_t *master_key; /* 32 bytes */
    void (*random)(uint8_t *out, size_t n); /* GCM nonces */
    /* Tests only: the migrations to run instead of this build's (index i
     * takes user_version i to i + 1). NULL: the build's. */
    const char *const *migrations;
    unsigned           nmigrations;
} oc_sql_cfg_t;

/* NULL with the reason in err: can't open, locked by another process, a
 * schema newer than this build, a failed migration or backup, or a master
 * key that does not open this database. */
oc_sql_t       *oc_sql_open(const oc_sql_cfg_t *cfg, char *err, size_t cap);
void            oc_sql_close(oc_sql_t *s);
oc_core_store_t oc_sql_store(oc_sql_t *s);
sqlite3        *oc_sql_db(oc_sql_t *s);      /* for the admin listings (read-only use) */
int             oc_sql_version(oc_sql_t *s); /* PRAGMA user_version */
const char     *oc_sql_backup(oc_sql_t *s);  /* the backup taken before migrating at open, or "" */
unsigned        oc_sql_unseal_failures(oc_sql_t *s); /* rows whose keys did not open (read as missing) */
/* This build's migration i (taking user_version i to i + 1), or NULL. */
const char     *oc_sql_migration(unsigned i);

#endif
```

Create `oc/oc_sql.c`:
```c
#define _GNU_SOURCE
#include "oc_sql.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "oc_sig_keys.h"
#include "oc_seal.h"

/* Schema v1 (network-core spec §5, the tables plan 8 uses; route, block and
 * binding_idx come with plans 10-11). meta holds the master-key check. */
static const char SCHEMA_V1[] =
    "CREATE TABLE meta(k TEXT PRIMARY KEY, v BLOB NOT NULL);"
    "CREATE TABLE network(key_id INTEGER PRIMARY KEY, sk_enc BLOB NOT NULL, pk BLOB NOT NULL,"
    " period_s INTEGER NOT NULL, created INTEGER NOT NULL);"
    "CREATE TABLE cell(cell_id INTEGER PRIMARY KEY, name TEXT NOT NULL, cert_fpr TEXT, mode INTEGER NOT NULL,"
    " enabled INTEGER NOT NULL, list_id INTEGER NOT NULL DEFAULT 0, boot_id INTEGER NOT NULL DEFAULT 0,"
    " last_seen INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE subscriber(number TEXT PRIMARY KEY, state INTEGER NOT NULL, tmid INTEGER NOT NULL,"
    " activated INTEGER NOT NULL, k_enc BLOB NOT NULL, opc_enc BLOB NOT NULL, sqn INTEGER NOT NULL,"
    " created INTEGER NOT NULL, updated INTEGER NOT NULL);"
    "CREATE INDEX subscriber_tmid ON subscriber(tmid) WHERE activated = 1;"
    "CREATE TABLE token(token_id BLOB PRIMARY KEY, number TEXT NOT NULL, secret_enc BLOB NOT NULL,"
    " expiry INTEGER NOT NULL, used_at INTEGER NOT NULL, used_by_tmid INTEGER NOT NULL);"
    "CREATE UNIQUE INDEX token_one_unused ON token(number) WHERE used_at = 0;"
    "CREATE TABLE av_issued(number TEXT NOT NULL, rand BLOB NOT NULL, xres BLOB NOT NULL, sqn INTEGER NOT NULL,"
    " cell_id INTEGER NOT NULL, issued INTEGER NOT NULL, confirmed INTEGER NOT NULL, PRIMARY KEY(number, rand));"
    "CREATE TABLE location(number TEXT PRIMARY KEY, cell_id INTEGER NOT NULL, tmid INTEGER NOT NULL,"
    " expires INTEGER NOT NULL);"
    "CREATE TABLE chan_list(list_id INTEGER PRIMARY KEY, ver INTEGER NOT NULL, entries BLOB NOT NULL);"
    "CREATE TABLE cdr(id INTEGER PRIMARY KEY AUTOINCREMENT, caller TEXT NOT NULL, called TEXT NOT NULL,"
    " cell_a INTEGER NOT NULL, cell_b INTEGER NOT NULL, setup INTEGER NOT NULL, answer INTEGER NOT NULL,"
    " \"end\" INTEGER NOT NULL, cause INTEGER NOT NULL);"
    "CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event INTEGER NOT NULL,"
    " number TEXT, tmid INTEGER NOT NULL, cell_id INTEGER NOT NULL, detail TEXT NOT NULL);";

static const char *const MIGRATIONS[] = { SCHEMA_V1 };

static const char KEY_CHECK[] = "OpenCell master key";

struct oc_sql {
    sqlite3 *db;
    uint8_t  key[32];
    void (*random)(uint8_t *out, size_t n);
    int      lock_fd;
    int      in_txn, began, failed;
    unsigned unseal_failures;
    char     backup[600];
};

/* ---- helpers ---- */

static sqlite3_stmt *prep(oc_sql_t *s, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) != SQLITE_OK) return NULL;
    return st;
}

/* A write: 0, or -1 (then, inside a transaction, the commit will fail). */
static int done(oc_sql_t *s, sqlite3_stmt *st)
{
    int rc = st != NULL ? sqlite3_step(st) : SQLITE_ERROR;
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return 0;
    if (s->in_txn) s->failed = 1;
    return -1;
}

/* A write refused before it starts: inside a failed transaction nothing is
 * written. SQLite rolls a transaction back by itself on some errors
 * (SQLITE_FULL, SQLITE_IOERR, SQLITE_NOMEM, SQLITE_BUSY), and the statements
 * after would run in autocommit, each durable on its own: a transaction
 * that has left SQLite's hands is doomed too. */
static int blocked(oc_sql_t *s)
{
    if (s->in_txn && s->began && !s->failed && sqlite3_get_autocommit(s->db)) s->failed = 1;
    return s->in_txn && s->failed;
}

static void num_text(const uint8_t n[OC_SIG_NUMBER_LEN], char out[OC_SIG_NUMBER_TEXT]) { oc_sig_number_to_text(n, out); }

static int num_col(sqlite3_stmt *st, int col, uint8_t out[OC_SIG_NUMBER_LEN])
{
    const char *t = (const char *)sqlite3_column_text(st, col);
    memset(out, 0, OC_SIG_NUMBER_LEN);
    return t != NULL && oc_sig_number_to_bcd(t, strlen(t), out) == 0 ? 0 : -1;
}

static void blob_col(sqlite3_stmt *st, int col, uint8_t *out, size_t n)
{
    const void *b = sqlite3_column_blob(st, col);
    memset(out, 0, n);
    if (b != NULL && (size_t)sqlite3_column_bytes(st, col) == n) memcpy(out, b, n);
}

static int seal_bind(oc_sql_t *s, sqlite3_stmt *st, int idx, const char *table, const char *column,
                     const uint8_t *pk, size_t pk_n, const uint8_t *pt, size_t n)
{
    uint8_t nonce[12], blob[OC_SEAL_PT_MAX + OC_SEAL_OVERHEAD];
    s->random(nonce, sizeof(nonce));
    if (oc_seal(s->key, table, column, pk, pk_n, pt, n, nonce, blob) != 0) return -1;
    return sqlite3_bind_blob(st, idx, blob, (int)(n + OC_SEAL_OVERHEAD), SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
}

static int unseal_col(oc_sql_t *s, sqlite3_stmt *st, int col, const char *table, const char *column,
                      const uint8_t *pk, size_t pk_n, uint8_t *pt, size_t n)
{
    const uint8_t *b = sqlite3_column_blob(st, col);
    size_t bn = (size_t)sqlite3_column_bytes(st, col);
    if (b == NULL || bn != n + OC_SEAL_OVERHEAD || oc_unseal(s->key, table, column, pk, pk_n, b, bn, pt) != 0) {
        s->unseal_failures++;
        return -1;
    }
    return 0;
}

#define S(c) ((oc_sql_t *)(c))

/* ---- transactions ---- */

static int begin(void *c)
{
    oc_sql_t *s = S(c);
    if (s->in_txn) return -1; /* already inside one: leave it be */
    s->in_txn = 1;
    s->began = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    s->failed = !s->began; /* puts until commit write nothing, and commit fails */
    return s->began ? 0 : -1;
}

static int commit(void *c)
{
    oc_sql_t *s = S(c);
    if (!s->in_txn) return -1;
    int ok = !blocked(s) && s->began && sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok && s->began) sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
    s->in_txn = s->began = s->failed = 0;
    return ok ? 0 : -1;
}

/* ---- network keys ---- */

static void key_pk(uint16_t key_id, uint8_t pk[2])
{
    pk[0] = (uint8_t)(key_id >> 8);
    pk[1] = (uint8_t)key_id;
}

static int netkey_get(void *c, uint16_t key_id, oc_core_netkey_t *out)
{
    oc_sql_t *s = S(c);
    uint8_t pk[2];
    sqlite3_stmt *st = prep(s, "SELECT sk_enc, pk, period_s, created FROM network WHERE key_id = ?");
    int rc = -1;
    if (st == NULL) return -1;
    sqlite3_bind_int(st, 1, key_id);
    key_pk(key_id, pk);
    memset(out, 0, sizeof(*out));
    if (sqlite3_step(st) == SQLITE_ROW &&
        unseal_col(s, st, 0, "network", "sk", pk, 2, out->sk, sizeof(out->sk)) == 0) {
        out->key_id = key_id;
        blob_col(st, 1, out->pk, sizeof(out->pk));
        out->period_s = (uint16_t)sqlite3_column_int(st, 2);
        out->created = (uint32_t)sqlite3_column_int64(st, 3);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int netkey_put(void *c, const oc_core_netkey_t *k)
{
    oc_sql_t *s = S(c);
    uint8_t pk[2];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO network(key_id, sk_enc, pk, period_s, created) VALUES(?,?,?,?,?)");
    if (st == NULL) return done(s, st);
    key_pk(k->key_id, pk);
    sqlite3_bind_int(st, 1, k->key_id);
    if (seal_bind(s, st, 2, "network", "sk", pk, 2, k->sk, sizeof(k->sk)) != 0) {
        sqlite3_finalize(st);
        return done(s, NULL);
    }
    sqlite3_bind_blob(st, 3, k->pk, sizeof(k->pk), SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, k->period_s);
    sqlite3_bind_int64(st, 5, k->created);
    return done(s, st);
}

/* ---- cells ---- */

static int cell_get(void *c, uint32_t cell_id, oc_core_cell_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT name, mode, enabled, list_id, boot_id, last_seen FROM cell WHERE cell_id = ?");
    int rc = -1;
    if (st == NULL) return -1;
    sqlite3_bind_int64(st, 1, cell_id);
    memset(out, 0, sizeof(*out));
    if (sqlite3_step(st) == SQLITE_ROW) {
        out->cell_id = cell_id;
        snprintf(out->name, sizeof(out->name), "%s", (const char *)sqlite3_column_text(st, 0));
        out->mode = (uint8_t)sqlite3_column_int(st, 1);
        out->enabled = (uint8_t)sqlite3_column_int(st, 2);
        out->list_id = (uint16_t)sqlite3_column_int(st, 3);
        out->boot_id = (uint64_t)sqlite3_column_int64(st, 4);
        out->last_seen = (uint32_t)sqlite3_column_int64(st, 5);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int cell_put(void *c, const oc_core_cell_t *x)
{
    oc_sql_t *s = S(c);
    if (blocked(s)) return -1;
    /* an upsert: cert_fpr (plan 9) is not oc_core's and survives */
    sqlite3_stmt *st = prep(s, "INSERT INTO cell(cell_id, name, mode, enabled, list_id, boot_id, last_seen)"
                               " VALUES(?,?,?,?,?,?,?) ON CONFLICT(cell_id) DO UPDATE SET name = excluded.name,"
                               " mode = excluded.mode, enabled = excluded.enabled, list_id = excluded.list_id,"
                               " boot_id = excluded.boot_id, last_seen = excluded.last_seen");
    if (st != NULL) {
        sqlite3_bind_int64(st, 1, x->cell_id);
        sqlite3_bind_text(st, 2, x->name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, x->mode);
        sqlite3_bind_int(st, 4, x->enabled);
        sqlite3_bind_int(st, 5, x->list_id);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)x->boot_id);
        sqlite3_bind_int64(st, 7, x->last_seen);
    }
    return done(s, st);
}

/* ---- channel lists: count x { freq_hz (4, BE), flags (1) } ---- */

static int list_get(void *c, uint16_t list_id, oc_sig_chan_list_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT ver, entries FROM chan_list WHERE list_id = ?");
    int rc = -1;
    if (st == NULL) return -1;
    sqlite3_bind_int(st, 1, list_id);
    memset(out, 0, sizeof(*out));
    if (sqlite3_step(st) == SQLITE_ROW) {
        const uint8_t *e = sqlite3_column_blob(st, 1);
        int n = sqlite3_column_bytes(st, 1);
        if (n % 5 == 0 && n / 5 <= (int)OC_SIG_CHAN_MAX) {
            out->ver = (uint8_t)sqlite3_column_int(st, 0);
            out->count = (uint8_t)(n / 5);
            for (int i = 0; i < out->count; i++) {
                out->freq_hz[i] = ((uint32_t)e[5 * i] << 24) | ((uint32_t)e[5 * i + 1] << 16) |
                                  ((uint32_t)e[5 * i + 2] << 8) | e[5 * i + 3];
                out->flags[i] = e[5 * i + 4];
            }
            rc = 0;
        }
    }
    sqlite3_finalize(st);
    return rc;
}

static int list_put(void *c, uint16_t list_id, const oc_sig_chan_list_t *l)
{
    oc_sql_t *s = S(c);
    uint8_t e[5 * OC_SIG_CHAN_MAX];
    if (blocked(s) || l->count > OC_SIG_CHAN_MAX) return -1;
    for (int i = 0; i < l->count; i++) {
        e[5 * i] = (uint8_t)(l->freq_hz[i] >> 24);
        e[5 * i + 1] = (uint8_t)(l->freq_hz[i] >> 16);
        e[5 * i + 2] = (uint8_t)(l->freq_hz[i] >> 8);
        e[5 * i + 3] = (uint8_t)l->freq_hz[i];
        e[5 * i + 4] = l->flags[i];
    }
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO chan_list(list_id, ver, entries) VALUES(?,?,?)");
    if (st != NULL) {
        sqlite3_bind_int(st, 1, list_id);
        sqlite3_bind_int(st, 2, l->ver);
        sqlite3_bind_blob(st, 3, e, 5 * l->count, SQLITE_TRANSIENT);
    }
    return done(s, st);
}

/* ---- subscribers ---- */

#define SUB_COLS "number, state, tmid, activated, k_enc, opc_enc, sqn, created, updated"

static int sub_row(oc_sql_t *s, sqlite3_stmt *st, oc_core_sub_t *out)
{
    memset(out, 0, sizeof(*out));
    if (num_col(st, 0, out->number) != 0) return -1;
    out->state = (uint8_t)sqlite3_column_int(st, 1);
    out->tmid = (uint32_t)sqlite3_column_int64(st, 2);
    out->activated = (uint8_t)sqlite3_column_int(st, 3);
    if (unseal_col(s, st, 4, "subscriber", "k", out->number, OC_SIG_NUMBER_LEN, out->k, 16) != 0 ||
        unseal_col(s, st, 5, "subscriber", "opc", out->number, OC_SIG_NUMBER_LEN, out->opc, 16) != 0) {
        oc_sig_wipe(out, sizeof(*out));
        return -1;
    }
    out->sqn = (uint64_t)sqlite3_column_int64(st, 6);
    out->created = (uint32_t)sqlite3_column_int64(st, 7);
    out->updated = (uint32_t)sqlite3_column_int64(st, 8);
    return 0;
}

static int sub_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_sub_t *out)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    sqlite3_stmt *st = prep(s, "SELECT " SUB_COLS " FROM subscriber WHERE number = ?");
    int rc = -1;
    if (st == NULL) return -1;
    num_text(number, t);
    sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) rc = sub_row(s, st, out);
    sqlite3_finalize(st);
    return rc;
}

static int sub_by_tmid(void *c, uint32_t tmid, oc_core_sub_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT " SUB_COLS " FROM subscriber WHERE tmid = ? AND activated = 1");
    int rc = -1;
    if (st == NULL) return -1;
    sqlite3_bind_int64(st, 1, tmid);
    if (sqlite3_step(st) == SQLITE_ROW) rc = sub_row(s, st, out);
    sqlite3_finalize(st);
    return rc;
}

static int sub_put(void *c, const oc_core_sub_t *x)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO subscriber(" SUB_COLS ") VALUES(?,?,?,?,?,?,?,?,?)");
    if (st == NULL) return done(s, NULL);
    num_text(x->number, t);
    sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, x->state);
    sqlite3_bind_int64(st, 3, x->tmid);
    sqlite3_bind_int(st, 4, x->activated);
    if (seal_bind(s, st, 5, "subscriber", "k", x->number, OC_SIG_NUMBER_LEN, x->k, 16) != 0 ||
        seal_bind(s, st, 6, "subscriber", "opc", x->number, OC_SIG_NUMBER_LEN, x->opc, 16) != 0) {
        sqlite3_finalize(st);
        return done(s, NULL);
    }
    sqlite3_bind_int64(st, 7, (sqlite3_int64)x->sqn);
    sqlite3_bind_int64(st, 8, x->created);
    sqlite3_bind_int64(st, 9, x->updated);
    return done(s, st);
}

/* ---- tokens ---- */

static int token_get(void *c, const uint8_t token_id[8], oc_core_token_t *out)
{
    oc_sql_t *s = S(c);
    sqlite3_stmt *st = prep(s, "SELECT number, secret_enc, expiry, used_at, used_by_tmid FROM token WHERE token_id = ?");
    int rc = -1;
    if (st == NULL) return -1;
    sqlite3_bind_blob(st, 1, token_id, 8, SQLITE_TRANSIENT);
    memset(out, 0, sizeof(*out));
    if (sqlite3_step(st) == SQLITE_ROW && num_col(st, 0, out->number) == 0 &&
        unseal_col(s, st, 1, "token", "secret", token_id, 8, out->secret, 16) == 0) {
        memcpy(out->token_id, token_id, 8);
        out->expiry = (uint32_t)sqlite3_column_int64(st, 2);
        out->used_at = (uint32_t)sqlite3_column_int64(st, 3);
        out->used_by_tmid = (uint32_t)sqlite3_column_int64(st, 4);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int token_put(void *c, const oc_core_token_t *x)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    /* an upsert on token_id only: a second unused token for a number is
     * refused (token_one_unused), never a silent replacement of the first */
    sqlite3_stmt *st = prep(s, "INSERT INTO token(token_id, number, secret_enc, expiry, used_at, used_by_tmid)"
                               " VALUES(?,?,?,?,?,?) ON CONFLICT(token_id) DO UPDATE SET number = excluded.number,"
                               " secret_enc = excluded.secret_enc, expiry = excluded.expiry,"
                               " used_at = excluded.used_at, used_by_tmid = excluded.used_by_tmid");
    if (st == NULL) return done(s, NULL);
    num_text(x->number, t);
    sqlite3_bind_blob(st, 1, x->token_id, 8, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, t, -1, SQLITE_TRANSIENT);
    if (seal_bind(s, st, 3, "token", "secret", x->token_id, 8, x->secret, 16) != 0) {
        sqlite3_finalize(st);
        return done(s, NULL);
    }
    sqlite3_bind_int64(st, 4, x->expiry);
    sqlite3_bind_int64(st, 5, x->used_at);
    sqlite3_bind_int64(st, 6, x->used_by_tmid);
    return done(s, st);
}

static int by_number(oc_sql_t *s, const char *sql, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, sql);
    num_text(number, t);
    if (st != NULL) sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
    return done(s, st);
}

static int by_int(oc_sql_t *s, const char *sql, sqlite3_int64 v)
{
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, sql);
    if (st != NULL) sqlite3_bind_int64(st, 1, v);
    return done(s, st);
}

static int token_void(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    return by_number(S(c), "DELETE FROM token WHERE number = ? AND used_at = 0", number);
}

/* ---- issued vectors ---- */

static int av_put(void *c, const oc_core_av_issued_t *a)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO av_issued(number, rand, xres, sqn, cell_id, issued, confirmed)"
                               " VALUES(?,?,?,?,?,?,?)");
    if (st != NULL) {
        num_text(a->number, t);
        sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, a->rand, 16, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, a->xres, 8, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)a->sqn);
        sqlite3_bind_int64(st, 5, a->cell_id);
        sqlite3_bind_int64(st, 6, a->issued);
        sqlite3_bind_int(st, 7, a->confirmed);
    }
    return done(s, st);
}

static int av_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], const uint8_t rand[16], oc_core_av_issued_t *out)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    sqlite3_stmt *st = prep(s, "SELECT xres, sqn, cell_id, issued, confirmed FROM av_issued WHERE number = ? AND rand = ?");
    int rc = -1;
    if (st == NULL) return -1;
    num_text(number, t);
    sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, rand, 16, SQLITE_TRANSIENT);
    memset(out, 0, sizeof(*out));
    if (sqlite3_step(st) == SQLITE_ROW) {
        memcpy(out->number, number, OC_SIG_NUMBER_LEN);
        memcpy(out->rand, rand, 16);
        blob_col(st, 0, out->xres, 8);
        out->sqn = (uint64_t)sqlite3_column_int64(st, 1);
        out->cell_id = (uint32_t)sqlite3_column_int64(st, 2);
        out->issued = (uint32_t)sqlite3_column_int64(st, 3);
        out->confirmed = (uint8_t)sqlite3_column_int(st, 4);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int av_drop_cell(void *c, uint32_t cell_id)
{
    return by_int(S(c), "DELETE FROM av_issued WHERE cell_id = ? AND confirmed = 0", cell_id);
}

static int av_prune(void *c, uint32_t before) { return by_int(S(c), "DELETE FROM av_issued WHERE issued < ?", before); }

/* ---- locations ---- */

static int loc_get(void *c, const uint8_t number[OC_SIG_NUMBER_LEN], oc_core_loc_t *out)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    sqlite3_stmt *st = prep(s, "SELECT cell_id, tmid, expires FROM location WHERE number = ?");
    int rc = -1;
    if (st == NULL) return -1;
    num_text(number, t);
    sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
    memset(out, 0, sizeof(*out));
    if (sqlite3_step(st) == SQLITE_ROW) {
        memcpy(out->number, number, OC_SIG_NUMBER_LEN);
        out->cell_id = (uint32_t)sqlite3_column_int64(st, 0);
        out->tmid = (uint32_t)sqlite3_column_int64(st, 1);
        out->expires = (uint32_t)sqlite3_column_int64(st, 2);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int loc_put(void *c, const oc_core_loc_t *l)
{
    oc_sql_t *s = S(c);
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT OR REPLACE INTO location(number, cell_id, tmid, expires) VALUES(?,?,?,?)");
    if (st != NULL) {
        num_text(l->number, t);
        sqlite3_bind_text(st, 1, t, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, l->cell_id);
        sqlite3_bind_int64(st, 3, l->tmid);
        sqlite3_bind_int64(st, 4, l->expires);
    }
    return done(s, st);
}

static int loc_del(void *c, const uint8_t number[OC_SIG_NUMBER_LEN])
{
    return by_number(S(c), "DELETE FROM location WHERE number = ?", number);
}

static int loc_purge_cell(void *c, uint32_t cell_id)
{
    return by_int(S(c), "DELETE FROM location WHERE cell_id = ?", cell_id);
}

/* ---- records ---- */

static int cdr_add(void *c, const oc_core_cdr_t *x)
{
    oc_sql_t *s = S(c);
    char a[OC_SIG_NUMBER_TEXT], b[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT INTO cdr(caller, called, cell_a, cell_b, setup, answer, \"end\", cause)"
                               " VALUES(?,?,?,?,?,?,?,?)");
    if (st != NULL) {
        num_text(x->caller, a);
        num_text(x->called, b);
        sqlite3_bind_text(st, 1, a, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, b, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, x->cell_a);
        sqlite3_bind_int64(st, 4, x->cell_b);
        sqlite3_bind_int64(st, 5, x->setup);
        sqlite3_bind_int64(st, 6, x->answer);
        sqlite3_bind_int64(st, 7, x->end);
        sqlite3_bind_int(st, 8, x->cause);
    }
    return done(s, st);
}

static int audit_add(void *c, const oc_core_audit_t *x)
{
    oc_sql_t *s = S(c);
    static const uint8_t zero[OC_SIG_NUMBER_LEN];
    char t[OC_SIG_NUMBER_TEXT];
    if (blocked(s)) return -1;
    sqlite3_stmt *st = prep(s, "INSERT INTO audit(ts, event, number, tmid, cell_id, detail) VALUES(?,?,?,?,?,?)");
    if (st != NULL) {
        sqlite3_bind_int64(st, 1, x->ts);
        sqlite3_bind_int(st, 2, x->event);
        if (memcmp(x->number, zero, OC_SIG_NUMBER_LEN) != 0) {
            num_text(x->number, t);
            sqlite3_bind_text(st, 3, t, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int64(st, 4, x->tmid);
        sqlite3_bind_int64(st, 5, x->cell_id);
        sqlite3_bind_text(st, 6, x->detail, (int)strnlen(x->detail, sizeof(x->detail)), SQLITE_TRANSIENT);
    }
    return done(s, st);
}

/* ---- open, migrate, close ---- */

static int user_version(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int backup_to(sqlite3 *db, const char *path)
{
    sqlite3 *out = NULL;
    int ok = sqlite3_open_v2(path, &out, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK;
    sqlite3_backup *b = ok ? sqlite3_backup_init(out, "main", db, "main") : NULL;
    ok = b != NULL && sqlite3_backup_step(b, -1) == SQLITE_DONE;
    if (b != NULL) sqlite3_backup_finish(b);
    ok = ok && sqlite3_errcode(out) == SQLITE_OK;
    sqlite3_close(out);
    if (ok) chmod(path, 0600);
    return ok ? 0 : -1;
}

static int migrate(oc_sql_t *s, const char *path, const char *const *mig, unsigned n, char *err, size_t cap)
{
    int v = user_version(s->db);
    if (v < 0 || (unsigned)v > n) {
        snprintf(err, cap, "%s: schema v%d is newer than this oc-core (v%u): install a newer oc-core", path, v, n);
        return -1;
    }
    if ((unsigned)v == n) return 0;
    if (v > 0 && strcmp(path, ":memory:") != 0) {
        snprintf(s->backup, sizeof(s->backup), "%s.v%d.%lld.bak", path, v, (long long)time(NULL));
        if (backup_to(s->db, s->backup) != 0) {
            snprintf(err, cap, "%s: backup before migrating failed; nothing changed", s->backup);
            return -1;
        }
    }
    for (unsigned i = (unsigned)v; i < n; i++) {
        char pragma[48];
        snprintf(pragma, sizeof(pragma), "PRAGMA user_version = %u", i + 1u);
        char *e = NULL;
        int ok = sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
                 sqlite3_exec(s->db, mig[i], NULL, NULL, &e) == SQLITE_OK &&
                 sqlite3_exec(s->db, pragma, NULL, NULL, NULL) == SQLITE_OK &&
                 sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        if (!ok) {
            sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
            snprintf(err, cap, "%s: migration to v%u failed (%s); the database stays at v%u", path, i + 1u,
                     e != NULL ? e : sqlite3_errmsg(s->db), i);
            sqlite3_free(e);
            return -1;
        }
    }
    return 0;
}

/* The master key must open the check value; a new database gets one. */
static int key_check(oc_sql_t *s, const char *path, char *err, size_t cap)
{
    uint8_t pt[sizeof(KEY_CHECK) - 1];
    sqlite3_stmt *st = prep(s, "SELECT v FROM meta WHERE k = 'key_check'");
    if (st == NULL) {
        snprintf(err, cap, "%s: %s", path, sqlite3_errmsg(s->db));
        return -1;
    }
    int rc;
    if (sqlite3_step(st) == SQLITE_ROW) {
        rc = unseal_col(s, st, 0, "meta", "key_check", (const uint8_t *)"", 0, pt, sizeof(pt)) == 0 &&
                     memcmp(pt, KEY_CHECK, sizeof(pt)) == 0
                 ? 0
                 : -1;
        if (rc != 0) snprintf(err, cap, "%s: the master key does not open this database", path);
        s->unseal_failures = 0;
    } else {
        sqlite3_stmt *ins = prep(s, "INSERT INTO meta(k, v) VALUES('key_check', ?)");
        if (ins != NULL && seal_bind(s, ins, 1, "meta", "key_check", (const uint8_t *)"", 0,
                                     (const uint8_t *)KEY_CHECK, sizeof(pt)) == 0) {
            rc = done(s, ins);
        } else {
            sqlite3_finalize(ins);
            rc = -1;
        }
        if (rc != 0) snprintf(err, cap, "%s: can't write the key check: %s", path, sqlite3_errmsg(s->db));
    }
    sqlite3_finalize(st);
    return rc;
}

oc_sql_t *oc_sql_open(const oc_sql_cfg_t *cfg, char *err, size_t cap)
{
    oc_sql_t *s = calloc(1, sizeof(*s));
    int mem = strcmp(cfg->path, ":memory:") == 0;
    if (s == NULL) {
        snprintf(err, cap, "out of memory");
        return NULL;
    }
    s->lock_fd = -1;
    memcpy(s->key, cfg->master_key, 32);
    s->random = cfg->random;
    if (!mem) {
        char lp[600];
        snprintf(lp, sizeof(lp), "%s.lock", cfg->path);
        s->lock_fd = open(lp, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (s->lock_fd < 0) {
            snprintf(err, cap, "%s: %s", lp, strerror(errno));
            oc_sql_close(s);
            return NULL;
        }
        if (flock(s->lock_fd, LOCK_EX | LOCK_NB) != 0) {
            snprintf(err, cap, "%s is in use (oc-core is running, or another admin --offline): stop it first",
                     cfg->path);
            oc_sql_close(s);
            return NULL;
        }
    }
    mode_t old = umask(0077); /* the database and its WAL: owner only */
    int rc = sqlite3_open_v2(cfg->path, &s->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    umask(old);
    if (rc != SQLITE_OK) {
        snprintf(err, cap, "%s: %s", cfg->path, s->db != NULL ? sqlite3_errmsg(s->db) : "can't open");
        oc_sql_close(s);
        return NULL;
    }
    sqlite3_busy_timeout(s->db, 2000);
    if (sqlite3_exec(s->db, "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(err, cap, "%s: %s", cfg->path, sqlite3_errmsg(s->db));
        oc_sql_close(s);
        return NULL;
    }
    const char *const *mig = cfg->migrations != NULL ? cfg->migrations : MIGRATIONS;
    unsigned n = cfg->migrations != NULL ? cfg->nmigrations : (unsigned)(sizeof(MIGRATIONS) / sizeof(MIGRATIONS[0]));
    if (migrate(s, cfg->path, mig, n, err, cap) != 0 || key_check(s, cfg->path, err, cap) != 0) {
        oc_sql_close(s);
        return NULL;
    }
    return s;
}

void oc_sql_close(oc_sql_t *s)
{
    if (s == NULL) return;
    if (s->db != NULL) sqlite3_close(s->db);
    if (s->lock_fd >= 0) close(s->lock_fd); /* drops the lock */
    oc_sig_wipe(s->key, sizeof(s->key));
    free(s);
}

const char *oc_sql_migration(unsigned i)
{
    return i < sizeof(MIGRATIONS) / sizeof(MIGRATIONS[0]) ? MIGRATIONS[i] : NULL;
}

sqlite3 *oc_sql_db(oc_sql_t *s) { return s->db; }
int oc_sql_version(oc_sql_t *s) { return user_version(s->db); }
const char *oc_sql_backup(oc_sql_t *s) { return s->backup; }
unsigned oc_sql_unseal_failures(oc_sql_t *s) { return s->unseal_failures; }

oc_core_store_t oc_sql_store(oc_sql_t *s)
{
    oc_core_store_t st = {
        .ctx = s,
        .begin = begin,
        .commit = commit,
        .netkey_get = netkey_get,
        .netkey_put = netkey_put,
        .cell_get = cell_get,
        .cell_put = cell_put,
        .list_get = list_get,
        .list_put = list_put,
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
    return st;
}
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_sql 2>&1 | grep -E "error|warning"; build/tests/test_oc_sql | tail -3`
Expected: no compiler output, then `10 Tests 0 Failures 0 Ignored` and `OK`.

If `store_contract` fails on a member this plan doesn't list (plan 1's final store interface grew one), implement that member in `oc_sql.c` the way the in-memory store (`oc_core/oc_core_mem.c`) does and add it to `oc_sql_store()`; the contract is the specification.

- [ ] **Step 5: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_core+3` (11 when validated).

- [ ] **Step 6: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add oc/CMakeLists.txt oc/include/oc_sql.h oc/oc_sql.c tests/CMakeLists.txt tests/test_oc_sql.c
git commit -m "oc_sql: the SQLite store with sealed keys, user_version migrations after a backup, one process per database

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 5: The admin commands, the channel-list text, and the import of ocbench's HSS

**Repo:** `opencell-core`, branch `oc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 4.

`oc-core admin …` replaces `ocbench mkqr` (spec §4.2) and is the operator's only tool until the portal. The commands run in one place, `oc_admin_run`, which the daemon calls for each admin-socket request (Task 6) and `--offline` calls directly on a stopped core's database; both go through `oc_core` and the store, and every command leaves an `ADMIN` audit record (§17.1). The channel-list text (`917.25,922.25:fixed`) was `ocb_net`'s; it moves here with the operator. The import takes ocbench's bench HSS into the database so T and T2 keep their identities (ruling 1).

**Files:**
- Modify: `oc_core/include/oc_core_store.h` (the `ADMIN` audit event), `oc/CMakeLists.txt`, `tests/CMakeLists.txt`
- Create: `oc/include/oc_admin.h`, `oc/oc_admin.c`, `oc/oc_import.c`
- Test: `tests/test_oc_admin.c`

**Interfaces:**
- Consumes: `oc_core_init`, `oc_core_netkey_new`, `oc_core_cell_add`, `oc_core_cell_revoke`, `oc_core_sub_add`, `oc_core_token_issue`, `oc_core_sub_disable`, `oc_core_chan_list_set`, `oc_core_route_find`/`_home`, `oc_core_number_reserved` (plan 1); `oc_sql_store`, `oc_sql_db`, `oc_sql_version`, `oc_sql_unseal_failures` (Task 4); `oc_sig_qr_format`, `oc_sig_number_normalize`/`_format`/`_to_text`, `oc_sig_x25519_public`, `oc_sig_sqn_get`, `oc_channel_of_freq`.
- Produces (library `oc_store`, `oc_admin.h`):
  ```c
  typedef struct { char *p; size_t n, cap; } oc_buf_t;
  void oc_buf_printf(oc_buf_t *b, const char *fmt, ...);
  void oc_buf_free(oc_buf_t *b);
  typedef struct {
      oc_sql_t *sql; const oc_core_route_t *route; const oc_core_cfg_t *cfg;
      oc_core_t *core;                                  /* the daemon's; NULL offline */
      void (*random)(uint8_t *out, size_t n);
      uint64_t (*now_us)(void);
      void (*drop_cell)(void *ctx, uint32_t cell_id);  /* the daemon's; NULL offline */
      void *ctx; uint32_t uid;
      oc_core_t own; int have_own;                      /* private */
  } oc_admin_t;
  int oc_admin_run(oc_admin_t *a, int argc, char **argv, oc_buf_t *out); /* 0 done, 1 refused, 2 usage */
  int oc_chan_parse(const char *text, oc_sig_chan_list_t *out, char *err, size_t cap);
  int oc_import_ocb_hss(oc_admin_t *a, const char *path, oc_buf_t *out);
  ```
- Produces (`oc_core_store.h`): `OC_CORE_AUDIT_ADMIN` (10).

- [ ] **Step 1: Write the failing test**

Create `tests/test_oc_admin.c`:
```c
#define _GNU_SOURCE
/* The admin commands (network-core spec §4.2, §17 decision 1) on a core's
 * database with no daemon (the --offline path; the daemon runs the same
 * code over its socket), the channel-list text, and the import of
 * ocbench's HSS. */
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "oc_sig_crypto.h"
#include "oc_sig_qr.h"
#include "oc_admin.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t KEY[32] = { 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                                 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 };
static uint32_t rng = 3;
static void rnd(uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((rng = rng * 1103515245u + 12345u) >> 16);
}

static oc_sql_t *sql;
static oc_core_route_t route;
static oc_core_cfg_t cfg;
static oc_admin_t adm;
static oc_buf_t out;

static void world(void)
{
    char err[256];
    oc_sql_cfg_t c = { ":memory:", KEY, rnd, NULL, 0 };
    sql = oc_sql_open(&c, err, sizeof(err));
    TEST_ASSERT_NOT_NULL_MESSAGE(sql, err);
    oc_core_route_init(&route, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&route, "8831606", 1, 1));
    memset(&cfg, 0, sizeof(cfg));
    cfg.core_id = 1;
    cfg.key_id = 1;
    oc_sig_number_to_bcd("+883160655500100", 16, cfg.echo_number);
    memset(&adm, 0, sizeof(adm));
    adm.sql = sql;
    adm.route = &route;
    adm.cfg = &cfg;
    adm.random = rnd;
    adm.uid = 1000;
}

static void done(void)
{
    oc_sql_close(sql);
    oc_buf_free(&out);
}

/* Runs one command line (words split on spaces); the output is in out.p. */
static int run(const char *line)
{
    char buf[512], *argv[16];
    int argc = 0;
    snprintf(buf, sizeof(buf), "%s", line);
    for (char *t = strtok(buf, " "); t != NULL && argc < 16; t = strtok(NULL, " ")) argv[argc++] = t;
    out.n = 0;
    if (out.p != NULL) out.p[0] = '\0';
    return oc_admin_run(&adm, argc, argv, &out);
}

#define HAS(s) TEST_ASSERT_NOT_NULL_MESSAGE(strstr(out.p != NULL ? out.p : "", s), out.p != NULL ? out.p : "(no output)")

static void test_first_setup_and_subscribers(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("status"));
    HAS("network key 1 (missing: net init)");
    HAS("offline");
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-606-555-01234"));
    HAS("no network key 1 in the database");
    TEST_ASSERT_EQUAL_INT(0, run("net init --period 900"));
    HAS("network key 1 made, registration period 900 s");
    TEST_ASSERT_EQUAL_INT(1, run("net init"));
    HAS("exists already");
    TEST_ASSERT_EQUAL_INT(0, run("cell add 1 benchA --mode part15"));
    TEST_ASSERT_EQUAL_INT(1, run("cell add 1 again"));
    TEST_ASSERT_EQUAL_INT(1, run("cell add 2 x --mode part16"));
    HAS("mode 'part16': part15 or part97");
    TEST_ASSERT_EQUAL_INT(0, run("sub add +883-1-606-555-01234"));
    HAS("subscriber +883160655501234 (+883-1-606-555-01234) added");
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-606-555-01234"));
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-606-555-00911")); /* reserved */
    TEST_ASSERT_EQUAL_INT(1, run("sub add +883-1-859-555-01234")); /* not our block */
    TEST_ASSERT_EQUAL_INT(1, run("sub add 555-1234"));
    HAS("not a full OpenCell number");
    TEST_ASSERT_EQUAL_INT(0, run("sub add")); /* a number picked for us */
    HAS("subscriber +8831606");
    TEST_ASSERT_EQUAL_INT(0, run("status"));
    HAS("subscribers 2 (0 activated, 0 disabled)");
    HAS("cell 1 \"benchA\": part15, enabled, list 0, not linked");
    done();
}

/* The code a phone scans, and what disabling does to it. */
static void test_issue_and_disable(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("net init"));
    TEST_ASSERT_EQUAL_INT(0, run("sub add +883160655501235"));
    TEST_ASSERT_EQUAL_INT(0, run("sub issue +883-1-606-555-01235 --valid-h 2"));
    HAS("valid 2 h");
    char *code = strstr(out.p, "opencell:2:");
    TEST_ASSERT_NOT_NULL(code);
    oc_sig_qr_t qr;
    TEST_ASSERT_EQUAL_INT(0, oc_sig_qr_parse(code, strcspn(code, "\n"), &qr));
    char t[OC_SIG_NUMBER_TEXT];
    oc_sig_number_to_text(qr.number, t);
    TEST_ASSERT_EQUAL_STRING("+883160655501235", t);
    TEST_ASSERT_EQUAL_UINT16(1, qr.key_id);
    TEST_ASSERT_EQUAL_UINT16(1, (uint16_t)((qr.token_id[0] << 8) | qr.token_id[1])); /* block index (§14.3) */
    TEST_ASSERT_EQUAL_INT(1, run("sub issue +883160655501235 --valid-h 0"));
    TEST_ASSERT_EQUAL_INT(0, run("sub disable +883160655501235"));
    TEST_ASSERT_EQUAL_INT(1, run("sub issue +883160655501235"));
    TEST_ASSERT_EQUAL_INT(0, run("sub list"));
    HAS("+883160655501235  disabled  not activated");
    TEST_ASSERT_EQUAL_INT(0, run("audit 50"));
    HAS("ADMIN        -  tmid 00000000  cell 0  u1000 sub disable +883160655501235");
    HAS("u1000 (refused) sub issue +883160655501235");
    HAS("TOKEN_ISSUE");
    HAS("SUB_DISABLE");
    TEST_ASSERT_EQUAL_INT(2, run("sub frobnicate"));
    HAS("commands: status");
    done();
}

static void test_channel_lists(void)
{
    world();
    TEST_ASSERT_EQUAL_INT(0, run("net init"));
    TEST_ASSERT_EQUAL_INT(0, run("list set 3 917.25,922.25:fixed"));
    HAS("list 3: version 1, 917.25 922.25:fixed");
    TEST_ASSERT_EQUAL_INT(0, run("list set 3 none"));
    HAS("list 3: version 2, (empty)");
    TEST_ASSERT_EQUAL_INT(1, run("list set 3 917.3"));
    HAS("'917.3' is not a 915 grid channel");
    TEST_ASSERT_EQUAL_INT(1, run("list set 0 917.25"));
    TEST_ASSERT_EQUAL_INT(0, run("list show"));
    HAS("list 3: version 2, (empty)");
    oc_sig_chan_list_t l;
    char err[96];
    TEST_ASSERT_EQUAL_INT(-1, oc_chan_parse("917.25:fast", &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_STRING("'917.25:fast': only ':fixed' may follow a frequency", err);
    TEST_ASSERT_EQUAL_INT(-1, oc_chan_parse("917.25, 922.25", &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_INT(-1, oc_chan_parse("902.25,902.75,903.25,903.75,904.25,904.75,905.25,905.75,906.25,906.75,"
                                            "907.25,907.75,908.25",
                                            &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_STRING("more than 12 entries", err);
    done();
}

/* An ocbench HSS file as ocb_hss_save wrote it. */
static char hss[64];
static uint8_t net_sk[32], net_pk[32];

static void write_hss(const char *extra, uint16_t key_id)
{
    char line[512];
    for (int i = 0; i < 32; i++) net_sk[i] = (uint8_t)(0x40 + i);
    TEST_ASSERT_EQUAL_INT(0, oc_sig_x25519_public(net_sk, net_pk));
    strcpy(hss, "/tmp/oc_admin_hss_XXXXXX");
    int fd = mkstemp(hss);
    TEST_ASSERT_TRUE(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fprintf(f, "# OpenCell network stand-in HSS (ocbench). Holds secrets: keep it private.\n");
    int n = snprintf(line, sizeof(line), "network key_id=%u sk=", key_id);
    for (int i = 0; i < 32; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", net_sk[i]);
    n += snprintf(line + n, sizeof(line) - (size_t)n, " pk=");
    for (int i = 0; i < 32; i++) n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", net_pk[i]);
    fprintf(f, "%s mode=part15 period=1800\n", line);
    fprintf(f, "sub number=+883160655501234 token_id=d5d37c57bd4ac802 token_secret=00112233445566778899aabbccddeeff "
               "expiry=1790637771 used=1 tmid=76ad0488 activated=1 k=0102030405060708090a0b0c0d0e0f10 "
               "opc=1112131415161718191a1b1c1d1e1f20 sqn=00000000001c\n");
    fprintf(f, "sub number=+883160655501235 token_id=e7cc4b4ba74a0070 token_secret=00112233445566778899aabbccddeeff "
               "expiry=1790637771 used=1 tmid=76ae2064 activated=1 k=2122232425262728292a2b2c2d2e2f30 "
               "opc=3132333435363738393a3b3c3d3e3f40 sqn=000000000005\n");
    fprintf(f, "sub number=+883160655509999 token_id=b8e799853e97664a token_secret=00112233445566778899aabbccddeeff "
               "expiry=1790637771 used=0 tmid=00000000 activated=0 k=00000000000000000000000000000000 "
               "opc=00000000000000000000000000000000 sqn=000000000000\n");
    fputs(extra, f);
    fclose(f);
}

static void test_import_keeps_activated_terminals(void)
{
    world();
    write_hss("", 1);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(0, run(cmd));
    HAS("network key 1 imported");
    HAS("+883160655501234  terminal 76ad0488  sqn 28  imported");
    HAS("+883160655509999  not activated: give it a code with `oc-core admin sub issue +883160655509999`");
    oc_core_store_t st = oc_sql_store(sql);
    oc_core_sub_t s;
    TEST_ASSERT_EQUAL_INT(0, st.sub_by_tmid(st.ctx, 0x76ae2064u, &s));
    TEST_ASSERT_EQUAL_UINT8(0x21, s.k[0]);
    TEST_ASSERT_EQUAL_UINT8(0x40, s.opc[15]);
    TEST_ASSERT_EQUAL_UINT64(5, s.sqn);
    oc_core_netkey_t key;
    TEST_ASSERT_EQUAL_INT(0, st.netkey_get(st.ctx, 1, &key));
    TEST_ASSERT_EQUAL_MEMORY(net_sk, key.sk, 32);
    TEST_ASSERT_EQUAL_UINT16(1800, key.period_s);
    TEST_ASSERT_EQUAL_INT(1, run(cmd)); /* twice: refused whole */
    HAS("+883160655501234: already a subscriber");
    TEST_ASSERT_EQUAL_INT(0, run("sub issue +883160655509999")); /* the network key issues codes */
    unlink(hss);
    done();
}

/* A bad line anywhere, a key id the config doesn't use, a TMID twice, or a
 * daemon that is running: nothing is written. */
static void test_import_is_all_or_nothing(void)
{
    char cmd[128];
    world();
    write_hss("sub number=+883160655501236 tmid=zz\n", 1);
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS(":6: not an ocbench HSS line (nothing imported)");
    unlink(hss);
    write_hss("", 2);
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS("network key 2, but key_id = 1 in oc-core.conf");
    unlink(hss);
    write_hss("sub number=+883160655501236 token_id=0000000000000000 token_secret=00000000000000000000000000000000 "
              "expiry=0 used=1 tmid=76ad0488 activated=1 k=00000000000000000000000000000000 "
              "opc=00000000000000000000000000000000 sqn=000000000000\n",
              1);
    snprintf(cmd, sizeof(cmd), "import-ocb-hss %s", hss);
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS("twice in the file");
    TEST_ASSERT_EQUAL_INT(0, run("status"));
    HAS("subscribers 0");
    oc_core_t fake; /* any non-NULL core: the daemon is running */
    adm.core = &fake;
    TEST_ASSERT_EQUAL_INT(1, run(cmd));
    HAS("import-ocb-hss runs only with --offline");
    adm.core = NULL;
    unlink(hss);
    done();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_first_setup_and_subscribers);
    RUN_TEST(test_issue_and_disable);
    RUN_TEST(test_channel_lists);
    RUN_TEST(test_import_keeps_activated_terminals);
    RUN_TEST(test_import_is_all_or_nothing);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
oc_test(test_oc_admin oc_store)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_admin 2>&1 | grep -oE "oc_admin.h: No such file or directory" | head -1`
Expected: `oc_admin.h: No such file or directory`.

- [ ] **Step 3: The audit event**

In `oc_core/include/oc_core_store.h`, replace:
```c
    OC_CORE_AUDIT_CELL_REJECT
} oc_core_audit_event_t;
```
with:
```c
    OC_CORE_AUDIT_CELL_REJECT, OC_CORE_AUDIT_ADMIN /* an operator's command (oc-core admin) */
} oc_core_audit_event_t;
```

- [ ] **Step 4: Implement the commands**

In `oc/CMakeLists.txt`, replace:
```cmake
add_library(oc_store STATIC oc_seal.c oc_sql.c)
```
with:
```cmake
add_library(oc_store STATIC oc_seal.c oc_sql.c oc_admin.c oc_import.c)
```

Create `oc/include/oc_admin.h`:
```c
/* `oc-core admin ...` (network-core spec §4.2, §17 decision 1): the
 * operator's commands, run inside the daemon (over the admin socket) or,
 * with --offline, straight on a stopped core's database. Either way they go
 * through oc_core and the store, so a disable in the daemon sends its
 * LOC_CANCEL at once. Every command is written to the audit log (event
 * OC_CORE_AUDIT_ADMIN, "u<uid> <command line>").
 *
 *   status
 *   net init [--period S]                  the network key pair (first setup)
 *   cell add ID NAME [--mode part15|part97] [--list N]
 *   cell mode ID part15|part97             the cell reconnects to take it
 *   cell revoke ID | cell list
 *   sub add [NUMBER] | sub issue NUMBER [--valid-h H] | sub disable NUMBER | sub list
 *   loc | cdr [N] | audit [N]
 *   list set ID MHZ[:fixed],...|none | list show
 *   import-ocb-hss FILE                    (--offline only) ocbench's bench HSS
 *
 * Numbers are taken in any full form (+883-1-606-555-01234) and shown in
 * the canonical one (+883160655501234). */
#ifndef OC_ADMIN_H
#define OC_ADMIN_H

#include <stddef.h>
#include <stdint.h>

#include "oc_core.h"
#include "oc_sql.h"

typedef struct {
    char  *p; /* NUL-terminated */
    size_t n, cap;
} oc_buf_t;

void oc_buf_printf(oc_buf_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void oc_buf_free(oc_buf_t *b);

typedef struct {
    oc_sql_t              *sql;
    const oc_core_route_t *route;
    const oc_core_cfg_t   *cfg;
    oc_core_t             *core; /* the daemon's; NULL offline (then a core of its own, once the key exists) */
    void (*random)(uint8_t *out, size_t n);
    uint64_t (*now_us)(void);                       /* the daemon's oc_core clock */
    void (*drop_cell)(void *ctx, uint32_t cell_id); /* the daemon closes the cell's link; NULL offline */
    void    *ctx;
    uint32_t uid; /* who asked (the socket peer), for the audit record */
    /* private */
    oc_core_t own;
    int       have_own;
} oc_admin_t;

/* Runs one command: argv[0] is its first word ("sub"). Output goes to out.
 * 0 done, 1 refused or failed (out says why), 2 not a command (out has the
 * usage). */
int oc_admin_run(oc_admin_t *a, int argc, char **argv, oc_buf_t *out);

/* "917.25,922.25:fixed" (MHz on the 915 grid, at most OC_SIG_CHAN_MAX, no
 * spaces), or "" / "none" for an empty list. 0, or -1 with err set. */
int oc_chan_parse(const char *text, oc_sig_chan_list_t *out, char *err, size_t cap);

/* ocbench's text HSS (tools/ocbench/ocb_hss.h in opencell-firmware before
 * network core 2): its network key pair and its subscribers, with their
 * TMIDs, K, OPc and SQN, so activated terminals keep working without a new
 * QR code. All or nothing. Tokens are not carried over (their ids have no
 * block index, spec §14.3). 0 or 1, as oc_admin_run. */
int oc_import_ocb_hss(oc_admin_t *a, const char *path, oc_buf_t *out);

#endif
```

Create `oc/oc_admin.c`:
```c
#define _GNU_SOURCE
#include "oc_admin.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "oc_phy.h"
#include "oc_sig_keys.h"
#include "oc_sig_qr.h"
#include "oc_log.h"

/* ---- output ---- */

void oc_buf_printf(oc_buf_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (b->n + (size_t)n + 1u > b->cap) {
        size_t cap = (b->cap == 0 ? 1024u : b->cap);
        while (cap < b->n + (size_t)n + 1u) cap *= 2u;
        char *p = realloc(b->p, cap);
        if (p == NULL) return;
        b->p = p;
        b->cap = cap;
    }
    va_start(ap, fmt);
    vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    b->n += (size_t)n;
}

void oc_buf_free(oc_buf_t *b)
{
    free(b->p);
    memset(b, 0, sizeof(*b));
}

/* ---- helpers ---- */

static const char USAGE[] =
    "commands: status | net init [--period S] | cell add ID NAME [--mode part15|part97] [--list N]\n"
    "  | cell mode ID part15|part97 | cell revoke ID | cell list | sub add [NUMBER]\n"
    "  | sub issue NUMBER [--valid-h H] | sub disable NUMBER | sub list | loc | cdr [N] | audit [N]\n"
    "  | list set ID MHZ[:fixed],...|none | list show | import-ocb-hss FILE (--offline only)\n";

static oc_core_store_t store(oc_admin_t *a) { return oc_sql_store(a->sql); }

static uint64_t now_us(oc_admin_t *a)
{
    if (a->now_us != NULL) return a->now_us();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int o_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    (void)link;
    (void)m;
    return -1; /* offline: no cell has a link */
}
static void o_random(void *c, uint8_t *out, size_t n) { ((oc_admin_t *)c)->random(out, n); }
static uint32_t o_unix(void *c)
{
    (void)c;
    return (uint32_t)time(NULL);
}

/* The daemon's core, or (offline) one of our own over the same store. */
static oc_core_t *core(oc_admin_t *a, oc_buf_t *out)
{
    if (a->core != NULL) return a->core;
    if (!a->have_own) {
        const oc_core_io_t io = { a, o_send, NULL, o_random, o_unix, oc_log_line };
        oc_core_store_t st = store(a);
        if (oc_core_init(&a->own, &io, &st, a->route, a->cfg) != 0) {
            oc_buf_printf(out, "no network key %u in the database: run `oc-core admin --offline ... net init` first\n",
                          a->cfg->key_id);
            return NULL;
        }
        a->have_own = 1;
    }
    return &a->own;
}

static int number_arg(const char *text, uint8_t out[OC_SIG_NUMBER_LEN], oc_buf_t *o)
{
    if (oc_sig_number_normalize(text, strlen(text), NULL, out) != 0) {
        oc_buf_printf(o, "'%s': not a full OpenCell number (e.g. +883-1-606-555-01234)\n", text);
        return -1;
    }
    return 0;
}

static const char *show(const uint8_t n[OC_SIG_NUMBER_LEN], char out[OC_SIG_NUMBER_TEXT + OC_SIG_NUMBER_SHOW + 4])
{
    char t[OC_SIG_NUMBER_TEXT], f[OC_SIG_NUMBER_SHOW];
    oc_sig_number_to_text(n, t);
    if (oc_sig_number_format(n, f, sizeof(f)) == 0) strcpy(f, t);
    snprintf(out, OC_SIG_NUMBER_TEXT + OC_SIG_NUMBER_SHOW + 4, "%s (%s)", t, f);
    return out;
}

/* "--flag VALUE" as a number lo..hi. 0 not given, 1 given, -1 bad. */
static int opt_num(int argc, char **argv, const char *flag, long lo, long hi, long *v, oc_buf_t *o)
{
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], flag) != 0) continue;
        char *end;
        long x = i + 1 < argc ? strtol(argv[i + 1], &end, 10) : 0;
        if (i + 1 >= argc || *end != '\0' || end == argv[i + 1] || x < lo || x > hi) {
            oc_buf_printf(o, "%s: a number %ld-%ld\n", flag, lo, hi);
            return -1;
        }
        *v = x;
        return 1;
    }
    return 0;
}

static const char *opt_str(int argc, char **argv, const char *flag)
{
    for (int i = 0; i + 1 < argc; i++) {
        if (strcmp(argv[i], flag) == 0) return argv[i + 1];
    }
    return NULL;
}

static int mode_arg(const char *s, uint8_t *mode, oc_buf_t *o)
{
    if (strcmp(s, "part15") == 0) *mode = OC_SIG_MODE_PART15;
    else if (strcmp(s, "part97") == 0) *mode = OC_SIG_MODE_PART97;
    else {
        oc_buf_printf(o, "mode '%s': part15 or part97\n", s);
        return -1;
    }
    return 0;
}

static const char *mode_name(int m) { return m == OC_SIG_MODE_PART97 ? "part97" : "part15"; }

static int linked(oc_admin_t *a, uint32_t cell_id)
{
    for (unsigned i = 0; a->core != NULL && i < OC_CORE_LINKS; i++) {
        if (a->core->links[i].used && a->core->links[i].cell_id == cell_id) return 1;
    }
    return 0;
}

static sqlite3_stmt *q(oc_admin_t *a, const char *sql)
{
    sqlite3_stmt *st = NULL;
    sqlite3_prepare_v2(oc_sql_db(a->sql), sql, -1, &st, NULL);
    return st;
}

static long count(oc_admin_t *a, const char *sql)
{
    sqlite3_stmt *st = q(a, sql);
    long n = st != NULL && sqlite3_step(st) == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

static const char *text_col(sqlite3_stmt *st, int col)
{
    const char *t = (const char *)sqlite3_column_text(st, col);
    return t != NULL ? t : "-";
}

/* ---- commands ---- */

static int cmd_status(oc_admin_t *a, oc_buf_t *o)
{
    oc_core_netkey_t key;
    oc_core_store_t st = store(a);
    int have_key = st.netkey_get(st.ctx, a->cfg->key_id, &key) == 0;
    oc_buf_printf(o, "core %u, network key %u%s, schema v%d, %s\n", a->cfg->core_id, a->cfg->key_id,
                  have_key ? "" : " (missing: net init)", oc_sql_version(a->sql),
                  a->core != NULL ? "running" : "offline");
    int calls = 0, links = 0;
    if (a->core != NULL) {
        for (unsigned i = 0; i < OC_CORE_CALLS; i++) calls += a->core->calls[i].used != 0;
        for (unsigned i = 0; i < OC_CORE_LINKS; i++) links += a->core->links[i].used != 0;
    }
    oc_buf_printf(o, "subscribers %ld (%ld activated, %ld disabled), locations %ld, calls %d, links %d\n",
                  count(a, "SELECT count(*) FROM subscriber"),
                  count(a, "SELECT count(*) FROM subscriber WHERE activated = 1"),
                  count(a, "SELECT count(*) FROM subscriber WHERE state = 2"),
                  count(a, "SELECT count(*) FROM location"), calls, links);
    sqlite3_stmt *s = q(a, "SELECT cell_id, name, mode, enabled, list_id, last_seen FROM cell ORDER BY cell_id");
    while (s != NULL && sqlite3_step(s) == SQLITE_ROW) {
        uint32_t id = (uint32_t)sqlite3_column_int64(s, 0);
        long ago = (long)time(NULL) - (long)sqlite3_column_int64(s, 5);
        oc_buf_printf(o, "cell %u \"%s\": %s, %s, list %d, %s", id, text_col(s, 1), mode_name(sqlite3_column_int(s, 2)),
                      sqlite3_column_int(s, 3) ? "enabled" : "revoked", sqlite3_column_int(s, 4),
                      linked(a, id) ? "linked" : "not linked");
        if (sqlite3_column_int64(s, 5) != 0) oc_buf_printf(o, ", last HELLO %ld s ago", ago);
        oc_buf_printf(o, "\n");
    }
    sqlite3_finalize(s);
    if (oc_sql_unseal_failures(a->sql) != 0) {
        oc_buf_printf(o, "WARNING: %u sealed values did not open (damaged rows): they read as missing\n",
                      oc_sql_unseal_failures(a->sql));
    }
    return 0;
}

static int cmd_net(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    long period = 1800;
    if (argc < 2 || strcmp(argv[1], "init") != 0) return 2;
    if (opt_num(argc, argv, "--period", 60, 65535, &period, o) < 0) return 1;
    oc_core_store_t st = store(a);
    oc_core_netkey_t key;
    if (st.netkey_get(st.ctx, a->cfg->key_id, &key) == 0) {
        oc_buf_printf(o, "network key %u exists already: nothing done\n", a->cfg->key_id);
        return 1;
    }
    uint8_t r[32];
    a->random(r, sizeof(r));
    int rc = oc_core_netkey_new(&st, a->cfg->key_id, (uint16_t)period, r, (uint32_t)time(NULL));
    oc_sig_wipe(r, sizeof(r));
    if (rc != 0) {
        oc_buf_printf(o, "can't store the network key\n");
        return 1;
    }
    oc_buf_printf(o, "network key %u made, registration period %ld s\n", a->cfg->key_id, period);
    return 0;
}

static int cmd_cell(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    oc_core_t *k;
    oc_core_store_t st = store(a);
    oc_core_cell_t c;
    char *end;
    if (argc >= 2 && strcmp(argv[1], "list") == 0) return cmd_status(a, o);
    if (argc < 3) return 2;
    unsigned long id = strtoul(argv[2], &end, 0);
    if (*end != '\0' || id == 0 || id > 0xFFFFFFFFul) {
        oc_buf_printf(o, "cell id '%s': 1-4294967295\n", argv[2]);
        return 1;
    }
    if (strcmp(argv[1], "add") == 0 && argc >= 4) {
        uint8_t mode = OC_SIG_MODE_PART15;
        long list = 0;
        const char *m = opt_str(argc, argv, "--mode");
        if ((m != NULL && mode_arg(m, &mode, o) != 0) || opt_num(argc, argv, "--list", 0, 65535, &list, o) < 0) return 1;
        if (strlen(argv[3]) >= sizeof(c.name) || argv[3][0] == '-') {
            oc_buf_printf(o, "cell name '%s': 1-%zu characters\n", argv[3], sizeof(c.name) - 1u);
            return 1;
        }
        if ((k = core(a, o)) == NULL) return 1;
        if (oc_core_cell_add(k, (uint32_t)id, argv[3], mode, (uint16_t)list) != 0) {
            oc_buf_printf(o, "cell %lu exists already (or the store failed)\n", id);
            return 1;
        }
        oc_buf_printf(o, "cell %lu \"%s\" added: %s, list %ld\n", id, argv[3], mode_name(mode), list);
        return 0;
    }
    if (st.cell_get(st.ctx, (uint32_t)id, &c) != 0) {
        oc_buf_printf(o, "no cell %lu\n", id);
        return 1;
    }
    if (strcmp(argv[1], "mode") == 0 && argc == 4) {
        if (mode_arg(argv[3], &c.mode, o) != 0) return 1;
        if (st.cell_put(st.ctx, &c) != 0) {
            oc_buf_printf(o, "store failed\n");
            return 1;
        }
        if (a->drop_cell != NULL && linked(a, (uint32_t)id)) {
            a->drop_cell(a->ctx, (uint32_t)id);
            oc_buf_printf(o, "cell %lu: %s; its link was dropped, it takes the mode when it reconnects\n", id, argv[3]);
        } else {
            oc_buf_printf(o, "cell %lu: %s, from its next HELLO\n", id, argv[3]);
        }
        return 0;
    }
    if (strcmp(argv[1], "revoke") == 0 && argc == 3) {
        if ((k = core(a, o)) == NULL) return 1;
        if (oc_core_cell_revoke(k, (uint32_t)id, now_us(a)) != 0) {
            oc_buf_printf(o, "store failed\n");
            return 1;
        }
        oc_buf_printf(o, "cell %lu revoked: its link is dropped and its HELLO refused\n", id);
        return 0;
    }
    return 2;
}

static int cmd_sub(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    oc_core_t *k;
    uint8_t n[OC_SIG_NUMBER_LEN], got[OC_SIG_NUMBER_LEN];
    char sh[OC_SIG_NUMBER_TEXT + OC_SIG_NUMBER_SHOW + 4];
    if (argc < 2) return 2;
    if (strcmp(argv[1], "list") == 0 && argc == 2) {
        sqlite3_stmt *s = q(a, "SELECT number, state, activated, tmid, sqn FROM subscriber ORDER BY number");
        while (s != NULL && sqlite3_step(s) == SQLITE_ROW) {
            oc_buf_printf(o, "%s  %s  %s  tmid %08x  sqn %lld\n", text_col(s, 0),
                          sqlite3_column_int(s, 1) == OC_CORE_SUB_DISABLED ? "disabled" : "active  ",
                          sqlite3_column_int(s, 2) ? "activated    " : "not activated",
                          (unsigned)sqlite3_column_int64(s, 3), (long long)sqlite3_column_int64(s, 4));
        }
        sqlite3_finalize(s);
        return 0;
    }
    if (strcmp(argv[1], "add") == 0 && argc <= 3) {
        if (argc == 3 && number_arg(argv[2], n, o) != 0) return 1;
        if ((k = core(a, o)) == NULL) return 1;
        if (oc_core_sub_add(k, argc == 3 ? n : NULL, got) != 0) {
            oc_buf_printf(o, "refused: not in a block this core is home for, reserved, already a subscriber, "
                             "or the store failed\n");
            return 1;
        }
        oc_buf_printf(o, "subscriber %s added\n", show(got, sh));
        return 0;
    }
    if (argc < 3) return 2;
    if (number_arg(argv[2], n, o) != 0) return 1;
    if (strcmp(argv[1], "issue") == 0) {
        long hours = 24;
        oc_sig_qr_t qr;
        char text[OC_SIG_QR_TEXT + 1];
        if (opt_num(argc, argv, "--valid-h", 1, 720, &hours, o) < 0) return 1;
        if ((k = core(a, o)) == NULL) return 1;
        if (oc_core_token_issue(k, n, (uint32_t)hours * 3600u, &qr) != 0) {
            oc_buf_printf(o, "refused: %s is not an active subscriber of a block this core is home for\n", argv[2]);
            return 1;
        }
        oc_sig_qr_format(&qr, text, sizeof(text));
        oc_buf_printf(o, "activation code for %s, valid %ld h (any older unused code is void):\n%s\n", show(n, sh),
                      hours, text);
        return 0;
    }
    if (strcmp(argv[1], "disable") == 0 && argc == 3) {
        if ((k = core(a, o)) == NULL) return 1;
        if (oc_core_sub_disable(k, n, now_us(a)) != 0) {
            oc_buf_printf(o, "refused: no such subscriber, or the store failed\n");
            return 1;
        }
        oc_buf_printf(o, "%s disabled: its codes are void and its cell was told\n", show(n, sh));
        return 0;
    }
    return 2;
}

static int cmd_loc(oc_admin_t *a, oc_buf_t *o)
{
    sqlite3_stmt *s = q(a, "SELECT number, cell_id, tmid, expires FROM location ORDER BY number");
    long now = (long)time(NULL);
    while (s != NULL && sqlite3_step(s) == SQLITE_ROW) {
        long left = (long)sqlite3_column_int64(s, 3) - now;
        oc_buf_printf(o, "%s  cell %u  tmid %08x  ", text_col(s, 0), (unsigned)sqlite3_column_int64(s, 1),
                      (unsigned)sqlite3_column_int64(s, 2));
        if (left > 0) oc_buf_printf(o, "expires in %ld s\n", left);
        else oc_buf_printf(o, "expired\n");
    }
    sqlite3_finalize(s);
    return 0;
}

static long last_n(int argc, char **argv, oc_buf_t *o)
{
    char *end;
    if (argc < 2) return 20;
    long n = strtol(argv[1], &end, 10);
    if (*end != '\0' || n < 1 || n > 10000) {
        oc_buf_printf(o, "'%s': a count 1-10000\n", argv[1]);
        return -1;
    }
    return n;
}

static int cmd_cdr(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    long n = last_n(argc, argv, o);
    if (n < 0) return 1;
    sqlite3_stmt *s = q(a, "SELECT id, caller, called, cell_a, cell_b, setup, answer, \"end\", cause FROM cdr"
                           " ORDER BY id DESC LIMIT ?");
    if (s != NULL) sqlite3_bind_int64(s, 1, n);
    while (s != NULL && sqlite3_step(s) == SQLITE_ROW) {
        long setup = (long)sqlite3_column_int64(s, 5), ans = (long)sqlite3_column_int64(s, 6);
        long end = (long)sqlite3_column_int64(s, 7);
        oc_buf_printf(o, "#%lld %s -> %s  cells %u -> %u  %s, %ld s, cause %d\n", (long long)sqlite3_column_int64(s, 0),
                      text_col(s, 1), text_col(s, 2), (unsigned)sqlite3_column_int64(s, 3),
                      (unsigned)sqlite3_column_int64(s, 4), ans != 0 ? "answered" : "not answered",
                      end > setup ? end - setup : 0, sqlite3_column_int(s, 8));
    }
    sqlite3_finalize(s);
    return 0;
}

static const char *event_name(int e)
{
    static const char *const names[] = { "?",           "ACTIVATE",    "ACT_FAIL",   "REGISTER",
                                         "AUTH_FAIL",   "RESYNC",      "LOC_CANCEL", "TOKEN_ISSUE",
                                         "SUB_DISABLE", "CELL_REJECT", "ADMIN" };
    return e >= 0 && e < (int)(sizeof(names) / sizeof(names[0])) ? names[e] : "?";
}

static int cmd_audit(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    long n = last_n(argc, argv, o);
    if (n < 0) return 1;
    sqlite3_stmt *s = q(a, "SELECT ts, event, number, tmid, cell_id, detail FROM audit ORDER BY id DESC LIMIT ?");
    if (s != NULL) sqlite3_bind_int64(s, 1, n);
    while (s != NULL && sqlite3_step(s) == SQLITE_ROW) {
        time_t ts = (time_t)sqlite3_column_int64(s, 0);
        char when[32];
        strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", gmtime(&ts));
        oc_buf_printf(o, "%s  %-11s  %s  tmid %08x  cell %u  %s\n", when, event_name(sqlite3_column_int(s, 1)),
                      text_col(s, 2), (unsigned)sqlite3_column_int64(s, 3), (unsigned)sqlite3_column_int64(s, 4),
                      text_col(s, 5));
    }
    sqlite3_finalize(s);
    return 0;
}

static void list_line(oc_buf_t *o, long id, const oc_sig_chan_list_t *l)
{
    oc_buf_printf(o, "list %ld: version %u,", id, l->ver);
    for (uint8_t i = 0; i < l->count; i++) {
        oc_buf_printf(o, " %u.%02u%s", (unsigned)(l->freq_hz[i] / 1000000u), (unsigned)(l->freq_hz[i] % 1000000u / 10000u),
                      (l->flags[i] & OC_SIG_CHAN_FIXED) ? ":fixed" : "");
    }
    oc_buf_printf(o, "%s\n", l->count == 0 ? " (empty)" : "");
}

static int cmd_list(oc_admin_t *a, int argc, char **argv, oc_buf_t *o)
{
    oc_core_store_t st = store(a);
    oc_sig_chan_list_t l;
    char err[128], *end;
    if (argc == 2 && strcmp(argv[1], "show") == 0) {
        sqlite3_stmt *s = q(a, "SELECT list_id FROM chan_list ORDER BY list_id");
        while (s != NULL && sqlite3_step(s) == SQLITE_ROW) {
            long id = (long)sqlite3_column_int64(s, 0);
            if (st.list_get(st.ctx, (uint16_t)id, &l) == 0) list_line(o, id, &l);
        }
        sqlite3_finalize(s);
        return 0;
    }
    if (argc != 4 || strcmp(argv[1], "set") != 0) return 2;
    long id = strtol(argv[2], &end, 10);
    if (*end != '\0' || id < 1 || id > 65535) {
        oc_buf_printf(o, "list id '%s': 1-65535\n", argv[2]);
        return 1;
    }
    if (oc_chan_parse(argv[3], &l, err, sizeof(err)) != 0) {
        oc_buf_printf(o, "%s\n", err);
        return 1;
    }
    oc_core_t *k = core(a, o);
    if (k == NULL) return 1;
    if (oc_core_chan_list_set(k, (uint16_t)id, &l, now_us(a)) < 0) {
        oc_buf_printf(o, "store failed\n");
        return 1;
    }
    st.list_get(st.ctx, (uint16_t)id, &l);
    list_line(o, id, &l);
    return 0;
}

/* "917.25" -> 917250000 exactly: at most 3 decimals. */
static int parse_mhz(const char *s, size_t len, uint32_t *hz)
{
    uint32_t whole = 0, frac = 0, scale = 1000000u;
    size_t i = 0;
    if (len == 0) return -1;
    for (; i < len && s[i] != '.'; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        whole = whole * 10u + (uint32_t)(s[i] - '0');
        if (whole > 999u) return -1;
    }
    if (i < len) {
        if (++i == len || len - i > 3) return -1;
        for (; i < len; i++) {
            if (s[i] < '0' || s[i] > '9') return -1;
            scale /= 10u;
            frac += (uint32_t)(s[i] - '0') * scale;
        }
    }
    *hz = whole * 1000000u + frac;
    return 0;
}

int oc_chan_parse(const char *text, oc_sig_chan_list_t *out, char *err, size_t cap)
{
    memset(out, 0, sizeof(*out));
    if (text[0] == '\0' || strcmp(text, "none") == 0) return 0;
    for (const char *c = text; *c != '\0'; c++) {
        if (isspace((unsigned char)*c)) {
            snprintf(err, cap, "'%s': no spaces (e.g. 917.25,922.25:fixed)", text);
            return -1;
        }
    }
    const char *p = text;
    for (;;) {
        const char *end = strchr(p, ',');
        size_t len = end != NULL ? (size_t)(end - p) : strlen(p), num = len;
        uint8_t flags = 0;
        const char *colon = memchr(p, ':', len);
        if (colon != NULL) {
            num = (size_t)(colon - p);
            if (len - num != 6 || strncmp(colon, ":fixed", 6) != 0) {
                snprintf(err, cap, "'%.*s': only ':fixed' may follow a frequency", (int)len, p);
                return -1;
            }
            flags = OC_SIG_CHAN_FIXED;
        }
        uint32_t hz;
        if (parse_mhz(p, num, &hz) != 0 || oc_channel_of_freq(OC_BAND_915, hz) == OC_INVALID_CHANNEL) {
            snprintf(err, cap, "'%.*s' is not a 915 grid channel (902.25-927.75 MHz, 0.5 MHz steps)", (int)num, p);
            return -1;
        }
        if (out->count == OC_SIG_CHAN_MAX) {
            snprintf(err, cap, "more than %u entries", OC_SIG_CHAN_MAX);
            return -1;
        }
        out->freq_hz[out->count] = hz;
        out->flags[out->count++] = flags;
        if (end == NULL) return 0;
        p = end + 1;
    }
}

/* ---- dispatch and audit ---- */

static void audit(oc_admin_t *a, int argc, char **argv, int rc)
{
    oc_core_audit_t r;
    oc_core_store_t st = store(a);
    memset(&r, 0, sizeof(r));
    r.ts = (uint32_t)time(NULL);
    r.event = OC_CORE_AUDIT_ADMIN;
    int n = snprintf(r.detail, sizeof(r.detail), "u%u%s", a->uid, rc == 0 ? "" : " (refused)");
    for (int i = 0; i < argc && n > 0 && (size_t)n < sizeof(r.detail); i++) {
        n += snprintf(r.detail + n, sizeof(r.detail) - (size_t)n, " %s", argv[i]);
    }
    if (st.audit_add(st.ctx, &r) != 0) oc_log(OC_LOG_ERR, "admin: audit write FAILED");
}

int oc_admin_run(oc_admin_t *a, int argc, char **argv, oc_buf_t *out)
{
    int rc = 2;
    if (argc < 1) {
        oc_buf_printf(out, "%s", USAGE);
        return 2;
    }
    const char *c = argv[0];
    if (strcmp(c, "status") == 0 && argc == 1) rc = cmd_status(a, out);
    else if (strcmp(c, "net") == 0) rc = cmd_net(a, argc, argv, out);
    else if (strcmp(c, "cell") == 0) rc = cmd_cell(a, argc, argv, out);
    else if (strcmp(c, "sub") == 0) rc = cmd_sub(a, argc, argv, out);
    else if (strcmp(c, "loc") == 0 && argc == 1) rc = cmd_loc(a, out);
    else if (strcmp(c, "cdr") == 0 && argc <= 2) rc = cmd_cdr(a, argc, argv, out);
    else if (strcmp(c, "audit") == 0 && argc <= 2) rc = cmd_audit(a, argc, argv, out);
    else if (strcmp(c, "list") == 0) rc = cmd_list(a, argc, argv, out);
    else if (strcmp(c, "import-ocb-hss") == 0 && argc == 2) {
        if (a->core != NULL) {
            oc_buf_printf(out, "import-ocb-hss runs only with --offline, on a stopped core\n");
            rc = 1;
        } else {
            rc = oc_import_ocb_hss(a, argv[1], out);
        }
    }
    if (rc == 2) oc_buf_printf(out, "%s", USAGE);
    else audit(a, argc, argv, rc);
    return rc;
}
```

Create `oc/oc_import.c`:
```c
#define _GNU_SOURCE
/* import-ocb-hss: ocbench's text HSS into the core's database. The file's
 * lines (ocb_hss.h, as ocbench wrote them):
 *   network key_id=1 sk=<64 hex> pk=<64 hex> mode=part15 period=1800
 *   sub number=+883160655501234 token_id=<16 hex> token_secret=<32 hex> expiry=<unix s>
 *       used=0|1 tmid=<8 hex> activated=0|1 k=<32 hex> opc=<32 hex> sqn=<12 hex>   (one line)
 * Everything is checked before anything is written, and then written in
 * one transaction. */
#include "oc_admin.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "oc_sig_crypto.h"
#include "oc_sig_keys.h"

#define IMPORT_SUBS 64u

typedef struct {
    uint8_t  number[OC_SIG_NUMBER_LEN];
    uint32_t tmid;
    int      activated;
    uint8_t  k[16], opc[16], sqn[6];
} imp_sub_t;

typedef struct {
    int       have_net;
    uint16_t  key_id, period;
    uint8_t   sk[32], pk[32];
    imp_sub_t sub[IMPORT_SUBS];
    unsigned  n;
} imp_t;

static int hex(const char *s, uint8_t *b, size_t n)
{
    if (strlen(s) != 2u * n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2u * i, "%2x", &v) != 1) return -1;
        b[i] = (uint8_t)v;
    }
    return 0;
}

static int num(const char *s, unsigned long max, unsigned long *out, int base)
{
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, base);
    if (errno != 0 || *s == '\0' || *end != '\0' || v > max) return -1;
    *out = v;
    return 0;
}

/* One line's fields: 0, or -1 (an unknown key, a bad value, a field missing). */
static int parse_line(imp_t *m, char *kind, char *save)
{
    unsigned seen = 0, want;
    unsigned long v;
    imp_sub_t s;
    memset(&s, 0, sizeof(s));
    int net = strcmp(kind, "network") == 0;
    if (!net && strcmp(kind, "sub") != 0) return -1;
    for (char *tok = strtok_r(NULL, " \t\n", &save); tok != NULL; tok = strtok_r(NULL, " \t\n", &save)) {
        char *val = strchr(tok, '=');
        if (val == NULL) return -1;
        *val++ = '\0';
        if (net && strcmp(tok, "key_id") == 0 && num(val, 65535, &v, 10) == 0) m->key_id = (uint16_t)v, seen |= 1;
        else if (net && strcmp(tok, "sk") == 0 && hex(val, m->sk, 32) == 0) seen |= 2;
        else if (net && strcmp(tok, "pk") == 0 && hex(val, m->pk, 32) == 0) seen |= 4;
        else if (net && strcmp(tok, "mode") == 0 && (strcmp(val, "part15") == 0 || strcmp(val, "part97") == 0)) seen |= 8;
        else if (net && strcmp(tok, "period") == 0 && num(val, 65535, &v, 10) == 0) m->period = (uint16_t)v, seen |= 16;
        else if (!net && strcmp(tok, "number") == 0 && oc_sig_number_to_bcd(val, strlen(val), s.number) == 0) seen |= 1;
        else if (!net && strcmp(tok, "tmid") == 0 && num(val, 0xFFFFFFFFul, &v, 16) == 0) s.tmid = (uint32_t)v, seen |= 2;
        else if (!net && strcmp(tok, "activated") == 0 && num(val, 1, &v, 10) == 0) s.activated = (int)v, seen |= 4;
        else if (!net && strcmp(tok, "k") == 0 && hex(val, s.k, 16) == 0) seen |= 8;
        else if (!net && strcmp(tok, "opc") == 0 && hex(val, s.opc, 16) == 0) seen |= 16;
        else if (!net && strcmp(tok, "sqn") == 0 && hex(val, s.sqn, 6) == 0) seen |= 32;
        else if (!net && (strcmp(tok, "token_id") == 0 || strcmp(tok, "token_secret") == 0 ||
                          strcmp(tok, "expiry") == 0 || strcmp(tok, "used") == 0)) seen |= 0; /* not carried over */
        else return -1;
    }
    want = net ? 31u : 63u;
    if (seen != want) return -1;
    if (net) {
        if (m->have_net) return -1; /* one network line */
        m->have_net = 1;
    } else {
        if (m->n >= IMPORT_SUBS) return -1;
        m->sub[m->n++] = s;
    }
    return 0;
}

int oc_import_ocb_hss(oc_admin_t *a, const char *path, oc_buf_t *o)
{
    static imp_t m;
    char line[512];
    unsigned ln = 0;
    memset(&m, 0, sizeof(m));
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        oc_buf_printf(o, "%s: %s\n", path, strerror(errno));
        return 1;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *save = NULL, *kind;
        ln++;
        kind = strtok_r(line, " \t\n", &save);
        if (kind == NULL || kind[0] == '#') continue;
        if (parse_line(&m, kind, save) != 0) {
            fclose(f);
            oc_buf_printf(o, "%s:%u: not an ocbench HSS line (nothing imported)\n", path, ln);
            return 1;
        }
    }
    fclose(f);

    /* checks, before anything is written */
    oc_core_store_t st = oc_sql_store(a->sql);
    oc_core_netkey_t have;
    uint8_t pk[32];
    if (!m.have_net || oc_sig_x25519_public(m.sk, pk) != 0 || memcmp(pk, m.pk, 32) != 0) {
        oc_buf_printf(o, "%s: no network line, or its key pair does not match (nothing imported)\n", path);
        return 1;
    }
    if (m.key_id != a->cfg->key_id) {
        oc_buf_printf(o, "%s: network key %u, but key_id = %u in oc-core.conf (nothing imported)\n", path, m.key_id,
                      a->cfg->key_id);
        return 1;
    }
    int key_there = st.netkey_get(st.ctx, m.key_id, &have) == 0;
    if (key_there && memcmp(have.pk, m.pk, 32) != 0) {
        oc_buf_printf(o, "a different network key %u is in the database already (nothing imported)\n", m.key_id);
        return 1;
    }
    for (unsigned i = 0; i < m.n; i++) {
        oc_core_sub_t x;
        char t[OC_SIG_NUMBER_TEXT];
        const uint8_t *n = m.sub[i].number;
        oc_sig_number_to_text(n, t);
        if (!oc_sig_number_valid(n) || oc_core_number_reserved(n) ||
            !oc_core_route_home(a->route, oc_core_route_find(a->route, n))) {
            oc_buf_printf(o, "%s: not a number of a block this core is home for, or reserved (nothing imported)\n", t);
            return 1;
        }
        int twice = 0;
        for (unsigned j = 0; j < i; j++) {
            twice |= memcmp(m.sub[j].number, n, OC_SIG_NUMBER_LEN) == 0 ||
                     (m.sub[i].activated && m.sub[j].activated && m.sub[j].tmid == m.sub[i].tmid);
        }
        if (twice || st.sub_get(st.ctx, n, &x) == 0) {
            oc_buf_printf(o, "%s: already a subscriber, or twice in the file (nothing imported)\n", t);
            return 1;
        }
        if (m.sub[i].activated && (m.sub[i].tmid == 0 || st.sub_by_tmid(st.ctx, m.sub[i].tmid, &x) == 0)) {
            oc_buf_printf(o, "%s: terminal %08x is bound already, or none (nothing imported)\n", t, m.sub[i].tmid);
            return 1;
        }
    }

    /* one transaction */
    uint32_t now = (uint32_t)time(NULL);
    st.begin(st.ctx);
    if (!key_there) {
        oc_core_netkey_t key;
        memset(&key, 0, sizeof(key));
        key.key_id = m.key_id;
        memcpy(key.sk, m.sk, 32);
        memcpy(key.pk, m.pk, 32);
        key.period_s = m.period;
        key.created = now;
        st.netkey_put(st.ctx, &key);
        oc_sig_wipe(&key, sizeof(key));
    }
    for (unsigned i = 0; i < m.n; i++) {
        oc_core_sub_t x;
        memset(&x, 0, sizeof(x));
        memcpy(x.number, m.sub[i].number, OC_SIG_NUMBER_LEN);
        x.state = OC_CORE_SUB_ACTIVE;
        if (m.sub[i].activated) {
            x.activated = 1;
            x.tmid = m.sub[i].tmid;
            memcpy(x.k, m.sub[i].k, 16);
            memcpy(x.opc, m.sub[i].opc, 16);
            x.sqn = oc_sig_sqn_get(m.sub[i].sqn);
        }
        x.created = x.updated = now;
        st.sub_put(st.ctx, &x);
    }
    int rc = st.commit(st.ctx);
    oc_sig_wipe(m.sk, sizeof(m.sk));
    for (unsigned i = 0; i < m.n; i++) {
        oc_sig_wipe(m.sub[i].k, sizeof(m.sub[i].k));
        oc_sig_wipe(m.sub[i].opc, sizeof(m.sub[i].opc));
    }
    if (rc != 0) {
        oc_buf_printf(o, "store failed: nothing imported\n");
        return 1;
    }
    oc_buf_printf(o, "network key %u %s\n", m.key_id, key_there ? "was there already" : "imported");
    for (unsigned i = 0; i < m.n; i++) {
        char t[OC_SIG_NUMBER_TEXT];
        oc_sig_number_to_text(m.sub[i].number, t);
        if (m.sub[i].activated) {
            oc_buf_printf(o, "%s  terminal %08x  sqn %llu  imported\n", t, m.sub[i].tmid,
                          (unsigned long long)oc_sig_sqn_get(m.sub[i].sqn));
        } else {
            oc_buf_printf(o, "%s  not activated: give it a code with `oc-core admin sub issue %s`\n", t, t);
        }
    }
    return 0;
}
```

- [ ] **Step 5: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build --target test_oc_admin 2>&1 | grep -E "error|warning"; build/tests/test_oc_admin | tail -3`
Expected: no compiler output, then `5 Tests 0 Failures 0 Ignored` and `OK` (the offline core's own log lines, `<6>channel list 3: …`, come first).

- [ ] **Step 6: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_core+4` (12 when validated).

- [ ] **Step 7: Commit**

```bash
cd /home/devin/Documents/opencell/core
git add oc_core/include/oc_core_store.h oc/CMakeLists.txt oc/include/oc_admin.h oc/oc_admin.c oc/oc_import.c \
        tests/CMakeLists.txt tests/test_oc_admin.c
git commit -m "oc-core admin commands (status, net, cell, sub, loc, cdr, audit, list), each audited; ocbench HSS import

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 6: The `oc-core` program: daemon, admin client, `--offline`; its unit and its process test

**Repo:** `opencell-core`, branch `oc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 5.

The daemon (spec §17.5): one thread, one `poll()` loop over the cell socket, the admin socket and each cell's link; frames go to `oc_core_rx`, `oc_core_tick` runs at least every 100 ms, and what `oc_core` sends goes out through `oc_conn`. When `oc_core` drops a link (a refused HELLO, silence, a revoked cell) the program closes it; when a peer vanishes the program tells `oc_core` (`oc_core_link_down`), after the call in progress returns. The admin client connects to the admin socket; `--offline` opens the database itself (and is refused while the daemon holds it). SIGTERM stops the daemon cleanly (sockets removed, database closed). A tiny test cell, `tool_oc_hello`, lets the process test speak HELLO.

**Files:**
- Create: `oc/oc_core_main.c`, `tests/tool_oc_hello.c`, `tests/test_oc_core_proc.sh`, `dist/systemd/oc-core.service`, `dist/oc-core.conf.example`
- Modify: `oc/CMakeLists.txt`, `tests/CMakeLists.txt`

**Interfaces:**
- Consumes: everything in `oc_util` (Task 2) and `oc_store` (Tasks 3–5); `oc_core_*` (plan 1).
- Produces: the program `oc-core` (`install(TARGETS …)` to `bin` when the core is the top-level project), with
  ```
  oc-core [--config FILE] [--key-file FILE] [--db PATH]
  oc-core admin [--socket PATH] [--config FILE] COMMAND...
  oc-core admin --offline [--config FILE] [--key-file FILE] [--db PATH] COMMAND...
  oc-core --version
  ```
  defaults `/etc/opencell/oc-core.conf`, `/run/opencell/admin.sock`, key from `$CREDENTIALS_DIRECTORY/master.key`; exit status 0, 1 (refused/failed), 2 (usage). The CMake variable `OC_VERSION` (from `-DOC_VERSION=…` or `git describe`).
- Produces: `dist/systemd/oc-core.service` (user `oc-core`, groups `oc-admin` and `oc-cell`, `LoadCredential=master.key:/etc/opencell/master.key`, `RuntimeDirectory=opencell`, `StateDirectory=opencell/core`).

- [ ] **Step 1: Write the failing test**

Create `tests/tool_oc_hello.c`:
```c
#define _GNU_SOURCE
/* A bare cell for the process tests: connects to a core's cell socket,
 * sends HELLO, prints what comes back, answers PING, and holds the link for
 * a while.
 *
 *   tool_oc_hello SOCKET CELL_ID BOOT_ID HOLD_S
 *
 * Prints "HELLO_ACK mode M period P", or "HELLO_NAK reason R", then "closed"
 * if the core drops the link while held. Exit 0 on HELLO_ACK. */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "oc_conn.h"

static oc_conn_t C;
static int acked = -1;

static void on_rx(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    if (m->type == OC_CORE_HELLO_ACK) {
        printf("HELLO_ACK mode %u period %u\n", m->u.hello_ack.mode, m->u.hello_ack.period_s);
        acked = 1;
    } else if (m->type == OC_CORE_HELLO_NAK) {
        printf("HELLO_NAK reason %u\n", m->u.hello_nak.reason);
        acked = 0;
    } else if (m->type == OC_CORE_PING) {
        oc_core_msg_t p;
        memset(&p, 0, sizeof(p));
        p.type = OC_CORE_PONG;
        oc_conn_send(&C, &p);
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: tool_oc_hello SOCKET CELL_ID BOOT_ID HOLD_S\n");
        return 2;
    }
    int fd = oc_unix_connect(argv[1]);
    if (fd < 0) {
        perror(argv[1]);
        return 1;
    }
    oc_conn_init(&C, fd);
    oc_core_msg_t h;
    memset(&h, 0, sizeof(h));
    h.type = OC_CORE_HELLO;
    h.u.hello.proto = OC_CORE_PROTO;
    h.u.hello.cell_id = (uint32_t)strtoul(argv[2], NULL, 0);
    h.u.hello.boot_id = strtoull(argv[3], NULL, 0);
    oc_conn_send(&C, &h);
    time_t end = time(NULL) + atoi(argv[4]);
    while (time(NULL) < end || acked < 0) {
        struct pollfd p = { C.fd, POLLIN, 0 };
        if (poll(&p, 1, 200) > 0 && oc_conn_read(&C, on_rx, NULL) != 0) {
            printf("closed\n");
            break;
        }
        if (acked < 0 && time(NULL) > end + 5) break;
    }
    oc_conn_close(&C);
    return acked == 1 ? 0 : 1;
}
```

Create `tests/test_oc_core_proc.sh`:
```bash
#!/bin/bash
# oc-core as a process (network-core spec §9.4, §17 decisions 1 and 8):
# first setup offline, the daemon on its sockets, admin over the socket, the
# lock against --offline while it runs, a cell's HELLO, a clean stop on
# SIGTERM, data kept across a restart, and a wrong master key refused.
#   test_oc_core_proc.sh OC_CORE TOOL_OC_HELLO
set -u
OC=$1
HELLO=$2
T=$(mktemp -d /tmp/oc_core_proc_XXXXXX)
PID=
fail() { echo "FAIL: $*"; [ -n "$PID" ] && kill "$PID" 2>/dev/null; echo "--- daemon log"; cat "$T/log" 2>/dev/null; rm -rf "$T"; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }

head -c 32 /dev/urandom >"$T/key" && chmod 0400 "$T/key"
cat >"$T/oc-core.conf" <<EOF
core_id = 1
key_id = 1
echo = +883160655500100
block = 8831606 1
db = $T/elsewhere.db
cell_socket = $T/core.sock
admin_socket = $T/admin.sock
EOF
ADM=("$OC" admin --offline --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db")

out=$("${ADM[@]}" net init 2>&1) || fail "net init: $out"
out=$("${ADM[@]}" cell add 1 bench 2>&1) || fail "cell add: $out"
out=$("${ADM[@]}" sub add +883-1-606-555-01234 2>&1) || fail "sub add: $out"
expect "$out" "+883160655501234"
[ -e "$T/elsewhere.db" ] && fail "--db did not override the config's db"

start() {
    "$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>>"$T/log" &
    PID=$!
    for _ in $(seq 50); do [ -S "$T/admin.sock" ] && return 0; sleep 0.1; done
    fail "the admin socket did not appear"
}

start
out=$("$OC" admin --socket "$T/admin.sock" status 2>&1) || fail "status: $out"
expect "$out" "running"
expect "$out" "subscribers 1"
[ "$(stat -c %a "$T/core.sock")" = 600 ] || fail "cell socket mode $(stat -c %a "$T/core.sock")"
out=$("${ADM[@]}" status 2>&1) && fail "--offline ran while the daemon holds the database"
expect "$out" "is in use (oc-core is running"

out=$("$HELLO" "$T/core.sock" 1 7 3) || fail "HELLO: $out"
expect "$out" "HELLO_ACK mode 1 period 1800"
"$HELLO" "$T/core.sock" 1 7 4 >"$T/hello" &
sleep 1
out=$("$OC" admin --config "$T/oc-core.conf" status 2>&1) || fail "status via config: $out"
expect "$out" 'cell 1 "bench": part15, enabled, list 0, linked'
out=$("$OC" admin --socket "$T/admin.sock" cell mode 1 part97 2>&1) || fail "cell mode: $out"
expect "$out" "its link was dropped"
sleep 0.5
expect "$(cat "$T/hello")" "closed"
out=$("$HELLO" "$T/core.sock" 9 7 1)
expect "$out" "HELLO_NAK reason 1"

kill -TERM "$PID"
for _ in $(seq 30); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
kill -0 "$PID" 2>/dev/null && fail "no exit 3 s after SIGTERM"
wait "$PID"; rc=$?; PID=
[ "$rc" = 0 ] || fail "exit status $rc after SIGTERM"
[ -e "$T/admin.sock" ] && fail "admin socket left behind"
grep -q '^<5>oc-core: stopping' "$T/log" || fail "no journald-prefixed stop line"

start
out=$("$OC" admin --socket "$T/admin.sock" audit 20 2>&1) || fail "audit: $out"
expect "$out" "ADMIN .* cell mode 1 part97"
expect "$out" "CELL_REJECT"
out=$("$OC" admin --socket "$T/admin.sock" cell list 2>&1)
expect "$out" 'cell 1 "bench": part97'
kill -TERM "$PID"; wait "$PID"; PID=

head -c 32 /dev/urandom >"$T/key2" && chmod 0400 "$T/key2"
out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key2" --db "$T/core.db" 2>&1) && fail "started with the wrong key"
expect "$out" "the master key does not open this database"
chmod 0644 "$T/key"
out=$("$OC" --config "$T/oc-core.conf" --key-file "$T/key" --db "$T/core.db" 2>&1) && fail "started with a readable key"
expect "$out" "readable by group or others"
out=$("$OC" admin --socket "$T/admin.sock" status 2>&1) && fail "admin without a daemon"
expect "$out" "oc-core is not running"

rm -rf "$T"
echo "OK"
```

Append to `tests/CMakeLists.txt`:
```cmake
add_executable(tool_oc_hello tool_oc_hello.c)
target_link_libraries(tool_oc_hello PRIVATE oc_util)
add_test(NAME test_oc_core_proc
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_oc_core_proc.sh $<TARGET_FILE:oc-core> $<TARGET_FILE:tool_oc_hello>)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build 2>&1 | grep -oE 'No target "oc-core"' | head -1`
Expected: `No target "oc-core"` (the test names a program that doesn't exist yet).

- [ ] **Step 3: Implement**

Append to `oc/CMakeLists.txt`:
```cmake

# The version the programs report: -DOC_VERSION=v1.2.3 (the deploy script
# passes the tag it builds), else what git says about this checkout.
if(NOT OC_VERSION)
  execute_process(COMMAND git describe --tags --always --dirty WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  OUTPUT_VARIABLE OC_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(NOT OC_VERSION)
    set(OC_VERSION unknown)
  endif()
endif()

add_executable(oc-core oc_core_main.c)
target_compile_definitions(oc-core PRIVATE OC_VERSION="${OC_VERSION}")
target_link_libraries(oc-core PRIVATE oc_store)
if(PROJECT_IS_TOP_LEVEL)
  install(TARGETS oc-core RUNTIME DESTINATION bin)
endif()
```

Create `oc/oc_core_main.c`:
```c
#define _GNU_SOURCE
/* oc-core: the network core daemon (network-core spec §4.2, §17 decisions
 * 1, 5, 8 and 9), and its admin client.
 *
 *   oc-core [--config FILE] [--key-file FILE] [--db PATH]
 *   oc-core admin [--socket PATH] [--config FILE] COMMAND...
 *   oc-core admin --offline [--config FILE] [--key-file FILE] [--db PATH] COMMAND...
 *   oc-core --version
 *
 * One thread: a poll() loop feeds oc_core the cells' frames and tick(now),
 * with SQLite on the same thread. Cells connect to cell_socket (the §6
 * Unix socket); `oc-core admin` talks to admin_socket, one command per
 * connection: the client sends its words, each ending in a NUL, and shuts
 * its side; the daemon answers "<status>\n" and the command's output. The
 * master key comes from --key-file or the systemd credential master.key
 * ($CREDENTIALS_DIRECTORY). Logs go to stderr with journald priorities. */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "oc_core.h"
#include "oc_sig_keys.h"
#include "oc_admin.h"
#include "oc_conn.h"
#include "oc_kv.h"
#include "oc_log.h"
#include "oc_seal.h"
#include "oc_sql.h"

#ifndef OC_VERSION
#define OC_VERSION "dev"
#endif

#define DEFAULT_CONFIG "/etc/opencell/oc-core.conf"
#define DEFAULT_ADMIN  "/run/opencell/admin.sock"
#define ADMIN_REQ_MAX  4096u

typedef struct {
    int       used;
    uint32_t  id;   /* oc_core's link handle: never reused */
    int       dead; /* a send or read failed: oc_core hears of it after the call in progress */
    oc_conn_t c;
} dlink_t;

static struct {
    oc_kv_t         kv;
    oc_core_cfg_t   cfg;
    oc_core_route_t route;
    const char     *db, *cell_sock, *admin_sock;
    oc_sql_t       *sql;
    oc_core_t       core;
    int             cell_l, admin_l;
    dlink_t         link[OC_CORE_LINKS];
    uint32_t        next_id;
    uint8_t         key[32];
} D;

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static uint64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void urandom(uint8_t *out, size_t n)
{
    while (n > 0) {
        ssize_t r = getrandom(out, n, 0);
        if (r > 0) {
            out += r;
            n -= (size_t)r;
        }
    }
}

/* ---- configuration ---- */

static const char *const KEYS[] = { "core_id", "key_id", "echo", "block", "db", "cell_socket", "cell_group",
                                    "admin_socket", "admin_group", NULL };

static int load_config(const char *path, const char *db)
{
    long long v;
    if (oc_kv_load(&D.kv, path) != 0 || !oc_kv_known(&D.kv, KEYS)) {
        oc_log(OC_LOG_ERR, "config: %s", D.kv.err);
        return -1;
    }
    memset(&D.cfg, 0, sizeof(D.cfg));
    if (oc_kv_num(&D.kv, "core_id", 1, 65535, 1, &v) != 0) goto bad;
    D.cfg.core_id = (uint16_t)v;
    if (oc_kv_num(&D.kv, "key_id", 1, 65535, 1, &v) != 0) goto bad;
    D.cfg.key_id = (uint16_t)v;
    const char *echo = oc_kv_get(&D.kv, "echo");
    if (echo == NULL) echo = "+883160655500100";
    if (oc_sig_number_normalize(echo, strlen(echo), NULL, D.cfg.echo_number) != 0) {
        oc_log(OC_LOG_ERR, "config: echo = '%s': a full OpenCell number", echo);
        return -1;
    }
    oc_core_route_init(&D.route, D.cfg.core_id);
    for (unsigned i = 0; oc_kv_nth(&D.kv, "block", i) != NULL; i++) {
        char prefix[32];
        unsigned idx;
        const char *b = oc_kv_nth(&D.kv, "block", i);
        if (sscanf(b, "%31s %u", prefix, &idx) != 2 || idx > 65535 ||
            oc_core_route_add(&D.route, prefix, (uint16_t)idx, D.cfg.core_id) != 0) {
            oc_log(OC_LOG_ERR, "config: block = '%s': PREFIX INDEX, e.g. 8831606 1 (a new prefix and index)", b);
            return -1;
        }
    }
    if (D.route.n == 0) {
        oc_log(OC_LOG_ERR, "config: no block: add e.g. block = 8831606 1");
        return -1;
    }
    D.db = db != NULL ? db : oc_kv_get(&D.kv, "db") ? oc_kv_get(&D.kv, "db") : "/var/lib/opencell/core/core.db";
    D.cell_sock = oc_kv_get(&D.kv, "cell_socket") ? oc_kv_get(&D.kv, "cell_socket") : "/run/opencell/core.sock";
    D.admin_sock = oc_kv_get(&D.kv, "admin_socket") ? oc_kv_get(&D.kv, "admin_socket") : DEFAULT_ADMIN;
    return 0;
bad:
    oc_log(OC_LOG_ERR, "config: %s", D.kv.err);
    return -1;
}

static int load_key(const char *key_file)
{
    char path[512], err[600];
    if (key_file == NULL) {
        const char *dir = getenv("CREDENTIALS_DIRECTORY");
        if (dir == NULL) {
            oc_log(OC_LOG_ERR, "no master key: give --key-file, or run under systemd with LoadCredential=master.key");
            return -1;
        }
        snprintf(path, sizeof(path), "%s/master.key", dir);
        key_file = path;
    }
    if (oc_key_load(key_file, D.key, err, sizeof(err)) != 0) {
        oc_log(OC_LOG_ERR, "%s", err);
        return -1;
    }
    return 0;
}

static int open_db(void)
{
    char err[700];
    oc_sql_cfg_t c = { D.db, D.key, urandom, NULL, 0 };
    D.sql = oc_sql_open(&c, err, sizeof(err));
    if (D.sql == NULL) {
        oc_log(OC_LOG_ERR, "%s", err);
        return -1;
    }
    if (oc_sql_backup(D.sql)[0] != '\0') {
        oc_log(OC_LOG_NOTICE, "database migrated to v%d; the old one is kept as %s", oc_sql_version(D.sql),
               oc_sql_backup(D.sql));
    }
    return 0;
}

/* ---- oc_core's transport ---- */

static dlink_t *dlink(uint32_t id)
{
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used && D.link[i].id == id) return &D.link[i];
    }
    return NULL;
}

static int k_send(void *c, uint32_t link, const oc_core_msg_t *m)
{
    (void)c;
    dlink_t *l = dlink(link);
    if (l == NULL || l->dead) return -1;
    if (oc_conn_send(&l->c, m) != 0) {
        oc_log(OC_LOG_WARNING, "link %u: send failed (the cell stopped reading): dropped", (unsigned)link);
        oc_conn_close(&l->c);
        l->dead = 1;
        return -1;
    }
    return 0;
}

static void k_close(void *c, uint32_t link) /* oc_core dropped it */
{
    (void)c;
    dlink_t *l = dlink(link);
    if (l == NULL) return;
    oc_conn_flush(&l->c); /* a HELLO_NAK goes out before the close */
    oc_conn_close(&l->c);
    l->used = 0;
}

static void k_random(void *c, uint8_t *out, size_t n)
{
    (void)c;
    urandom(out, n);
}

static uint32_t k_unix(void *c)
{
    (void)c;
    return (uint32_t)time(NULL);
}

static void on_frame(void *ctx, const oc_core_msg_t *m)
{
    dlink_t *l = ctx;
    oc_core_rx(&D.core, l->id, m, mono_us());
}

/* The transport lost a link: oc_core hears of it (its calls end). */
static void link_lost(dlink_t *l)
{
    uint32_t id = l->id;
    oc_conn_close(&l->c);
    l->used = 0;
    oc_core_link_down(&D.core, id, mono_us());
}

static void drop_cell(void *ctx, uint32_t cell_id)
{
    (void)ctx;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (!D.core.links[i].used || D.core.links[i].cell_id != cell_id) continue;
        dlink_t *l = dlink(D.core.links[i].link);
        if (l != NULL) link_lost(l);
    }
}

static void accept_cell(void)
{
    int fd = accept4(D.cell_l, NULL, NULL, SOCK_CLOEXEC);
    if (fd < 0) return;
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used) continue;
        dlink_t *l = &D.link[i];
        memset(l, 0, sizeof(*l));
        l->used = 1;
        l->id = ++D.next_id;
        oc_conn_init(&l->c, fd);
        oc_core_link_up(&D.core, l->id, mono_us());
        return;
    }
    oc_log(OC_LOG_WARNING, "cell socket: %u links already, connection refused", OC_CORE_LINKS);
    close(fd);
}

/* ---- the admin socket ---- */

static void serve_admin(void)
{
    int fd = accept4(D.admin_l, NULL, NULL, SOCK_CLOEXEC);
    if (fd < 0) return;
    struct ucred cr;
    socklen_t cl = sizeof(cr);
    struct timeval tv = { 2, 0 };
    char req[ADMIN_REQ_MAX + 1];
    size_t n = 0;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) != 0) cr.uid = (uid_t)-1;
    for (;;) {
        ssize_t r = read(fd, req + n, ADMIN_REQ_MAX - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (n == ADMIN_REQ_MAX) break;
    }
    req[n] = '\0';
    char *argv[32];
    int argc = 0;
    for (size_t i = 0; i < n && argc < 32; i += strlen(req + i) + 1u) {
        if (memchr(req + i, '\0', n - i) == NULL) break; /* a word without its NUL: cut off */
        argv[argc++] = req + i;
    }
    oc_admin_t a;
    memset(&a, 0, sizeof(a));
    a.sql = D.sql;
    a.route = &D.route;
    a.cfg = &D.cfg;
    a.core = &D.core;
    a.random = urandom;
    a.now_us = mono_us;
    a.drop_cell = drop_cell;
    a.uid = (uint32_t)cr.uid;
    oc_buf_t out = { 0 };
    int rc = oc_admin_run(&a, argc, argv, &out);
    oc_log(OC_LOG_INFO, "admin (uid %u): %s%s -> %d", (unsigned)cr.uid, argc > 0 ? argv[0] : "", argc > 1 ? " ..." : "",
           rc);
    char head[8];
    int hn = snprintf(head, sizeof(head), "%d\n", rc);
    if (write(fd, head, (size_t)hn) == hn && out.n > 0) {
        size_t off = 0;
        while (off < out.n) {
            ssize_t w = write(fd, out.p + off, out.n - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
    }
    oc_buf_free(&out);
    close(fd);
}

/* ---- the daemon ---- */

static int run_daemon(const char *config, const char *key_file, const char *db)
{
    if (load_config(config, db) != 0 || load_key(key_file) != 0 || open_db() != 0) return 1;
    oc_core_store_t st = oc_sql_store(D.sql);
    const oc_core_io_t io = { NULL, k_send, k_close, k_random, k_unix, oc_log_line };
    if (oc_core_init(&D.core, &io, &st, &D.route, &D.cfg) != 0) {
        oc_log(OC_LOG_ERR, "no network key %u in %s: run `oc-core admin --offline net init` first", D.cfg.key_id, D.db);
        return 1;
    }
    const char *cg = oc_kv_get(&D.kv, "cell_group"), *ag = oc_kv_get(&D.kv, "admin_group");
    D.cell_l = oc_unix_listen(D.cell_sock, cg != NULL ? 0660 : 0600, cg);
    if (D.cell_l < 0) {
        oc_log(OC_LOG_ERR, "%s: %s", D.cell_sock, strerror(errno));
        return 1;
    }
    D.admin_l = oc_unix_listen(D.admin_sock, ag != NULL ? 0660 : 0600, ag);
    if (D.admin_l < 0) {
        oc_log(OC_LOG_ERR, "%s: %s", D.admin_sock, strerror(errno));
        return 1;
    }
    oc_log(OC_LOG_NOTICE, "oc-core %s: core %u, key %u, %u blocks, db %s (v%d), cells on %s, admin on %s", OC_VERSION,
           D.cfg.core_id, D.cfg.key_id, D.route.n, D.db, oc_sql_version(D.sql), D.cell_sock, D.admin_sock);
    while (!g_stop) {
        struct pollfd p[2 + OC_CORE_LINKS];
        dlink_t *who[2 + OC_CORE_LINKS];
        nfds_t np = 0;
        p[np] = (struct pollfd){ D.cell_l, POLLIN, 0 };
        who[np++] = NULL;
        p[np] = (struct pollfd){ D.admin_l, POLLIN, 0 };
        who[np++] = NULL;
        for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
            dlink_t *l = &D.link[i];
            if (!l->used || l->dead) continue;
            p[np] = (struct pollfd){ l->c.fd, (short)(POLLIN | (l->c.tn > 0 ? POLLOUT : 0)), 0 };
            who[np++] = l;
        }
        int r = poll(p, np, 100);
        if (r < 0 && errno != EINTR) {
            oc_log(OC_LOG_ERR, "poll: %s", strerror(errno));
            break;
        }
        if (r > 0) {
            if (p[0].revents & POLLIN) accept_cell();
            if (p[1].revents & POLLIN) serve_admin();
            for (nfds_t i = 2; i < np; i++) {
                dlink_t *l = who[i];
                if (!l->used || l->dead) continue;
                if ((p[i].revents & POLLOUT) && oc_conn_flush(&l->c) != 0) l->dead = 1;
                if ((p[i].revents & (POLLIN | POLLHUP | POLLERR)) && oc_conn_read(&l->c, on_frame, l) != 0 &&
                    l->used) {
                    l->dead = 1;
                }
            }
        }
        oc_core_tick(&D.core, mono_us());
        for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
            if (D.link[i].used && D.link[i].dead) link_lost(&D.link[i]);
        }
    }
    oc_log(OC_LOG_NOTICE, "oc-core: stopping");
    for (unsigned i = 0; i < OC_CORE_LINKS; i++) {
        if (D.link[i].used) oc_conn_close(&D.link[i].c);
    }
    close(D.cell_l);
    close(D.admin_l);
    unlink(D.cell_sock);
    unlink(D.admin_sock);
    oc_sql_close(D.sql);
    oc_sig_wipe(D.key, sizeof(D.key));
    return 0;
}

/* ---- oc-core admin ---- */

/* Offline, run as root: the key is read first, then the process becomes
 * the owner of the database's directory, so the files it makes are the
 * daemon's. */
static int drop_to_db_owner(void)
{
    char dir[512];
    struct stat st;
    if (geteuid() != 0) return 0;
    snprintf(dir, sizeof(dir), "%s", D.db);
    if (stat(dirname(dir), &st) != 0) {
        oc_log(OC_LOG_ERR, "%s: %s", dir, strerror(errno));
        return -1;
    }
    if (st.st_uid == 0) return 0;
    if (setgroups(0, NULL) != 0 || setgid(st.st_gid) != 0 || setuid(st.st_uid) != 0) {
        oc_log(OC_LOG_ERR, "can't become the database's owner (uid %u)", (unsigned)st.st_uid);
        return -1;
    }
    return 0;
}

static int admin_offline(const char *config, const char *key_file, const char *db, int argc, char **argv)
{
    if (load_config(config, db) != 0 || load_key(key_file) != 0 || drop_to_db_owner() != 0 || open_db() != 0) return 1;
    oc_admin_t a;
    memset(&a, 0, sizeof(a));
    a.sql = D.sql;
    a.route = &D.route;
    a.cfg = &D.cfg;
    a.random = urandom;
    a.uid = (uint32_t)getuid();
    oc_buf_t out = { 0 };
    int rc = oc_admin_run(&a, argc, argv, &out);
    if (out.n > 0) fputs(out.p, rc == 0 ? stdout : stderr);
    oc_buf_free(&out);
    oc_sql_close(D.sql);
    return rc;
}

/* The QR code itself, if qrencode is installed and a person is looking. */
static void draw_qr(const char *text)
{
    const char *code = strstr(text, "opencell:");
    if (code == NULL || !isatty(STDOUT_FILENO) || system("command -v qrencode >/dev/null 2>&1") != 0) return;
    char line[256];
    snprintf(line, sizeof(line), "%.*s", (int)strcspn(code, "\n"), code);
    fflush(stdout);
    FILE *q = popen("qrencode -t ANSIUTF8", "w");
    if (q != NULL) {
        fputs(line, q);
        pclose(q);
    }
}

static int admin_client(const char *sock, int argc, char **argv)
{
    int fd = oc_unix_connect(sock);
    if (fd < 0) {
        fprintf(stderr, "oc-core is not running (%s: %s); for a stopped core: oc-core admin --offline ...\n", sock,
                strerror(errno));
        return 1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    for (int i = 0; i < argc; i++) {
        if (write(fd, argv[i], strlen(argv[i]) + 1u) < 0) {
            fprintf(stderr, "%s: %s\n", sock, strerror(errno));
            close(fd);
            return 1;
        }
    }
    shutdown(fd, SHUT_WR);
    oc_buf_t in = { 0 };
    char buf[4096];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) oc_buf_printf(&in, "%.*s", (int)r, buf);
    close(fd);
    if (in.n < 2 || in.p[1] != '\n') {
        fprintf(stderr, "no answer from oc-core\n");
        oc_buf_free(&in);
        return 1;
    }
    int rc = in.p[0] - '0';
    fputs(in.p + 2, rc == 0 ? stdout : stderr);
    if (rc == 0 && argc >= 2 && strcmp(argv[0], "sub") == 0 && strcmp(argv[1], "issue") == 0) draw_qr(in.p + 2);
    oc_buf_free(&in);
    return rc;
}

static int usage(void)
{
    fprintf(stderr, "usage: oc-core [--config FILE] [--key-file FILE] [--db PATH]\n"
                    "       oc-core admin [--socket PATH] [--config FILE] COMMAND...\n"
                    "       oc-core admin --offline [--config FILE] [--key-file FILE] [--db PATH] COMMAND...\n"
                    "       oc-core --version\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *config = DEFAULT_CONFIG, *key_file = NULL, *sock = NULL, *db = NULL;
    int admin = 0, offline = 0, i = 1;
    signal(SIGPIPE, SIG_IGN);
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("oc-core %s\n", OC_VERSION);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "admin") == 0) {
        admin = 1;
        i = 2;
    }
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) config = argv[++i];
        else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) key_file = argv[++i];
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) db = argv[++i];
        else if (admin && strcmp(argv[i], "--socket") == 0 && i + 1 < argc) sock = argv[++i];
        else if (admin && strcmp(argv[i], "--offline") == 0) offline = 1;
        else return usage();
    }
    if (!admin) {
        if (i != argc) return usage();
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        return run_daemon(config, key_file, db);
    }
    if (i == argc) return usage();
    if (offline) return admin_offline(config, key_file, db, argc - i, argv + i);
    if (sock == NULL) {
        static oc_kv_t kv;
        sock = oc_kv_load(&kv, config) == 0 && oc_kv_get(&kv, "admin_socket") != NULL ? oc_kv_get(&kv, "admin_socket")
                                                                                      : DEFAULT_ADMIN;
    }
    return admin_client(sock, argc - i, argv + i);
}
```

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; bash tests/test_oc_core_proc.sh build/oc/oc-core build/tests/tool_oc_hello; build/oc/oc-core --version | cut -c1-8`
Expected: no compiler output, then `OK`, then `oc-core ` (followed by what `git describe` says).

- [ ] **Step 5: The unit and the example config**

Create `dist/systemd/oc-core.service`:
```ini
# oc-core, the OpenCell network core (network-core spec §4.2, §17). Installed
# by tools/deploy/oc-deploy. The master key is /etc/opencell/master.key
# (root, 0400), handed over as a credential: the service user never reads
# the file itself. Group oc-admin may use the admin socket; group oc-cell
# the cell socket (a single site runs oc-cell on the same machine). Plan 9
# (the VM, TLS) drops oc-cell from SupplementaryGroups there.
[Unit]
Description=OpenCell network core (oc-core)
After=network.target

[Service]
Type=simple
User=oc-core
Group=oc-core
SupplementaryGroups=oc-admin oc-cell
ExecStart=/usr/local/bin/oc-core --config /etc/opencell/oc-core.conf
LoadCredential=master.key:/etc/opencell/master.key
RuntimeDirectory=opencell
RuntimeDirectoryMode=0755
StateDirectory=opencell/core
StateDirectoryMode=0700
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes

[Install]
WantedBy=multi-user.target
```

Create `dist/oc-core.conf.example`:
```ini
# /etc/opencell/oc-core.conf: the network core (network-core spec §4.2).
# key = value; '#' starts a comment. An unknown key stops oc-core.
core_id = 1
key_id = 1
echo = +883160655500100
# PREFIX INDEX: a numbering block this core is home for (one line each)
block = 8831606 1
db = /var/lib/opencell/core/core.db
cell_socket = /run/opencell/core.sock
cell_group = oc-cell
admin_socket = /run/opencell/admin.sock
admin_group = oc-admin
```

Run: `cd /home/devin/Documents/opencell/core && grep -v '^#' dist/oc-core.conf.example | grep -c ' = '`
Expected: `9` (every key `oc-core` knows).

- [ ] **Step 6: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_core+5` (13 when validated).

- [ ] **Step 7: Commit and push**

```bash
cd /home/devin/Documents/opencell/core
git add oc/CMakeLists.txt oc/oc_core_main.c tests/CMakeLists.txt tests/tool_oc_hello.c tests/test_oc_core_proc.sh \
        dist/systemd/oc-core.service dist/oc-core.conf.example
git commit -m "oc-core: the daemon (one poll loop, cell and admin sockets), admin client, --offline; unit and example config

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push -u origin oc-core
```

---

### Task 7: `opencell-pi`: the submodule, the build, and `ocr`, the radio backend

**Repo:** `opencell-pi`, branch `oc-cell`, at `/home/devin/Documents/opencell/pi`. **Starts:** after Task 6 (`oc-core` pushed).

The Pi repository gets its first code. One submodule, `third_party/opencell-core`, brings the core and (nested) the firmware; the build adds the firmware components `ocb_cell` needs and the ocbench library. `ocr` is `oc-cell`'s radio backend on one W12 (spec §4.1 "`ocb_cell` over USB"): what `ocbench net --one-board` did for the radio, with `oc_cell` as the network side. It is I/O-free, so its test runs a perfect board: every SCHEDULE `ocr` sends is executed at once, its DL slots delivered to an `oc_sig_term` terminal and its UL and RACH slots answered with that terminal's payloads, while `oc_cell` talks to a real `oc_core` on the in-memory store. That is §9.3's "plan-5 air path with the new glue and a core", at the level of the board's messages.

It also carries the Pi bench's timing: with the board's internal PPS, `ocr` learns the frame from STATUS and labels with `ocb_time` (Task 1), and relabels a board that reset (Review Focus 4). And it makes the beacon follow the core: the mode from HELLO_ACK sets PART97, the channel list's version sets `cfg_ver`.

**Files:**
- Create: `.gitmodules` and `third_party/opencell-core` (by `git submodule add`), `CMakeLists.txt`, `.gitignore`, `oc-cell/CMakeLists.txt`, `oc-cell/ocr.h`, `oc-cell/ocr.c`, `tests/CMakeLists.txt`
- Test: `tests/test_ocr.c`

**Interfaces:**
- Consumes: `oc_cell_*`, `oc_cell_list_ver`, `oc_cell_t.net.cfg.mode` (plan 1); `ocb_cell_init`, `ocb_cell_set_hooks`, `ocb_cell_legs`, `ocb_cell_set_sync`, `ocb_cell_on_rx`, `ocb_cell_dl_push`, `ocb_cell_page`, `ocb_cell_release`, `ocb_cell_granted`, `ocb_merge_bands` (firmware `tools/ocbench`); `ocb_time_*` (Task 1); `oc_frame_from_unix_us` (`oc_clock.h`).
- Produces (library `occ_lib`, `oc-cell/ocr.h`):
  ```c
  #define OCR_LEAD_FRAMES 3u
  #define OCR_STALE_US    1500000u
  typedef struct { int internal; uint32_t cell_seed; oc_tier_t tier; oc_band_t dl_band, ul_band; int attach_idle;
                   uint8_t mode; int sync_ch; int fixed_sync; } ocr_cfg_t;
  typedef struct { void *ctx; int (*board_send)(void *ctx, oc_msg_t *m); void (*log)(void *ctx, const char *line); } ocr_io_t;
  typedef struct { ...; ocb_cell_t cell; oc_cell_t *net; ocb_time_t time; ocb_one_map_t map[OCB_ONE_MAP_FRAMES];
                   int board_has_time; uint32_t next_f; uint32_t schedules; ... } ocr_t;
  int  ocr_init(ocr_t *b, const ocr_io_t *io, const ocr_cfg_t *cfg, oc_cell_t *net, uint64_t rt_us);
  void ocr_config_msg(const ocr_cfg_t *cfg, oc_msg_t *m);
  void ocr_board_rx(ocr_t *b, const oc_msg_t *m, uint64_t rt_us, uint64_t mono_us);
  void ocr_tick(ocr_t *b, uint64_t rt_us, uint64_t mono_us);
  int  ocr_dl(ocr_t *b, uint32_t tmid, const uint8_t *p, uint8_t n);
  void ocr_channel(ocr_t *b, uint32_t tmid, int on);
  void ocr_status_line(const ocr_t *b, char *out, size_t cap);
  ```
- Produces (CMake): option `OC_PI_TESTS`, the function `oc_test(name lib)` in `tests/CMakeLists.txt`.

- [ ] **Step 1: The submodule**

```bash
cd /home/devin/Documents/opencell/pi
git submodule add ../opencell-core.git third_party/opencell-core
git -C third_party/opencell-core checkout -q origin/oc-core
git submodule update --init --recursive
```

Run: `cd /home/devin/Documents/opencell/pi && ls third_party/opencell-core/oc/include/oc_conn.h third_party/opencell-core/third_party/opencell-firmware/tools/ocbench/ocb_time.h`
Expected: both paths printed.

- [ ] **Step 2: Write the failing test**

Create `tests/CMakeLists.txt`:
```cmake
# Host tests (Unity), one executable per tests/<name>.c.
include(FetchContent)
FetchContent_Declare(unity
  GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
  GIT_TAG v2.6.1)
FetchContent_MakeAvailable(unity)

function(oc_test name lib)
  add_executable(${name} ${name}.c)
  target_link_libraries(${name} PRIVATE ${lib} unity)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

oc_test(test_ocr occ_lib)
```

Create `tests/test_ocr.c`:
```c
/* ocr, oc-cell's radio backend, at the level of the board's messages: every
 * SCHEDULE it sends is run by a perfect board, whose RX reports carry what
 * one oc_sig_term terminal sends in its slots (network-core spec §9.3: the
 * plan-5 air path, now with oc_cell and a core behind it). The core is
 * oc_core on the in-memory store, over a queue in each direction.
 *
 * Also: TIME labels and the board's frame with the internal PPS
 * (opencell-firmware#2), stale STATUS, the beacon following the core's mode
 * and channel-list version, and an anchor the mode forbids. */
#include "unity.h"

#include <stdio.h>
#include <string.h>

#include "oc_air.h"
#include "oc_clock.h"
#include "oc_core.h"
#include "oc_core_mem.h"
#include "oc_sig_term.h"
#include "ocr.h"

void setUp(void) {}
void tearDown(void) {}

#define HOST0 1790000000000000ull /* realtime at t = 0 */
#define ECHO  "+883160655500100"
#define NUM   "+883160655501234"
#define TMID  0x76AD0488u

static ocr_t R;
static oc_cell_t C;
static oc_core_t K;
static oc_core_mem_t MEM;
static oc_core_store_t ST;
static oc_core_route_t RT;
static uint64_t now; /* monotonic, µs */

/* ---- the core link: a queue each way, delivered each step ---- */

typedef struct {
    oc_core_msg_t m[64];
    int n;
} q_t;
static q_t to_core, to_cell;
static int linked;

static int c_core_send(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    if (!linked || to_core.n == 64) return -1;
    to_core.m[to_core.n++] = *m;
    return 0;
}
static int k_send(void *ctx, uint32_t link, const oc_core_msg_t *m)
{
    (void)ctx;
    (void)link;
    if (!linked || to_cell.n == 64) return -1;
    to_cell.m[to_cell.n++] = *m;
    return 0;
}
static uint32_t rng = 11;
static void k_random(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((rng = rng * 1103515245u + 12345u) >> 16);
}
static uint32_t k_unix(void *ctx)
{
    (void)ctx;
    return (uint32_t)(HOST0 / 1000000u + now / 1000000u);
}

static void deliver(void)
{
    q_t a = to_core, b = to_cell;
    to_core.n = to_cell.n = 0;
    for (int i = 0; i < a.n; i++) oc_core_rx(&K, 1, &a.m[i], now);
    for (int i = 0; i < b.n; i++) oc_cell_core_rx(&C, &b.m[i], now);
}

static void link_up(void)
{
    linked = 1;
    oc_core_link_up(&K, 1, now);
    oc_cell_core_up(&C, now);
}

static void link_down(void)
{
    linked = 0;
    to_core.n = to_cell.n = 0;
    oc_core_link_down(&K, 1, now);
    oc_cell_core_down(&C, now);
}

/* ---- the terminal ---- */

typedef struct {
    uint8_t p[32][OC_SIG_LINK_MAX], n[32];
    int head, count;
} tq_t;

static struct {
    oc_sig_ident_t id;
    oc_sig_term_t t;
    tq_t ul;
    int attach;     /* send ATTACH in the next RACH slot */
    int page_reply; /* ...or PAGE_REPLY */
    uint8_t svc;    /* ...or this RACH UPPER (0: none) */
    int attached;
    uint8_t evs[64];
    int nev;
    uint8_t app[OC_SIG_APP_MAX], app_n;
    uint8_t bcn_flags, bcn_cfg_ver;
    int beacons;
} T;

static int t_send(void *c, const uint8_t *p, uint8_t n)
{
    (void)c;
    if (T.ul.count == 32) return -1;
    int i = (T.ul.head + T.ul.count++) % 32;
    memcpy(T.ul.p[i], p, n);
    T.ul.n[i] = n;
    return 0;
}
static int t_svc(void *c, uint8_t cause)
{
    (void)c;
    T.svc = (uint8_t)(OC_SIG_KIND_SVC | cause);
    return 0;
}
static void t_event(void *c, const uint8_t *e, uint8_t n)
{
    (void)c;
    (void)n;
    T.evs[T.nev++ % 64] = e[0];
}

static int had_event(uint8_t code)
{
    for (int i = 0; i < T.nev && i < 64; i++) {
        if (T.evs[i] == code) return 1;
    }
    return 0;
}

/* ---- the board: runs each SCHEDULE as it arrives ---- */

static int schedules, times, configs;
static oc_msg_t last_time;

static void report(uint32_t f, uint8_t slot, const oc_air_msg_t *a)
{
    static uint8_t buf[OC_AIR_MAX_FRAME];
    oc_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_MSG_RX_REPORT;
    size_t n = oc_air_encode(a, buf, sizeof(buf));
    m.u.rx_report = (oc_rx_report_t){ f, slot, -60, 40, 1, (uint8_t)n, buf, OC_RX_END_UNKNOWN };
    ocr_board_rx(&R, &m, HOST0 + now, now);
}

static void run_schedule(const oc_schedule_t *s)
{
    uint32_t f = s->frame_number;
    const ocb_one_map_t *map = &R.map[f % OCB_ONE_MAP_FRAMES];
    TEST_ASSERT_EQUAL_UINT32(f, map->frame);
    for (uint8_t i = 0; i < s->slot_count; i++) {
        const ocb_cell_kinds_t *kd = &R.cell.kinds[map->band[i]][f % OCB_CELL_KIND_FRAMES];
        uint8_t kind = kd->kind[map->idx[i]], term = kd->term[map->idx[i]];
        const oc_slot_t *sl = &s->slots[i];
        oc_air_msg_t a;
        if (kind == OCB_SLOT_BEACON && oc_air_decode(sl->payload, sl->payload_len, &a) == 0) {
            T.bcn_flags = a.u.beacon.flags;
            T.bcn_cfg_ver = a.u.beacon.cfg_ver;
            T.beacons++;
            for (uint8_t p = 0; p < a.u.beacon.page_count; p++) {
                if (a.u.beacon.page_tmid[p] == TMID) T.page_reply = 1;
            }
        } else if (kind == OCB_SLOT_RACH && (T.attach || T.page_reply || T.svc)) {
            static uint8_t svc;
            memset(&a, 0, sizeof(a));
            a.type = OC_AIR_RACH;
            if (T.attach) {
                a.u.rach = (oc_rach_t){ TMID, OC_RACH_ATTACH, 0, NULL };
                T.attach = 0;
                T.attached = 1;
            } else if (T.page_reply) {
                a.u.rach = (oc_rach_t){ TMID, OC_RACH_PAGE_REPLY, 0, NULL };
                T.page_reply = 0;
            } else {
                svc = T.svc; /* the payload is read when the report is encoded */
                a.u.rach = (oc_rach_t){ TMID, OC_RACH_UPPER, 1, &svc };
                T.svc = 0;
            }
            report(f, i, &a);
        } else if (kind == OCB_SLOT_DL && R.cell.terms[term].tmid == TMID &&
                   oc_air_decode(sl->payload, sl->payload_len, &a) == 0 && a.type == OC_AIR_DATA &&
                   a.u.data.payload_len > 0) {
            const uint8_t *p = a.u.data.payload;
            if ((p[0] & 0xF0u) == OC_SIG_KIND_SIG) oc_sig_term_rx(&T.t, p, a.u.data.payload_len, now);
            else if (p[0] == OC_SIG_KIND_DATA) oc_sig_term_data_in(&T.t, p, a.u.data.payload_len, T.app, &T.app_n);
        } else if (kind == OCB_SLOT_UL && R.cell.terms[term].tmid == TMID) {
            uint8_t p[OC_SIG_LINK_MAX], n = 0;
            if (T.ul.count > 0) {
                n = T.ul.n[T.ul.head];
                memcpy(p, T.ul.p[T.ul.head], n);
                T.ul.head = (T.ul.head + 1) % 32;
                T.ul.count--;
            }
            memset(&a, 0, sizeof(a));
            a.type = OC_AIR_DATA;
            a.u.data = (oc_data_t){ TMID, 0, 0, n, p };
            report(f, i, &a);
        }
    }
}

static int board_send(void *ctx, oc_msg_t *m)
{
    (void)ctx;
    static uint8_t seq;
    m->seq = seq++;
    if (m->type == OC_MSG_SCHEDULE) {
        schedules++;
        run_schedule(&m->u.schedule);
    } else if (m->type == OC_MSG_TIME) {
        times++;
        last_time = *m;
    } else if (m->type == OC_MSG_CONFIG) {
        configs++;
    }
    return m->seq;
}

static const ocr_io_t IO = { NULL, board_send, NULL };

/* ---- the world ---- */

static int l_radio_send(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    (void)ctx;
    return ocr_dl(&R, tmid, p, n);
}
static void l_radio_channel(void *ctx, uint32_t tmid, int on)
{
    (void)ctx;
    ocr_channel(&R, tmid, on);
}

static ocr_cfg_t radio_cfg(int internal)
{
    ocr_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.internal = internal;
    c.cell_seed = 0xCAFEF00Du;
    c.tier = OC_TIER_EDGE;
    c.dl_band = c.ul_band = OC_BAND_915;
    c.mode = OC_SIG_MODE_PART15;
    c.sync_ch = -1;
    return c;
}

static void world(int internal)
{
    uint8_t r[32];
    memset(&T, 0, sizeof(T));
    to_core.n = to_cell.n = 0;
    schedules = times = configs = 0;
    now = 0;
    oc_core_mem_init(&MEM);
    ST = oc_core_mem_store(&MEM);
    memset(r, 0x33, 32);
    TEST_ASSERT_EQUAL_INT(0, oc_core_netkey_new(&ST, 1, 1800, r, (uint32_t)(HOST0 / 1000000u)));
    oc_core_route_init(&RT, 1);
    TEST_ASSERT_EQUAL_INT(0, oc_core_route_add(&RT, "8831606", 1, 1));
    oc_core_cfg_t kc;
    memset(&kc, 0, sizeof(kc));
    kc.core_id = 1;
    kc.key_id = 1;
    oc_sig_number_to_bcd(ECHO, strlen(ECHO), kc.echo_number);
    const oc_core_io_t kio = { NULL, k_send, NULL, k_random, k_unix, NULL };
    TEST_ASSERT_EQUAL_INT(0, oc_core_init(&K, &kio, &ST, &RT, &kc));
    TEST_ASSERT_EQUAL_INT(0, oc_core_cell_add(&K, 1, "bench", OC_SIG_MODE_PART15, 1));
    const oc_cell_io_t cio = { NULL, c_core_send, NULL, l_radio_send, l_radio_channel, NULL };
    const oc_cell_cfg_t ccfg = { 1, 0xB0B, { 0, 1, 0 }, OC_SIG_MODE_PART15, 1800 };
    oc_cell_init(&C, &cio, &ccfg);
    ocr_cfg_t rc = radio_cfg(internal);
    TEST_ASSERT_EQUAL_INT(0, ocr_init(&R, &IO, &rc, &C, HOST0 + now));
}

/* One 10 ms step, as oc-cell's loop: board, radio, cell, core. */
static void step(void)
{
    now += 10000u;
    deliver();
    int granted = ocb_cell_granted(&R.cell, TMID);
    oc_sig_term_link(&T.t, T.attached, T.attached && granted, now);
    oc_sig_term_cell_mode(&T.t, (T.bcn_flags & OC_BCN_FLAG_PART97) ? OC_SIG_MODE_PART97 : OC_SIG_MODE_PART15, now);
    oc_sig_term_tick(&T.t, now);
    ocr_tick(&R, HOST0 + now, now);
    oc_cell_tick(&C, now);
    oc_core_tick(&K, now);
}

static void run_ms(uint32_t ms)
{
    for (uint32_t i = 0; i < ms / 10u; i++) step();
}

static void terminal_on(void)
{
    uint8_t r[32];
    memset(r, 0x5A, 32);
    oc_sig_ident_new(&T.id, r);
    const oc_sig_term_io_t io = { NULL, t_send, t_svc, NULL, t_event };
    oc_sig_term_init(&T.t, &io, &T.id, TMID, now);
    T.attach = 1;
}

static void command(const uint8_t *cmd, size_t n) { TEST_ASSERT_EQUAL_INT(0, oc_sig_term_command(&T.t, cmd, n, now)); }

static void activate(void)
{
    uint8_t num[OC_SIG_NUMBER_LEN], got[OC_SIG_NUMBER_LEN], cmd[1 + OC_SIG_QR_TEXT + 1];
    oc_sig_qr_t qr;
    oc_sig_number_to_bcd(NUM, strlen(NUM), num);
    TEST_ASSERT_EQUAL_INT(0, oc_core_sub_add(&K, num, got));
    TEST_ASSERT_EQUAL_INT(0, oc_core_token_issue(&K, num, 3600, &qr));
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    command(cmd, 1 + oc_sig_qr_format(&qr, (char *)cmd + 1, sizeof(cmd) - 1));
}

/* ---- tests ---- */

/* §9.3: activation and registration through ocr, oc_cell and the core; the
 * core then has the terminal on cell 1. */
static void test_a_terminal_activates_and_registers_through_the_board(void)
{
    world(0);
    link_up();
    run_ms(500);
    TEST_ASSERT_TRUE(C.ready);
    terminal_on();
    activate();
    run_ms(15000);
    TEST_ASSERT_TRUE_MESSAGE(had_event(OC_SIG_EV_ACTIVATED), "activated");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(OC_SIG_ST_REGISTERED, oc_sig_term_state(&T.t), "registered");
    uint8_t num[OC_SIG_NUMBER_LEN];
    oc_core_loc_t l;
    oc_sig_number_to_bcd(NUM, strlen(NUM), num);
    TEST_ASSERT_EQUAL_INT(0, ST.loc_get(ST.ctx, num, &l));
    TEST_ASSERT_EQUAL_UINT32(1, l.cell_id);
    TEST_ASSERT_EQUAL_UINT32(TMID, l.tmid);
    TEST_ASSERT_TRUE(R.cell.attaches >= 1);
    TEST_ASSERT_EQUAL_UINT8(0, T.bcn_flags & OC_BCN_FLAG_PART97);
}

/* The echo service through the core: MO call, ring, answer, app data back;
 * the terminal idles between (released) and asks for a grant (RACH UPPER,
 * page, PAGE_REPLY) to dial. */
static void test_a_call_to_the_echo_service(void)
{
    world(0);
    link_up();
    run_ms(500);
    terminal_on();
    activate();
    run_ms(15000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&T.t));
    TEST_ASSERT_FALSE(ocb_cell_granted(&R.cell, TMID)); /* released after 5 s of silence */
    uint8_t dial[1 + 16] = { OC_SIG_CMD_DIAL };
    memcpy(dial + 1, ECHO, 16);
    command(dial, sizeof(dial));
    run_ms(8000);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(OC_SIG_ST_IN_CALL, oc_sig_term_state(&T.t), "in call");
    uint8_t out[OC_SIG_LINK_MAX], on;
    TEST_ASSERT_EQUAL_INT(0, oc_sig_term_data_out(&T.t, (const uint8_t *)"ping", 4, out, &on));
    t_send(NULL, out, on);
    run_ms(2000);
    TEST_ASSERT_EQUAL_UINT8(4, T.app_n);
    TEST_ASSERT_EQUAL_MEMORY("ping", T.app, 4);
}

/* The beacon follows the core: the group's channel list version (CELL_CFG)
 * becomes cfg_ver, and the cell's mode (HELLO_ACK) the PART97 flag; the
 * terminal re-registers under the new mode. */
static void test_the_beacon_follows_the_core(void)
{
    world(0);
    link_up();
    run_ms(500);
    terminal_on();
    activate();
    run_ms(15000);
    TEST_ASSERT_EQUAL_UINT8(0, T.bcn_cfg_ver);
    oc_sig_chan_list_t l;
    memset(&l, 0, sizeof(l));
    l.count = 1;
    l.freq_hz[0] = 917250000u;
    TEST_ASSERT_EQUAL_INT(1, oc_core_chan_list_set(&K, 1, &l, now));
    TEST_ASSERT_EQUAL_INT(2, oc_core_chan_list_set(&K, 1, &l, now));
    run_ms(1000);
    TEST_ASSERT_EQUAL_UINT8(2, oc_cell_list_ver(&C));
    TEST_ASSERT_EQUAL_UINT8(2, T.bcn_cfg_ver);

    oc_core_cell_t cell;
    TEST_ASSERT_EQUAL_INT(0, ST.cell_get(ST.ctx, 1, &cell));
    cell.mode = OC_SIG_MODE_PART97;
    TEST_ASSERT_EQUAL_INT(0, ST.cell_put(ST.ctx, &cell));
    link_down(); /* oc-core admin cell mode drops the link; the cell reconnects */
    run_ms(1000);
    link_up();
    int nev = T.nev;
    run_ms(15000);
    TEST_ASSERT_EQUAL_HEX8(OC_BCN_FLAG_PART97, T.bcn_flags & OC_BCN_FLAG_PART97);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&T.t));
    int again = 0;
    for (int i = nev; i < T.nev && i < 64; i++) again |= T.evs[i] == OC_SIG_EV_REGISTERED;
    TEST_ASSERT_TRUE_MESSAGE(again, "registered again under part97");
}

/* Fixed sync is Part 97 only: refused at start in part15, and a cell whose
 * core moves it to part15 goes off air rather than beacon wrongly. */
static void test_fixed_sync_needs_part97(void)
{
    world(0);
    ocr_cfg_t c = radio_cfg(0);
    c.sync_ch = 40;
    c.fixed_sync = 1;
    TEST_ASSERT_EQUAL_INT(-1, ocr_init(&R, &IO, &c, &C, HOST0));
    c.mode = OC_SIG_MODE_PART97;
    C.net.cfg.mode = OC_SIG_MODE_PART97;
    TEST_ASSERT_EQUAL_INT(0, ocr_init(&R, &IO, &c, &C, HOST0));
    run_ms(500);
    TEST_ASSERT_TRUE(schedules > 0);
    TEST_ASSERT_EQUAL_INT(0, R.cell.off);
    C.net.cfg.mode = OC_SIG_MODE_PART15; /* what a HELLO_ACK would do */
    run_ms(500);
    TEST_ASSERT_EQUAL_INT(1, R.cell.off);
}

static void board_status(uint32_t frame)
{
    oc_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_MSG_STATUS;
    m.u.status.frame_number = frame;
    ocr_board_rx(&R, &m, HOST0 + now, now);
}

static void board_ack(uint8_t seq, uint8_t status)
{
    oc_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_MSG_ACK;
    m.u.ack.acked_seq = seq;
    m.u.ack.status = status;
    ocr_board_rx(&R, &m, HOST0 + now, now);
}

/* Internal PPS (the Pi bench): no SCHEDULE before the board has a timebase;
 * a late label is tried again; a STATUS queued before the start is not
 * believed; once STATUS shows a frame, frames follow it and labels stop; a
 * board that resets is labelled again and nothing is scheduled meanwhile. */
static void test_internal_pps_labels_then_schedules(void)
{
    world(1);
    run_ms(20);
    TEST_ASSERT_EQUAL_INT(1, times); /* a label at once */
    TEST_ASSERT_EQUAL_INT(0, schedules);
    board_ack(last_time.seq, OC_ACK_ERR_LATE);
    run_ms(200);
    TEST_ASSERT_EQUAL_INT(1, times);
    run_ms(200);
    TEST_ASSERT_EQUAL_INT(2, times); /* 300 ms after the refusal */
    board_status(123456);            /* stale: within 1.5 s of the start */
    run_ms(200);
    TEST_ASSERT_EQUAL_INT(0, schedules);
    board_ack(last_time.seq, OC_ACK_OK);
    run_ms(1200);
    TEST_ASSERT_EQUAL_INT(2, times); /* held after the accepted label */
    board_status(123456);
    run_ms(500);
    TEST_ASSERT_TRUE(schedules >= 4);
    TEST_ASSERT_EQUAL_UINT32(123456u + (500u / 120u) + OCR_LEAD_FRAMES + 1u, R.next_f);
    run_ms(5000);
    TEST_ASSERT_EQUAL_INT(2, times); /* the board counts on by itself */
    board_status(0);                 /* it reset */
    run_ms(100);
    TEST_ASSERT_EQUAL_INT(3, times);
    int s = schedules;
    run_ms(1000);
    TEST_ASSERT_EQUAL_INT(s, schedules); /* nothing it could run */
    char line[200];
    ocr_status_line(&R, line, sizeof(line));
    TEST_ASSERT_NOT_NULL(strstr(line, "NO TIMEBASE"));
    TEST_ASSERT_NOT_NULL(strstr(line, "(late 1)"));
}

/* GPS PPS: frames follow the host clock at once; one label a second. */
static void test_gps_pps_follows_the_host_clock(void)
{
    world(0);
    run_ms(3000);
    TEST_ASSERT_TRUE(times >= 2 && times <= 3);
    TEST_ASSERT_TRUE(schedules >= 24);
    TEST_ASSERT_EQUAL_UINT32(oc_frame_from_unix_us(HOST0 + now) + OCR_LEAD_FRAMES + 1u, R.next_f);
    oc_msg_t m;
    ocr_config_msg(&R.cfg, &m);
    TEST_ASSERT_EQUAL_UINT8(OC_ROLE_BS_RADIO, m.u.config.role);
    TEST_ASSERT_EQUAL_UINT32(0xCAFEF00Du, m.u.config.cell_seed);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a_terminal_activates_and_registers_through_the_board);
    RUN_TEST(test_a_call_to_the_echo_service);
    RUN_TEST(test_the_beacon_follows_the_core);
    RUN_TEST(test_fixed_sync_needs_part97);
    RUN_TEST(test_internal_pps_labels_then_schedules);
    RUN_TEST(test_gps_pps_follows_the_host_clock);
    return UNITY_END();
}
```

Create `CMakeLists.txt`:
```cmake
# opencell-pi: the base station's daemon, oc-cell (network-core spec §4.1,
# §17 decision 10). The network core (opencell-core: oc_core, oc_cell and the
# oc_util library) is the submodule third_party/opencell-core; the firmware
# (oc_sig, oc_air, oc_link, ocbench's ocb_cell) is that submodule's own
# submodule, so one pin names a core and firmware that were tested together.
cmake_minimum_required(VERSION 3.21)
project(opencell_pi C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror)
option(OC_PI_TESTS "Build the host tests (fetches Unity)" ${PROJECT_IS_TOP_LEVEL})

set(OC_CORE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/opencell-core)
set(OC_FW ${OC_CORE}/third_party/opencell-firmware)
if(NOT EXISTS ${OC_FW}/tools/ocbench/ocb_cell.c)
  message(FATAL_ERROR "third_party/opencell-core is empty: run git submodule update --init --recursive")
endif()
# oc_phy, oc_link, oc_sig, oc_core, oc_cell, oc_util (and oc-core, built only
# when something here needs it: the process tests)
add_subdirectory(${OC_CORE} opencell-core EXCLUDE_FROM_ALL)
add_subdirectory(${OC_FW}/firmware/components/oc_clock oc_clock)
add_subdirectory(${OC_FW}/firmware/components/oc_exec oc_exec)
add_subdirectory(${OC_FW}/firmware/components/oc_air oc_air)
add_subdirectory(${OC_FW}/firmware/components/oc_term oc_term)
add_subdirectory(${OC_FW}/tools/ocbench ocbench EXCLUDE_FROM_ALL) # ocbench_core: ocb_cell, ocb_merge, ocb_time
add_subdirectory(oc-cell)

if(OC_PI_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
```

Create `.gitignore`:
```
build/
```

Create `oc-cell/CMakeLists.txt`:
```cmake
# oc-cell: ocr (the ocb_cell radio backend), and from Task 8 the simulated
# radio, the config file, the board's port and the program.
add_library(occ_lib STATIC ocr.c)
target_include_directories(occ_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(occ_lib PUBLIC oc_cell ocbench_core oc_util)
```

- [ ] **Step 3: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build 2>&1 | grep -oE "Cannot find source file" | head -1`
Expected: `Cannot find source file` (the library names `ocr.c`, which doesn't exist yet).

- [ ] **Step 4: Implement**

Create `oc-cell/ocr.h`:
```c
/* ocr: oc-cell's radio backend on one W12 bs-radio over USB (network-core
 * spec §4.1, "ocb_cell over USB"): ocb_cell builds each 120 ms frame's
 * SCHEDULE, one board carries both bands' slots (ocb_merge), and the
 * board's RX reports feed oc_cell. It is what `ocbench net ... --one-board`
 * did, without the network stand-in: the network side is oc_cell.
 *
 * Time: with GPS PPS on the board (role bs) frames follow the host clock;
 * with the board's internal PPS (role bench, the Pi bench: the GPS HAT's PPS
 * is not wired to the board) the board's frame is learned from its STATUS,
 * and TIME labels follow ocb_time.h (opencell-firmware#2).
 *
 * The network side's state reaches the beacon: its mode (from the core's
 * HELLO_ACK) sets the PART97 flag, and the version of its channel list
 * (CELL_CFG) sets cfg_ver.
 *
 * I/O-free: oc-cell's main moves the board's messages and gives two clocks,
 * the host's realtime (frames, labels) and the monotonic one oc_cell runs on. */
#ifndef OCR_H
#define OCR_H

#include <stddef.h>
#include <stdint.h>

#include "oc_cell.h"
#include "oc_link.h"
#include "ocb_cell.h"
#include "ocb_merge.h"
#include "ocb_time.h"

#define OCR_LEAD_FRAMES 3u       /* schedule this far ahead of the board's frame (the W12 takes up to 3) */
#define OCR_STALE_US    1500000u /* STATUS queued before we started is stale */

typedef struct {
    int       internal;    /* the board runs its internal 1 Hz PPS (role bench) */
    uint32_t  cell_seed;
    oc_tier_t tier;
    oc_band_t dl_band, ul_band;
    int       attach_idle; /* answer ATTACH with an empty grant */
    uint8_t   mode;        /* OC_SIG_MODE_*: the beacon's until the core says otherwise */
    int       sync_ch;     /* the anchor, 0-51; -1: the cell's default (seed % 6) */
    int       fixed_sync;  /* every beacon on the anchor (Part 97 only) */
} ocr_cfg_t;

typedef struct {
    void *ctx;
    int  (*board_send)(void *ctx, oc_msg_t *m); /* the seq it went out with (0-255), or -1 */
    void (*log)(void *ctx, const char *line);
} ocr_io_t;

typedef struct {
    ocr_io_t      io;
    ocr_cfg_t     cfg;
    ocb_cell_t    cell;
    oc_cell_t    *net;
    ocb_time_t    time;
    ocb_one_map_t map[OCB_ONE_MAP_FRAMES];
    uint64_t      started;        /* realtime */
    uint32_t      status_frame;   /* the board's frame at status_at (realtime) */
    uint64_t      status_at;
    int           have_status;    /* a STATUS with a frame, since the board last lost its time */
    int           board_has_time; /* the latest STATUS had a frame */
    uint32_t      next_f;
    int           have_nf;
    uint32_t      last_host_frame;
    uint64_t      mono;           /* oc_cell's clock, for the hooks */
    uint8_t       mode_on_air;
    uint8_t       sent_type[256]; /* message type per seq, to name ACK errors */
    uint32_t      ack_err[16][8]; /* [message type][ack status] */
    uint32_t      schedules;
} ocr_t;

/* 0, or -1 with the reason logged: the tier and bands don't fit a frame, or
 * the anchor is not one this mode allows. */
int  ocr_init(ocr_t *b, const ocr_io_t *io, const ocr_cfg_t *cfg, oc_cell_t *net, uint64_t rt_us);
/* The CONFIG message oc-cell sends the board at start. */
void ocr_config_msg(const ocr_cfg_t *cfg, oc_msg_t *m);
/* A message from the board. */
void ocr_board_rx(ocr_t *b, const oc_msg_t *m, uint64_t rt_us, uint64_t mono_us);
/* Labels, link states, the network's mode and list version, and every
 * SCHEDULE due. Call at least every 10 ms. */
void ocr_tick(ocr_t *b, uint64_t rt_us, uint64_t mono_us);
/* oc_cell's radio: one DL payload for tmid (0 queued), and its channel
 * (on: page it if it has no legs; off: release them). */
int  ocr_dl(ocr_t *b, uint32_t tmid, const uint8_t *p, uint8_t n);
void ocr_channel(ocr_t *b, uint32_t tmid, int on);
/* One line for the log: timebase, frame, counters, ACK errors, terminals. */
void ocr_status_line(const ocr_t *b, char *out, size_t cap);

#endif
```

Create `oc-cell/ocr.c`:
```c
#include "ocr.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "oc_clock.h"

static void say(ocr_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(ocr_t *b, const char *fmt, ...)
{
    char line[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (b->io.log != NULL) b->io.log(b->io.ctx, line);
}

static int bsend(ocr_t *b, oc_msg_t *m)
{
    int seq = b->io.board_send(b->io.ctx, m);
    if (seq >= 0) b->sent_type[seq & 0xFF] = m->type;
    return seq;
}

/* ocb_cell's hooks: the radio's upper layer is oc_cell. */
static void on_ul(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    ocr_t *b = ctx;
    oc_cell_ul(b->net, tmid, p, n, b->mono);
}

static void on_upper(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    ocr_t *b = ctx;
    oc_cell_upper(b->net, tmid, p, n, b->mono);
}

/* The beacon's PART97 flag and anchor for a mode. 0, or -1 (the anchor is
 * not allowed in it: the cell goes off air rather than beacon wrongly). */
static int apply_mode(ocr_t *b, uint8_t mode)
{
    b->cell.part97 = mode == OC_SIG_MODE_PART97;
    b->mode_on_air = mode;
    if (b->cfg.sync_ch < 0 && !b->cfg.fixed_sync) {
        b->cell.off = 0;
        return 0;
    }
    uint8_t ch = b->cfg.sync_ch >= 0 ? (uint8_t)b->cfg.sync_ch : b->cell.sync_ch;
    if (ocb_cell_set_sync(&b->cell, ch, b->cfg.fixed_sync) != 0) {
        b->cell.off = 1;
        say(b, "radio: anchor %u%s is not allowed in %s: the cell is OFF AIR (fix sync_ch/fixed_sync or the cell's "
               "mode)",
            ch, b->cfg.fixed_sync ? " with fixed sync" : "", mode == OC_SIG_MODE_PART97 ? "part97" : "part15");
        return -1;
    }
    b->cell.off = 0;
    return 0;
}

void ocr_config_msg(const ocr_cfg_t *cfg, oc_msg_t *m)
{
    memset(m, 0, sizeof(*m));
    m->type = OC_MSG_CONFIG;
    m->u.config.role = cfg->internal ? OC_ROLE_BS_RADIO_BENCH : OC_ROLE_BS_RADIO;
    m->u.config.band = OC_BAND_915;
    m->u.config.radio_index = 0;
    m->u.config.cell_seed = cfg->cell_seed;
}

int ocr_init(ocr_t *b, const ocr_io_t *io, const ocr_cfg_t *cfg, oc_cell_t *net, uint64_t rt_us)
{
    oc_grant_leg_t dl, ul;
    memset(b, 0, sizeof(*b));
    b->io = *io;
    b->cfg = *cfg;
    b->net = net;
    b->started = rt_us;
    ocb_time_init(&b->time, cfg->internal);
    ocb_cell_init(&b->cell, cfg->cell_seed, cfg->tier, cfg->dl_band, cfg->ul_band);
    b->cell.attach_idle = cfg->attach_idle;
    const ocb_cell_hooks_t h = { b, on_ul, on_upper };
    ocb_cell_set_hooks(&b->cell, &h);
    if (ocb_cell_legs(&b->cell, 0, &dl, &ul) != 0) {
        say(b, "radio: the tier and bands don't fit the frame");
        return -1;
    }
    if (apply_mode(b, cfg->mode) != 0) return -1;
    say(b, "radio: seed %08x, anchor ch %u (%u.%02u MHz), %s sync, %s PPS", (unsigned)cfg->cell_seed, b->cell.sync_ch,
        (unsigned)(oc_channel_freq_hz(OC_BAND_915, b->cell.sync_ch) / 1000000u),
        (unsigned)(oc_channel_freq_hz(OC_BAND_915, b->cell.sync_ch) % 1000000u / 10000u),
        b->cell.fixed_sync ? "fixed" : "cycle", cfg->internal ? "internal" : "GPS");
    return 0;
}

void ocr_board_rx(ocr_t *b, const oc_msg_t *m, uint64_t rt_us, uint64_t mono_us)
{
    b->mono = mono_us;
    if (m->type == OC_MSG_STATUS) {
        if (rt_us - b->started < OCR_STALE_US) return; /* queued on the board before we opened it */
        int had = b->board_has_time;
        b->board_has_time = m->u.status.frame_number != 0;
        if (b->board_has_time) {
            b->status_frame = m->u.status.frame_number;
            b->status_at = rt_us;
            b->have_status = 1;
            if (!had) say(b, "radio: board timebase, frame %u (%u labels sent)", (unsigned)b->status_frame, b->time.sent);
        } else if (had) {
            say(b, "radio: the board LOST its timebase (reset?): labelling it again");
            b->have_status = 0;
            b->have_nf = 0;
        }
    } else if (m->type == OC_MSG_ACK) {
        uint8_t st = m->u.ack.status;
        if (st != OC_ACK_OK) b->ack_err[b->sent_type[m->u.ack.acked_seq] & 15][st & 7]++;
        if (b->sent_type[m->u.ack.acked_seq] == OC_MSG_TIME) ocb_time_ack(&b->time, m->u.ack.acked_seq, st, rt_us);
    } else if (m->type == OC_MSG_RX_REPORT) {
        oc_rx_report_t r = m->u.rx_report;
        const ocb_one_map_t *map = &b->map[r.frame_number % OCB_ONE_MAP_FRAMES];
        if (map->frame != r.frame_number || r.slot_index >= map->n) return;
        oc_band_t band = map->band[r.slot_index] ? OC_BAND_2G4 : OC_BAND_915;
        r.slot_index = map->idx[r.slot_index];
        ocb_cell_on_rx(&b->cell, band, &r);
    }
}

void ocr_tick(ocr_t *b, uint64_t rt_us, uint64_t mono_us)
{
    oc_msg_t m;
    b->mono = mono_us;

    uint32_t s = ocb_time_due(&b->time, rt_us, b->board_has_time);
    if (s != 0) {
        memset(&m, 0, sizeof(m));
        m.type = OC_MSG_TIME;
        m.u.time.unix_s = s;
        int seq = bsend(b, &m);
        if (seq >= 0) ocb_time_sent(&b->time, (uint8_t)seq, rt_us);
    }

    for (unsigned k = 0; k < OCB_CELL_MAX_TERMS; k++) {
        if (b->cell.terms[k].used) {
            uint32_t tmid = b->cell.terms[k].tmid;
            oc_cell_radio_link(b->net, tmid, ocb_cell_granted(&b->cell, tmid), mono_us);
        }
    }

    uint8_t mode = b->net->net.cfg.mode;
    if (mode != b->mode_on_air) {
        say(b, "radio: the core says %s: the beacon follows", mode == OC_SIG_MODE_PART97 ? "part97" : "part15");
        apply_mode(b, mode);
    }
    uint8_t cv = (uint8_t)(oc_cell_list_ver(b->net) & OC_BCN_MAX_CFG_VER);
    if (cv != b->cell.cfg_ver) {
        b->cell.cfg_ver = cv;
        say(b, "radio: beacon cfg_ver %u (channel list v%u)", cv, oc_cell_list_ver(b->net));
    }

    uint32_t hf = oc_frame_from_unix_us(rt_us);
    if (hf == b->last_host_frame) return;
    b->last_host_frame = hf;
    uint32_t f;
    if (!b->cfg.internal) {
        f = hf;
    } else if (b->have_status) {
        f = b->status_frame + (uint32_t)((rt_us - b->status_at) / OC_FRAME_US);
    } else {
        return; /* no timebase yet: nothing the board could run */
    }
    /* every board frame up to f + lead gets one schedule, gaps included, as
     * ocbench does: a skipped frame loses its UL */
    uint32_t target = f + OCR_LEAD_FRAMES;
    int32_t ahead = (int32_t)(target - b->next_f);
    if (!b->have_nf || ahead > 8 || ahead < -8) {
        b->have_nf = 1;
        b->next_f = target;
    }
    while ((int32_t)(target - b->next_f) >= 0) {
        if (ocb_merge_bands(&b->cell, b->next_f++, 0, b->map, &m) == 0 && bsend(b, &m) >= 0) b->schedules++;
    }
}

int ocr_dl(ocr_t *b, uint32_t tmid, const uint8_t *p, uint8_t n) { return ocb_cell_dl_push(&b->cell, tmid, p, n); }

void ocr_channel(ocr_t *b, uint32_t tmid, int on)
{
    if (on && !ocb_cell_granted(&b->cell, tmid)) ocb_cell_page(&b->cell, tmid);
    else if (!on) ocb_cell_release(&b->cell, tmid);
}

void ocr_status_line(const ocr_t *b, char *out, size_t cap)
{
    uint32_t errs = 0, late = 0;
    for (int t = 0; t < 16; t++) {
        for (int k = 1; k < 8; k++) errs += b->ack_err[t][k];
        late += b->ack_err[t][OC_ACK_ERR_LATE];
    }
    int n = snprintf(out, cap, "radio: %s, frame %u, schedules %u, rach %u attach %u grants %u, ack errors %u (late %u)",
                     b->board_has_time ? "timebase" : "NO TIMEBASE", (unsigned)b->next_f, b->schedules, b->cell.rach_rx,
                     b->cell.attaches, b->cell.grants_sent, errs, late);
    for (unsigned k = 0; k < OCB_CELL_MAX_TERMS && n > 0 && (size_t)n < cap; k++) {
        const ocb_cell_term_t *t = &b->cell.terms[k];
        if (t->used) n += snprintf(out + n, cap - (size_t)n, " | %08x %s ul %u", t->tmid, t->have_cur ? "granted" : "idle", t->ul_rx);
    }
}
```

- [ ] **Step 5: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build >/dev/null && cmake --build build --target test_ocr 2>&1 | grep -E "error|warning"; build/tests/test_ocr | tail -3`
Expected: no compiler output, then `6 Tests 0 Failures 0 Ignored` and `OK`.

If `test_a_call_to_the_echo_service` fails at its `TEST_ASSERT_FALSE(ocb_cell_granted(...))`, the plan-1 `oc_sig_net` no longer releases an idle terminal after 5 s; drop that one assertion (the call must still connect) and report it.

- [ ] **Step 6: The whole suite**

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 1`.

- [ ] **Step 7: Commit**

```bash
cd /home/devin/Documents/opencell/pi
git add .gitmodules third_party/opencell-core CMakeLists.txt .gitignore oc-cell/CMakeLists.txt oc-cell/ocr.h oc-cell/ocr.c \
        tests/CMakeLists.txt tests/test_ocr.c
git commit -m "oc-cell: the core as a submodule; ocr, the radio backend on one W12 (ocb_cell + oc_cell), board-level test

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 8: The `oc-cell` program: config, the board's port, the simulated radio, the core client

**Repo:** `opencell-pi`, branch `oc-cell`, at `/home/devin/Documents/opencell/pi`. **Starts:** after Task 7.

`oc-cell` wraps `oc_cell` and a radio in one `poll()` loop (spec §4.1): the board's serial port (or, `radio = sim`, simulated terminals driven through a control FIFO), the link to the core, and two clocks. At start it opens the board exclusively (Review Focus 2), resets it (a fresh PPS phase), sends it a CONFIG and waits for the ACK only a bs-radio sends, then starts `ocr`. It dials the core, and after a drop dials again 1 s later, doubling to 30 s, back to 1 s once a HELLO is accepted; a fresh random boot id per start tells the core the process is new (§7.9). `ocs`, the simulated radio, is plan 1's `net_sim.h` terminal model inside the program, so Task 9 can run whole processes; a simulated terminal keeps its identity in a file, as a real terminal keeps it in NVS.

**Files:**
- Create: `oc-cell/occ_cfg.h`, `oc-cell/occ_cfg.c`, `oc-cell/occ_board.h`, `oc-cell/occ_board.c`, `oc-cell/ocs.h`, `oc-cell/ocs.c`, `oc-cell/occ_main.c`, `dist/oc-cell.conf.example`, `dist/systemd/oc-cell.service`
- Modify: `oc-cell/CMakeLists.txt`, `tests/CMakeLists.txt`
- Test: `tests/test_occ_cfg.c`

**Interfaces:**
- Consumes: `ocr_*` (Task 7); `oc_kv_*`, `oc_conn_*`, `oc_unix_connect`, `oc_backoff_next`, `oc_log*` (Task 2); `oc_cell_*` (plan 1); `oc_sig_term_*`, `oc_sig_ident_pack/unpack/new` (firmware); `oc_link_write_frame`, `oc_framer_*`; `ocb_parse_tier`.
- Produces (`occ_lib`):
  ```c
  typedef struct { uint32_t cell_id; char core[160]; int sim; char board[160]; int board_reset; ocr_cfg_t radio;
                   uint16_t period_s; struct { uint32_t tmid; char qr[160]; } sim_term[4]; unsigned nsim;
                   char sim_state[160], sim_control[160]; } occ_cfg_t;
  int  occ_cfg_parse(occ_cfg_t *c, oc_kv_t *kv, char *err, size_t cap);
  typedef struct { int fd; oc_framer_t framer; uint8_t seq; } oc_board_t;
  int  oc_board_open(oc_board_t *b, const char *path, char *err, size_t cap);
  void oc_board_reset(oc_board_t *b);
  int  oc_board_send(oc_board_t *b, oc_msg_t *m);
  int  oc_board_read(oc_board_t *b, void (*cb)(void *ctx, const oc_msg_t *m), void *ctx);
  void oc_board_close(oc_board_t *b);
  void ocs_init(ocs_t *s, oc_cell_t *net, void (*log)(void *ctx, const char *line), void *ctx);
  int  ocs_add(ocs_t *s, uint32_t tmid, const char *qr, const char *dir, uint64_t mono_us);
  void ocs_tick(ocs_t *s, uint64_t mono_us);
  int  ocs_dl(ocs_t *s, uint32_t tmid, const uint8_t *p, uint8_t n);
  int  ocs_command(ocs_t *s, const char *line, uint64_t mono_us); /* "TMID dial NUMBER|answer|reject|hangup|talk TEXT|off|on" */
  ```
- Produces: the program `oc-cell [--config FILE] | --version` (default `/etc/opencell/oc-cell.conf`); its log lines that Task 9 and the bench read: `sim TMID: activating|known terminal, registering|registered|incoming|connected|ended cause N|data 'TEXT'`, `core: connected to …`, `core: HELLO accepted`, `core: link lost; again in N s`, `radio: board timebase, frame N (M labels sent)`, and every 60 s `core linked|DOWN | radio: …`.
- Produces: `dist/systemd/oc-cell.service` (user `oc-cell`, groups `oc-cell` and `dialout`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_occ_cfg.c`:
```c
#define _GNU_SOURCE
/* oc-cell.conf, and the board's serial port on a pseudo-terminal: frames
 * both ways, and one process per port. */
#include "unity.h"

#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "occ_board.h"
#include "occ_cfg.h"

void setUp(void) {}
void tearDown(void) {}

static int parse(const char *text, occ_cfg_t *c, char *err)
{
    oc_kv_t kv;
    TEST_ASSERT_EQUAL_INT(0, oc_kv_parse(&kv, text, "oc-cell.conf"));
    return occ_cfg_parse(c, &kv, err, 256);
}

static void test_a_board_cell(void)
{
    occ_cfg_t c;
    char err[256] = "";
    TEST_ASSERT_EQUAL_INT_MESSAGE(0,
                                  parse("cell_id = 1\nboard = /dev/serial/by-id/x\nboard_role = bench\n"
                                        "cell_seed = 0xcafef00d\ntier = edge\nmode = part97\nsync_ch = 40\n"
                                        "fixed_sync = 1\n",
                                        &c, err),
                                  err);
    TEST_ASSERT_EQUAL_UINT32(1, c.cell_id);
    TEST_ASSERT_EQUAL_STRING("/run/opencell/core.sock", c.core);
    TEST_ASSERT_EQUAL_INT(0, c.sim);
    TEST_ASSERT_EQUAL_STRING("/dev/serial/by-id/x", c.board);
    TEST_ASSERT_EQUAL_INT(1, c.board_reset);
    TEST_ASSERT_EQUAL_INT(1, c.radio.internal);
    TEST_ASSERT_EQUAL_HEX32(0xCAFEF00Du, c.radio.cell_seed);
    TEST_ASSERT_EQUAL_INT(OC_TIER_EDGE, c.radio.tier);
    TEST_ASSERT_EQUAL_INT(OC_BAND_915, c.radio.dl_band);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_MODE_PART97, c.radio.mode);
    TEST_ASSERT_EQUAL_INT(40, c.radio.sync_ch);
    TEST_ASSERT_EQUAL_INT(1, c.radio.fixed_sync);
    TEST_ASSERT_EQUAL_UINT16(1800, c.period_s);
    TEST_ASSERT_EQUAL_INT(0, parse("cell_id = 2\nboard = /x\n", &c, err));
    TEST_ASSERT_EQUAL_INT(-1, c.radio.sync_ch); /* the cell's default anchor */
    TEST_ASSERT_EQUAL_INT(0, c.radio.internal);
}

static void test_bad_configs_are_named(void)
{
    occ_cfg_t c;
    char err[256];
    TEST_ASSERT_EQUAL_INT(-1, parse("board = /x\n", &c, err));
    TEST_ASSERT_EQUAL_STRING("cell_id is missing", err);
    TEST_ASSERT_EQUAL_INT(-1, parse("cell_id = 1\n", &c, err));
    TEST_ASSERT_NOT_NULL(strstr(err, "board is missing"));
    TEST_ASSERT_EQUAL_INT(-1, parse("cell_id = 1\nboard = /x\nmode = part16\n", &c, err));
    TEST_ASSERT_EQUAL_STRING("mode = 'part16': part15 or part97", err);
    TEST_ASSERT_EQUAL_INT(-1, parse("cell_id = 1\nboard = /x\nsync_ch = 52\n", &c, err));
    TEST_ASSERT_EQUAL_STRING("sync_ch = '52': a number 0-51", err);
    TEST_ASSERT_EQUAL_INT(-1, parse("cell_id = 1\nboard = /x\nbord_role = bench\n", &c, err));
    TEST_ASSERT_EQUAL_STRING("line 3: unknown key 'bord_role'", err);
    TEST_ASSERT_EQUAL_INT(-1, parse("cell_id = 1\nradio = sim\n", &c, err));
    TEST_ASSERT_EQUAL_STRING("radio = sim needs sim_term and sim_state", err);
    TEST_ASSERT_EQUAL_INT(0, parse("cell_id = 1\nradio = sim\nsim_state = /tmp\nsim_term = 76000001 opencell:2:x\n"
                                   "sim_term = 76000002 opencell:2:y\n",
                                   &c, err));
    TEST_ASSERT_EQUAL_UINT(2, c.nsim);
    TEST_ASSERT_EQUAL_HEX32(0x76000002u, c.sim_term[1].tmid);
    TEST_ASSERT_EQUAL_STRING("opencell:2:y", c.sim_term[1].qr);
}

/* The example the bench copies to /etc/opencell/oc-cell.conf. */
static void test_the_example_config_parses(void)
{
    oc_kv_t kv;
    occ_cfg_t c;
    char err[256] = "";
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_kv_load(&kv, OCC_EXAMPLE), kv.err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, occ_cfg_parse(&c, &kv, err, sizeof(err)), err);
    TEST_ASSERT_EQUAL_UINT32(1, c.cell_id);
    TEST_ASSERT_EQUAL_INT(1, c.radio.internal);
    TEST_ASSERT_NOT_NULL(strstr(c.board, "44:B1:76:AE:1A:E8"));
}

static int got_type = -1;
static void on_msg(void *ctx, const oc_msg_t *m)
{
    (void)ctx;
    got_type = m->type;
}

/* Frames cross the port both ways. */
static void test_frames_on_the_port(void)
{
    int master, slave;
    char name[64], err[256];
    TEST_ASSERT_EQUAL_INT(0, openpty(&master, &slave, name, NULL, NULL));
    close(slave);
    oc_board_t b;
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_board_open(&b, name, err, sizeof(err)), err);
    oc_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_MSG_STATUS;
    m.u.status.frame_number = 77;
    uint8_t wire[OC_FRAMER_RAW_CAP + 2];
    size_t n = oc_link_write_frame(&m, wire, sizeof(wire));
    TEST_ASSERT_EQUAL_INT((int)n, (int)write(master, wire, n));
    usleep(20000);
    TEST_ASSERT_EQUAL_INT(0, oc_board_read(&b, on_msg, NULL));
    TEST_ASSERT_EQUAL_INT(OC_MSG_STATUS, got_type);

    memset(&m, 0, sizeof(m));
    m.type = OC_MSG_TIME;
    m.u.time.unix_s = 1790000000u;
    TEST_ASSERT_EQUAL_INT(0, oc_board_send(&b, &m));
    TEST_ASSERT_EQUAL_INT(1, oc_board_send(&b, &m)); /* seq counts */
    usleep(20000);
    uint8_t buf[256];
    ssize_t r = read(master, buf, sizeof(buf));
    oc_framer_t fr;
    oc_framer_init(&fr);
    oc_msg_t in;
    int frames = 0;
    for (ssize_t i = 0; i < r; i++) frames += oc_framer_push(&fr, buf[i], &in);
    TEST_ASSERT_EQUAL_INT(2, frames);
    TEST_ASSERT_EQUAL_UINT8(OC_MSG_TIME, in.type);
    TEST_ASSERT_EQUAL_UINT32(1790000000u, in.u.time.unix_s);
    oc_board_close(&b);
    close(master);
}

/* Review Focus 2: a second process on the port is refused; the first keeps it. */
static void test_the_board_port_is_exclusive(void)
{
    int master, slave;
    char name[64], err[256];
    TEST_ASSERT_EQUAL_INT(0, openpty(&master, &slave, name, NULL, NULL));
    close(slave);
    oc_board_t a, b;
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_board_open(&a, name, err, sizeof(err)), err);
    TEST_ASSERT_EQUAL_INT(-1, oc_board_open(&b, name, err, sizeof(err)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err, "in use by another process"), err);
    int other = open(name, O_RDWR | O_NOCTTY); /* ocbench, oc_console.py */
    if (geteuid() != 0) TEST_ASSERT_EQUAL_INT(-1, other);
    else if (other >= 0) close(other);
    oc_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_MSG_TIME;
    TEST_ASSERT_TRUE(oc_board_send(&a, &m) >= 0); /* the first still has it */
    oc_board_close(&a);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, oc_board_open(&b, name, err, sizeof(err)), err); /* free again */
    oc_board_close(&b);
    TEST_ASSERT_EQUAL_INT(-1, oc_board_open(&b, "/dev/null", err, sizeof(err)));
    TEST_ASSERT_EQUAL_STRING("/dev/null: not a serial port", err);
    close(master);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a_board_cell);
    RUN_TEST(test_bad_configs_are_named);
    RUN_TEST(test_the_example_config_parses);
    RUN_TEST(test_frames_on_the_port);
    RUN_TEST(test_the_board_port_is_exclusive);
    return UNITY_END();
}
```

Append to `tests/CMakeLists.txt`:
```cmake
oc_test(test_occ_cfg occ_lib)
target_compile_definitions(test_occ_cfg PRIVATE OCC_EXAMPLE="${PROJECT_SOURCE_DIR}/dist/oc-cell.conf.example")
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build >/dev/null && cmake --build build --target test_occ_cfg 2>&1 | grep -oE "occ_board.h: No such file or directory" | head -1`
Expected: `occ_board.h: No such file or directory`.

- [ ] **Step 3: The config and the board's port**

Create `oc-cell/occ_cfg.h`:
```c
/* oc-cell.conf (network-core spec §4.1 "Config"): key = value lines, see
 * dist/oc-cell.conf.example.
 *
 *   cell_id = 1                          this cell, as `oc-core admin cell add` made it
 *   core = /run/opencell/core.sock       the core's cell socket (plan 9: host:port with TLS)
 *   radio = board                        board: one W12 on USB; sim: simulated terminals (tests)
 *   board = /dev/serial/by-id/...        the bs-radio W12
 *   board_role = bench                   bench: its internal 1 Hz PPS; bs: GPS PPS on its header
 *   board_reset = 1                      reset the board at start (a fresh PPS phase, no stale state)
 *   cell_seed = 0xcafef00d               hopping seed (the default anchor is seed % 6)
 *   tier = edge                          near | mid | edge
 *   dl_band = 915, ul_band = 915         915 | 2g4 (one board switches bands per slot)
 *   mode = part15                        part15 | part97, until the core's HELLO_ACK says
 *   sync_ch = 1, fixed_sync = 0          the anchor (0-51) and FIXED sync (Part 97 only)
 *   attach_idle = 0                      1: an attaching terminal gets no legs until paged
 *   period = 1800                        registration period, until the core's HELLO_ACK says
 *   sim_term = 76000001 opencell:2:...   (radio = sim) a terminal and its activation code; up to 4
 *   sim_state = /var/lib/...             (radio = sim) where terminals keep their identity
 *   sim_control = /run/.../ctl           (radio = sim) a FIFO of commands: "76000001 dial +883..."
 */
#ifndef OCC_CFG_H
#define OCC_CFG_H

#include <stddef.h>
#include <stdint.h>

#include "oc_kv.h"
#include "ocr.h"

#define OCC_SIM_TERMS 4u

typedef struct {
    uint32_t  cell_id;
    char      core[OC_KV_VAL];
    int       sim;
    char      board[OC_KV_VAL];
    int       board_reset;
    ocr_cfg_t radio;
    uint16_t  period_s;
    struct {
        uint32_t tmid;
        char     qr[OC_KV_VAL];
    } sim_term[OCC_SIM_TERMS];
    unsigned nsim;
    char     sim_state[OC_KV_VAL];
    char     sim_control[OC_KV_VAL];
} occ_cfg_t;

/* 0, or -1 with the reason in err (an unknown key, a missing or bad value). */
int occ_cfg_parse(occ_cfg_t *c, oc_kv_t *kv, char *err, size_t cap);

#endif
```

Create `oc-cell/occ_cfg.c`:
```c
#include "occ_cfg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ocbench_core.h"

static const char *const KEYS[] = { "cell_id", "core", "radio", "board", "board_role", "board_reset", "cell_seed",
                                    "tier", "dl_band", "ul_band", "mode", "sync_ch", "fixed_sync", "attach_idle",
                                    "period", "sim_term", "sim_state", "sim_control", NULL };

/* v is a or b: *out 0 or 1. -1 otherwise. */
static int one_of(const char *v, const char *a, const char *b, int *out)
{
    if (strcmp(v, a) == 0) *out = 0;
    else if (strcmp(v, b) == 0) *out = 1;
    else return -1;
    return 0;
}

int occ_cfg_parse(occ_cfg_t *c, oc_kv_t *kv, char *err, size_t cap)
{
    long long v;
    int x;
    const char *s;
    memset(c, 0, sizeof(*c));
    if (!oc_kv_known(kv, KEYS)) goto kv_err;
    if (oc_kv_get(kv, "cell_id") == NULL) {
        snprintf(err, cap, "cell_id is missing");
        return -1;
    }
    if (oc_kv_num(kv, "cell_id", 1, 0xFFFFFFFFll, 0, &v) != 0) goto kv_err;
    c->cell_id = (uint32_t)v;
    snprintf(c->core, sizeof(c->core), "%s", oc_kv_get(kv, "core") ? oc_kv_get(kv, "core") : "/run/opencell/core.sock");
    s = oc_kv_get(kv, "radio");
    if (s != NULL && one_of(s, "board", "sim", &c->sim) != 0) {
        snprintf(err, cap, "radio = '%s': board or sim", s);
        return -1;
    }
    if (!c->sim) {
        if (oc_kv_get(kv, "board") == NULL) {
            snprintf(err, cap, "board is missing: the bs-radio W12's /dev/serial/by-id/... path");
            return -1;
        }
        snprintf(c->board, sizeof(c->board), "%s", oc_kv_get(kv, "board"));
    }
    s = oc_kv_get(kv, "board_role");
    x = 0;
    if (s != NULL && one_of(s, "bs", "bench", &x) != 0) {
        snprintf(err, cap, "board_role = '%s': bs (GPS PPS) or bench (internal PPS)", s);
        return -1;
    }
    c->radio.internal = x;
    if (oc_kv_num(kv, "board_reset", 0, 1, 1, &v) != 0) goto kv_err;
    c->board_reset = (int)v;
    if (oc_kv_num(kv, "cell_seed", 0, 0xFFFFFFFFll, 0xCAFEF00Dll, &v) != 0) goto kv_err;
    c->radio.cell_seed = (uint32_t)v;
    s = oc_kv_get(kv, "tier");
    c->radio.tier = OC_TIER_EDGE;
    if (s != NULL && ocb_parse_tier(s, &c->radio.tier) != 0) {
        snprintf(err, cap, "tier = '%s': near, mid or edge", s);
        return -1;
    }
    const char *bands[2] = { "dl_band", "ul_band" };
    for (int i = 0; i < 2; i++) {
        s = oc_kv_get(kv, bands[i]);
        x = 0;
        if (s != NULL && one_of(s, "915", "2g4", &x) != 0) {
            snprintf(err, cap, "%s = '%s': 915 or 2g4", bands[i], s);
            return -1;
        }
        if (i == 0) c->radio.dl_band = x ? OC_BAND_2G4 : OC_BAND_915;
        else c->radio.ul_band = x ? OC_BAND_2G4 : OC_BAND_915;
    }
    s = oc_kv_get(kv, "mode");
    x = 0;
    if (s != NULL && one_of(s, "part15", "part97", &x) != 0) {
        snprintf(err, cap, "mode = '%s': part15 or part97", s);
        return -1;
    }
    c->radio.mode = x ? OC_SIG_MODE_PART97 : OC_SIG_MODE_PART15;
    if (oc_kv_num(kv, "sync_ch", 0, 51, -1, &v) != 0) goto kv_err;
    c->radio.sync_ch = (int)v;
    if (oc_kv_num(kv, "fixed_sync", 0, 1, 0, &v) != 0) goto kv_err;
    c->radio.fixed_sync = (int)v;
    if (oc_kv_num(kv, "attach_idle", 0, 1, 0, &v) != 0) goto kv_err;
    c->radio.attach_idle = (int)v;
    if (oc_kv_num(kv, "period", 60, 65535, 1800, &v) != 0) goto kv_err;
    c->period_s = (uint16_t)v;
    for (unsigned i = 0; (s = oc_kv_nth(kv, "sim_term", i)) != NULL; i++) {
        char *end;
        unsigned long tmid = strtoul(s, &end, 16);
        while (*end == ' ') end++;
        if (i >= OCC_SIM_TERMS || tmid == 0 || tmid > 0xFFFFFFFFul || *end == '\0') {
            snprintf(err, cap, "sim_term = '%s': TMID (hex) and activation code; at most %u", s, OCC_SIM_TERMS);
            return -1;
        }
        c->sim_term[i].tmid = (uint32_t)tmid;
        snprintf(c->sim_term[i].qr, sizeof(c->sim_term[i].qr), "%s", end);
        c->nsim = i + 1u;
    }
    snprintf(c->sim_state, sizeof(c->sim_state), "%s", oc_kv_get(kv, "sim_state") ? oc_kv_get(kv, "sim_state") : "");
    snprintf(c->sim_control, sizeof(c->sim_control), "%s",
             oc_kv_get(kv, "sim_control") ? oc_kv_get(kv, "sim_control") : "");
    if (c->sim && (c->nsim == 0 || c->sim_state[0] == '\0')) {
        snprintf(err, cap, "radio = sim needs sim_term and sim_state");
        return -1;
    }
    return 0;
kv_err:
    snprintf(err, cap, "%s", kv->err);
    return -1;
}
```

Create `oc-cell/occ_board.h`:
```c
/* The bs-radio W12's serial port (its USB-Serial-JTAG): raw, 2 Mbit/s, HUPCL
 * off (dropping DTR/RTS on close would reset an ESP32-S3), and held
 * exclusively (TIOCEXCL and flock): one process per serial port, so a second
 * oc-cell, ocbench or oc_console.py is refused instead of silently splitting
 * the board's frames with this one. Frames are oc_link's. */
#ifndef OCC_BOARD_H
#define OCC_BOARD_H

#include <stddef.h>
#include <stdint.h>

#include "oc_link.h"

typedef struct {
    int         fd;
    oc_framer_t framer;
    uint8_t     seq;
} oc_board_t;

/* 0, or -1 with the reason in err (no such port, not a tty, in use). */
int  oc_board_open(oc_board_t *b, const char *path, char *err, size_t cap);
/* Restart the board: an RTS pulse with DTR low, as esptool does on the
 * ESP32-S3's USB-Serial-JTAG (the port stays open). */
void oc_board_reset(oc_board_t *b);
/* The seq it went out with, or -1. */
int  oc_board_send(oc_board_t *b, oc_msg_t *m);
/* Reads what the port has; each whole message to cb. 0, or -1 (the port
 * went away: unplugged, or the board re-enumerated). */
int  oc_board_read(oc_board_t *b, void (*cb)(void *ctx, const oc_msg_t *m), void *ctx);
void oc_board_close(oc_board_t *b);

#endif
```

Create `oc-cell/occ_board.c`:
```c
#define _GNU_SOURCE
#include "occ_board.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

int oc_board_open(oc_board_t *b, const char *path, char *err, size_t cap)
{
    memset(b, 0, sizeof(*b));
    b->fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (b->fd < 0) {
        snprintf(err, cap, "%s: %s%s", path, strerror(errno),
                 errno == EBUSY ? " (in use by another process: one process per serial port)" : "");
        return -1;
    }
    if (!isatty(b->fd)) {
        snprintf(err, cap, "%s: not a serial port", path);
        oc_board_close(b);
        return -1;
    }
    if (flock(b->fd, LOCK_EX | LOCK_NB) != 0 || ioctl(b->fd, TIOCEXCL) != 0) {
        snprintf(err, cap, "%s: in use by another process (one process per serial port: stop it first)", path);
        oc_board_close(b);
        return -1;
    }
    struct termios t;
    if (tcgetattr(b->fd, &t) == 0) {
        cfmakeraw(&t);
        cfsetispeed(&t, B2000000);
        cfsetospeed(&t, B2000000);
        t.c_cflag |= CLOCAL | CREAD;
        t.c_cflag &= ~(tcflag_t)HUPCL; /* dropping DTR/RTS on close resets an ESP32-S3 on its USB port */
        tcsetattr(b->fd, TCSANOW, &t);
        tcflush(b->fd, TCIOFLUSH);
    }
    oc_framer_init(&b->framer);
    return 0;
}

void oc_board_reset(oc_board_t *b)
{
    int dtr = TIOCM_DTR, rts = TIOCM_RTS;
    struct timespec pulse = { 0, 200000000 };
    ioctl(b->fd, TIOCMBIC, &dtr);
    ioctl(b->fd, TIOCMBIS, &rts);
    nanosleep(&pulse, NULL);
    ioctl(b->fd, TIOCMBIC, &rts);
}

int oc_board_send(oc_board_t *b, oc_msg_t *m)
{
    uint8_t wire[OC_FRAMER_RAW_CAP + 2];
    m->seq = b->seq++;
    size_t n = oc_link_write_frame(m, wire, sizeof(wire)), off = 0;
    if (n == 0) return -1;
    for (int spins = 0; off < n && spins < 1000; spins++) {
        ssize_t w = write(b->fd, wire + off, n - off);
        if (w > 0) off += (size_t)w;
        else if (w < 0 && errno != EAGAIN && errno != EINTR) return -1;
    }
    return off == n ? m->seq : -1;
}

int oc_board_read(oc_board_t *b, void (*cb)(void *ctx, const oc_msg_t *m), void *ctx)
{
    uint8_t buf[4096];
    static oc_msg_t m;
    for (;;) {
        ssize_t r = read(b->fd, buf, sizeof(buf));
        if (r == 0) return -1;
        if (r < 0) return errno == EAGAIN || errno == EINTR ? 0 : -1;
        for (ssize_t k = 0; k < r; k++) {
            if (oc_framer_push(&b->framer, buf[k], &m)) cb(ctx, &m);
        }
    }
}

void oc_board_close(oc_board_t *b)
{
    if (b->fd >= 0) {
        ioctl(b->fd, TIOCNXCL); /* a pty keeps the flag after the last close; a USB port drops it anyway */
        close(b->fd);
    }
    b->fd = -1;
}
```

Create `dist/oc-cell.conf.example`:
```ini
# /etc/opencell/oc-cell.conf: one cell (network-core spec §4.1); the keys
# are described in oc-cell/occ_cfg.h. An unknown key stops oc-cell.
# This is the Pi bench (opencell-bs1, board A on USB, internal PPS).
cell_id = 1
core = /run/opencell/core.sock
radio = board
board = /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_44:B1:76:AE:1A:E8-if00
board_role = bench
board_reset = 1
cell_seed = 0xcafef00d
tier = edge
dl_band = 915
ul_band = 915
mode = part15
attach_idle = 0
```

- [ ] **Step 4: The simulated radio**

Create `oc-cell/ocs.h`:
```c
/* ocs: oc-cell's simulated radio (radio = sim), for the process tests of
 * network-core spec §9.4: oc_sig_term terminals attached straight to
 * oc_cell, one UL and one DL payload each per 120 ms frame, always granted,
 * as the multi-cell simulation (tests/net_sim.h in opencell-core) does. A
 * terminal keeps its identity in a file (sim_state/term-TMID.bin), so it
 * survives an oc-cell restart as a real terminal survives a Pi restart; the
 * first time it activates with its code. Its events, and the app data it
 * receives, go to the log ("sim 76000001: registered"). */
#ifndef OCS_H
#define OCS_H

#include <stdint.h>

#include "oc_cell.h"
#include "oc_sig_term.h"

#define OCS_TERMS 4u
#define OCS_Q     32u

typedef struct {
    uint8_t p[OCS_Q][OC_SIG_LINK_MAX], n[OCS_Q];
    int     head, count;
} ocs_q_t;

typedef struct {
    struct ocs *s;
    uint32_t    tmid;
    int         on; /* in the cell's coverage */
    oc_sig_ident_t id;
    oc_sig_term_t  t;
    ocs_q_t        ul, dl;
    char           path[256];
} ocs_term_t;

typedef struct ocs {
    oc_cell_t *net;
    ocs_term_t term[OCS_TERMS];
    unsigned   n;
    uint64_t   next_frame;
    uint64_t   now; /* of the frame being run */
    void (*log)(void *ctx, const char *line);
    void      *ctx;
} ocs_t;

void ocs_init(ocs_t *s, oc_cell_t *net, void (*log)(void *ctx, const char *line), void *ctx);
/* A terminal: its identity from dir/term-TMID.bin, or else a new one that
 * activates with qr. 0, or -1 (full, or a code that doesn't parse). */
int  ocs_add(ocs_t *s, uint32_t tmid, const char *qr, const char *dir, uint64_t mono_us);
/* One frame when 120 ms have passed. */
void ocs_tick(ocs_t *s, uint64_t mono_us);
/* oc_cell's radio_send. */
int  ocs_dl(ocs_t *s, uint32_t tmid, const uint8_t *p, uint8_t n);
/* A control line: "TMID dial NUMBER | answer | reject | hangup | talk TEXT |
 * off | on" (off: out of coverage). 0, or -1 (logged). */
int  ocs_command(ocs_t *s, const char *line, uint64_t mono_us);

#endif
```

Create `oc-cell/ocs.c`:
```c
#define _GNU_SOURCE
#include "ocs.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "oc_air.h"

#define OCS_FRAME_US 120000u

static void say(ocs_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(ocs_t *s, const char *fmt, ...)
{
    char line[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (s->log != NULL) s->log(s->ctx, line);
}

static int qpush(ocs_q_t *q, const uint8_t *p, uint8_t n)
{
    if (q->count == (int)OCS_Q) return -1;
    int i = (q->head + q->count++) % (int)OCS_Q;
    memcpy(q->p[i], p, n);
    q->n[i] = n;
    return 0;
}

static int qpop(ocs_q_t *q, uint8_t *p, uint8_t *n)
{
    if (q->count == 0) return -1;
    memcpy(p, q->p[q->head], q->n[q->head]);
    *n = q->n[q->head];
    q->head = (q->head + 1) % (int)OCS_Q;
    q->count--;
    return 0;
}

static int t_send(void *c, const uint8_t *p, uint8_t n) { return qpush(&((ocs_term_t *)c)->ul, p, n); }

static int t_svc(void *c, uint8_t cause)
{
    ocs_term_t *t = c;
    uint8_t p = (uint8_t)(OC_SIG_KIND_SVC | cause);
    if (t->on) oc_cell_upper(t->s->net, t->tmid, &p, 1, t->s->now);
    return 0;
}

static void t_save(void *c, const oc_sig_ident_t *id)
{
    ocs_term_t *t = c;
    uint8_t blob[OC_SIG_IDENT_BLOB];
    size_t n = oc_sig_ident_pack(id, blob);
    int fd = open(t->path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, blob, n) != (ssize_t)n) say(t->s, "sim %08x: can't save its identity to %s", t->tmid, t->path);
    if (fd >= 0) close(fd);
}

static void t_event(void *c, const uint8_t *e, uint8_t n)
{
    ocs_term_t *t = c;
    static const char *const names[] = { "?",       "activated", "act_failed", "registered", "reg_failed",
                                         "incoming", "ringing",   "connected",  "ended",      "deactivated" };
    const char *name = e[0] < sizeof(names) / sizeof(names[0]) ? names[e[0]] : "?";
    if (e[0] == OC_SIG_EV_ENDED && n > 5) say(t->s, "sim %08x: ended cause %u", t->tmid, e[5]);
    else say(t->s, "sim %08x: %s", t->tmid, name);
}

void ocs_init(ocs_t *s, oc_cell_t *net, void (*log)(void *ctx, const char *line), void *ctx)
{
    memset(s, 0, sizeof(*s));
    s->net = net;
    s->log = log;
    s->ctx = ctx;
}

int ocs_add(ocs_t *s, uint32_t tmid, const char *qr, const char *dir, uint64_t mono_us)
{
    if (s->n >= OCS_TERMS) return -1;
    ocs_term_t *t = &s->term[s->n];
    memset(t, 0, sizeof(*t));
    t->s = s;
    t->tmid = tmid;
    t->on = 1;
    snprintf(t->path, sizeof(t->path), "%s/term-%08x.bin", dir, tmid);
    uint8_t blob[OC_SIG_IDENT_BLOB + 1];
    int fd = open(t->path, O_RDONLY | O_CLOEXEC);
    ssize_t got = fd >= 0 ? read(fd, blob, sizeof(blob)) : -1;
    if (fd >= 0) close(fd);
    int known = got > 0 && oc_sig_ident_unpack(blob, (size_t)got, &t->id) == 0;
    if (!known) {
        uint8_t r[32];
        if (getrandom(r, sizeof(r), 0) != (ssize_t)sizeof(r) || oc_sig_ident_new(&t->id, r) != 0) return -1;
    }
    const oc_sig_term_io_t io = { t, t_send, t_svc, t_save, t_event };
    oc_sig_term_init(&t->t, &io, &t->id, tmid, mono_us);
    if (!known || !t->id.activated) {
        uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
        size_t n = strlen(qr);
        if (n > OC_SIG_QR_TEXT) return -1;
        cmd[0] = OC_SIG_CMD_ACTIVATE;
        memcpy(cmd + 1, qr, n);
        if (oc_sig_term_command(&t->t, cmd, 1 + n, mono_us) != 0) {
            say(s, "sim %08x: its activation code is refused", tmid);
            return -1;
        }
    }
    say(s, "sim %08x: %s", tmid, known && t->id.activated ? "known terminal, registering" : "activating");
    s->n++;
    return 0;
}

static ocs_term_t *term_of(ocs_t *s, uint32_t tmid)
{
    for (unsigned i = 0; i < s->n; i++) {
        if (s->term[i].tmid == tmid) return &s->term[i];
    }
    return NULL;
}

int ocs_dl(ocs_t *s, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    ocs_term_t *t = term_of(s, tmid);
    if (t == NULL || !t->on) return 0; /* sent; nobody here hears it */
    return qpush(&t->dl, p, n);
}

void ocs_tick(ocs_t *s, uint64_t mono_us)
{
    if (s->next_frame == 0) s->next_frame = mono_us;
    if (mono_us < s->next_frame) return;
    s->next_frame += OCS_FRAME_US;
    uint64_t now = s->now = mono_us;
    for (unsigned i = 0; i < s->n; i++) {
        ocs_term_t *t = &s->term[i];
        uint8_t p[OC_SIG_LINK_MAX], n, app[OC_SIG_APP_MAX], an;
        oc_sig_term_link(&t->t, t->on, t->on, now);
        oc_sig_term_cell_mode(&t->t, s->net->net.cfg.mode, now);
        oc_sig_term_cell_cfg(&t->t, (uint8_t)(oc_cell_list_ver(s->net) & OC_BCN_MAX_CFG_VER), now);
        oc_sig_term_tick(&t->t, now);
        if (!t->on) continue;
        oc_cell_radio_link(s->net, t->tmid, 1, now);
        if (qpop(&t->ul, p, &n) == 0) oc_cell_ul(s->net, t->tmid, p, n, now);
        else oc_cell_ul(s->net, t->tmid, NULL, 0, now); /* its UL slot was heard, empty */
        if (qpop(&t->dl, p, &n) != 0) continue;
        if ((p[0] & 0xF0u) == OC_SIG_KIND_SIG) {
            oc_sig_term_rx(&t->t, p, n, now);
        } else if (p[0] == OC_SIG_KIND_DATA && oc_sig_term_data_in(&t->t, p, n, app, &an) == 0) {
            say(s, "sim %08x: data '%.*s'", t->tmid, (int)an, (const char *)app);
        }
    }
}

int ocs_command(ocs_t *s, const char *line, uint64_t mono_us)
{
    s->now = mono_us;
    char verb[16] = "", arg[64] = "";
    unsigned long tmid = 0;
    if (sscanf(line, "%lx %15s %63[^\n]", &tmid, verb, arg) < 2) {
        say(s, "sim: '%s': TMID COMMAND [ARGUMENT]", line);
        return -1;
    }
    ocs_term_t *t = term_of(s, (uint32_t)tmid);
    if (t == NULL) {
        say(s, "sim: no terminal %08lx", tmid);
        return -1;
    }
    uint8_t cmd[1 + OC_SIG_DIAL_MAX];
    size_t n = 1;
    if (strcmp(verb, "off") == 0 || strcmp(verb, "on") == 0) {
        t->on = verb[1] == 'n';
        say(s, "sim %08x: %s", t->tmid, t->on ? "back in coverage" : "out of coverage");
        return 0;
    }
    if (strcmp(verb, "talk") == 0) {
        uint8_t out[OC_SIG_LINK_MAX], on;
        size_t len = strlen(arg) > OC_SIG_APP_MAX ? OC_SIG_APP_MAX : strlen(arg);
        if (oc_sig_term_data_out(&t->t, (const uint8_t *)arg, (uint8_t)len, out, &on) != 0 || qpush(&t->ul, out, on) != 0) {
            say(s, "sim %08x: talk refused (not in a call?)", t->tmid);
            return -1;
        }
        return 0;
    }
    if (strcmp(verb, "dial") == 0 && arg[0] != '\0' && strlen(arg) <= OC_SIG_DIAL_MAX) {
        cmd[0] = OC_SIG_CMD_DIAL;
        memcpy(cmd + 1, arg, strlen(arg));
        n += strlen(arg);
    } else if (strcmp(verb, "answer") == 0) {
        cmd[0] = OC_SIG_CMD_ANSWER;
    } else if (strcmp(verb, "reject") == 0) {
        cmd[0] = OC_SIG_CMD_REJECT;
    } else if (strcmp(verb, "hangup") == 0) {
        cmd[0] = OC_SIG_CMD_HANGUP;
    } else {
        say(s, "sim: '%s': dial NUMBER, answer, reject, hangup, talk TEXT, off, on", line);
        return -1;
    }
    int r = oc_sig_term_command(&t->t, cmd, n, mono_us);
    if (r != 0) say(s, "sim %08x: %s refused (%d)", t->tmid, verb, r);
    return r == 0 ? 0 : -1;
}
```

- [ ] **Step 5: The program**

Create `oc-cell/occ_main.c`:
```c
#define _GNU_SOURCE
/* oc-cell: a cell's daemon (network-core spec §4.1, §17 decision 2).
 *
 *   oc-cell [--config FILE]      (default /etc/opencell/oc-cell.conf)
 *   oc-cell --version
 *
 * One thread: a poll() loop over the board's serial port (or, radio = sim,
 * a control FIFO), the link to the core, and the clocks. oc_cell is the
 * network side (plan 1); ocr (or ocs) is the radio. The core link comes and
 * goes: it is dialled at start and again after a drop, 1 s later, doubling
 * to 30 s, back to 1 s once a HELLO is accepted. A new boot id at every
 * start tells the core this is a new process (spec §7.9). Logs go to stderr
 * with journald priorities. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "oc_cell.h"
#include "occ_board.h"
#include "occ_cfg.h"
#include "oc_conn.h"
#include "oc_log.h"
#include "ocr.h"
#include "ocs.h"

#ifndef OC_VERSION
#define OC_VERSION "dev"
#endif

#define DEFAULT_CONFIG "/etc/opencell/oc-cell.conf"
#define STATUS_EVERY_US 60000000u

static struct {
    occ_cfg_t cfg;
    oc_cell_t     cell;
    ocr_t         radio;
    ocs_t         sim;
    oc_board_t    board;
    oc_conn_t     core;      /* fd -1: no link */
    int           core_dead; /* a send failed inside a call: closed after it */
    uint64_t      next_try;  /* monotonic µs */
    uint32_t      backoff_ms;
    int           was_ready;
    int           ctl_fd;
    char          ctl[512];
    size_t        ctl_n;
    int           acked, ack_status, config_seq;
} G;

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static uint64_t clock_us(clockid_t id)
{
    struct timespec ts;
    clock_gettime(id, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}
static uint64_t mono_us(void) { return clock_us(CLOCK_MONOTONIC); }
static uint64_t rt_us(void) { return clock_us(CLOCK_REALTIME); }

/* ---- the core link ---- */

static void retry_later(const char *why)
{
    G.backoff_ms = oc_backoff_next(G.backoff_ms);
    G.next_try = mono_us() + (uint64_t)G.backoff_ms * 1000u;
    oc_log(OC_LOG_WARNING, "core: %s; again in %u s", why, G.backoff_ms / 1000u);
}

static void core_lost(const char *why)
{
    if (G.core.fd < 0) return;
    oc_conn_close(&G.core);
    G.core_dead = 0;
    oc_cell_core_down(&G.cell, mono_us());
    retry_later(why);
}

static void core_connect(void)
{
    int fd = oc_unix_connect(G.cfg.core);
    if (fd < 0) {
        char why[300];
        snprintf(why, sizeof(why), "%s: %s", G.cfg.core, strerror(errno));
        retry_later(why);
        return;
    }
    oc_conn_init(&G.core, fd);
    oc_log(OC_LOG_INFO, "core: connected to %s", G.cfg.core);
    oc_cell_core_up(&G.cell, mono_us());
}

static void on_core_msg(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    oc_cell_core_rx(&G.cell, m, mono_us());
}

/* ---- oc_cell's io ---- */

static int c_core_send(void *ctx, const oc_core_msg_t *m)
{
    (void)ctx;
    if (G.core.fd < 0 || G.core_dead) return -1;
    if (oc_conn_send(&G.core, m) != 0) {
        G.core_dead = 1; /* closed by the loop, after the oc_cell call that sent this */
        return -1;
    }
    return 0;
}

static void c_core_close(void *ctx) /* oc_cell gave up on the link (HELLO refused, silence) */
{
    (void)ctx;
    if (G.core.fd < 0) return;
    oc_conn_close(&G.core);
    G.core_dead = 0;
    retry_later("link dropped by the cell");
}

static int c_radio_send(void *ctx, uint32_t tmid, const uint8_t *p, uint8_t n)
{
    (void)ctx;
    return G.cfg.sim ? ocs_dl(&G.sim, tmid, p, n) : ocr_dl(&G.radio, tmid, p, n);
}

static void c_radio_channel(void *ctx, uint32_t tmid, int on)
{
    (void)ctx;
    if (!G.cfg.sim) ocr_channel(&G.radio, tmid, on); /* simulated terminals are always granted */
}

/* ---- the board ---- */

static int b_send(void *ctx, oc_msg_t *m)
{
    (void)ctx;
    return oc_board_send(&G.board, m);
}

static void on_board_msg(void *ctx, const oc_msg_t *m)
{
    (void)ctx;
    if (m->type == OC_MSG_ACK && m->u.ack.acked_seq == (uint8_t)G.config_seq) {
        G.acked = 1;
        G.ack_status = m->u.ack.status;
    }
    if (G.radio.net != NULL) ocr_board_rx(&G.radio, m, rt_us(), mono_us());
}

static void drain(int ms)
{
    uint64_t end = mono_us() + (uint64_t)ms * 1000u;
    while (mono_us() < end && !G.acked) {
        struct pollfd p = { G.board.fd, POLLIN, 0 };
        if (poll(&p, 1, 20) > 0) oc_board_read(&G.board, on_board_msg, NULL);
    }
}

/* Open, reset, CONFIG (answered only by a bs-radio), then the backend. */
static int board_start(void)
{
    char err[300];
    oc_msg_t m;
    if (oc_board_open(&G.board, G.cfg.board, err, sizeof(err)) != 0) {
        oc_log(OC_LOG_ERR, "%s", err);
        return -1;
    }
    if (G.cfg.board_reset) {
        oc_board_reset(&G.board);
        drain(2500); /* its boot, and heartbeats we don't want */
    }
    ocr_config_msg(&G.cfg.radio, &m);
    G.acked = 0;
    G.config_seq = oc_board_send(&G.board, &m);
    drain(1500);
    if (!G.acked) {
        oc_log(OC_LOG_ERR, "%s: no bs-radio answers (a terminal ignores link frames; or no board there)",
               G.cfg.board);
        return -1;
    }
    if (G.ack_status != OC_ACK_OK) {
        oc_log(OC_LOG_ERR, "%s: the board refused its CONFIG (ack %d)", G.cfg.board, G.ack_status);
        return -1;
    }
    const ocr_io_t io = { NULL, b_send, oc_log_line };
    return ocr_init(&G.radio, &io, &G.cfg.radio, &G.cell, rt_us());
}

/* ---- the simulated radio's control FIFO ---- */

static void read_control(void)
{
    ssize_t r = read(G.ctl_fd, G.ctl + G.ctl_n, sizeof(G.ctl) - 1u - G.ctl_n);
    if (r <= 0) return;
    G.ctl_n += (size_t)r;
    G.ctl[G.ctl_n] = '\0';
    char *nl;
    while ((nl = strchr(G.ctl, '\n')) != NULL) {
        *nl = '\0';
        if (G.ctl[0] != '\0') ocs_command(&G.sim, G.ctl, mono_us());
        size_t used = (size_t)(nl - G.ctl) + 1u;
        memmove(G.ctl, nl + 1, G.ctl_n - used + 1u);
        G.ctl_n -= used;
    }
    if (G.ctl_n == sizeof(G.ctl) - 1u) G.ctl_n = 0; /* a line too long: dropped */
}

/* ---- main ---- */

static void sw_version(uint8_t v[3])
{
    unsigned a = 0, b = 0, c = 0;
    memset(v, 0, 3);
    if (sscanf(OC_VERSION, "v%u.%u.%u", &a, &b, &c) == 3 && a < 256 && b < 256 && c < 256) {
        v[0] = (uint8_t)a;
        v[1] = (uint8_t)b;
        v[2] = (uint8_t)c;
    }
}

int main(int argc, char **argv)
{
    const char *config = DEFAULT_CONFIG;
    char err[300];
    static oc_kv_t kv;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("oc-cell %s\n", OC_VERSION);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--config") == 0) config = argv[2];
    else if (argc != 1) {
        fprintf(stderr, "usage: oc-cell [--config FILE] | --version\n");
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    if (oc_kv_load(&kv, config) != 0 || occ_cfg_parse(&G.cfg, &kv, err, sizeof(err)) != 0) {
        oc_log(OC_LOG_ERR, "config: %s", kv.err[0] != '\0' ? kv.err : err);
        return 1;
    }

    oc_cell_cfg_t cc;
    memset(&cc, 0, sizeof(cc));
    cc.cell_id = G.cfg.cell_id;
    while (cc.boot_id == 0) {
        if (getrandom(&cc.boot_id, sizeof(cc.boot_id), 0) != (ssize_t)sizeof(cc.boot_id)) cc.boot_id = 0;
    }
    sw_version(cc.sw_version);
    cc.mode = G.cfg.radio.mode;
    cc.period_s = G.cfg.period_s;
    const oc_cell_io_t io = { NULL, c_core_send, c_core_close, c_radio_send, c_radio_channel, oc_log_line };
    oc_cell_init(&G.cell, &io, &cc);
    G.core.fd = -1;
    G.board.fd = -1;
    G.ctl_fd = -1;
    oc_log(OC_LOG_NOTICE, "oc-cell %s: cell %u, boot %016llx, core %s, radio %s", OC_VERSION, G.cfg.cell_id,
           (unsigned long long)cc.boot_id, G.cfg.core, G.cfg.sim ? "sim" : G.cfg.board);

    if (G.cfg.sim) {
        ocs_init(&G.sim, &G.cell, oc_log_line, NULL);
        for (unsigned i = 0; i < G.cfg.nsim; i++) {
            if (ocs_add(&G.sim, G.cfg.sim_term[i].tmid, G.cfg.sim_term[i].qr, G.cfg.sim_state, mono_us()) != 0) {
                oc_log(OC_LOG_ERR, "sim_term %08x: refused", G.cfg.sim_term[i].tmid);
                return 1;
            }
        }
        if (G.cfg.sim_control[0] != '\0') {
            G.ctl_fd = open(G.cfg.sim_control, O_RDWR | O_NONBLOCK | O_CLOEXEC); /* RDWR: never an EOF */
            if (G.ctl_fd < 0) {
                oc_log(OC_LOG_ERR, "%s: %s", G.cfg.sim_control, strerror(errno));
                return 1;
            }
        }
    } else if (board_start() != 0) {
        return 1;
    }

    core_connect();
    uint64_t next_status = mono_us() + STATUS_EVERY_US;
    while (!g_stop) {
        struct pollfd p[3];
        nfds_t np = 0;
        int ib = -1, ic = -1, ik = -1;
        if (G.board.fd >= 0) p[ib = (int)np++] = (struct pollfd){ G.board.fd, POLLIN, 0 };
        if (G.ctl_fd >= 0) p[ik = (int)np++] = (struct pollfd){ G.ctl_fd, POLLIN, 0 };
        if (G.core.fd >= 0) p[ic = (int)np++] = (struct pollfd){ G.core.fd, (short)(POLLIN | (G.core.tn ? POLLOUT : 0)), 0 };
        int r = poll(p, np, 5);
        if (r < 0 && errno != EINTR) {
            oc_log(OC_LOG_ERR, "poll: %s", strerror(errno));
            break;
        }
        if (ib >= 0 && (p[ib].revents & (POLLIN | POLLHUP | POLLERR)) &&
            oc_board_read(&G.board, on_board_msg, NULL) != 0) {
            oc_log(OC_LOG_ERR, "%s: the board went away (unplugged or reset into another mode)", G.cfg.board);
            return 1; /* systemd starts us again */
        }
        if (ik >= 0 && (p[ik].revents & POLLIN)) read_control();
        if (ic >= 0 && G.core.fd >= 0) {
            if ((p[ic].revents & POLLOUT) && oc_conn_flush(&G.core) != 0) G.core_dead = 1;
            if ((p[ic].revents & (POLLIN | POLLHUP | POLLERR)) && oc_conn_read(&G.core, on_core_msg, NULL) != 0 &&
                G.core.fd >= 0) {
                G.core_dead = 1;
            }
        }
        if (G.core_dead) core_lost("link lost");
        uint64_t mono = mono_us();
        if (G.cfg.sim) ocs_tick(&G.sim, mono);
        else ocr_tick(&G.radio, rt_us(), mono);
        oc_cell_tick(&G.cell, mono);
        if (G.core_dead) core_lost("link lost");
        if (G.cell.ready && !G.was_ready) G.backoff_ms = 0; /* HELLO accepted: the next drop retries after 1 s */
        G.was_ready = G.cell.ready;
        if (G.core.fd < 0 && mono >= G.next_try) core_connect();
        if (mono >= next_status) {
            char line[300];
            next_status = mono + STATUS_EVERY_US;
            if (G.cfg.sim) snprintf(line, sizeof(line), "radio: sim, %u terminals", G.sim.n);
            else ocr_status_line(&G.radio, line, sizeof(line));
            oc_log(OC_LOG_INFO, "core %s | %s", G.cell.ready ? "linked" : "DOWN", line);
        }
    }
    oc_log(OC_LOG_NOTICE, "oc-cell: stopping");
    oc_conn_close(&G.core);
    oc_board_close(&G.board);
    return 0;
}
```

Replace the whole of `oc-cell/CMakeLists.txt` with:
```cmake
# oc-cell: ocr (the ocb_cell radio backend), ocs (the simulated radio for
# the process tests), the config file, the board's port, and the program.
add_library(occ_lib STATIC ocr.c ocs.c occ_cfg.c occ_board.c)
target_include_directories(occ_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(occ_lib PUBLIC oc_cell ocbench_core oc_util)

# -DOC_VERSION=v1.2.3 (the deploy script passes the tag it builds), else
# what git says about this checkout. HELLO carries it as sw_version.
if(NOT OC_VERSION)
  execute_process(COMMAND git describe --tags --always --dirty WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  OUTPUT_VARIABLE OC_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(NOT OC_VERSION)
    set(OC_VERSION unknown)
  endif()
endif()
add_executable(oc-cell occ_main.c)
target_compile_definitions(oc-cell PRIVATE OC_VERSION="${OC_VERSION}")
target_link_libraries(oc-cell PRIVATE occ_lib)
install(TARGETS oc-cell RUNTIME DESTINATION bin)
```

Create `dist/systemd/oc-cell.service`:
```ini
# oc-cell, an OpenCell cell (network-core spec §4.1, §17). Installed by
# opencell-core's tools/deploy/oc-deploy. User oc-cell is in dialout (the
# board's USB port) and in oc-cell (the core's cell socket, 0660). No
# PrivateDevices: it needs /dev/serial.
[Unit]
Description=OpenCell cell (oc-cell)
After=network.target oc-core.service
Wants=oc-core.service

[Service]
Type=simple
User=oc-cell
Group=oc-cell
SupplementaryGroups=dialout
ExecStart=/usr/local/bin/oc-cell --config /etc/opencell/oc-cell.conf
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 6: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; build/tests/test_occ_cfg | tail -3; build/oc-cell/oc-cell --version | cut -c1-8`
Expected: no compiler output, `5 Tests 0 Failures 0 Ignored`, `OK`, then `oc-cell ` (followed by what `git describe` says).

Run: `cd /home/devin/Documents/opencell/pi && printf 'cell_id = 1\nboard = /dev/null\nboard_reset = 0\n' > build/null.conf && build/oc-cell/oc-cell --config build/null.conf; echo "rc=$?"`
Expected: a line ending `/dev/null: not a serial port`, then `rc=1`.

- [ ] **Step 7: The whole suite**

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of 2`.

- [ ] **Step 8: Commit**

```bash
cd /home/devin/Documents/opencell/pi
git add oc-cell tests/CMakeLists.txt tests/test_occ_cfg.c dist
git commit -m "oc-cell: the program (config, exclusive board port, CONFIG handshake, core client with backoff), simulated radio

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
```

---

### Task 9: Process tests: two cells and a core (spec §9.4)

**Repo:** `opencell-pi`, branch `oc-cell`, at `/home/devin/Documents/opencell/pi`. **Starts:** after Task 8.

Spec §9.4: "`oc-core` and two `oc-cell --radio sim` processes on localhost, over Unix sockets …; kill/restart tests." One script starts the core and two simulated cells from a fresh database, and checks, through the logs and `oc-core admin`: activation and registration through the core; a call from cell 1 to cell 2 with app data both ways and a CDR; the echo service; cell 2 killed (`SIGKILL`) in a call — the far leg ends with cause 5 within 10 s ("Done means"), and the restarted cell's terminal registers again; the core killed and restarted — the cells reconnect by themselves, keep their locations without registering again, and calls work (Review Focus 1); a disabled subscriber loses its location and becomes unreachable (cause 4). It takes about 12 s.

**Files:**
- Create: `tests/test_proc_cells.sh`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Consumes: the programs `oc-core` (Task 6, built here from the submodule) and `oc-cell` (Task 8), their log lines and admin commands.

- [ ] **Step 1: Write the test**

Create `tests/test_proc_cells.sh`:
```bash
#!/bin/bash
# Two cells and a core as processes (network-core spec §9.4): oc-core and two
# `oc-cell` with `radio = sim` on Unix sockets. Activation and registration
# through the core, a call from cell 1 to cell 2 with app data both ways,
# the echo service, a cell killed in a call (the far leg ends, cause 5, and
# the restarted cell's terminal registers again), the core killed and
# restarted (the cells reconnect by themselves and keep their locations),
# and a disabled subscriber becoming unreachable.
#   test_proc_cells.sh OC_CORE OCC
set -u
OC=$1
CELL=$2
T=$(mktemp -d /tmp/oc_proc_cells_XXXXXX)
CORE= C1= C2=
A=+883160655501234
B=+883160655501235
TA=76000001
TB=76000002

stop_all() { for p in $CORE $C1 $C2; do kill -9 "$p" 2>/dev/null; done; }
fail() {
    echo "FAIL: $*"
    stop_all
    for f in core cell1 cell2; do echo "--- $f.log"; tail -25 "$T/$f.log"; done
    rm -rf "$T"
    exit 1
}
# wait_count FILE PATTERN N SECONDS: until PATTERN is in FILE N times
wait_count() {
    for _ in $(seq $(($4 * 10))); do
        [ "$(grep -c -- "$2" "$1" 2>/dev/null)" -ge "$3" ] && return 0
        sleep 0.1
    done
    fail "'$2' not seen $3 times in $(basename "$1") within $4 s"
}
count() { grep -c -- "$2" "$1" 2>/dev/null; }
admin() { "$OC" admin --socket "$T/admin.sock" "$@" 2>&1; }
say() { echo "$2" >"$T/ctl$1"; }

head -c 32 /dev/urandom >"$T/key" && chmod 0400 "$T/key"
cat >"$T/core.conf" <<EOF
core_id = 1
key_id = 1
block = 8831606 1
db = $T/core.db
cell_socket = $T/core.sock
admin_socket = $T/admin.sock
EOF
ADM=("$OC" admin --offline --config "$T/core.conf" --key-file "$T/key")
"${ADM[@]}" net init >/dev/null || fail "net init"
"${ADM[@]}" cell add 1 one >/dev/null || fail "cell add 1"
"${ADM[@]}" cell add 2 two >/dev/null || fail "cell add 2"
"${ADM[@]}" sub add $A >/dev/null || fail "sub add A"
"${ADM[@]}" sub add $B >/dev/null || fail "sub add B"
QA=$("${ADM[@]}" sub issue $A | grep '^opencell:') || fail "issue A"
QB=$("${ADM[@]}" sub issue $B | grep '^opencell:') || fail "issue B"

start_core() {
    "$OC" --config "$T/core.conf" --key-file "$T/key" 2>>"$T/core.log" &
    CORE=$!
    for _ in $(seq 50); do [ -S "$T/admin.sock" ] && return 0; sleep 0.1; done
    fail "the core did not start"
}
start_cell() { # N TMID CODE
    mkdir -p "$T/s$1"
    [ -p "$T/ctl$1" ] || mkfifo "$T/ctl$1"
    cat >"$T/cell$1.conf" <<EOF
cell_id = $1
core = $T/core.sock
radio = sim
sim_state = $T/s$1
sim_control = $T/ctl$1
sim_term = $2 $3
EOF
    "$CELL" --config "$T/cell$1.conf" 2>>"$T/cell$1.log" &
    eval "C$1=$!"
}

start_core
start_cell 1 $TA "$QA"
start_cell 2 $TB "$QB"
wait_count "$T/cell1.log" "sim $TA: registered" 1 30
wait_count "$T/cell2.log" "sim $TB: registered" 1 30
out=$(admin loc)
grep -q "$A  cell 1  tmid $TA" <<<"$out" || fail "A not on cell 1: $out"
grep -q "$B  cell 2  tmid $TB" <<<"$out" || fail "B not on cell 2: $out"
echo "ok: activated and registered through the core"

# a call from cell 1 to cell 2, app data both ways, hung up by the callee
say 1 "$TA dial $B"
wait_count "$T/cell2.log" "sim $TB: incoming" 1 15
say 2 "$TB answer"
wait_count "$T/cell1.log" "sim $TA: connected" 1 15
wait_count "$T/cell2.log" "sim $TB: connected" 1 15
say 1 "$TA talk hello"
wait_count "$T/cell2.log" "sim $TB: data 'hello'" 1 10
say 2 "$TB talk back"
wait_count "$T/cell1.log" "sim $TA: data 'back'" 1 10
say 2 "$TB hangup"
wait_count "$T/cell1.log" "sim $TA: ended cause 0" 1 10
out=$(admin cdr 5)
grep -q "$A -> $B  cells 1 -> 2  answered" <<<"$out" || fail "no CDR: $out"
echo "ok: a call across cells"

# the echo service
say 1 "$TA dial +883160655500100"
wait_count "$T/cell1.log" "sim $TA: connected" 2 15
say 1 "$TA talk ping"
wait_count "$T/cell1.log" "sim $TA: data 'ping'" 1 10
say 1 "$TA hangup"
wait_count "$T/cell1.log" "sim $TA: ended cause 0" 2 10
echo "ok: the echo service"

# cell 2 dies in a call: A's leg ends with cause 5 within 10 s
say 1 "$TA dial $B"
wait_count "$T/cell2.log" "sim $TB: incoming" 2 15
say 2 "$TB answer"
wait_count "$T/cell1.log" "sim $TA: connected" 3 15
kill -9 "$C2"
wait "$C2" 2>/dev/null
wait_count "$T/cell1.log" "sim $TA: ended cause 5" 1 10
start_cell 2 $TB "$QB" # a new boot; the terminal keeps its identity file
wait_count "$T/cell2.log" "sim $TB: known terminal, registering" 1 5
wait_count "$T/cell2.log" "sim $TB: registered" 2 30
echo "ok: a cell killed in a call, and back"

# the core dies and comes back: the cells reconnect and keep their locations
regs1=$(count "$T/cell1.log" "sim $TA: registered")
kill -9 "$CORE"
wait "$CORE" 2>/dev/null
wait_count "$T/cell1.log" "core: link lost" 1 5
start_core
wait_count "$T/cell1.log" "core: HELLO accepted" 2 10
wait_count "$T/cell2.log" "core: HELLO accepted" 2 10
sleep 1
out=$(admin loc)
grep -q "$A  cell 1" <<<"$out" || fail "A's location lost: $out"
grep -q "$B  cell 2" <<<"$out" || fail "B's location lost: $out"
[ "$(count "$T/cell1.log" "sim $TA: registered")" = "$regs1" ] || fail "A had to register again"
say 1 "$TA dial $B"
wait_count "$T/cell2.log" "sim $TB: incoming" 3 15
say 2 "$TB reject"
wait_count "$T/cell1.log" "sim $TA: ended cause 1" 1 10
echo "ok: the core killed and back"

# B is disabled: its cell drops it and a call to it is unreachable
admin sub disable $B >/dev/null || fail "disable"
sleep 1
admin loc | grep -q "$B" && fail "B still has a location"
say 1 "$TA dial $B"
wait_count "$T/cell1.log" "sim $TA: ended cause 4" 1 15
echo "ok: a disabled subscriber"

kill -TERM $CORE $C1 $C2
for p in $CORE $C1 $C2; do
    wait "$p"
    rc=$?
    [ "$rc" = 0 ] || fail "exit status $rc after SIGTERM"
done
rm -rf "$T"
echo "OK"
```

Append to `tests/CMakeLists.txt`:
```cmake
# The process tests (spec §9.4) run both programs; oc-core comes from the
# core submodule, which is otherwise not built here.
add_custom_target(proc_programs ALL DEPENDS oc-core oc-cell)
add_test(NAME test_proc_cells
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_proc_cells.sh $<TARGET_FILE:oc-core> $<TARGET_FILE:oc-cell>)
```

- [ ] **Step 2: Run it**

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; bash tests/test_proc_cells.sh build/opencell-core/oc/oc-core build/oc-cell/oc-cell`
Expected: no compiler output, then `ok: activated and registered through the core`, `ok: a call across cells`, `ok: the echo service`, `ok: a cell killed in a call, and back`, `ok: the core killed and back`, `ok: a disabled subscriber`, `OK`.

These exercise code that Tasks 2–8 and plan 1 already wrote, so they pass at once. A `FAIL:` line names the step, and the script prints the last lines of each process's log: fix the owning file (and its own test) rather than the script.

- [ ] **Step 3: The whole suite, three times**

Run: `cd /home/devin/Documents/opencell/pi && for i in 1 2 3; do (cd build && ctest | grep 'tests passed'); done`
Expected: `100% tests passed, 0 tests failed out of 3`, three times (timing-sensitive tests must not be flaky).

- [ ] **Step 4: Commit and push**

```bash
cd /home/devin/Documents/opencell/pi
git add tests/CMakeLists.txt tests/test_proc_cells.sh
git commit -m "Process tests (network-core spec 9.4): two oc-cell and an oc-core; calls, echo, kills and restarts, disable

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push -u origin oc-cell
```

---

### Task 10: The deploy script (spec §17.4)

**Repo:** `opencell-core`, branch `oc-core`, at `/home/devin/Documents/opencell/core`. **Starts:** after Task 6 (may run while Tasks 7–9 do).

§17.4: "A deploy script run from the laptop (`tools/deploy/`). It takes a tagged revision (`vX.Y.Z`; only tags are deployed), sends it over SSH or Tailscale, builds on the target …, installs to `/usr/local` with a systemd unit, and keeps the previous build for `rollback`. No packages for now." One script serves both programs: it knows `opencell-core` (→ `oc-core`) from `opencell-pi` (→ `oc-cell`) by their files, packs the tag's tree with every submodule's tree at the commit the tag pins (recursively: the Pi repository's firmware is two levels down), copies it with `scp`, builds on the host as the SSH user with the tests off, and installs with `sudo` into `/usr/local/lib/opencell/NAME/TAG`, switching `current` and keeping `previous`. The host needs no GitHub access. Its test runs the host side locally (`OC_DEPLOY_LOCAL`) on a toy repository with nested submodules.

**Files:**
- Create: `tools/deploy/oc-deploy` (mode 0755), `tests/test_oc_deploy.sh`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `OC_CORE_TESTS` (Task 2), `OC_PI_TESTS` (Task 7), `-DOC_VERSION` (Tasks 6, 8), the `install()` rules of `oc-core` and `oc-cell`, `dist/systemd/NAME.service` in each repository.
- Produces:
  ```
  oc-deploy deploy REPO_DIR TAG HOST    build TAG of REPO_DIR on HOST, install, restart its unit (if enabled)
  oc-deploy rollback HOST NAME          back to the previous build of NAME
  oc-deploy list HOST NAME              the builds of NAME on HOST: "vX.Y.Z (current)", "vX.Y.Z (previous)"
  ```
  Host layout: `/usr/local/lib/opencell/NAME/{TAG/{bin/NAME,NAME.service},current,previous}`, `/usr/local/bin/NAME`, `/etc/systemd/system/NAME.service`. Environment for tests: `OC_DEPLOY_LOCAL=ROOT`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_oc_deploy.sh`:
```bash
#!/bin/bash
# tools/deploy/oc-deploy (network-core spec §17 decisions 4 and 11), with the
# host side run here (OC_DEPLOY_LOCAL): a toy "opencell-core" with a
# submodule that has its own submodule is deployed at two tags, listed,
# rolled back, and refused anything that is not a tag vX.Y.Z.
#   test_oc_deploy.sh OC_DEPLOY
set -u
DEPLOY=$1
T=$(mktemp -d /tmp/oc_deploy_XXXXXX)
fail() { echo "FAIL: $*"; rm -rf "$T"; exit 1; }
expect() { grep -q -- "$2" <<<"$1" || fail "expected '$2' in: $1"; }
g() { git -c user.name=t -c user.email=t@t -c protocol.file.allow=always "$@"; }

mkdir -p "$T/deep" "$T/sub" "$T/top/oc" "$T/top/dist/systemd"
g -C "$T/deep" init -q && echo '#define DEEP 2' >"$T/deep/deep.h" && g -C "$T/deep" add . && g -C "$T/deep" commit -qm deep
g -C "$T/sub" init -q && echo '#define SUB 1' >"$T/sub/sub.h" && g -C "$T/sub" add . && g -C "$T/sub" commit -qm sub
g -C "$T/sub" submodule add -q "$T/deep" deep && g -C "$T/sub" commit -qm "deep in sub"
cd "$T/top" || fail "cd"
g init -q
cat >CMakeLists.txt <<'CM'
cmake_minimum_required(VERSION 3.21)
project(toy C)
add_executable(oc-core oc/oc_core_main.c)
target_include_directories(oc-core PRIVATE third_party/sub third_party/sub/deep)
target_compile_definitions(oc-core PRIVATE OC_VERSION="${OC_VERSION}")
install(TARGETS oc-core RUNTIME DESTINATION bin)
CM
printf '#include <stdio.h>\n#include "sub.h"\n#include "deep.h"\nint main(void) { printf("oc-core %%s %%d\\n", OC_VERSION, SUB + DEEP); return 0; }\n' >oc/oc_core_main.c
printf '[Service]\nExecStart=/usr/local/bin/oc-core\n' >dist/systemd/oc-core.service
g submodule add -q "$T/sub" third_party/sub && g submodule update -q --init --recursive
g add . && g commit -qm one && g tag v0.0.1
sed -i 's/SUB + DEEP/SUB + DEEP + 10/' oc/oc_core_main.c && g commit -qam two && g tag v0.0.2
echo "/* not tagged */" >>oc/oc_core_main.c && g commit -qam three

export OC_DEPLOY_LOCAL=$T/root
out=$("$DEPLOY" deploy "$T/top" v0.0.1 somehost 2>&1) || fail "deploy v0.0.1: $out"
expect "$out" "oc-core v0.0.1 installed (previous: none)"
out=$("$T/root/bin/oc-core") || fail "run v0.0.1"
[ "$out" = "oc-core v0.0.1 3" ] || fail "v0.0.1 runs as: $out" # both submodules were packed
[ -f "$T/root/lib/opencell/oc-core/v0.0.1/oc-core.service" ] || fail "the unit was not kept with the build"
out=$("$DEPLOY" deploy "$T/top" v0.0.2 somehost 2>&1) || fail "deploy v0.0.2: $out"
expect "$out" "installed (previous: v0.0.1)"
[ "$("$T/root/bin/oc-core")" = "oc-core v0.0.2 13" ] || fail "v0.0.2 is not current"
out=$("$DEPLOY" list somehost oc-core 2>&1)
expect "$out" "v0.0.1 (previous)"
expect "$out" "v0.0.2 (current)"
out=$("$DEPLOY" rollback somehost oc-core 2>&1) || fail "rollback: $out"
expect "$out" "oc-core back to v0.0.1 (previous: v0.0.2)"
[ "$("$T/root/bin/oc-core")" = "oc-core v0.0.1 3" ] || fail "rollback did not take"
out=$("$DEPLOY" deploy "$T/top" v0.0.2 somehost 2>&1) || fail "redeploy v0.0.2: $out"
[ "$(ls "$T/root/lib/opencell/oc-core" | grep -c '^v')" = 2 ] || fail "more than two builds kept"

out=$("$DEPLOY" deploy "$T/top" master somehost 2>&1) && fail "a branch was deployed"
expect "$out" "deploys take a tag vX.Y.Z"
out=$("$DEPLOY" deploy "$T/top" v0.1 somehost 2>&1) && fail "v0.1 was deployed"
out=$("$DEPLOY" deploy "$T/top" v9.9.9 somehost 2>&1) && fail "a missing tag was deployed"
expect "$out" "has no tag v9.9.9"
out=$("$DEPLOY" deploy "$T/sub" v0.0.1 somehost 2>&1) && fail "a repository that is no program"
out=$("$DEPLOY" rollback somehost oc-cell 2>&1) && fail "rolled back a program never deployed"
expect "$out" "no previous build of oc-cell"
rm -rf "$T"
echo "OK"
```

Append to `tests/CMakeLists.txt`:
```cmake
add_test(NAME test_oc_deploy COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test_oc_deploy.sh ${PROJECT_SOURCE_DIR}/tools/deploy/oc-deploy)
```

- [ ] **Step 2: Run it to see it fail**

Run: `cd /home/devin/Documents/opencell/core && bash tests/test_oc_deploy.sh $PWD/tools/deploy/oc-deploy 2>&1 | tail -1`
Expected: `FAIL: deploy v0.0.1: tests/test_oc_deploy.sh: line …: …/tools/deploy/oc-deploy: No such file or directory`.

- [ ] **Step 3: Implement**

Create `tools/deploy/oc-deploy`:
```bash
#!/bin/bash
# oc-deploy: install a tagged OpenCell program on a host (network-core spec
# §17 decisions 4 and 11). Run from the laptop.
#
#   oc-deploy deploy REPO_DIR TAG HOST   build TAG of REPO_DIR on HOST, install, restart its unit
#   oc-deploy rollback HOST NAME         back to the previous build of NAME (oc-core, oc-cell)
#   oc-deploy list HOST NAME             the builds of NAME on HOST
#
# REPO_DIR is a local clone of opencell-core (the program oc-core) or
# opencell-pi (oc-cell), with its submodules checked out; only tags vX.Y.Z
# are deployed. The tag's tree and every submodule's tree at the commits the
# tag pins are packed, copied over SSH (HOST as in ~/.ssh/config, or a
# Tailscale name), built on the host as the SSH user (Debian 13, cmake,
# gcc, libssl-dev, libsqlite3-dev), and installed with sudo:
#   /usr/local/lib/opencell/NAME/TAG/          the build (bin/NAME, NAME.service)
#   /usr/local/lib/opencell/NAME/current       -> TAG
#   /usr/local/lib/opencell/NAME/previous      -> the build before (kept for rollback)
#   /usr/local/bin/NAME                        -> ../lib/opencell/NAME/current/bin/NAME
#   /etc/systemd/system/NAME.service           from the build's dist/systemd/NAME.service
# Older builds are removed. The unit is restarted if it is enabled; the
# first time, enabling it is left to the operator.
#
# Tests: OC_DEPLOY_LOCAL=ROOT runs the host side here, under ROOT, without
# ssh, sudo or systemctl.
set -euo pipefail

die() { echo "oc-deploy: $*" >&2; exit 1; }

# ---- the host side (run there over ssh, or here with OC_DEPLOY_LOCAL) ----

host_activate() { # NAME
    local name=$1 d=$OC_PREFIX/lib/opencell/$1
    [ "$OC_SYSTEMD" = 1 ] || return 0
    $OC_SUDO install -m 0644 "$d/current/$name.service" "/etc/systemd/system/$name.service"
    $OC_SUDO systemctl daemon-reload
    if systemctl is-enabled -q "$name" 2>/dev/null; then
        $OC_SUDO systemctl restart "$name"
        echo "$name restarted"
    else
        echo "$name is not enabled yet: sudo systemctl enable --now $name"
    fi
}

host_install() { # NAME TAG TGZ
    local name=$1 tag=$2 tgz=$3
    local d=$OC_PREFIX/lib/opencell/$name b=$OC_CACHE/$name/$tag
    rm -rf "$b"
    mkdir -p "$b/src"
    tar -xzf "$tgz" -C "$b/src"
    rm -f "$tgz"
    cmake -S "$b/src" -B "$b/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DOC_CORE_TESTS=OFF -DOC_PI_TESTS=OFF \
        -DOC_VERSION="$tag" >"$b/cmake.log" 2>&1 || { tail -20 "$b/cmake.log"; exit 1; }
    cmake --build "$b/build" -j2 >"$b/build.log" 2>&1 || { tail -30 "$b/build.log"; exit 1; }
    $OC_SUDO rm -rf "${d:?}/$tag"
    $OC_SUDO cmake --install "$b/build" --prefix "$d/$tag" >/dev/null
    [ -x "$d/$tag/bin/$name" ] || { echo "the build installed no bin/$name"; exit 1; }
    $OC_SUDO install -m 0644 "$b/src/dist/systemd/$name.service" "$d/$tag/$name.service"
    local old
    old=$(readlink "$d/current" 2>/dev/null || true)
    if [ -n "$old" ] && [ "$old" != "$tag" ]; then $OC_SUDO ln -sfn "$old" "$d/previous"; fi
    $OC_SUDO ln -sfn "$tag" "$d/current"
    $OC_SUDO mkdir -p "$OC_PREFIX/bin"
    $OC_SUDO ln -sfn "../lib/opencell/$name/current/bin/$name" "$OC_PREFIX/bin/$name"
    local prev
    prev=$(readlink "$d/previous" 2>/dev/null || true)
    for x in "$d"/v*; do
        [ -d "$x" ] || continue
        case "$(basename "$x")" in "$tag" | "$prev") ;; *) $OC_SUDO rm -rf "$x" ;; esac
    done
    rm -rf "$b"
    echo "$name $tag installed (previous: ${old:-none})"
    host_activate "$name"
}

host_rollback() { # NAME
    local name=$1 d=$OC_PREFIX/lib/opencell/$1 cur prev
    cur=$(readlink "$d/current" 2>/dev/null || true)
    prev=$(readlink "$d/previous" 2>/dev/null || true)
    [ -n "$prev" ] && [ -d "$d/$prev" ] || { echo "no previous build of $name to go back to"; exit 1; }
    $OC_SUDO ln -sfn "$prev" "$d/current"
    $OC_SUDO ln -sfn "$cur" "$d/previous"
    echo "$name back to $prev (previous: $cur)"
    host_activate "$name"
}

host_list() { # NAME
    local name=$1 d=$OC_PREFIX/lib/opencell/$1
    local cur prev
    cur=$(readlink "$d/current" 2>/dev/null || true)
    prev=$(readlink "$d/previous" 2>/dev/null || true)
    for x in "$d"/v*; do
        [ -d "$x" ] || continue
        local t mark=""
        t=$(basename "$x")
        [ "$t" = "$cur" ] && mark=" (current)"
        [ "$t" = "$prev" ] && mark=" (previous)"
        echo "$t$mark"
    done
}

HOST_FUNCS="$(declare -f host_activate host_install host_rollback host_list)"

# Run a host function on HOST (or here, under OC_DEPLOY_LOCAL).
on_host() { # HOST FUNCTION ARGS...
    local host=$1
    shift
    if [ -n "${OC_DEPLOY_LOCAL:-}" ]; then
        (OC_PREFIX=$OC_DEPLOY_LOCAL OC_SUDO="" OC_SYSTEMD=0 OC_CACHE=$OC_DEPLOY_LOCAL/cache "$@")
    else
        # shellcheck disable=SC2029
        ssh "$host" "OC_PREFIX=/usr/local OC_SUDO=sudo OC_SYSTEMD=1 OC_CACHE=\$HOME/.cache/oc-deploy bash -euo pipefail -s" \
            <<<"$HOST_FUNCS
$(printf '%q ' "$@")"
    fi
}

# ---- the laptop side ----

# The tree of REPO at REV into DEST/PREFIX, and every submodule's at the
# commit REV pins, recursively.
pack() { # REPO REV DEST PREFIX
    local repo=$1 rev=$2 dest=$3 prefix=$4
    mkdir -p "$dest/$prefix"
    git -C "$repo" archive --format=tar "$rev" | tar -x -C "$dest/$prefix"
    git -C "$repo" ls-tree -r "$rev" | while read -r mode type sha path; do
        [ "$type" = commit ] || continue
        [ -e "$repo/$path/.git" ] || die "$repo/$path: submodule not checked out (git submodule update --init --recursive)"
        git -C "$repo/$path" cat-file -e "$sha^{commit}" 2>/dev/null ||
            die "$repo/$path lacks $sha, which $rev pins (git -C $repo submodule update --init --recursive)"
        pack "$repo/$path" "$sha" "$dest" "$prefix$path/"
        : "$mode"
    done
}

deploy() { # REPO TAG HOST
    local repo=$1 tag=$2 host=$3 name
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'$tag': deploys take a tag vX.Y.Z"
    git -C "$repo" rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "$repo has no tag $tag"
    if [ -f "$repo/oc/oc_core_main.c" ]; then name=oc-core
    elif [ -f "$repo/oc-cell/occ_main.c" ]; then name=oc-cell
    else die "$repo is neither opencell-core nor opencell-pi"; fi
    local tgz
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    pack "$repo" "$tag^{commit}" "$TMP/tree" ""
    tar -czf "$TMP/src.tgz" -C "$TMP/tree" .
    echo "$name $tag: $(du -h "$TMP/src.tgz" | cut -f1) of source to $host"
    if [ -n "${OC_DEPLOY_LOCAL:-}" ]; then
        tgz=$TMP/src.tgz
    else
        tgz=/tmp/oc-deploy-$name-$tag.tgz
        scp -q "$TMP/src.tgz" "$host:$tgz"
    fi
    on_host "$host" host_install "$name" "$tag" "$tgz"
}

case "${1:-}" in
deploy) [ $# = 4 ] || die "usage: oc-deploy deploy REPO_DIR TAG HOST"; deploy "$2" "$3" "$4" ;;
rollback) [ $# = 3 ] || die "usage: oc-deploy rollback HOST NAME"; on_host "$2" host_rollback "$3" ;;
list) [ $# = 3 ] || die "usage: oc-deploy list HOST NAME"; on_host "$2" host_list "$3" ;;
*) die "usage: oc-deploy deploy REPO_DIR TAG HOST | rollback HOST NAME | list HOST NAME" ;;
esac
```

Run: `cd /home/devin/Documents/opencell/core && chmod 0755 tools/deploy/oc-deploy && bash -n tools/deploy/oc-deploy && echo syntax-ok`
Expected: `syntax-ok`.

- [ ] **Step 4: Run it to see it pass**

Run: `cd /home/devin/Documents/opencell/core && bash tests/test_oc_deploy.sh $PWD/tools/deploy/oc-deploy`
Expected: `OK`.

- [ ] **Step 5: The real repositories, locally**

The script on this repository and on the Pi's (with its submodules checked out), at scratch tags that are deleted afterwards:

Run: `cd /home/devin/Documents/opencell/core && git tag v0.0.0 && git -C ../pi tag v0.0.0 && R=$(mktemp -d) && OC_DEPLOY_LOCAL=$R tools/deploy/oc-deploy deploy $PWD v0.0.0 x | tail -1 && OC_DEPLOY_LOCAL=$R tools/deploy/oc-deploy deploy $PWD/../pi v0.0.0 x | tail -1 && $R/bin/oc-core --version && $R/bin/oc-cell --version; rm -rf $R; git tag -d v0.0.0 >/dev/null; git -C ../pi tag -d v0.0.0 >/dev/null`
Expected: `oc-core v0.0.0 installed (previous: none)`, `oc-cell v0.0.0 installed (previous: none)`, `oc-core v0.0.0`, `oc-cell v0.0.0`. (The Pi repository at `oc-cell`'s tip pins a core without this task's commit; that is fine: the deploy packs what the tag pins.)

- [ ] **Step 6: The whole suite**

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_core+6` (14 when validated).

- [ ] **Step 7: Commit and push**

```bash
cd /home/devin/Documents/opencell/core
git add tools/deploy/oc-deploy tests/test_oc_deploy.sh tests/CMakeLists.txt
git commit -m "tools/deploy/oc-deploy: deploy a tag of oc-core or oc-cell to a host, build there, keep the previous for rollback

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push
```

---

### Task 11: The bench on the Pi (spec §9.5a, §17 decision 2)

**Repos:** `opencell-core` and `opencell-pi` (tags, and the bench record in `opencell-pi`); hardware: the laptop and `opencell-bs1`. **Starts:** after Tasks 9 and 10 (both branches pushed). Not validated while writing: it needs the boards.

§17.2: "`oc-cell` runs on the Pi (`opencell-bs1`) with board A on USB (the `ocb_cell` backend). `oc-core` runs on the same Pi over the Unix socket of §6 … Terminals: T on the Pi's USB (console only), T2 on the laptop, both over the air." The plan-5 done list (plan-5 spec §1) runs again, now through `oc-cell` and `oc-core`, plus what is new: the TIME labels on a board with the internal PPS (#2), restarts of each daemon, and the mode switch from the core.

**Preconditions (check them; stop and ask the user if one fails):**
- The Pi sits within a few metres of the laptop: LoRa range between board A and both terminals, and BLE range from the laptop to T (the laptop drives T and T2 with `oc_ble.py`; beyond a few metres the BLE link drops, `oc_ble.py`'s own note).
- Board A (`…44:B1:76:AE:1A:E8`) and T (`…44:B1:76:AD:04:88`) are on the Pi's USB; T2 (`…44:B1:76:AE:20:64`) on the laptop's.
- Nothing else holds a board's port: no `ocbench`, no logger (one process per serial port). Stop them with `pkill -x ocbench` (never `pkill -f`).
- The phone app is force-stopped (`adb shell am force-stop org.opencell.app`), so the terminals accept the laptop's connection.
- `~/.config/opencell/hss-bench.txt` on the laptop holds T and T2 (activated) and `+883160655509999`.

**Files:**
- Create: `docs/bench/network-core-bench.md` (in `opencell-pi`)
- On the Pi (not in a repository): `/etc/opencell/{master.key,oc-core.conf,oc-cell.conf}`, `/var/lib/opencell/core/core.db`, users `oc-core` and `oc-cell`, group `oc-admin`, `~/.venvs/opencell` (esptool, bleak, pyserial), `~/fw-image/`.

**Interfaces:**
- Consumes: `oc-deploy` (Task 10), `oc-core admin` (Tasks 5–6), `oc-cell` and its log lines (Task 8), `dist/*.conf.example` and the units, the terminals' BLE contract through `tools/ble/oc_ble.py` (firmware `main`).
- Produces: tags `v0.1.0` on `opencell-core` (`oc-core` tip) and `opencell-pi` (`oc-cell` tip); `oc-core` and `oc-cell` enabled on `opencell-bs1`; the bench record.

In the steps, `A`, `T` and `T2` are the ports: `A=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_44:B1:76:AE:1A:E8-if00`, `T=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_44:B1:76:AD:04:88-if00`, `T2=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_44:B1:76:AE:20:64-if00`; `PI=opencell@opencell-bs1`; `BLE="$HOME/.venvs/opencell/bin/python /home/devin/Documents/opencell/firmware/tools/ble/oc_ble.py"`.

- [ ] **Step 1: The bench is free**

Run: `pgrep -ax ocbench; ls /dev/serial/by-id/ | grep -c 44:B1:76:AE:20:64; ssh opencell@opencell-bs1 'pgrep -ax ocbench; pgrep -ax oc-cell; ls /dev/serial/by-id/ | grep -c "44:B1:76:AE:1A:E8\|44:B1:76:AD:04:88"'`
Expected: `1`, then `2` (no process lines).

- [ ] **Step 2: T2 is a terminal again (laptop)**

T2's NVS was erased on 2026-09-28 so it could stand in as a cell; its terminal identity and bonds are in the archive. The firmware image has both roles; the NVS decides (`oc/term`; the archive backup still says `lc/term`, which the image moves to `oc/term` at its first boot).

Run: `sha256sum ~/Documents/opencell-archive/nvs-backups/t2-76ae2064-nvs-20260928.bin | cut -c1-8; stat -c %s ~/Documents/opencell-archive/nvs-backups/t2-76ae2064-nvs-20260928.bin`
Expected: `91ec738d`, then `24576` (0x6000, the NVS partition).

```bash
cd /home/devin/Documents/opencell/firmware
git fetch -q && git worktree add -f ../firmware-main origin/main   # the image T runs: firmware main
cd ../firmware-main
source ~/.espressif/tools/activate_idf_v6.0.1.sh
idf.py -C firmware -DOC_BENCH_LOW_POWER=1 build
T2=/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_44:B1:76:AE:20:64-if00
idf.py -C firmware -DOC_BENCH_LOW_POWER=1 -p "$T2" flash
esptool.py -p "$T2" --after no-reset write_flash 0x9000 ~/Documents/opencell-archive/nvs-backups/t2-76ae2064-nvs-20260928.bin   # no reset: the next line logs the boot that moves lc* to oc*
timeout 20 ~/.venvs/opencell/bin/python tools/ble/oc_console.py --reset "$T2" /tmp/t2-restore.log; grep -E "oc_nvs|role: terminal|tmid|registered|activated" /tmp/t2-restore.log | head -8
```

Expected: the flash and `write_flash` end with `Hash of data verified.` and `Hard resetting`; the console shows `oc_nvs: NVS lc -> oc: 1 key(s) moved` and `oc_nvs: NVS lc_id -> oc_id: 1 key(s) moved` (the backup's old names, moved at this first boot), `role: terminal` and T2's identity (TMID `76ae2064`, `+883160655501235`). It can't register yet: no cell runs. <!-- lc2oc: keep -->

- [ ] **Step 3: Board A on the same image (from the Pi)**

The Pi has no ESP-IDF; esptool from a venv flashes the image built in Step 2. `write_flash` of these four regions leaves A's NVS (0x9000, its bs-radio CONFIG) alone.

```bash
cd /home/devin/Documents/opencell/firmware-main/firmware/build
ssh opencell@opencell-bs1 'mkdir -p ~/fw-image/bootloader ~/fw-image/partition_table'
scp -q flash_args opencell_w12.bin ota_data_initial.bin opencell@opencell-bs1:fw-image/
scp -q bootloader/bootloader.bin opencell@opencell-bs1:fw-image/bootloader/
scp -q partition_table/partition-table.bin opencell@opencell-bs1:fw-image/partition_table/
scp -q /home/devin/Documents/opencell/firmware-main/tools/ble/oc_ble.py /home/devin/Documents/opencell/firmware-main/tools/ble/oc_console.py opencell@opencell-bs1:fw-image/
ssh opencell@opencell-bs1 'python3 -m venv ~/.venvs/opencell && ~/.venvs/opencell/bin/pip -q install esptool pyserial bleak'
ssh opencell@opencell-bs1 'cd ~/fw-image && ~/.venvs/opencell/bin/esptool.py -p /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_44:B1:76:AE:1A:E8-if00 write_flash @flash_args'
```

Expected: `Hash of data verified.` four times, then `Hard resetting via RTS pin...`. Then remove the worktree on the laptop: `git -C /home/devin/Documents/opencell/firmware worktree remove ../firmware-main`.

- [ ] **Step 4: The Pi's packages, users, key and directories**

```bash
ssh opencell@opencell-bs1 'set -e
sudo apt-get install -y -q libssl-dev libsqlite3-dev sqlite3 qrencode
id oc-core >/dev/null 2>&1 || sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin oc-core
id oc-cell >/dev/null 2>&1 || sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin -G dialout oc-cell
sudo groupadd -f oc-admin && sudo usermod -aG oc-admin opencell
sudo install -d -m 0755 /etc/opencell /var/lib/opencell
sudo install -d -o oc-core -g oc-core -m 0700 /var/lib/opencell/core
[ -e /etc/opencell/master.key ] || sudo sh -c "umask 077; head -c 32 /dev/urandom > /etc/opencell/master.key"
sudo chmod 0400 /etc/opencell/master.key
sudo stat -c "%a %U %s" /etc/opencell/master.key'
```

Expected: the apt lines, then `400 root 32`.

The master key is backed up once, offline (§5, §16.4): `ssh opencell@opencell-bs1 sudo cat /etc/opencell/master.key > ~/Documents/opencell-archive/keys/opencell-bs1-master.key && chmod 0400 ~/Documents/opencell-archive/keys/opencell-bs1-master.key` (make `keys/` first, mode 0700). Tell the user where it is: without it the database's keys can't be opened.

- [ ] **Step 5: Tags, and the deploys**

§17.4/§17.11: only tags are deployed. These tags go on the branch tips (ruling 4).

```bash
cd /home/devin/Documents/opencell/core && git status --short && git tag -a v0.1.0 -m "oc-core 0.1.0: network core 2 on the bench" && git push -q origin v0.1.0
cd /home/devin/Documents/opencell/pi && git status --short && git tag -a v0.1.0 -m "oc-cell 0.1.0: network core 2 on the bench" && git push -q origin v0.1.0
cd /home/devin/Documents/opencell/core && tools/deploy/oc-deploy deploy /home/devin/Documents/opencell/core v0.1.0 opencell@opencell-bs1
tools/deploy/oc-deploy deploy /home/devin/Documents/opencell/pi v0.1.0 opencell@opencell-bs1
```

Expected: `oc-core v0.1.0 installed (previous: none)` and `oc-core is not enabled yet: sudo systemctl enable --now oc-core`; the same for `oc-cell`. (A Pi 4 builds each in a minute or two.) Then:

Run: `ssh opencell@opencell-bs1 'oc-core --version; oc-cell --version; readlink /usr/local/lib/opencell/oc-core/current'`
Expected: `oc-core v0.1.0`, `oc-cell v0.1.0`, `v0.1.0`.

- [ ] **Step 6: The configs, and the database from ocbench's HSS**

```bash
cd /home/devin/Documents/opencell
scp -q core/dist/oc-core.conf.example pi/dist/oc-cell.conf.example opencell@opencell-bs1:/tmp/
scp -q ~/.config/opencell/hss-bench.txt opencell@opencell-bs1:/tmp/hss-bench.txt
ssh opencell@opencell-bs1 'set -e
sudo install -m 0644 /tmp/oc-core.conf.example /etc/opencell/oc-core.conf
sudo install -m 0644 /tmp/oc-cell.conf.example /etc/opencell/oc-cell.conf
sudo install -o oc-core -m 0600 /tmp/hss-bench.txt /var/lib/opencell/core/import.txt
shred -u /tmp/hss-bench.txt
K="--offline --key-file /etc/opencell/master.key"
sudo oc-core admin $K import-ocb-hss /var/lib/opencell/core/import.txt
sudo shred -u /var/lib/opencell/core/import.txt
sudo oc-core admin $K cell add 1 bench-pi --mode part15
sudo oc-core admin $K status
ls -l /var/lib/opencell/core'
```

Expected:
```
network key 1 imported
+883160655501234  terminal 76ad0488  sqn 28  imported
+883160655501235  terminal 76ae2064  sqn 5  imported
+883160655509999  not activated: give it a code with `oc-core admin sub issue +883160655509999`
cell 1 "bench-pi" added: part15, list 0
core 1, network key 1, schema v1, offline
subscribers 3 (2 activated, 0 disabled), locations 0, calls 0, links 0
cell 1 "bench-pi": part15, enabled, list 0, not linked
```
(the SQN values are whatever the file held), and `core.db`, `core.db.lock` owned by `oc-core` (the offline command ran as that user after reading the key). Then move the laptop's copy out of use: `mv ~/.config/opencell/hss-bench.txt ~/Documents/opencell-archive/hss-bench-imported-20260928.txt` (it keeps mode 0600).

- [ ] **Step 7: Start the core and the cell**

Run: `ssh opencell@opencell-bs1 'sudo systemctl enable --now oc-core oc-cell && sleep 8 && systemctl is-active oc-core oc-cell && journalctl -u oc-cell -b --no-pager | grep -E "HELLO accepted|board timebase|radio: seed" && sudo oc-core admin status'`
Expected: `active`, `active`; `radio: seed cafef00d, anchor ch …, cycle sync, internal PPS`, `core: HELLO accepted`, `radio: board timebase, frame N (k labels sent)` with k from 1 to 3; the status shows `running` and `cell 1 "bench-pi": part15, enabled, list 0, linked`.

- [ ] **Step 8: TIME labels at any PPS phase (issue #2 on the board)**

Each start resets board A (`board_reset = 1`): a new PPS phase each time.

Run: `ssh opencell@opencell-bs1 'for i in 1 2 3 4 5; do sudo systemctl restart oc-cell; sleep 10; journalctl -u oc-cell --since "-10s" --no-pager | grep -c "board timebase"; done'`
Expected: `1` five times. (Before the fix a start whose phase fell 0.1–0.2 s after the second never got one.)

- [ ] **Step 9: T and T2 register through the core**

Both were registered on ocbench's cell with the same seed; each finds the cell again and registers with the vectors the core now issues from the imported K, OPc and SQN (a stale SQN resyncs through the core).

Run: `sleep 60; ssh opencell@opencell-bs1 sudo oc-core admin loc`
Expected: `+883160655501234  cell 1  tmid 76ad0488  expires in …` and `+883160655501235  cell 1  tmid 76ae2064  expires in …`. If one is missing after 3 minutes, reset that terminal (`oc_console.py --reset`, T from the Pi, T2 from the laptop) and look at its console and `journalctl -u oc-cell -u oc-core`.

- [ ] **Step 10: The plan-5 done list, through `oc-cell` and `oc-core`**

Keep a console log of each terminal while the rows run: on the laptop `~/.venvs/opencell/bin/python /home/devin/Documents/opencell/firmware/tools/ble/oc_console.py $T2 /tmp/t2.log &`, on the Pi `~/.venvs/opencell/bin/python ~/fw-image/oc_console.py $T /tmp/t.log &` (stop them at the end with `kill` of the PIDs that `$!` gave). Two-terminal rows start the callee's `oc_ble.py` first, in the background.

| # | Row | Commands (laptop) | Expected |
|---|---|---|---|
| 1 | Outgoing call answered by the network's far end (the echo service) | `$BLE --name OpenCell-76AE2064 wait:registered:60 dial:+883160655500100 wait:connected:30 ping:5 hangup wait:ended:15` | exit 0; `connected` about 3 s after `ringing`; 5 frames back |
| 2 | T calls T2 on the same cell: rings, connects, app data both ways, caller hangs up | `$BLE --name OpenCell-76AE2064 wait:incoming:60 answer recv:5 send:5 wait:ended:60 &` then `$BLE --name OpenCell-76AD0488 dial:606-555-1235 wait:connected:30 send:5 recv:5 hangup` | both exit 0 |
| 3 | The callee hangs up | as row 2 with the roles of `hangup` and `wait:ended` swapped | both exit 0; the caller's `ended` cause 0 |
| 4 | The callee rejects | `$BLE --name OpenCell-76AD0488 wait:incoming:60 reject &` then `$BLE --name OpenCell-76AE2064 dial:+883160655501234 wait:ended:30` | T2's `ended` cause 1 |
| 5 | An incoming call answered on the other terminal | row 2 with T2 calling T | both exit 0 |
| 6 | A rebooted terminal registers again by itself | `timeout 60 ~/.venvs/opencell/bin/python …/oc_console.py --reset $T2 /tmp/t2-boot.log; grep -c registered /tmp/t2-boot.log` | `1` or more; `admin loc` lists T2 |
| 7 | A code from `oc-core admin` activates the terminal; the same code again fails ("token used") | `$BLE --name OpenCell-76AE2064 deactivate`; on the Pi `sudo oc-core admin sub issue +883160655501235` (take the `opencell:2:…` line); `$BLE --name OpenCell-76AE2064 activate:CODE wait:activated:60 wait:registered:60`; `$BLE … deactivate`; `$BLE … activate:CODE wait:act_failed:60`; a new code: `sub issue` again, `activate:NEWCODE wait:activated:60 wait:registered:60` | activated and registered; `act_failed` for the used code; `admin audit 20` shows `TOKEN_ISSUE`, `ACTIVATE`, `ACT_FAIL` |
| 8 | Part 97 mode from the core | on the Pi `sudo oc-core admin cell mode 1 part97`; wait 60 s; `$BLE --name OpenCell-76AD0488 status` and row 1 on T; then `cell mode 1 part15` | `journalctl -u oc-cell`: `the core says part97`; both terminals `registered` again (STATUS mode part97); the echo call works; back in part15 both register again |
| 9 | `oc-cell` restarts | `sudo systemctl restart oc-cell`; after 2 min `sudo oc-core admin loc` | both terminals listed again (a new boot purged them, their re-attach registered them) |
| 10 | `oc-core` restarts in a call | row 1 on T2 with `ping:60` in the background; after the `connected` line `sudo systemctl restart oc-core` | T2's call `ended` cause 5 within 10 s; `journalctl -u oc-cell`: `core: link lost`, then `core: HELLO accepted`; `admin loc` still lists both without a new `REGISTER` in `admin audit`; row 1 again passes |
| 11 | Records | `sudo oc-core admin cdr 20; sudo oc-core admin audit 50` | CDRs for the echo calls (`cells 1 -> 0`, answered) and row 10's (`cause 5`); local calls (rows 2–5) are switched in the cell and have none (spec §7.3); `ADMIN` records for every admin command |
| 12 | Health | `ssh $PI 'journalctl -u oc-core -u oc-cell -b -p warning --no-pager'`; `grep -a -E "Guru Meditation|stack overflow|abort\(\)|assert failed" /tmp/t2.log` and the same on the Pi for `/tmp/t.log`; the last `core linked | radio: …` line of `journalctl -u oc-cell` | only the warnings rows 8–10 caused; no crash lines; ack errors: a few `late` (labels) at most |

A row that fails is a defect to find (systematic debugging), fixed in the task that owns the code, with a host test that would have caught it; then the row runs again. Record it.

- [ ] **Step 11: The bench record**

Create `docs/bench/network-core-bench.md` in `opencell-pi` with: the date; the setup (boards and ports, firmware image commit, `oc-core`/`oc-cell` `v0.1.0` and their commits, the Pi's OS); the import output of Step 6; Step 8's five results; the rows table above with what each row showed (times, causes, counts); the defects found and their fixes; the end state (both units enabled on the Pi, T and T2 registered on cell 1, T2's NVS no longer the archived one if row 7 re-activated it, the master key backed up at `~/Documents/opencell-archive/keys/`). Then:

```bash
cd /home/devin/Documents/opencell/pi
git add docs/bench/network-core-bench.md
git commit -m "Bench: oc-core and oc-cell on opencell-bs1 (network-core spec 9.5a)

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push
gh issue close 2 -R opencell-dev/opencell-firmware -c "Fixed on oc-bench by ocb_time (TIME labels only until the board has a timebase, retried after late). On opencell-bs1 board A took its labels on 5 of 5 starts (network core 2, Task 11)."
```

---

### Task 12: `ocbench net`, `ocbench mkqr`, `ocb_net` and `ocb_hss` retire

**Repo:** `opencell-firmware`, branch `oc-bench`, at `/home/devin/Documents/opencell/firmware`. **Starts:** after Task 11 (the bench passed: `oc-cell` and `oc-core` replaced them on hardware).

Spec §11 row 8: "`oc-cell` on the `ocb_cell` backend (replaces `ocbench net`; `ocb_net` and `ocb_hss` retire)". What happens to each (ruling 5):
- `ocbench net` and `ocbench mkqr`: removed. `oc-cell` is the cell; `oc-core admin sub issue` makes activation codes; ocbench's HSS file was imported in Task 11 and archived.
- `ocb_net.[ch]`, `ocb_hss.[ch]`: deleted. The HSS text format is read only by `oc-core admin import-ocb-hss` (its own parser, Task 5).
- `ocbench cell` stays for terminal bring-up without a network, and gains `--mode part15|part97` (the beacon's flag, which `--fixed-sync` needs; it used to come from `net`'s HSS).
- The tests. `test_term_sim.c` ran part of its air-path tests over `ocb_net`; they move to the bare `oc_sig_net` on the fake core the rest of that file uses (`sig_start_mode`, `net_list_text`, `net_restart`), keeping every assertion, so the channel-list regressions from the chan-list bench (the M1 fix, the bump after a restart, FIXED sync in Part 97) stay covered. The stand-in's own end-to-end test goes: its simulated far end is the core's echo service now, covered by `test_ocr`, `test_net_sim` and the process tests. `test_ocbench.c` loses the HSS file tests, the `--chan-list` parser tests (the parser is `oc_chan_parse` now, tested in `test_oc_admin`) and plan 1's `ocb_net` call test.

**Files:**
- Delete: `tools/ocbench/ocb_net.c`, `tools/ocbench/ocb_net.h`, `tools/ocbench/ocb_hss.c`, `tools/ocbench/ocb_hss.h`
- Modify: `tools/ocbench/ocbench.c`, `tools/ocbench/CMakeLists.txt`, `tools/ocbench/ocb_cell.h` (a comment), `host-tests/test_term_sim.c`, `host-tests/test_ocbench.c`, `README.md`

**Interfaces:**
- Consumes: `oc_sig_net_set_chan_list`, `oc_sig_net_init`, `fc_init` (`host-tests/sig_fake_core.h`, plan 1), `OC_SIG_SVC_CONFIG`, `OC_BCN_MAX_CFG_VER`.
- Produces: `ocbench cell … [--mode part15|part97]`; no `ocbench net`, no `ocbench mkqr`; the `ocbench_core` library without `ocb_net`/`ocb_hss` (what `oc-cell` links: `ocb_cell`, `ocb_merge`, `ocb_time`, `ocbench_core`).

The replacements below were cut from the files as plan 1 left them (firmware `net-core` at `3c9581f`) with Task 1 applied. If one is not there verbatim (a later bench fix touched ocbench.c), make the same change by hand; the whole-function replacements of `test_term_sim.c` differ from the old text only where `ocb_net` was used. If plan 1's `test_ocb_net_mo_call_to_unregistered_subscriber_refused` is not in `test_ocbench.c`, skip its two replacements.

- [ ] **Step 1: The baseline**

Run: `cd /home/devin/Documents/opencell/firmware && git branch --show-current && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; for t in test_term_sim test_ocbench; do host-tests/build/$t | grep Tests; done`
Expected: `oc-bench`, then `25 Tests 0 Failures 0 Ignored` and `26 Tests 0 Failures 0 Ignored` (the counts when validated; write them down).

- [ ] **Step 2: The edits**

In `tools/ocbench/ocbench.c`, replace:
```c
 *                  [--sync-ch N] [--fixed-sync]  (anchor channel 0-51, default seed % 6; FIXED:
 *                  every beacon on it, Part 97 only: `net --mode part97`)
 *                  Runs a minimal cell (ocb_cell.h) for terminal bring-up; 2.4 GHz legs need
 *                  --tty-2g4 and shared GPS PPS, or --one-board (one W12 switches bands per slot).
 *   ocbench mkqr   --number +883-1-606-555-01234 [--hss FILE] [--expires-h H] [--mode part15|part97]
 *                  Plays the web portal: issues an activation token, prints the QR text (and
 *                  the QR itself with qrencode, if installed). Refused while `ocbench net` runs
 *                  on the same HSS (it holds FILE.lock): stop net, mkqr, start net again.
 *   ocbench net    <tty_915> <near|mid|edge> <seconds> [--hss FILE] [--mode part15|part97]
 *                  [--call-in +883-1-... --after S] [--peer-hangup S]
 *                  [--chan-list MHZ[:fixed],...] [--list-ver N] [--bump-list-after S] [cell options]
 *                  `cell` plus the network stand-in (ocb_net.h): activation, registration, calls
 *                  to a simulated far end that answers after 3 s (and hangs up S s after connect
 *                  with --peer-hangup), app data echo. It pushes a channel list (CHAN_LIST) after
 *                  every registration: --chan-list (at most 12 grid channels, in order), or the
 *                  cell's own anchor; its version (--list-ver 0-255, default 1) goes in the beacon
 *                  mod 4, and --bump-list-after S (1-86400; list-ver at most 254 then) adds 1 to
 *                  it S s in (terminals then ask for the list). Bad option values exit 1 before
 *                  the HSS or a board is touched.
```
with:
```c
 *                  [--sync-ch N] [--fixed-sync] [--mode part15|part97]  (anchor channel 0-51,
 *                  default seed % 6; FIXED: every beacon on it, Part 97 only)
 *                  Runs a minimal cell (ocb_cell.h) for terminal bring-up; 2.4 GHz legs need
 *                  --tty-2g4 and shared GPS PPS, or --one-board (one W12 switches bands per slot).
 *
 * The network stand-in (`ocbench net`, `ocbench mkqr`, ocb_net, ocb_hss) retired
 * with network core 2: the network is oc-cell (opencell-pi) and oc-core
 * (opencell-core), and `oc-core admin sub issue` makes activation codes.
```

In `tools/ocbench/ocbench.c`, replace:
```c
#include "ocb_cell.h"
#include "ocb_hss.h"
#include "ocb_merge.h"
#include "ocb_net.h"
```
with:
```c
#include "ocb_cell.h"
#include "ocb_merge.h"
```

In `tools/ocbench/ocbench.c`, replace:
```c
/* ---- network stand-in: HSS file, token issue (mkqr), ocb_net on the cell (net) ---- */

static void urandom(uint8_t *out, size_t n)
{
    while (n > 0) {
        ssize_t r = getrandom(out, n, 0);
        if (r > 0) {
            out += r;
            n -= (size_t)r;
        }
    }
}

/* ~/.config/opencell/hss.txt, creating the directories. */
static const char *hss_default_path(void)
{
    static char path[512];
    const char *home = getenv("HOME");
    snprintf(path, sizeof(path), "%s/.config", home != NULL ? home : ".");
    mkdir(path, 0700);
    strncat(path, "/opencell", sizeof(path) - strlen(path) - 1);
    mkdir(path, 0700);
    strncat(path, "/hss.txt", sizeof(path) - strlen(path) - 1);
    return path;
}

/* Load the HSS, making the network key pair on first use, and apply --mode. */
static int hss_open(ocb_hss_t *h, const char *path, const char *mode)
{
    if (ocb_hss_load(h, path) != 0) {
        if (h->err[0] != '\0') {
            fprintf(stderr, "%s\n", h->err);
        } else {
            fprintf(stderr, "%s: unreadable HSS file\n", path);
        }
        return -1;
    }
    int dirty = !h->have_network;
    if (ocb_hss_ensure_network(h, urandom) != 0) return -1;
    if (mode != NULL) {
        uint8_t m = strcmp(mode, "part97") == 0 ? OC_SIG_MODE_PART97 : OC_SIG_MODE_PART15;
        dirty |= m != h->mode;
        h->mode = m;
    }
    if (dirty && ocb_hss_save(h, path) != 0) {
        fprintf(stderr, "%s: can't write\n", path);
        return -1;
    }
    return 0;
}

static int cmd_mkqr(int argc, char **argv)
{
    const char *number = NULL, *path = NULL, *mode = NULL;
    uint32_t hours = 24;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--number") == 0 && i + 1 < argc) number = argv[++i];
        else if (strcmp(argv[i], "--hss") == 0 && i + 1 < argc) path = argv[++i];
        else if (strcmp(argv[i], "--expires-h") == 0 && i + 1 < argc) hours = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
        else return 2;
    }
    uint8_t bcd[OC_SIG_NUMBER_LEN];
    if (number == NULL || oc_sig_number_normalize(number, strlen(number), NULL, bcd) != 0) {
        fprintf(stderr, "--number must be a full OpenCell number, e.g. +883-1-606-555-01234\n");
        return 1;
    }
    if (ocb_hss_v1_number(bcd)) {
        fprintf(stderr, "--number %s has 13 digits (numbering v1): use the 15-digit form, e.g. +883-1-606-555-01234\n",
                number);
        return 1;
    }
    if (path == NULL) path = hss_default_path();
    /* ocbench net rewrites the whole HSS on every save: a token added under
     * it would be erased. Held until exit. */
    int lk = ocb_hss_lock(path);
    if (lk == -1) {
        fprintf(stderr, "%s: ocbench net is running on this HSS; stop it first\n", path);
        return 1;
    }
    if (lk < 0) {
        fprintf(stderr, "%s.lock: can't open the lock file\n", path);
        return 1;
    }
    static ocb_hss_t h;
    if (hss_open(&h, path, mode) != 0) return 1;
    oc_sig_sub_t *sub = ocb_hss_issue(&h, bcd, (uint32_t)time(NULL) + hours * 3600u, urandom);
    if (sub == NULL || ocb_hss_save(&h, path) != 0) {
        fprintf(stderr, "%s: HSS full or not writable\n", path);
        return 1;
    }
    oc_sig_qr_t q;
    char text[OC_SIG_QR_TEXT + 1];
    ocb_hss_qr(&h, sub, &q);
    oc_sig_qr_format(&q, text, sizeof(text));
    char num[OC_SIG_NUMBER_TEXT], show[OC_SIG_NUMBER_SHOW];
    oc_sig_number_to_text(sub->number, num);
    oc_sig_number_format(sub->number, show, sizeof(show));
    printf("%s: token for %s (%s), valid %u h, network key %u (%s)\n%s\n", path, num, show, hours, h.key_id,
           h.mode == OC_SIG_MODE_PART97 ? "part97" : "part15", text);
    fflush(stdout); /* qrencode below writes to the inherited stdout fd directly, bypassing our
                      * buffering: flush first so the text line precedes the QR art when piped. */
    FILE *qr = system("command -v qrencode >/dev/null 2>&1") == 0 ? popen("qrencode -t ANSIUTF8", "w") : NULL;
    if (qr != NULL) {
        fputs(text, qr);
        pclose(qr);
    } else {
        printf("(draw it: ~/.venvs/opencell/bin/python tools/qr/qr.py '%s')\n", text);
    }
    return 0;
}

static void net_log(const char *line)
{
    printf("net: %s\n", line);
    fflush(stdout);
}

static int cmd_cell(int argc, char **argv, int net)
```
with:
```c
static int cmd_cell(int argc, char **argv)
```

In `tools/ocbench/ocbench.c`, replace:
```c
    const char *hss_path = NULL, *mode = NULL, *call_in = NULL, *chan_list = NULL;
    uint32_t call_after = 10, peer_hangup = 0, bump_after = 0;
    int sync_ch = -1, fixed_sync = 0, list_ver = 1;
```
with:
```c
    const char *mode = NULL;
    int sync_ch = -1, fixed_sync = 0;
```

In `tools/ocbench/ocbench.c`, replace:
```c
        } else if (net && strcmp(argv[i], "--chan-list") == 0 && i + 1 < argc) {
            chan_list = argv[++i];
        } else if (net && strcmp(argv[i], "--list-ver") == 0 && i + 1 < argc) {
            if (ocb_parse_int(argv[++i], 0, 255, &v) != 0) {
                fprintf(stderr, "--list-ver '%s': a version, 0-255\n", argv[i]);
                return 1;
            }
            list_ver = (int)v;
        } else if (net && strcmp(argv[i], "--bump-list-after") == 0 && i + 1 < argc) {
            if (ocb_parse_int(argv[++i], 1, 86400, &v) != 0) {
                fprintf(stderr, "--bump-list-after '%s': seconds, 1-86400\n", argv[i]);
                return 1;
            }
            bump_after = (uint32_t)v;
        } else if (net && strcmp(argv[i], "--hss") == 0 && i + 1 < argc) {
            hss_path = argv[++i];
        } else if (net && strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (net && strcmp(argv[i], "--call-in") == 0 && i + 1 < argc) {
            call_in = argv[++i];
        } else if (net && strcmp(argv[i], "--after") == 0 && i + 1 < argc) {
            call_after = (uint32_t)atoi(argv[++i]);
        } else if (net && strcmp(argv[i], "--peer-hangup") == 0 && i + 1 < argc) {
            peer_hangup = (uint32_t)atoi(argv[++i]);
```
with:
```c
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
            if (strcmp(mode, "part15") != 0 && strcmp(mode, "part97") != 0) {
                fprintf(stderr, "--mode '%s': part15 or part97\n", mode);
                return 1;
            }
```

In `tools/ocbench/ocbench.c`, replace:
```c
    if (bump_after != 0 && list_ver == 255) {
        fprintf(stderr, "--bump-list-after with --list-ver 255: the bump would wrap to 0 (use 0-254)\n");
        return 1;
    }
    static oc_sig_chan_list_t list;
    if (chan_list != NULL) {
        char err[96];
        if (ocb_net_parse_chan_list(chan_list, (uint8_t)list_ver, &list, err, sizeof(err)) != 0) {
            fprintf(stderr, "--chan-list: %s\n", err);
            return 1;
        }
    }
    ocb_cell_init(&cell, seed, tier, dl, ul);
```
with:
```c
    ocb_cell_init(&cell, seed, tier, dl, ul);
    cell.part97 = mode != NULL && strcmp(mode, "part97") == 0; /* the beacon's flag: it decides the anchors */
```

In `tools/ocbench/ocbench.c`, replace:
```c
    static ocb_hss_t hss;
    static ocb_net_t lnet;
    uint8_t call_in_bcd[OC_SIG_NUMBER_LEN];
    if (net) {
        if (hss_path == NULL) hss_path = hss_default_path();
        if (call_in != NULL && oc_sig_number_normalize(call_in, strlen(call_in), NULL, call_in_bcd) != 0) {
            fprintf(stderr, "--call-in must be a full OpenCell number, e.g. +883-1-606-555-01234\n");
            return 2;
        }
        if (call_in != NULL && ocb_hss_v1_number(call_in_bcd)) {
            fprintf(stderr,
                    "--call-in %s has 13 digits (numbering v1): use the 15-digit form, e.g. +883-1-606-555-01234\n",
                    call_in);
            return 1;
        }
        /* The HSS is ours until exit (the fd stays open): mkqr refuses meanwhile. */
        int lk = ocb_hss_lock(hss_path);
        if (lk == -1) {
            fprintf(stderr, "%s: another ocbench (net or mkqr) is using this HSS\n", hss_path);
            return 1;
        }
        if (lk < 0) {
            fprintf(stderr, "%s.lock: can't open the lock file\n", hss_path);
            return 1;
        }
        if (hss_open(&hss, hss_path, mode) != 0) return 1;
        ocb_net_init(&lnet, &cell, &hss, hss_path, urandom, now_us, net_log);
        lnet.peer_hangup_us = peer_hangup * 1000000u;
        printf("net: %s, key %u, %s, %u subscribers\n", hss_path, hss.key_id,
               hss.mode == OC_SIG_MODE_PART97 ? "part97" : "part15", hss.n);
    }
    /* After ocb_net_init: it sets the cell's mode, which decides what the anchor may be. */
```
with:
```c

```

In `tools/ocbench/ocbench.c`, replace:
```c
                fixed_sync && !cell.part97 ? "FIXED sync is Part 97 only (ocbench net --mode part97)"
```
with:
```c
                fixed_sync && !cell.part97 ? "FIXED sync is Part 97 only (--mode part97)"
```

In `tools/ocbench/ocbench.c`, replace:
```c
    if (net) {
        if (chan_list == NULL) {
            ocb_net_own_chan_list(&cell, (uint8_t)list_ver, &list);
        }
        for (uint8_t i = 0; i < list.count; i++) {
            if ((list.flags[i] & OC_SIG_CHAN_FIXED) && !cell.part97) {
                fprintf(stderr, "--chan-list: ':fixed' entries are Part 97 only (--mode part97)\n");
                return 1;
            }
        }
        ocb_net_set_chan_list(&lnet, &list);
    }
```
with:
```c

```

In `tools/ocbench/ocbench.c`, replace:
```c
    int paged = 0, bumped = 0;
    if (net && call_in != NULL) {
        ocb_net_call_in(&lnet, call_in_bcd, start + (uint64_t)call_after * 1000000u);
    }
    while (now_us() < end) {
        pump(bs, nb, 5, on_cell_msg, &ctx);
        uint64_t t = now_us();
        if (net) {
            ocb_net_tick(&lnet, t);
        }
        uint32_t s = (uint32_t)(t / 1000000u);
        send_labels(bs, nb, t);
        if (net && bump_after && !bumped && t - start >= (uint64_t)bump_after * 1000000u) {
            list.ver++; /* the beacon's cfg_ver changes: registered terminals ask (SERVICE_REQ 4) */
            ocb_net_set_chan_list(&lnet, &list);
            bumped = 1;
        }
```
with:
```c
    int paged = 0;
    while (now_us() < end) {
        pump(bs, nb, 5, on_cell_msg, &ctx);
        uint64_t t = now_us();
        uint32_t s = (uint32_t)(t / 1000000u);
        send_labels(bs, nb, t);
```

In `tools/ocbench/ocbench.c`, replace:
```c
            "  ocbench mkqr   --number +883-1-606-555-01234 [--hss FILE] [--expires-h H] [--mode part15|part97]\n"
            "                 (not while ocbench net runs on the same HSS: it holds FILE.lock)\n"
            "  ocbench net    <tty_915> <near|mid|edge> <seconds> [--hss FILE] [--mode part15|part97]\n"
            "                 [--call-in +883-1-... --after S] [--peer-hangup S]\n"
            "                 [--chan-list MHZ[:fixed],...] [--list-ver N] [--bump-list-after S] [cell options]\n");
```
with:
```c
            "                 [--mode part15|part97]\n");
```

In `tools/ocbench/ocbench.c`, replace:
```c
    if (strcmp(cmd, "cell") == 0 || strcmp(cmd, "net") == 0) {
        int r = cmd_cell(argc, argv, strcmp(cmd, "net") == 0);
        return r == 2 ? usage() : r;
    }
    if (strcmp(cmd, "mkqr") == 0) {
        int r = cmd_mkqr(argc, argv);
        return r == 2 ? usage() : r;
    }
```
with:
```c
    if (strcmp(cmd, "cell") == 0) {
        int r = cmd_cell(argc, argv);
        return r == 2 ? usage() : r;
    }
```

In `tools/ocbench/ocb_cell.h`, replace:
```c
/* Signalling hooks (ocbench net): UL DATA payloads and RACH UPPER payloads
```
with:
```c
/* Signalling hooks (oc-cell's radio backend): UL DATA payloads and RACH UPPER payloads
```

In `README.md`, replace:
```markdown
- `tools/ocbench/`: the bench tool (cell, network stand-in `ocbench net`, activation codes `ocbench mkqr`, radio probes).
```
with:
```markdown
- `tools/ocbench/`: the bench tool (a minimal cell for terminal bring-up, radio probes, board config and flashing). The network (activation codes, registration, calls) is `oc-core` and `oc-cell`, in [opencell-core](https://github.com/opencell-dev/opencell-core) and [opencell-pi](https://github.com/opencell-dev/opencell-pi).
```

In `tools/ocbench/CMakeLists.txt`, replace:
```cmake
add_library(ocbench_core STATIC ocbench_core.c ocb_cell.c ocb_hss.c ocb_net.c ocb_merge.c ocb_time.c)
```
with:
```cmake
add_library(ocbench_core STATIC ocbench_core.c ocb_cell.c ocb_merge.c ocb_time.c)
```

In `host-tests/test_term_sim.c`, replace:
```c
#include "ocb_hss.h"
#include "ocb_net.h"
```
with:
```c

```

In `host-tests/test_term_sim.c`, replace:
```c
#include <string.h>
#include <time.h>
```
with:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
```

In `host-tests/test_term_sim.c`, replace:
```c
static const oc_sig_net_io_t snet_io = { NULL, fc_act_req, fc_av_req, fc_resync_req, NULL, NULL, s_send,
                                         s_channel, s_call, NULL };
```
with:
```c
static int net_svc_config; /* service requests with cause 4 (config) the network got */
static int net_cl_taken;   /* CHAN_LIST_ACKs oc_sig_net logged */
static void s_log(void *c, const char *line)
{
    (void)c;
    if (strstr(line, "channel list v") != NULL && strstr(line, " taken by terminal ") != NULL) net_cl_taken++;
}
static const oc_sig_net_io_t snet_io = { NULL, fc_act_req, fc_av_req, fc_resync_req, NULL, NULL, s_send,
                                         s_channel, s_call, s_log };
```

In `host-tests/test_term_sim.c`, replace:
```c
    if (n == 1 && (p[0] & 0xF0u) == OC_SIG_KIND_SVC) oc_sig_net_service_req(&snet, tmid, p[0] & 0x0Fu, sim_now());
```
with:
```c
    if (n == 1 && (p[0] & 0xF0u) == OC_SIG_KIND_SVC) {
        if ((p[0] & 0x0Fu) == OC_SIG_SVC_CONFIG) net_svc_config++;
        oc_sig_net_service_req(&snet, tmid, p[0] & 0x0Fu, sim_now());
    }
```

In `host-tests/test_term_sim.c`, replace:
```c
static void sig_start(void)
{
    uint8_t skn[32], r[32];
    memset(skn, 0x11, 32);
    oc_sig_net_cfg_t cfg = { OC_SIG_MODE_PART15, 1800 };
```
with:
```c
static void sig_start_mode(uint8_t mode)
{
    uint8_t skn[32], r[32];
    memset(skn, 0x11, 32);
    oc_sig_net_cfg_t cfg = { mode, 1800 };
    cell.part97 = mode == OC_SIG_MODE_PART97; /* the beacon announces it */
```

In `host-tests/test_term_sim.c`, replace:
```c
    sig_nevs = snet_mo = snet_ended = 0;
    app_rx_n = 0;
    sig_on = 1;
}
```
with:
```c
    sig_nevs = snet_mo = snet_ended = 0;
    app_rx_n = 0;
    net_svc_config = net_cl_taken = 0;
    sig_on = 1;
}

static void sig_start(void) { sig_start_mode(OC_SIG_MODE_PART15); }

/* The cell's channel list, as oc-cell serves the core's CELL_CFG: oc_sig_net
 * pushes it, and the beacon's cfg_ver is its version mod 4. text:
 * "902.25,917.25:fixed" (MHz on the 915 grid). */
static void net_list_text(const char *text, uint8_t ver)
{
    oc_sig_chan_list_t l;
    char buf[128], *save = NULL;
    memset(&l, 0, sizeof(l));
    l.ver = ver;
    snprintf(buf, sizeof(buf), "%s", text);
    for (char *t = strtok_r(buf, ",", &save); t != NULL; t = strtok_r(NULL, ",", &save)) {
        l.flags[l.count] = strstr(t, ":fixed") != NULL ? OC_SIG_CHAN_FIXED : 0u;
        l.freq_hz[l.count++] = (uint32_t)(strtod(t, NULL) * 1000000.0 + 0.5);
    }
    oc_sig_net_set_chan_list(&snet, &l);
    cell.cfg_ver = (uint8_t)(ver & OC_BCN_MAX_CFG_VER);
}

/* The network restarts: a new oc_sig_net (no sessions, no list), the
 * subscriber record in the fake core kept, as a real core keeps it. */
static void net_restart(void)
{
    uint8_t skn[32];
    memset(skn, 0x11, 32);
    oc_sig_net_cfg_t cfg = { cell.part97 ? OC_SIG_MODE_PART97 : OC_SIG_MODE_PART15, 1800 };
    oc_sig_net_init(&snet, &snet_io, &cfg);
    fc_init(&snet, &ssub, &nssub, skn, 1790000000u, sim_now);
    net_svc_config = net_cl_taken = 0;
}
```

In `host-tests/test_term_sim.c`, replace:
```c
/* ---- ocb_net (the stand-in ocbench net runs) instead of the bare oc_sig_net ---- */

static ocb_hss_t lhss;
static ocb_net_t lnet;
static int net_lines;
static uint8_t sim_rnd_ctr;

static void sim_rnd(uint8_t *o, size_t n) { for (size_t i = 0; i < n; i++) o[i] = (uint8_t)(sim_rnd_ctr++ * 29u + 3u); }
static char net_dials[96]; /* ocb_net's last "dials" line */
static int net_svc_config;  /* ocb_net logged a service request with cause 4 */
static int net_cl_taken;    /* ocb_net logged a CHAN_LIST_ACK */
static void sim_net_log(const char *line)
{
    net_lines++;
    if (strstr(line, " dials ") != NULL) snprintf(net_dials, sizeof(net_dials), "%s", line);
    if (strstr(line, "service request 4") != NULL) net_svc_config++;
    if (strstr(line, "channel list v") != NULL && strstr(line, " taken by terminal ") != NULL) net_cl_taken++;
}

static void net_start_mode(uint8_t mode)
{
    uint8_t num[OC_SIG_NUMBER_LEN], r[32];
    memset(&lhss, 0, sizeof(lhss));
    TEST_ASSERT_EQUAL_INT(0, ocb_hss_ensure_network(&lhss, sim_rnd));
    lhss.mode = mode; /* ocb_net_init sets the cell's PART97 flag from it */
    oc_sig_number_to_bcd("+883160655501234", 16, num);
    oc_sig_sub_t *s = ocb_hss_issue(&lhss, num, (uint32_t)time(NULL) + 3600u, sim_rnd);
    ocb_hss_qr(&lhss, s, &sqr);
    memset(r, 0x42, 32);
    oc_sig_ident_new(&sig_id, r);
    oc_term_sig_init(&glue, &term, &glue_user_io, &sig_id, 0x75123456u, now_local);
    glue.app_down = g_app_down;
    ocb_net_init(&lnet, &cell, &lhss, NULL, sim_rnd, sim_now, sim_net_log);
    sig_nevs = 0;
    app_rx_n = 0;
    net_lines = 0;
    net_svc_config = 0;
    net_cl_taken = 0;
    sig_on = 2;
}

static void net_start(void) { net_start_mode(OC_SIG_MODE_PART15); }
```
with:
```c
/* The tests that ran over ocbench's network stand-in (ocb_net, retired
 * with network core 2) run over the bare oc_sig_net and the fake core. */
static void net_start_mode(uint8_t mode) { sig_start_mode(mode); }
static void net_start(void) { sig_start(); }
```

In `host-tests/test_term_sim.c`, replace:
```c
            if (sig_on == 2) {
                ocb_net_tick(&lnet, t_build);
            } else if (sig_on) {
```
with:
```c
            if (sig_on) {
```

In `host-tests/test_term_sim.c`, replace:
```c
/* ocbench net's stand-in end to end: the peer rings and answers an outgoing
 * call by itself, echoes app data, places an incoming call and hangs it up. */
static void test_ocb_net_peer_answers_echoes_and_calls_in(void)
{
    sim_start(0x4d2u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    net_start();
    run_for(15000);
    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&sqr, (char *)cmd + 1, sizeof(cmd) - 1);
    sig_command(cmd, 1 + n);
    run_for(20000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_TRUE(lhss.subs[0].activated);
    TEST_ASSERT_EQUAL_HEX32(0x75123456u, lhss.subs[0].tmid);
    TEST_ASSERT_TRUE(lhss.subs[0].token_used);

    static const uint8_t dial[] = "\x02" "606-555-0100"; /* the echo service, dialled in-country */
    net_dials[0] = '\0';
    sig_command(dial, sizeof(dial) - 1);
    run_for(4000); /* page from IDLE and grant ~2 s, then CALL_SETUP / CALL_PROC / ALERTING */
    TEST_ASSERT_TRUE(sig_has(OC_SIG_EV_RINGING));
    TEST_ASSERT_FALSE(sig_has(OC_SIG_EV_CONNECTED));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(net_dials, "dials +883-1-606-555-00100;"), net_dials); /* shown to people */
    run_for(6000); /* the peer answers 3 s after it starts ringing */
    TEST_ASSERT_TRUE(sig_has(OC_SIG_EV_CONNECTED));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_IN_CALL, oc_sig_term_state(&glue.sig));

    TEST_ASSERT_EQUAL_INT(0, oc_term_sig_app_up(&glue, (const uint8_t *)"PING", 4));
    run_for(3000);
    TEST_ASSERT_EQUAL_UINT8(4, app_rx_n);
    TEST_ASSERT_EQUAL_MEMORY("PING", app_rx, 4);
    TEST_ASSERT_EQUAL_UINT32(1, lnet.echoed);

    uint8_t c = OC_SIG_CMD_HANGUP;
    sig_command(&c, 1);
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));

    lnet.peer_hangup_us = 8000000u; /* this time the peer hangs up, 8 s after connect */
    ocb_net_call_in(&lnet, lhss.subs[0].number, sim_now() + 1000000u);
    run_for(10000);
    TEST_ASSERT_TRUE(sig_has(OC_SIG_EV_INCOMING));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_RINGING_IN, oc_sig_term_state(&glue.sig));
    c = OC_SIG_CMD_ANSWER;
    sig_command(&c, 1);
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_IN_CALL, oc_sig_term_state(&glue.sig));
    sig_nevs = 0;
    run_for(8000);
    TEST_ASSERT_TRUE(sig_has(OC_SIG_EV_ENDED));
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_TRUE(net_lines >= 6); /* calls logged */
}
```
with:
```c

```

In `host-tests/test_term_sim.c`, replace:
```c
    RUN_TEST(test_ocb_net_peer_answers_echoes_and_calls_in);
```
with:
```c

```

In `host-tests/test_term_sim.c`, replace:
```c
/* Channel-list spec §7 over the simulated air with ocbench net's stand-in:
```
with:
```c
/* Channel-list spec §7 over the simulated air (the bare oc_sig_net):
```

In `host-tests/test_term_sim.c`, replace:
```c
static void test_chan_list_over_the_air(void)
{
    sim_start(0x4d2u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    net_start();
    user_list(1, (const uint8_t[]){ 20 }, 0);
    oc_sig_chan_list_t l;
    char err[96];
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("902.25,917.25", 1, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&lnet, &l);
    TEST_ASSERT_EQUAL_UINT8(1, cell.cfg_ver);
    run_for(15000);
    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&sqr, (char *)cmd + 1, sizeof(cmd) - 1);
    sig_command(cmd, 1 + n);
    run_for(20000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(2, term.scan.n_net);
    TEST_ASSERT_EQUAL_UINT32(917250000u, term.scan.net[1].freq_hz);
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART15, term.scan.mode);
    TEST_ASSERT_EQUAL_INT(0, net_svc_config);
    run_for(10000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_IDLE, term.state); /* the idle channel was released */

    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("922.25:fixed", 2, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&lnet, &l); /* the beacon now says cfg_ver 2 */
    run_for(15000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config);
    TEST_ASSERT_EQUAL_UINT8(2, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_EQUAL_HEX8(OC_SCAN_F_FIXED, term.scan.net[0].flags);
    run_for(40000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config); /* up to date: asked once */

    term.scan.n_learn = 1; /* as if an earlier cell had served */
    term.scan.learn[0] = (oc_scan_ent_t){ chf(44), 0 };
    static const uint8_t deact[2] = { OC_SIG_CMD_DEACTIVATE, 0xA5 };
    sig_command(deact, 2);
    TEST_ASSERT_EQUAL_UINT8(0, term.scan.n_net);
    TEST_ASSERT_EQUAL_UINT8(0, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(0, term.scan.n_learn);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_user);
    TEST_ASSERT_TRUE(term.scan.dirty);
}
```
with:
```c
static void test_chan_list_over_the_air(void)
{
    sim_start(0x4d2u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    net_start();
    user_list(1, (const uint8_t[]){ 20 }, 0);
    net_list_text("902.25,917.25", 1);
    TEST_ASSERT_EQUAL_UINT8(1, cell.cfg_ver);
    run_for(15000);
    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&sqr, (char *)cmd + 1, sizeof(cmd) - 1);
    sig_command(cmd, 1 + n);
    run_for(20000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(2, term.scan.n_net);
    TEST_ASSERT_EQUAL_UINT32(917250000u, term.scan.net[1].freq_hz);
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART15, term.scan.mode);
    TEST_ASSERT_EQUAL_INT(0, net_svc_config);
    run_for(10000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_IDLE, term.state); /* the idle channel was released */

    net_list_text("922.25:fixed", 2); /* the beacon now says cfg_ver 2 */
    run_for(15000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config);
    TEST_ASSERT_EQUAL_UINT8(2, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_EQUAL_HEX8(OC_SCAN_F_FIXED, term.scan.net[0].flags);
    run_for(40000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config); /* up to date: asked once */

    term.scan.n_learn = 1; /* as if an earlier cell had served */
    term.scan.learn[0] = (oc_scan_ent_t){ chf(44), 0 };
    static const uint8_t deact[2] = { OC_SIG_CMD_DEACTIVATE, 0xA5 };
    sig_command(deact, 2);
    TEST_ASSERT_EQUAL_UINT8(0, term.scan.n_net);
    TEST_ASSERT_EQUAL_UINT8(0, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(0, term.scan.n_learn);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_user);
    TEST_ASSERT_TRUE(term.scan.dirty);
}
```

In `host-tests/test_term_sim.c`, replace:
```c
static void test_bump_after_a_restart(void)
{
    sim_start(0x4d2u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    net_start();
    user_list(1, (const uint8_t[]){ 20 }, 0);
    oc_sig_chan_list_t l;
    char err[96];
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("902.25,917.25", 3, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&lnet, &l);
    TEST_ASSERT_EQUAL_UINT8(3, cell.cfg_ver);
    run_for(15000);
    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&sqr, (char *)cmd + 1, sizeof(cmd) - 1);
    sig_command(cmd, 1 + n);
    run_for(20000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(3, term.scan.net_ver);

    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("922.25:fixed", 4, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&lnet, &l); /* the beacon now says cfg_ver 4 */
    run_for(15000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config); /* asked once, and answered */
    TEST_ASSERT_EQUAL_UINT8(4, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(4, glue.sig.list_ver);

    /* the cell goes away and comes back as a freshly restarted network that
     * only knows list v3 (like a reboot: the stand-in HSS's subscriber
     * record survives - a real HSS would too - but the live session and the
     * chan-list config in RAM don't). */
    cell.off = 1;
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_SEARCH, term.state);
    ocb_net_init(&lnet, &cell, &lhss, NULL, sim_rnd, sim_now, sim_net_log);
    net_svc_config = 0;
    net_cl_taken = 0;
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("902.25,917.25", 3, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&lnet, &l);
    cell.off = 0;
    run_for(20000);
    TEST_ASSERT_TRUE(term.state != OC_TERM_SEARCH); /* re-attached (idle or granted) */
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(3, glue.sig.list_ver); /* v3 taken from the restarted network */
    TEST_ASSERT_EQUAL_UINT8(3, term.scan.net_ver);

    /* the beacon bumps back to cfg_ver 4 - the same value that was already
     * "answered" before the restart. list_ver has since moved to 3, so M1
     * must not still think this exact ask was answered: it must ask again. */
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("922.25:fixed", 4, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&lnet, &l);
    run_for(15000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config); /* asked once, not silently skipped */
    TEST_ASSERT_EQUAL_UINT8(4, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(4, glue.sig.list_ver);
}
```
with:
```c
static void test_bump_after_a_restart(void)
{
    sim_start(0x4d2u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    net_start();
    user_list(1, (const uint8_t[]){ 20 }, 0);
    net_list_text("902.25,917.25", 3);
    TEST_ASSERT_EQUAL_UINT8(3, cell.cfg_ver);
    run_for(15000);
    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&sqr, (char *)cmd + 1, sizeof(cmd) - 1);
    sig_command(cmd, 1 + n);
    run_for(20000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(3, term.scan.net_ver);

    net_list_text("922.25:fixed", 4); /* the beacon now says cfg_ver 4 */
    run_for(15000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config); /* asked once, and answered */
    TEST_ASSERT_EQUAL_UINT8(4, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(4, glue.sig.list_ver);

    /* the cell goes away and comes back as a freshly restarted network that
     * only knows list v3 (like a reboot: the stand-in HSS's subscriber
     * record survives - a real HSS would too - but the live session and the
     * chan-list config in RAM don't). */
    cell.off = 1;
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_SEARCH, term.state);
    net_restart();
    net_list_text("902.25,917.25", 3);
    cell.off = 0;
    run_for(20000);
    TEST_ASSERT_TRUE(term.state != OC_TERM_SEARCH); /* re-attached (idle or granted) */
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(3, glue.sig.list_ver); /* v3 taken from the restarted network */
    TEST_ASSERT_EQUAL_UINT8(3, term.scan.net_ver);

    /* the beacon bumps back to cfg_ver 4 - the same value that was already
     * "answered" before the restart. list_ver has since moved to 3, so M1
     * must not still think this exact ask was answered: it must ask again. */
    net_list_text("922.25:fixed", 4);
    run_for(15000);
    TEST_ASSERT_EQUAL_INT(1, net_svc_config); /* asked once, not silently skipped */
    TEST_ASSERT_EQUAL_UINT8(4, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(4, glue.sig.list_ver);
}
```

In `host-tests/test_term_sim.c`, replace:
```c
static void test_fixed_part97_found_again_after_sync_loss(void)
{
    sim_start(0x30000000u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    net_start_mode(OC_SIG_MODE_PART97);
    TEST_ASSERT_EQUAL_INT(1, cell.part97);
    TEST_ASSERT_EQUAL_INT(0, ocb_cell_set_sync(&cell, 30, 1));
    oc_sig_chan_list_t l;
    ocb_net_own_chan_list(&cell, 1, &l); /* ocbench net's default: { 917.25:fixed } */
    ocb_net_set_chan_list(&lnet, &l);
    user_list(1, (const uint8_t[]){ 30 }, 0); /* CYCLE: active in Part 15, dwells on ch 30 */
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART15, term.scan.mode);
    run_for(15000);
    TEST_ASSERT_TRUE(term.state == OC_TERM_IDLE || term.state == OC_TERM_GRANTED); /* attached */
    TEST_ASSERT_EQUAL_UINT32(chf(30), term.scan.last.freq_hz);
    TEST_ASSERT_EQUAL_HEX8(OC_SCAN_F_FIXED, term.scan.last.flags); /* recorded before any REG_ACK */
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART15, term.scan.mode);

    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&sqr, (char *)cmd + 1, sizeof(cmd) - 1);
    sig_command(cmd, 1 + n);
    run_for(20000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART97, term.scan.mode);
    TEST_ASSERT_EQUAL_INT(1, net_cl_taken);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_EQUAL_HEX8(OC_SCAN_F_FIXED, term.scan.net[0].flags);
    TEST_ASSERT_EQUAL_INT(0, oc_term_scan_set_user(&term.scan, 0, NULL)); /* no CYCLE entry on 30 any more */
    term.scan.dirty = 0; /* as if saved */

    cell.off = 1;
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_SEARCH, term.state);
    cell.off = 0;
    run_for(8500); /* within one round: last (0.36 s) and the six defaults (7.2 s) */
    TEST_ASSERT_TRUE(term.state != OC_TERM_SEARCH);
    TEST_ASSERT_EQUAL_UINT8(30, term.anchor);
    TEST_ASSERT_EQUAL_UINT8(1, term.fixed_sync);
    TEST_ASSERT_EQUAL_UINT8(OC_SCAN_SRC_LAST, term.scan.cur_src);

    run_for(20000); /* registers again; the network pushes v1 again */
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_INT(2, net_cl_taken);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_FALSE(term.scan.dirty); /* identical list and version: no NVS write */

    /* A different list under the same version (no cfg_ver change, so no ask):
     * taken at the next registration, and applied. */
    char err[96];
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("902.25", 1, &l, err, sizeof(err))); /* same count too */
    ocb_net_set_chan_list(&lnet, &l);
    cell.off = 1;
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_SEARCH, term.state);
    cell.off = 0;
    run_for(30000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_INT(3, net_cl_taken);
    TEST_ASSERT_EQUAL_INT(0, net_svc_config);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_EQUAL_UINT32(chf(0), term.scan.net[0].freq_hz);
    TEST_ASSERT_EQUAL_HEX8(0, term.scan.net[0].flags);
    TEST_ASSERT_TRUE(term.scan.dirty);
}
```
with:
```c
static void test_fixed_part97_found_again_after_sync_loss(void)
{
    sim_start(0x30000000u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    net_start_mode(OC_SIG_MODE_PART97);
    TEST_ASSERT_EQUAL_INT(1, cell.part97);
    TEST_ASSERT_EQUAL_INT(0, ocb_cell_set_sync(&cell, 30, 1));
    net_list_text("917.25:fixed", 1); /* the cell's own anchor */
    user_list(1, (const uint8_t[]){ 30 }, 0); /* CYCLE: active in Part 15, dwells on ch 30 */
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART15, term.scan.mode);
    run_for(15000);
    TEST_ASSERT_TRUE(term.state == OC_TERM_IDLE || term.state == OC_TERM_GRANTED); /* attached */
    TEST_ASSERT_EQUAL_UINT32(chf(30), term.scan.last.freq_hz);
    TEST_ASSERT_EQUAL_HEX8(OC_SCAN_F_FIXED, term.scan.last.flags); /* recorded before any REG_ACK */
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART15, term.scan.mode);

    uint8_t cmd[1 + OC_SIG_QR_TEXT + 1];
    cmd[0] = OC_SIG_CMD_ACTIVATE;
    size_t n = oc_sig_qr_format(&sqr, (char *)cmd + 1, sizeof(cmd) - 1);
    sig_command(cmd, 1 + n);
    run_for(20000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_UINT8(OC_PHY_MODE_PART97, term.scan.mode);
    TEST_ASSERT_EQUAL_INT(1, net_cl_taken);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_EQUAL_HEX8(OC_SCAN_F_FIXED, term.scan.net[0].flags);
    TEST_ASSERT_EQUAL_INT(0, oc_term_scan_set_user(&term.scan, 0, NULL)); /* no CYCLE entry on 30 any more */
    term.scan.dirty = 0; /* as if saved */

    cell.off = 1;
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_SEARCH, term.state);
    cell.off = 0;
    run_for(8500); /* within one round: last (0.36 s) and the six defaults (7.2 s) */
    TEST_ASSERT_TRUE(term.state != OC_TERM_SEARCH);
    TEST_ASSERT_EQUAL_UINT8(30, term.anchor);
    TEST_ASSERT_EQUAL_UINT8(1, term.fixed_sync);
    TEST_ASSERT_EQUAL_UINT8(OC_SCAN_SRC_LAST, term.scan.cur_src);

    run_for(20000); /* registers again; the network pushes v1 again */
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_INT(2, net_cl_taken);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_FALSE(term.scan.dirty); /* identical list and version: no NVS write */

    /* A different list under the same version (no cfg_ver change, so no ask):
     * taken at the next registration, and applied. */
    net_list_text("902.25", 1); /* same count too */
    cell.off = 1;
    run_for(5000);
    TEST_ASSERT_EQUAL_UINT8(OC_TERM_SEARCH, term.state);
    cell.off = 0;
    run_for(30000);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_ST_REGISTERED, oc_sig_term_state(&glue.sig));
    TEST_ASSERT_EQUAL_INT(3, net_cl_taken);
    TEST_ASSERT_EQUAL_INT(0, net_svc_config);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.net_ver);
    TEST_ASSERT_EQUAL_UINT8(1, term.scan.n_net);
    TEST_ASSERT_EQUAL_UINT32(chf(0), term.scan.net[0].freq_hz);
    TEST_ASSERT_EQUAL_HEX8(0, term.scan.net[0].flags);
    TEST_ASSERT_TRUE(term.scan.dirty);
}
```

In `host-tests/test_ocbench.c`, replace:
```c
#include "ocb_hss.h"
```
with:
```c

```

In `host-tests/test_ocbench.c`, replace:
```c
#include "ocb_net.h"
```
with:
```c

```

In `host-tests/test_ocbench.c`, replace:
```c
/* ocbench net --chan-list: MHz on the 915 grid, ':fixed', at most 12. */
static void test_chan_list_parse(void)
{
    oc_sig_chan_list_t l;
    char err[96];
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("917.25,922.25:fixed,902.25", 7, &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_UINT8(7, l.ver);
    TEST_ASSERT_EQUAL_UINT8(3, l.count);
    TEST_ASSERT_EQUAL_UINT32(917250000u, l.freq_hz[0]);
    TEST_ASSERT_EQUAL_UINT32(922250000u, l.freq_hz[1]);
    TEST_ASSERT_EQUAL_HEX8(OC_SIG_CHAN_FIXED, l.flags[1]);
    TEST_ASSERT_EQUAL_HEX8(0, l.flags[2]);
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("927.750", 1, &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_UINT32(927750000u, l.freq_hz[0]);
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("", 2, &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_UINT8(0, l.count);
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("none", 2, &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_UINT8(0, l.count);
    static const char *bad[] = { "903", "917.3", "928.25", "901.75", "917.25:fix", "917.25:fixedx", "abc",
                                 "917.2500", "917.", "917.25,,922.25", "917.25," };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        TEST_ASSERT_EQUAL_INT_MESSAGE(-1, ocb_net_parse_chan_list(bad[i], 1, &l, err, sizeof(err)), bad[i]);
        TEST_ASSERT_TRUE(err[0] != '\0');
    }
    TEST_ASSERT_EQUAL_INT(-1, ocb_net_parse_chan_list("902.25,902.75,903.25,903.75,904.25,904.75,905.25,905.75,"
                                                      "906.25,906.75,907.25,907.75,908.25", 1, &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("902.25,902.75,903.25,903.75,904.25,904.75,905.25,905.75,"
                                                     "906.25,906.75,907.25,907.75", 1, &l, err, sizeof(err)));
    TEST_ASSERT_EQUAL_UINT8(12, l.count);

    static ocb_cell_t c; /* no --chan-list: the cell's own anchor */
    ocb_cell_init(&c, 0x1234u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    c.part97 = 1;
    TEST_ASSERT_EQUAL_INT(0, ocb_cell_set_sync(&c, 30, 1));
    ocb_net_own_chan_list(&c, 1, &l);
    TEST_ASSERT_EQUAL_UINT8(1, l.count);
    TEST_ASSERT_EQUAL_UINT32(917250000u, l.freq_hz[0]);
    TEST_ASSERT_EQUAL_HEX8(OC_SIG_CHAN_FIXED, l.flags[0]);

    ocb_cell_init(&c, 0x1234u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915); /* a CYCLE cell on its seed's anchor */
    TEST_ASSERT_EQUAL_UINT8(0x1234u % 6u, c.sync_ch);
    ocb_net_own_chan_list(&c, 3, &l);
    TEST_ASSERT_EQUAL_UINT8(3, l.ver);
    TEST_ASSERT_EQUAL_UINT8(1, l.count);
    TEST_ASSERT_EQUAL_UINT32(oc_channel_freq_hz(OC_BAND_915, 0x1234u % 6u), l.freq_hz[0]);
    TEST_ASSERT_EQUAL_HEX8(0, l.flags[0]);
}

/* --chan-list takes no whitespace, and says so. */
static void test_chan_list_parse_rejects_whitespace(void)
{
    oc_sig_chan_list_t l;
    char err[96];
    static const char *bad[] = { " 917.25", "917.25 ", "917.25, 922.25", "917.25 ,922.25", "917.25\t", "917.25:fixed ",
                                 " " };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        TEST_ASSERT_EQUAL_INT_MESSAGE(-1, ocb_net_parse_chan_list(bad[i], 1, &l, err, sizeof(err)), bad[i]);
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err, "space"), err);
    }
}

static char net_log[8][300];
static int net_log_n;
static void net_log_line(const char *line) { snprintf(net_log[net_log_n++ % 8], sizeof(net_log[0]), "%s", line); }
static void net_rnd(uint8_t *out, size_t n) { for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(i * 13u + 5u); }
static uint64_t net_now(void) { return 0; }

/* ocb_net_set_chan_list's log line (the bench greps it): every entry, even
 * twelve ':fixed' ones, and the list as stored (at most 12). */
static void test_chan_list_log_line(void)
{
    static ocb_cell_t c;
    static ocb_hss_t h;
    static ocb_net_t n;
    memset(&h, 0, sizeof(h));
    TEST_ASSERT_EQUAL_INT(0, ocb_hss_ensure_network(&h, net_rnd));
    ocb_cell_init(&c, 0x1234u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    ocb_net_init(&n, &c, &h, NULL, net_rnd, net_now, net_log_line);
    net_log_n = 0;
    oc_sig_chan_list_t l;
    char err[96];
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("917.25,922.25:fixed", 1, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&n, &l);
    TEST_ASSERT_EQUAL_INT(1, net_log_n);
    TEST_ASSERT_EQUAL_STRING("channel list v1: 917.25 922.25:fixed", net_log[0]);
    TEST_ASSERT_EQUAL_UINT8(1, c.cfg_ver);
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("none", 6, &l, err, sizeof(err)));
    ocb_net_set_chan_list(&n, &l);
    TEST_ASSERT_EQUAL_STRING("channel list v6: (empty)", net_log[1]);
    TEST_ASSERT_EQUAL_UINT8(2, c.cfg_ver);
    TEST_ASSERT_EQUAL_INT(0, ocb_net_parse_chan_list("902.25:fixed,902.75:fixed,903.25:fixed,903.75:fixed,904.25:fixed,"
                                                     "904.75:fixed,905.25:fixed,905.75:fixed,906.25:fixed,906.75:fixed,"
                                                     "927.25:fixed,927.75:fixed", 255, &l, err, sizeof(err)));
    l.count = 13; /* more than the network stores: the line shows what is pushed */
    ocb_net_set_chan_list(&n, &l);
    TEST_ASSERT_EQUAL_STRING("channel list v255: 902.25:fixed 902.75:fixed 903.25:fixed 903.75:fixed 904.25:fixed "
                             "904.75:fixed 905.25:fixed 905.75:fixed 906.25:fixed 906.75:fixed 927.25:fixed "
                             "927.75:fixed", net_log[2]);
}
```
with:
```c

```

In `host-tests/test_ocbench.c`, replace:
```c
/* ocb_net's io_call (ocb_net.c ~:96): a call to a number that IS a
 * subscriber of this bench's own HSS, but isn't registered here right now,
 * is refused at once (cause 4) rather than treated as a call to the
 * simulated far end (which would ring and auto-answer). A's session is
 * registered by direct struct access - its AKA is exercised elsewhere; this
 * test is only about io_call's own branch. */
static void test_ocb_net_mo_call_to_unregistered_subscriber_refused(void)
{
    static ocb_cell_t c;
    static ocb_hss_t h;
    static ocb_net_t n;
    memset(&h, 0, sizeof(h));
    TEST_ASSERT_EQUAL_INT(0, ocb_hss_ensure_network(&h, net_rnd));
    ocb_cell_init(&c, 0x1234u, OC_TIER_EDGE, OC_BAND_915, OC_BAND_915);
    uint8_t a_num[OC_SIG_NUMBER_LEN], b_num[OC_SIG_NUMBER_LEN];
    oc_sig_number_to_bcd("+883160655501234", 16, a_num);
    oc_sig_number_to_bcd("+883160655501235", 16, b_num);
    TEST_ASSERT_NOT_NULL(ocb_hss_issue(&h, a_num, 1790003600u, net_rnd));
    TEST_ASSERT_NOT_NULL(ocb_hss_issue(&h, b_num, 1790003600u, net_rnd)); /* B: a subscriber, not registered here */
    net_log_n = 0;
    ocb_net_init(&n, &c, &h, NULL, net_rnd, net_now, net_log_line);

    uint32_t tmid = 0x76ad0488u;
    oc_sig_net_link(&n.net, tmid, 1, 0);
    oc_sig_net_sess_t *s = NULL;
    for (unsigned i = 0; i < OC_SIG_NET_TERMS && s == NULL; i++) {
        if (n.net.s[i].used && n.net.s[i].tmid == tmid) s = &n.net.s[i];
    }
    TEST_ASSERT_NOT_NULL(s);
    memcpy(s->number, a_num, OC_SIG_NUMBER_LEN); /* A: registered, without driving a full AKA here */
    s->registered = 1;
    s->reg_until = 4000000000ull;
    uint8_t ki[16], ke[16];
    memset(ki, 0x11, 16);
    memset(ke, 0x22, 16);
    oc_sig_sec_key(&s->ch.sec, ki, ke, 0);

    oc_sig_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = OC_SIG_CALL_SETUP;
    m.u.call_setup.ref = 1;
    memcpy(m.u.call_setup.called, b_num, OC_SIG_NUMBER_LEN);
    oc_sig_sec_t txsec;
    oc_sig_sec_init(&txsec, 0);
    oc_sig_sec_key(&txsec, ki, ke, 0);
    uint8_t buf[OC_SIG_MAX_MSG];
    size_t bn = oc_sig_seal(&txsec, &m, buf, sizeof(buf));
    TEST_ASSERT_NOT_EQUAL(0, bn);
    uint8_t frag[OC_SIG_MAX_FRAGS][OC_SIG_LINK_MAX], flen[OC_SIG_MAX_FRAGS];
    uint8_t nf = oc_sig_fragment(buf, bn, 0, frag, flen);
    for (uint8_t i = 0; i < nf; i++) oc_sig_net_rx(&n.net, tmid, frag[i], flen[i], 0);

    int found = 0;
    for (int i = 0; i < net_log_n && i < 8; i++) {
        if (strstr(net_log[i], "not registered") != NULL) found = 1;
    }
    TEST_ASSERT_TRUE(found);
    TEST_ASSERT_EQUAL_UINT8(OC_SIG_CAUSE_UNREACHABLE, s->end_cause);
}
```
with:
```c

```

In `host-tests/test_ocbench.c`, replace:
```c
    RUN_TEST(test_ocb_net_mo_call_to_unregistered_subscriber_refused);
```
with:
```c

```

In `host-tests/test_ocbench.c`, replace:
```c
static uint8_t rnd_ctr;
static void test_rnd(uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(rnd_ctr++ * 73u + 5u);
}

/* The HSS file round-trips every field, re-issuing a number replaces its
 * token, a missing file is an empty HSS and a damaged one is refused. */
static void test_hss_file_roundtrip(void)
{
    static const char *path = "test_hss.txt";
    static ocb_hss_t a, b;
    unlink(path);
    TEST_ASSERT_EQUAL_INT(0, ocb_hss_load(&a, path));
    TEST_ASSERT_FALSE(a.have_network);
    TEST_ASSERT_EQUAL_INT(0, ocb_hss_ensure_network(&a, test_rnd));
    uint8_t pk[32];
    oc_sig_x25519_public(a.sk, pk);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(pk, a.pk, 32);
    uint8_t num[OC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd("+883160655501234", 16, num));
    oc_sig_sub_t *s = ocb_hss_issue(&a, num, 1790003600u, test_rnd);
    TEST_ASSERT_NOT_NULL(s);
    uint8_t first_token[8];
    memcpy(first_token, s->token_id, 8);
    s->tmid = 0x76ad0488u;
    s->activated = 1;
    s->token_used = 1;
    memset(s->k, 0x4b, 16);
    memset(s->opc, 0x0c, 16);
    s->sqn[5] = 0x20;
    a.mode = OC_SIG_MODE_PART97;
    TEST_ASSERT_EQUAL_INT(0, ocb_hss_save(&a, path));
    TEST_ASSERT_EQUAL_INT(0, ocb_hss_load(&b, path));
    TEST_ASSERT_EQUAL_MEMORY(&a, &b, sizeof(a));
    TEST_ASSERT_EQUAL_PTR(&b.subs[0], ocb_hss_by_tmid(&b, 0x76ad0488u));
    TEST_ASSERT_EQUAL_PTR(&b.subs[0], ocb_hss_by_token(&b, first_token));
    char text[OC_SIG_NUMBER_TEXT];
    oc_sig_number_to_text(b.subs[0].number, text);
    TEST_ASSERT_EQUAL_STRING("+883160655501234", text);
    TEST_ASSERT_EQUAL_STRING("", b.err);

    s = ocb_hss_issue(&b, num, 1790007200u, test_rnd); /* re-issued: same record, new unused token */
    TEST_ASSERT_EQUAL_PTR(&b.subs[0], s);
    TEST_ASSERT_EQUAL_UINT(1, b.n);
    TEST_ASSERT_FALSE(s->token_used);
    TEST_ASSERT_TRUE(memcmp(first_token, s->token_id, 8) != 0);
    oc_sig_qr_t q;
    ocb_hss_qr(&b, s, &q);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(b.pk, q.pkn, 32);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(s->token_secret, q.token_secret, 16);

    FILE *f = fopen(path, "a");
    fputs("sub number=+883160655500000 token_id=zz\n", f);
    fclose(f);
    TEST_ASSERT_EQUAL_INT(-1, ocb_hss_load(&b, path));
    TEST_ASSERT_EQUAL_STRING("test_hss.txt:4: malformed line", b.err);
    unlink(path);
}

/* numbering v2 §6.4: an HSS written before numbering v2 is refused with a
 * message that says what to do, not just "malformed". */
static void test_hss_v1_number_refused_with_migration_message(void)
{
    static const char *path = "test_hss_v1.txt";
    static ocb_hss_t h;
    FILE *f = fopen(path, "w");
    fputs("# OpenCell network stand-in HSS (ocbench). Holds secrets: keep it private.\n", f);
    fputs("sub number=+8836065551234 token_id=a0a1a2a3a4a5a6a7 token_secret=b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
          " expiry=1790003600 used=1 tmid=76ad0488 activated=1 k=4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"
          " opc=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c sqn=000000000020\n", f);
    fclose(f);
    TEST_ASSERT_EQUAL_INT(-1, ocb_hss_load(&h, path));
    TEST_ASSERT_EQUAL_STRING(
        "test_hss_v1.txt:2: 13-digit number (numbering v1): remove the sub lines and issue new codes", h.err);
    unlink(path);
    uint8_t num[OC_SIG_NUMBER_LEN];
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd("+8836065551234", 14, num)); /* well-formed (CC 60)... */
    TEST_ASSERT_TRUE(ocb_hss_v1_number(num));                                   /* ...but a v1 leftover */
    TEST_ASSERT_EQUAL_INT(0, oc_sig_number_to_bcd("+883160655501234", 16, num));
    TEST_ASSERT_FALSE(ocb_hss_v1_number(num));
}

/* Final review M1: the migration message must survive a long HSS path.
 * err[] used to be sized only for a short path, so the "%s:%u: %s" snprintf
 * cut the reason text off the end when path was long. */
static void test_hss_v1_migration_message_survives_long_path(void)
{
    char dir[200];
    memset(dir, 'x', sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    TEST_ASSERT_EQUAL_INT(0, mkdir(dir, 0700));
    char path[240];
    snprintf(path, sizeof(path), "%s/hss.txt", dir);

    FILE *f = fopen(path, "w");
    TEST_ASSERT_NOT_NULL(f);
    fputs("# OpenCell network stand-in HSS (ocbench). Holds secrets: keep it private.\n", f);
    fputs("sub number=+8836065551234 token_id=a0a1a2a3a4a5a6a7 token_secret=b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
          " expiry=1790003600 used=1 tmid=76ad0488 activated=1 k=4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"
          " opc=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c sqn=000000000020\n", f);
    fclose(f);

    static ocb_hss_t h;
    TEST_ASSERT_EQUAL_INT(-1, ocb_hss_load(&h, path));
    TEST_ASSERT_NOT_NULL(strstr(h.err, "13-digit number (numbering v1): remove the sub lines and issue new codes"));

    unlink(path);
    rmdir(dir);
}

/* Final review I4: `ocbench net` holds the HSS lock for its lifetime, so a
 * `mkqr` meanwhile (whose token net's next save would erase) is refused.
 * flock locks belong to the open file description, so two lock attempts in
 * one process conflict exactly as two processes would. */
static void test_hss_lock_is_exclusive(void)
{
    static const char *path = "test_hss_lock.txt";
    int a = ocb_hss_lock(path);
    TEST_ASSERT_TRUE(a >= 0);
    TEST_ASSERT_EQUAL_INT(-1, ocb_hss_lock(path)); /* held: refused at once, not waited for */
    ocb_hss_unlock(a);
    int b = ocb_hss_lock(path);
    TEST_ASSERT_TRUE(b >= 0); /* free again */
    ocb_hss_unlock(b);
    TEST_ASSERT_EQUAL_INT(-2, ocb_hss_lock("no-such-dir/hss.txt")); /* can't make the lock file */
    unlink("test_hss_lock.txt.lock");
}
```
with:
```c

```

In `host-tests/test_ocbench.c`, replace:
```c
    RUN_TEST(test_hss_file_roundtrip);
    RUN_TEST(test_hss_v1_number_refused_with_migration_message);
    RUN_TEST(test_hss_v1_migration_message_survives_long_path);
    RUN_TEST(test_hss_lock_is_exclusive);
```
with:
```c

```

In `host-tests/test_ocbench.c`, replace:
```c
    RUN_TEST(test_chan_list_parse);
    RUN_TEST(test_chan_list_parse_rejects_whitespace);
    RUN_TEST(test_chan_list_log_line);
```
with:
```c

```

- [ ] **Step 3: The files go**

```bash
cd /home/devin/Documents/opencell/firmware
git rm -q tools/ocbench/ocb_net.c tools/ocbench/ocb_net.h tools/ocbench/ocb_hss.c tools/ocbench/ocb_hss.h
```

Run: `cd /home/devin/Documents/opencell/firmware && grep -rn "ocb_net_\|ocb_hss_\|ocb_net\.h\|ocb_hss\.h\|\blnet\b\|\blhss\b" tools host-tests --include=*.c --include=*.h --include=*.txt | grep -v /build/ | wc -l`
Expected: `0`.

- [ ] **Step 4: The suite, ocbench, and the retired commands**

Run: `cd /home/devin/Documents/opencell/firmware && rm -rf host-tests/build && cmake -S host-tests -B host-tests/build >/dev/null && cmake --build host-tests/build -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build && ctest | tail -3); for t in test_term_sim test_ocbench; do host-tests/build/$t | grep Tests; done`
Expected: no compiler output, `100% tests passed, 0 tests failed out of N_fw+1` (35 when validated), then `24 Tests 0 Failures 0 Ignored` (one fewer: the stand-in's own test) and `18 Tests 0 Failures 0 Ignored` (eight fewer; seven without plan 1's `ocb_net` call test).

Run: `cd /home/devin/Documents/opencell/firmware && host-tests/build/test_term_sim | grep -E "test_chan_list_over_the_air|test_bump_after_a_restart|test_sig_init_takes_the_saved_list_version|test_fixed_part97_found_again_after_sync_loss" | grep -c PASS`
Expected: `4` (the moved tests, on the bare `oc_sig_net`).

Run: `cd /home/devin/Documents/opencell/firmware && rm -rf tools/ocbench/build && cmake -S tools/ocbench -B tools/ocbench/build -G Ninja >/dev/null && cmake --build tools/ocbench/build 2>&1 | grep -E "error|warning"; tools/ocbench/build/ocbench net /dev/null edge 1 2>&1 | grep -c "ocbench net\|mkqr"; tools/ocbench/build/ocbench 2>&1 | grep -c -- "--mode part15|part97"`
Expected: no compiler output, `0` (`net` is now an unknown command: the usage lists neither), then `1`.

- [ ] **Step 5: The same suite under the sanitizers**

Run: `cd /home/devin/Documents/opencell/firmware && cmake -S host-tests -B host-tests/build/asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null && cmake --build host-tests/build/asan -j8 2>&1 | grep -E "error|warning"; (cd host-tests/build/asan && ctest | tail -3)`
Expected: `100% tests passed, 0 tests failed out of N_fw+1` (35 when validated).

- [ ] **Step 6: Commit and push**

```bash
cd /home/devin/Documents/opencell/firmware
git add -A tools/ocbench host-tests/test_term_sim.c host-tests/test_ocbench.c README.md
git commit -m "ocbench: retire net and mkqr, ocb_net and ocb_hss (oc-cell and oc-core replace them); air-path tests on the bare oc_sig_net

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push
```

---

### Task 13: The pins on the final tips; suites and sanitizers; READMEs; push

**Repos:** all three. **Starts:** after Task 12.

Each repository's pin moves to the tip of the one below it, so the three branches the controller merges name code that was built and tested together: the core's firmware pin to `oc-bench` (with Task 12), the Pi's core pin to `oc-core` (with Task 10). Then every suite runs, plain and under ASan/UBSan, and the READMEs say what is there now.

**Files:**
- Modify: `third_party/opencell-firmware` (core), `third_party/opencell-core` (Pi), `README.md` (core, Pi)
- Replace: `docs/superpowers/specs/2026-09-27-network-core-design.md` (core; the docs repository's, with §17), and add this plan to `docs/superpowers/plans/` in the core and the Pi repositories.

**Interfaces:**
- Consumes: everything above. Produces nothing new.

- [ ] **Step 1: The core on the firmware's final tip**

```bash
cd /home/devin/Documents/opencell/core
git -C third_party/opencell-firmware fetch -q origin
git -C third_party/opencell-firmware checkout -q origin/oc-bench
```

Run: `cd /home/devin/Documents/opencell/core && ls third_party/opencell-firmware/tools/ocbench/ocb_net.c 2>&1 | grep -c "No such file"; rm -rf build && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `1`, no compiler output, `100% tests passed, 0 tests failed out of N_core+6` (14 when validated).

Run: `cd /home/devin/Documents/opencell/core && cmake -S . -B build/asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null && cmake --build build/asan -j8 2>&1 | grep -E "error|warning"; (cd build/asan && ctest | tail -3)`
Expected: no compiler output, `100% tests passed, 0 tests failed out of N_core+6` (14 when validated).

- [ ] **Step 2: The core's README and docs**

**Repo (opencell-core):** `/home/devin/Documents/opencell/core`.

Replace the whole of `README.md` with:
```markdown
# OpenCell network core (oc-core)

The central network software of [OpenCell](https://github.com/opencell-dev/opencell): the subscriber database (HSS/AuC with MILENAGE), activation, registration, the location registry, call routing and switching between cells, and the echo service. Later, for several servers: asynchronous replication, block (NPA) transfer between tenants, and OCSS, the core-to-core signalling system.

- `oc_core/`: the core as a portable C11 library (no OS calls): the cell-core codec, HSS/AuC, registry, switch, echo service, a channel list per group of cells.
- `oc_cell/`: a cell's network side (`oc_sig_net` and the core client), which `oc-cell` in [opencell-pi](https://github.com/opencell-dev/opencell-pi) runs.
- `oc/`: the Linux side: the `oc-core` program (the daemon and `oc-core admin ...`), the SQLite store with AES-256-GCM sealed keys, and `oc_util` (config files, the framing on Unix sockets, logging), which `oc-cell` shares.
- `tools/deploy/oc-deploy`: installs a tag of `oc-core` or `oc-cell` on a host over SSH, builds it there, keeps the previous build for `rollback`.
- `dist/`: the systemd unit and an example `/etc/opencell/oc-core.conf`.
- `third_party/opencell-firmware`: the firmware repository (for `oc_sig`), a submodule pinned to a commit.

Build and test (Debian 13: `cmake gcc libssl-dev libsqlite3-dev`):

~~~bash
git submodule update --init
cmake -S . -B build && cmake --build build -j && (cd build && ctest)
~~~

A new core, as root on its host after `oc-deploy` (the master key is 32 random bytes, root-only; back it up offline):

~~~bash
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin oc-core
groupadd -f oc-admin; groupadd -f oc-cell
install -d -m 0755 /etc/opencell; install -d -o oc-core -g oc-core -m 0700 /var/lib/opencell/core
(umask 077; head -c 32 /dev/urandom > /etc/opencell/master.key)
cp dist/oc-core.conf.example /etc/opencell/oc-core.conf
oc-core admin --offline --key-file /etc/opencell/master.key net init
oc-core admin --offline --key-file /etc/opencell/master.key cell add 1 my-cell
systemctl enable --now oc-core
oc-core admin sub add +883-1-606-555-01234 && oc-core admin sub issue +883-1-606-555-01234
~~~

Design: `docs/superpowers/specs/2026-09-27-network-core-design.md` (§17 for these programs). Plans: `docs/superpowers/plans/2026-09-27-net-core-1-lc-core.md` (the libraries) and `docs/superpowers/plans/2026-09-28-oc-core-oc-cell-bench.md` (the programs, on the Pi bench).
```

```bash
cd /home/devin/Documents/opencell/core
cp ../docs/docs/superpowers/specs/2026-09-27-network-core-design.md docs/superpowers/specs/
cp ../docs/docs/superpowers/plans/2026-09-28-oc-core-oc-cell-bench.md docs/superpowers/plans/
git add third_party/opencell-firmware README.md docs
git commit -m "Firmware pin on oc-bench's tip (ocbench net retired); README for the programs; spec 17 and plan 8 copied

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push
```

- [ ] **Step 3: The Pi on the core's final tip**

```bash
cd /home/devin/Documents/opencell/pi
git -C third_party/opencell-core fetch -q origin
git -C third_party/opencell-core checkout -q origin/oc-core
git submodule update --init --recursive
```

Run: `cd /home/devin/Documents/opencell/pi && ls third_party/opencell-core/tools/deploy/oc-deploy && rm -rf build && cmake -S . -B build >/dev/null && cmake --build build -j8 2>&1 | grep -E "error|warning"; (cd build && ctest | tail -3)`
Expected: `third_party/opencell-core/tools/deploy/oc-deploy`, no compiler output, `100% tests passed, 0 tests failed out of 3`.

Run: `cd /home/devin/Documents/opencell/pi && cmake -S . -B build/asan -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null && cmake --build build/asan -j8 2>&1 | grep -E "error|warning"; (cd build/asan && ctest | tail -3)`
Expected: no compiler output, `100% tests passed, 0 tests failed out of 3` (the process test runs the sanitized programs too).

- [ ] **Step 4: The Pi's README and docs**

**Repo (opencell-pi):** `/home/devin/Documents/opencell/pi`.

Replace the whole of `README.md` with:
```markdown
# OpenCell Pi base station

The base station of [OpenCell](https://github.com/opencell-dev/opencell) runs `oc-cell`: the cell's network side (`oc_cell`, from [opencell-core](https://github.com/opencell-dev/opencell-core)) and its radio. Today the radio is one W12 bs-radio on USB, driven by `ocb_cell` (from [opencell-firmware](https://github.com/opencell-dev/opencell-firmware)'s ocbench); the Pi 5 scheduler with several W12s on UARTs (`rhu_bs`, `docs/superpowers/plans/2026-09-25-rhu-scheduler.md`) replaces it later. A single site runs the network core `oc-core` on the same Pi.

- `oc-cell/`: `ocr` (the radio backend: schedules, TIME labels, the beacon following the core), `ocs` (simulated terminals, for tests), the config file, the board's serial port, and the program.
- `dist/`: the systemd unit and an example `/etc/opencell/oc-cell.conf` (the bench's board A).
- `tests/`: the board-level test of `ocr` with a core, the config and port tests, and the process test (two `oc-cell` and an `oc-core`).
- `third_party/opencell-core`: the core, a submodule; the firmware is its own submodule inside it.

Build and test (Debian 13: `cmake gcc libssl-dev libsqlite3-dev`):

~~~bash
git submodule update --init --recursive
cmake -S . -B build && cmake --build build -j && (cd build && ctest)
~~~

Deploy a tag from the laptop: `third_party/opencell-core/tools/deploy/oc-deploy deploy . v0.1.0 opencell@opencell-bs1`, then on the Pi (once) `groupadd -f oc-cell && useradd --system -g oc-cell -G dialout --no-create-home --shell /usr/sbin/nologin oc-cell`, `/etc/opencell/oc-cell.conf` from `dist/`, and `systemctl enable --now oc-cell`. The bench record: `docs/bench/network-core-bench.md`.
```

```bash
cd /home/devin/Documents/opencell/pi
cp ../docs/docs/superpowers/plans/2026-09-28-oc-core-oc-cell-bench.md docs/superpowers/plans/
git add third_party/opencell-core README.md docs
git commit -m "Core pin on oc-core's tip (the deploy script); README for oc-cell; plan 8 copied

Co-Authored-By: <your model name> <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Ks9at6TKDGWcTJjAWKNFRL"
git push
```

- [ ] **Step 5: Report**

Report to the controller: the three branches ready to merge (`opencell-firmware` `oc-bench`, `opencell-core` `oc-core`, `opencell-pi` `oc-cell`; each after its plan-1 branch), their tips, the test counts, the tags `v0.1.0`, the bench record, and anything the bench left open. Merging, and re-tagging on `main` if the controller prefers tags there, are the controller's decisions.
