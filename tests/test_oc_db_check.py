#!/usr/bin/env python3
"""tools/db/oc-db-check: conditions from facts, and the alert state machine.
usage: test_oc_db_check.py PATH_TO_OC_DB_CHECK"""
import copy
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # no __pycache__ beside the script
PATH = sys.argv.pop(1) if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "tools", "db", "oc-db-check")
loader = importlib.machinery.SourceFileLoader("oc_db_check", PATH)
spec = importlib.util.spec_from_loader("oc_db_check", loader)
chk = importlib.util.module_from_spec(spec)
loader.exec_module(chk)

NOW = 1_800_000_000
LDN = "https://10.99.0.3:2379"
ETCD = ["https://10.99.0.4:2379", "https://10.99.0.2:2379", LDN]


def cfg(role="witness"):
    return {
        "host": "oc-ldn-1", "role": role, "tls_dir": "/x", "mail_env": "/x", "drill_dir": "/x",
        "clusters": {"oc-east": {"port": 5432, "rest": 8008, "home": "oc-db-1", "sync": True},
                     "oc-west": {"port": 5433, "rest": 8009, "home": "oc-core-2", "sync": False}},
        "members": {"oc-db-1": "10.99.0.4", "oc-core-2": "10.99.0.2"},
        "etcd": ETCD, "london_etcd": LDN if role == "member" else "",
        "filesystems": ["/"], "certs": [], "wg_peers": {},
    }


def primary():
    return {"replication": [{"name": "x", "sync_state": "sync", "replay_lag_s": 0.01, "bytes_behind": 0}],
            "slots": [{"name": "x", "retained": 1000}],
            "archiver": {"failed_count": 0, "last_archived_age_s": 30}, "ready": 0}


def healthy():
    east = [{"name": "oc-db-1", "role": "leader", "state": "running"},
            {"name": "oc-core-2", "role": "sync_standby", "state": "streaming", "lag": 0}]
    west = [{"name": "oc-core-2", "role": "leader", "state": "running"},
            {"name": "oc-db-1", "role": "sync_standby", "state": "streaming", "lag": 0}]
    return {
        "clusters": {n: {"members": m, "rest_errors": {}, "primary": primary(), "heartbeat": {"ok": True}}
                     for n, m in (("oc-east", east), ("oc-west", west))},
        "etcd": [{"endpoint": e, "health": True} for e in ETCD],
        "backups": {n: {"status": 0, "message": "ok", "last_full": NOW - 3 * 86400, "last_any": NOW - 3600}
                    for n in ("oc-east", "oc-west")},
        "drills": {n: {"result": "pass", "last_pass": NOW - 86400} for n in ("oc-east", "oc-west")},
        "wg": {"oc-core-2": NOW - 20, "oc-db-1": NOW - 40}, "disks": {"/": 0.3}, "certs": {}, "errors": {},
        # keyed (cluster, leader) (review I2): oc-east's leader is oc-db-1, oc-west's is oc-core-2
        "prev_archive_failed": {"oc-east:oc-db-1": 0, "oc-west:oc-core-2": 0},
    }


class Evaluate(unittest.TestCase):
    def test_healthy_has_no_conditions(self):
        self.assertEqual(chk.evaluate(healthy(), cfg(), NOW), {})

    def test_no_leader(self):
        f = healthy()
        f["clusters"]["oc-east"]["members"][0].update(role="replica", state="stopped")
        self.assertIn("no-leader:oc-east", chk.evaluate(f, cfg(), NOW))

    def test_no_member_answers_is_no_leader(self):
        f = healthy()
        f["clusters"]["oc-west"] = {"rest_errors": {"oc-db-1": "timeout", "oc-core-2": "timeout"}}
        c = chk.evaluate(f, cfg(), NOW)
        self.assertIn("no-leader:oc-west", c)
        self.assertIn("member:oc-west:oc-core-2", c)

    def test_leader_away_from_home(self):
        f = healthy()
        f["clusters"]["oc-east"]["members"] = [{"name": "oc-core-2", "role": "leader", "state": "running"},
                                               {"name": "oc-db-1", "role": "sync_standby", "state": "streaming", "lag": 0}]
        c = chk.evaluate(f, cfg(), NOW)
        self.assertIn("leader-away:oc-east", c)
        self.assertNotIn("not-sync:oc-east", c)

    def test_portal_without_sync_standby(self):
        f = healthy()
        f["clusters"]["oc-east"]["members"][1].update(role="replica", state="stopped", lag="unknown")
        c = chk.evaluate(f, cfg(), NOW)
        self.assertIn("not-sync:oc-east", c)
        self.assertIn("lag:oc-east:oc-core-2", c)

    def test_async_cluster_needs_no_sync_standby(self):
        f = healthy()
        f["clusters"]["oc-west"]["members"][1]["role"] = "replica"
        self.assertEqual(chk.evaluate(f, cfg(), NOW), {})

    def test_lag_in_bytes_and_in_seconds(self):
        f = healthy()
        f["clusters"]["oc-east"]["members"][1]["lag"] = 17 * 1024 * 1024
        f["clusters"]["oc-west"]["primary"]["replication"][0]["replay_lag_s"] = 11
        c = chk.evaluate(f, cfg(), NOW)
        self.assertIn("lag:oc-east:oc-core-2", c)
        self.assertIn("lag:oc-west:x", c)

    def test_slot_archive_and_queue(self):
        f = healthy()
        p = f["clusters"]["oc-east"]["primary"]
        p["slots"][0]["retained"] = 3 * 1024 ** 3
        p["archiver"] = {"failed_count": 2, "last_archived_age_s": 900}
        p["ready"] = 40  # 640 MB > 25 % of 2 GB
        c = chk.evaluate(f, cfg(), NOW)
        for k in ("slot:oc-east:x", "archive-failing:oc-east", "archive-stale:oc-east", "archive-queue:oc-east"):
            self.assertIn(k, c)
        p["ready"] = 100  # 1600 MB > 75 %
        c = chk.evaluate(f, cfg(), NOW)
        self.assertIn("archive-queue-high:oc-east", c)
        self.assertNotIn("archive-queue:oc-east", c)

    def test_waiting_wal_is_stale_an_idle_cluster_is_not(self):
        f = healthy()
        f["clusters"]["oc-west"]["primary"]["archiver"]["last_archived_age_s"] = None
        self.assertEqual(chk.evaluate(f, cfg(), NOW), {})  # idle, nothing waiting
        f["clusters"]["oc-west"]["primary"]["ready"] = 1
        self.assertIn("archive-stale:oc-west", chk.evaluate(f, cfg(), NOW))

    def test_heartbeat_failure(self):
        f = healthy()
        f["clusters"]["oc-east"]["heartbeat"] = {"ok": False, "error": "read-only"}
        self.assertIn("heartbeat:oc-east", chk.evaluate(f, cfg(), NOW))

    def test_etcd_member_and_quorum(self):
        f = healthy()
        f["etcd"][0]["health"] = False
        c = chk.evaluate(f, cfg(), NOW)
        self.assertIn("etcd:https://10.99.0.4:2379", c)
        self.assertNotIn("etcd-quorum:", c)
        f["etcd"][1]["health"] = False
        self.assertIn("etcd-quorum:", chk.evaluate(f, cfg(), NOW))

    def test_backups_and_drills(self):
        f = healthy()
        f["backups"]["oc-east"].update(last_full=NOW - 9 * 86400, last_any=NOW - 27 * 3600)
        f["backups"]["oc-west"] = {"status": 1, "message": "missing stanza path", "last_full": None, "last_any": None}
        f["drills"]["oc-east"] = {"result": "fail", "detail": "heartbeat too old", "last_pass": NOW - 86400}
        f["drills"]["oc-west"] = None
        c = chk.evaluate(f, cfg(), NOW)
        for k in ("backup-full:oc-east", "backup-diff:oc-east", "stanza:oc-west", "backup-full:oc-west",
                  "drill:oc-east", "drill:oc-west"):
            self.assertIn(k, c)

    def test_member_leaves_clusters_to_the_witness(self):
        f = healthy()
        del f["backups"], f["drills"]
        f["clusters"]["oc-east"]["members"][0]["state"] = "stopped"
        self.assertEqual(chk.evaluate(f, cfg("member"), NOW), {})

    def test_member_checks_clusters_while_london_is_silent(self):
        f = healthy()
        f["etcd"][2]["health"] = False
        f["clusters"]["oc-east"]["members"][0]["state"] = "stopped"
        c = chk.evaluate(f, cfg("member"), NOW)
        self.assertIn("london-silent:", c)
        self.assertIn("no-leader:oc-east", c)
        self.assertNotIn("drill:oc-east", c)

    def test_local_role_checks_only_the_host(self):
        f = {"wg": {"oc-db-1": NOW - 400, "oc-ldn-1": None}, "disks": {"/": 0.85},
             "certs": {"/etc/opencell/db-tls/db.crt": NOW + 10 * 86400}, "errors": {}}
        c = chk.evaluate(f, cfg("local"), NOW)
        self.assertEqual(set(c), {"wg:oc-db-1", "wg:oc-ldn-1", "disk:/", "cert:/etc/opencell/db-tls/db.crt"})


class DeadMan(unittest.TestCase):
    """Review final I2: each checker watches the other's heartbeat rows, so a
    stopped timer, a hung unit or a dead host's checker is noticed."""

    @staticmethod
    def with_heartbeats(f, **sources):
        for c in f["clusters"].values():
            c["heartbeats"] = dict(sources)
        return f

    def test_witness_quiet_while_the_member_checker_writes(self):
        f = self.with_heartbeats(healthy(), **{"oc-db-1": NOW - 70, "oc-ldn-1": NOW - 10})
        self.assertEqual(chk.evaluate(f, dict(cfg(), peer_checker="oc-db-1"), NOW), {})

    def test_witness_raises_when_the_member_checker_is_stale(self):
        f = self.with_heartbeats(healthy(), **{"oc-db-1": NOW - 700, "oc-ldn-1": NOW - 10})
        c = chk.evaluate(f, dict(cfg(), peer_checker="oc-db-1"), NOW)
        self.assertEqual(set(c), {"checker-silent:oc-db-1"})
        self.assertIn("oc-db-1", c["checker-silent:oc-db-1"])

    def test_a_checker_that_never_wrote_is_silent(self):
        f = self.with_heartbeats(healthy(), **{"oc-ldn-1": NOW - 10})
        self.assertIn("checker-silent:oc-db-1", chk.evaluate(f, dict(cfg(), peer_checker="oc-db-1"), NOW))

    def test_no_heartbeat_read_means_no_verdict(self):
        # no primary answered: the cluster conditions speak, not this one
        self.assertNotIn("checker-silent:oc-db-1",
                         chk.evaluate(healthy(), dict(cfg(), peer_checker="oc-db-1"), NOW))

    def test_the_newest_row_on_any_cluster_counts(self):
        f = self.with_heartbeats(healthy(), **{"oc-db-1": NOW - 700})
        f["clusters"]["oc-west"]["heartbeats"] = {"oc-db-1": NOW - 60}
        self.assertEqual(chk.evaluate(f, dict(cfg(), peer_checker="oc-db-1"), NOW), {})

    def test_member_covers_when_londons_checker_is_stale_though_its_etcd_answers(self):
        f = self.with_heartbeats(healthy(), **{"oc-ldn-1": NOW - 700, "oc-db-1": NOW - 10})
        del f["backups"], f["drills"]
        f["clusters"]["oc-east"]["members"][0]["state"] = "stopped"
        c = chk.evaluate(f, dict(cfg("member"), peer_checker="oc-ldn-1"), NOW)
        self.assertIn("checker-silent:oc-ldn-1", c)
        self.assertIn("no-leader:oc-east", c)
        self.assertNotIn("london-silent:", c)  # London's etcd is fine; its checker is not

    def test_member_leaves_clusters_to_a_fresh_london(self):
        f = self.with_heartbeats(healthy(), **{"oc-ldn-1": NOW - 30, "oc-db-1": NOW - 10})
        del f["backups"], f["drills"]
        f["clusters"]["oc-east"]["members"][0]["state"] = "stopped"
        self.assertEqual(chk.evaluate(f, dict(cfg("member"), peer_checker="oc-ldn-1"), NOW), {})

    def test_member_covering_is_not_a_handoff_back(self):
        f = self.with_heartbeats(healthy(), **{"oc-ldn-1": NOW - 700})
        self.assertFalse(chk.london_covers(f, dict(cfg("member"), peer_checker="oc-ldn-1"), NOW))
        f = self.with_heartbeats(healthy(), **{"oc-ldn-1": NOW - 30})
        self.assertTrue(chk.london_covers(f, dict(cfg("member"), peer_checker="oc-ldn-1"), NOW))


class Digest(unittest.TestCase):
    """Review final I2: a daily mail whose absence the user notices."""

    def test_all_quiet(self):
        f = DeadMan.with_heartbeats(healthy(), **{"oc-db-1": NOW - 70, "oc-ldn-1": NOW - 10})
        subject, body = chk.digest_text(f, dict(cfg(), peer_checker="oc-db-1"), {}, {}, NOW)
        self.assertIn("daily", subject)
        self.assertIn("all quiet", subject)
        for word in ("oc-east", "oc-west", "oc-db-1 leader/running", "oc-core-2 leader/running",
                     "etcd: 3 of 3 healthy", "full", "drill", "oc-ldn-1", "1 min ago"):
            self.assertIn(word, body)

    def test_alerting_conditions_are_named(self):
        f = healthy()
        state = {"conditions": {"backup-diff:oc-west": {"raised": True, "level": "warning", "first": NOW - 90000,
                                                        "message": "oc-west: no backup for 1 d"}}}
        current = {"backup-diff:oc-west": "oc-west: no backup for 1 d"}
        subject, body = chk.digest_text(f, cfg(), state, current, NOW)
        self.assertIn("1 alerting", subject)
        self.assertIn("backup-diff:oc-west", body)

    def test_main_digest_without_mail_prints_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "db-check.conf")
            with open(conf, "w") as f:
                f.write("[check]\nhost = oc-ldn-1\nrole = witness\npeer_checker = oc-db-1\n"
                        f"[etcd]\nendpoints = {LDN}\n")
            state_path = os.path.join(d, "state.json")
            empty_bin = os.path.join(d, "bin")
            os.mkdir(empty_bin)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = empty_bin
            try:
                rc = chk.main(["--config", conf, "--state", state_path, "--digest", "--no-mail"])
            finally:
                os.environ["PATH"] = old_path
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.exists(state_path))  # the digest never touches the alert state

class State(unittest.TestCase):
    def test_raise_after_hold_then_clear_once(self):
        s = {}
        s, ev = chk.update_state(s, {"no-leader:oc-east": "m"}, NOW)
        self.assertEqual(ev, [])  # critical after 30 s
        s, ev = chk.update_state(s, {"no-leader:oc-east": "m"}, NOW + 60)
        self.assertEqual(ev, [["raise", "critical", "no-leader:oc-east", "m"]])
        s = chk.mark_sent(s)
        s, ev = chk.update_state(s, {"no-leader:oc-east": "m"}, NOW + 120)
        self.assertEqual(ev, [])  # not mailed twice
        s, ev = chk.update_state(s, {}, NOW + 180)
        self.assertEqual(ev, [])  # review I2: a clear waits out its own hold too
        s, ev = chk.update_state(s, {}, NOW + 180 + chk.CLEAR_HOLD_MIN)
        self.assertEqual(ev, [["clear", "critical", "no-leader:oc-east", "m"]])
        s = chk.mark_sent(s)
        s, ev = chk.update_state(s, {}, NOW + 180 + chk.CLEAR_HOLD_MIN + 60)
        self.assertEqual(ev, [])

    def test_a_blip_shorter_than_the_hold_is_never_mailed(self):
        s, ev = chk.update_state({}, {"leader-away:oc-east": "m"}, NOW)
        s, ev = chk.update_state(s, {}, NOW + 60)
        self.assertEqual(ev, [])
        self.assertEqual(s["conditions"], {})

    def test_archive_stale_waits_ten_minutes(self):
        s, ev = chk.update_state({}, {"archive-stale:oc-east": "m"}, NOW)
        s, ev = chk.update_state(s, {"archive-stale:oc-east": "m"}, NOW + 540)
        self.assertEqual(ev, [])
        s, ev = chk.update_state(s, {"archive-stale:oc-east": "m"}, NOW + 600)
        self.assertEqual(ev, [["raise", "warning", "archive-stale:oc-east", "m"]])

    def test_zero_hold_raises_at_once(self):
        s, ev = chk.update_state({}, {"disk:/": "85 %"}, NOW)
        self.assertEqual(ev, [["raise", "warning", "disk:/", "85 %"]])

    def test_unsent_events_are_kept_for_the_next_run(self):
        s, ev = chk.update_state({}, {"disk:/": "85 %"}, NOW)
        s, ev = chk.update_state(copy.deepcopy(s), {"disk:/": "86 %"}, NOW + 60)
        self.assertEqual(ev, [["raise", "warning", "disk:/", "85 %"]])  # the mail failed: still due

    def test_flapping_condition_raises_once_and_never_clears(self):
        # review I2: archive-failing (hold 0) present on even runs, absent on
        # odd ones, 60 s apart -- a real pattern during a London outage
        # (async archive-push retries roughly once a minute).
        s = {}
        events = []
        for i in range(10):
            current = {"archive-failing:oc-east": "m"} if i % 2 == 0 else {}
            s, ev = chk.update_state(s, current, NOW + i * 60)
            events += ev
            s = chk.mark_sent(s)  # each run's mail "succeeds", as in normal operation
        self.assertEqual([e for e in events if e[0] == "raise"],
                          [["raise", "warning", "archive-failing:oc-east", "m"]])
        self.assertEqual([e for e in events if e[0] == "clear"], [])

    def test_reappearing_before_the_clear_hold_cancels_it(self):
        s, ev = chk.update_state({}, {"disk:/": "85 %"}, NOW)
        self.assertEqual(ev, [["raise", "warning", "disk:/", "85 %"]])
        s = chk.mark_sent(s)
        s, ev = chk.update_state(s, {}, NOW + 60)  # absent: the clear countdown starts at +60
        self.assertEqual(ev, [])
        s, ev = chk.update_state(s, {"disk:/": "85 %"}, NOW + 90)  # back: cancelled
        self.assertEqual(ev, [])
        s, ev = chk.update_state(s, {}, NOW + 150)  # absent again: the countdown restarts at +150
        self.assertEqual(ev, [])
        s, ev = chk.update_state(s, {}, NOW + 150 + chk.CLEAR_HOLD_MIN - 1)
        self.assertEqual(ev, [])  # not yet -- the old (uncancelled) +60 countdown would have fired by now
        s, ev = chk.update_state(s, {}, NOW + 150 + chk.CLEAR_HOLD_MIN)
        self.assertEqual(ev, [["clear", "warning", "disk:/", "85 %"]])

    def test_mail_text(self):
        subject, body = chk.mail_text([["raise", "critical", "no-leader:oc-east", "oc-east: no running leader"],
                                       ["clear", "warning", "disk:/", "/ is 85 % full"]], "oc-ldn-1")
        self.assertTrue(subject.startswith("[OpenCell db] CRITICAL no-leader: oc-east: no running leader"))
        self.assertIn("RAISED CRITICAL  oc-east: no running leader", body)
        self.assertIn("CLEARED  / is 85 % full", body)


class Parse(unittest.TestCase):
    def test_backup_info(self):
        info = [{"name": "oc-east", "status": {"code": 0, "message": "ok"},
                 "backup": [{"type": "full", "timestamp": {"start": 1, "stop": 10}},
                            {"type": "diff", "timestamp": {"start": 20, "stop": 30}}]},
                {"name": "oc-west", "status": {"code": 2, "message": "no valid backups"}, "backup": []}]
        self.assertEqual(chk.parse_backup_info(info), {
            "oc-east": {"status": 0, "message": "ok", "last_full": 10, "last_any": 30},
            "oc-west": {"status": 2, "message": "no valid backups", "last_full": None, "last_any": None}})

    def test_config(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write("[check]\nhost = oc-db-1\nrole = member\npeer_checker = oc-ldn-1\n"
                    "[clusters]\noc-east = 5432 8008 oc-db-1 sync\noc-west = 5433 8009 oc-core-2 async\n"
                    "[members]\noc-db-1 = 10.99.0.4\noc-core-2 = 10.99.0.2\n"
                    f"[etcd]\nendpoints = {','.join(ETCD)}\nlondon = {LDN}\n"
                    "[local]\nfilesystems = / /var/lib/postgresql\ncerts = /etc/opencell/db-tls/db.crt\n"
                    "[wg_peers]\noc-core-2 = gEIo3gPxNdIe6Vv+N9DQVAXBW3zOXebRw8m8IvvuhjU=\n")
        c = chk.load_config(f.name)
        os.unlink(f.name)
        self.assertEqual(c["clusters"]["oc-east"], {"port": 5432, "rest": 8008, "home": "oc-db-1", "sync": True})
        self.assertFalse(c["clusters"]["oc-west"]["sync"])
        self.assertEqual(c["etcd"], ETCD)
        self.assertEqual(c["london_etcd"], LDN)
        self.assertEqual(c["filesystems"], ["/", "/var/lib/postgresql"])
        self.assertEqual(c["wg_peers"]["oc-core-2"], "gEIo3gPxNdIe6Vv+N9DQVAXBW3zOXebRw8m8IvvuhjU=")
        self.assertEqual(c["peer_checker"], "oc-ldn-1")


class Handoff(unittest.TestCase):
    CLUSTERS = ("oc-east", "oc-west")

    def test_drop_handoff_conditions_removes_only_cluster_keys(self):
        # review M10
        state = {"conditions": {
            "no-leader:oc-east": {"first": NOW - 1000, "raised": True, "message": "m1",
                                   "level": "critical", "absent_since": None},
            "wg:oc-core-2": {"first": NOW - 1000, "raised": True, "message": "m2",
                              "level": "warning", "absent_since": None}},
            "pending": [["raise", "critical", "no-leader:oc-east", "m1"]]}
        chk.drop_handoff_conditions(state, self.CLUSTERS)
        self.assertNotIn("no-leader:oc-east", state["conditions"])
        self.assertIn("wg:oc-core-2", state["conditions"])  # not a cluster-check key: untouched
        self.assertEqual(state["pending"], [])

    def test_drop_handoff_conditions_removes_cluster_scoped_collect_keys(self):
        # review N4: collect:oc-east:primary is cluster-scoped (evaluate() only
        # raises it while covering) and must drop; collect:etcd and
        # collect:wireguard are host-level and must not.
        state = {"conditions": {
            "collect:oc-east:primary": {"first": NOW - 1000, "raised": True, "message": "m1",
                                         "level": "warning", "absent_since": None},
            "collect:etcd": {"first": NOW - 1000, "raised": True, "message": "m2",
                              "level": "warning", "absent_since": None},
            "collect:wireguard": {"first": NOW - 1000, "raised": True, "message": "m3",
                                   "level": "warning", "absent_since": None}},
            "pending": [["raise", "warning", "collect:oc-east:primary", "m1"]]}
        chk.drop_handoff_conditions(state, self.CLUSTERS)
        self.assertNotIn("collect:oc-east:primary", state["conditions"])
        self.assertIn("collect:etcd", state["conditions"])
        self.assertIn("collect:wireguard", state["conditions"])
        self.assertEqual(state["pending"], [])

    def test_london_return_drops_member_conditions_without_a_clear(self):
        # A member (oc-db-1) was covering for a silent London and had raised
        # no-leader:oc-east. London answers again this run: evaluate() stops
        # reporting oc-east's conditions (the witness owns them now), and that
        # must not read as "resolved" -- no CLEARED mail, ever, for this key.
        f = healthy()
        state = {"conditions": {
            "no-leader:oc-east": {"first": NOW - 1000, "raised": True, "message": "old",
                                   "level": "critical", "absent_since": None}},
            "pending": []}
        state = chk.drop_handoff_conditions(state, cfg("member")["clusters"])
        current = chk.evaluate(f, cfg("member"), NOW)  # london_ok in f/cfg(): etcd all healthy
        state, ev = chk.update_state(state, current, NOW)
        self.assertEqual(ev, [])  # no CLEARED mail
        self.assertNotIn("no-leader:oc-east", state["conditions"])

    def test_london_return_drops_collect_condition_without_a_clear(self):
        # review N4, end to end: a role=member run raised collect:oc-east:primary
        # while covering (cannot reach the primary as oc_monitor); London
        # returns, and the same silent-drop applies to it.
        f = healthy()
        f["clusters"]["oc-east"]["primary"] = None
        f["clusters"]["oc-east"]["primary_error"] = "connection refused"
        state = {"conditions": {
            "collect:oc-east:primary": {"first": NOW - 1000, "raised": True, "message": "old",
                                         "level": "warning", "absent_since": None}},
            "pending": []}
        state = chk.drop_handoff_conditions(state, cfg("member")["clusters"])
        current = chk.evaluate(f, cfg("member"), NOW)
        state, ev = chk.update_state(state, current, NOW)
        self.assertEqual(ev, [])
        self.assertNotIn("collect:oc-east:primary", state["conditions"])


class Main(unittest.TestCase):
    def test_main_survives_a_missing_etcdctl_and_wg(self):
        # review I1: a missing (or hanging) subprocess helper must become a
        # fact, not an uncaught exception that skips saving state and mailing.
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "db-check.conf")
            with open(conf, "w") as f:
                f.write("[check]\nhost = oc-db-1\nrole = witness\n"
                        f"[etcd]\nendpoints = {LDN}\n"
                        "[wg_peers]\noc-core-2 = gEIo3gPxNdIe6Vv+N9DQVAXBW3zOXebRw8m8IvvuhjU=\n")
            state_path = os.path.join(d, "state.json")
            empty_bin = os.path.join(d, "bin")
            os.mkdir(empty_bin)
            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = empty_bin  # no etcdctl, no wg, no runuser, no pgbackrest
            try:
                rc = chk.main(["--config", conf, "--state", state_path, "--no-mail"])
            finally:
                os.environ["PATH"] = old_path
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(state_path))
            with open(state_path) as f:
                saved = json.load(f)
            self.assertTrue(any(k.startswith("collect:") for k in saved.get("conditions", {})),
                             saved.get("conditions"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
