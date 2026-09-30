#!/usr/bin/env python3
"""tools/db/oc-db-check: conditions from facts, and the alert state machine.
usage: test_oc_db_check.py PATH_TO_OC_DB_CHECK"""
import copy
import importlib.machinery
import importlib.util
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
        "prev_archive_failed": {"oc-east": 0, "oc-west": 0},
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
        self.assertEqual(ev, [["clear", "critical", "no-leader:oc-east", "m"]])
        s = chk.mark_sent(s)
        s, ev = chk.update_state(s, {}, NOW + 240)
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
            f.write("[check]\nhost = oc-db-1\nrole = member\n"
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
