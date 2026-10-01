#!/usr/bin/env python3
"""tools/db/oc-db-upgrade (runbook R9, automated) against a fake fleet: the
order, never upgrading a host while it leads a cluster, stopping on a failure
with a rollback, and the holds always put back.
usage: test_oc_db_upgrade.py PATH_TO_OC_DB_UPGRADE"""
import importlib.machinery
import importlib.util
import os
import sys
import unittest

sys.dont_write_bytecode = True
PATH = sys.argv.pop(1) if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "..", "tools", "db", "oc-db-upgrade")
loader = importlib.machinery.SourceFileLoader("oc_db_upgrade", PATH)
spec = importlib.util.spec_from_loader("oc_db_upgrade", loader)
up = importlib.util.module_from_spec(spec)
loader.exec_module(up)


class Fleet:
    """Three hosts, two clusters, etcd; records every call."""

    def __init__(self, upgradable=True):
        new = "17.12-0+deb13u1"
        self.versions_ = {
            "oc-ldn-1": {"postgresql-17": ["17.11-0+deb13u1", new], "etcd-server": ["3.5.16-4", "3.5.16-5"],
                         "pgbackrest": ["2.55.1-1", "2.55.1-1"]},
            "oc-db-1": {"postgresql-17": ["17.11-0+deb13u1", new], "patroni": ["4.0.7-3~deb13u1", "4.0.7-3~deb13u1"],
                        "etcd-server": ["3.5.16-4", "3.5.16-5"], "pgbackrest": ["2.55.1-1", "2.55.1-1"]},
            "oc-core-2": {"postgresql-17": ["17.11-0+deb13u1", new], "patroni": ["4.0.7-3~deb13u1", "4.0.7-3~deb13u1"],
                          "etcd-server": ["3.5.16-4", "3.5.16-5"], "pgbackrest": ["2.55.1-1", "2.55.1-1"]},
        }
        if not upgradable:
            for v in self.versions_.values():
                for p in v:
                    v[p][1] = v[p][0]
        self.leaders = {"oc-east": "oc-db-1", "oc-west": "oc-core-2"}
        self.calls = []
        self.held = {h: True for h in self.versions_}
        self.fail = {}          # (kind, host) -> remaining failures
        self.etcd_bad_after_restart_on = None
        self.etcd = 3
        self.sync = True

    def _maybe_fail(self, kind, host):
        if self.fail.get((kind, host), 0) > 0:
            self.fail[(kind, host)] -= 1
            raise up.Stop(f"{host}: {kind} failed (injected)")

    # -- the Remote interface
    def versions(self, host):
        return {p: tuple(v) for p, v in self.versions_[host].items()}

    def clusters(self):
        out = {}
        for c, lead in self.leaders.items():
            other = "oc-core-2" if lead == "oc-db-1" else "oc-db-1"
            out[c] = [{"name": lead, "role": "Leader", "state": "running", "lag": None},
                      {"name": other, "role": "Sync Standby" if self.sync else "Replica", "state": "streaming", "lag": 0}]
        return out

    def etcd_healthy(self):
        return self.etcd

    def switchover(self, cluster, leader, candidate):
        self.calls.append(("switchover", cluster, leader, candidate))
        assert self.leaders[cluster] == leader
        self.leaders[cluster] = candidate

    def install(self, host, packages):
        self.calls.append(("install", host, tuple(packages)))
        # the property R9 exists for: never upgrade a host that leads a cluster
        assert host not in self.leaders.values(), f"install on {host} while it leads {self.leaders}"
        self._maybe_fail("install", host)
        for p in packages:
            self.versions_[host][p][0] = self.versions_[host][p][1]
        self.held[host] = True  # the remote install re-holds in a trap

    def downgrade(self, host, versions):
        self.calls.append(("downgrade", host, dict(versions)))
        for p, v in versions.items():
            self.versions_[host][p][0] = v

    def hold(self, host, packages):
        self.calls.append(("hold", host))
        self.held[host] = True

    def restart(self, host, unit):
        self.calls.append(("restart", host, unit))
        if unit.startswith("patroni@"):
            assert host not in self.leaders.values(), f"Patroni restarted on {host} while it leads {self.leaders}"
        if unit == "etcd" and host == self.etcd_bad_after_restart_on:
            self.etcd = 2

    def pending_restart(self, host):
        return []

    def kinds(self, kind):
        return [c for c in self.calls if c[0] == kind]


def run(fleet, **kw):
    log = []
    clock = [0.0]
    u = up.Upgrade(fleet, log=log.append, sleep=lambda s: clock.__setitem__(0, clock[0] + s),
                   clock=lambda: clock[0])
    return u.run(**kw), log


class Order(unittest.TestCase):
    def test_nothing_to_upgrade_touches_nothing(self):
        f = Fleet(upgradable=False)
        rc, log = run(f)
        self.assertEqual(rc, 0)
        self.assertEqual([c for c in f.calls if c[0] != "hold"], [])
        self.assertIn("nothing to upgrade", log[-1])

    def test_witness_first_then_each_member_with_its_leaders_moved_off(self):
        f = Fleet()
        rc, log = run(f)
        self.assertEqual(rc, 0, log)
        installs = [c[1] for c in f.kinds("install")]
        self.assertEqual(installs, ["oc-ldn-1", "oc-db-1", "oc-core-2"])
        # the only packages installed are the ones with a newer candidate
        self.assertEqual(f.kinds("install")[0], ("install", "oc-ldn-1", ("etcd-server", "postgresql-17")))
        i_db1 = f.calls.index(("install", "oc-db-1", ("etcd-server", "postgresql-17")))
        self.assertIn(("switchover", "oc-east", "oc-db-1", "oc-core-2"), f.calls[:i_db1])

    def test_leaders_end_at_home_and_the_holds_are_back(self):
        f = Fleet()
        rc, _ = run(f)
        self.assertEqual(rc, 0)
        self.assertEqual(f.leaders, {"oc-east": "oc-db-1", "oc-west": "oc-core-2"})
        self.assertEqual({c[1] for c in f.kinds("hold")}, {"oc-ldn-1", "oc-db-1", "oc-core-2"})

    def test_patroni_and_etcd_restart_on_each_upgraded_member(self):
        f = Fleet()
        run(f)
        for h in ("oc-db-1", "oc-core-2"):
            for unit in ("etcd", "patroni@oc-east", "patroni@oc-west"):
                self.assertIn(("restart", h, unit), f.calls)
        self.assertNotIn(("restart", "oc-ldn-1", "patroni@oc-east"), f.calls)


class Stops(unittest.TestCase):
    def test_preflight_without_a_sync_standby_changes_nothing(self):
        f = Fleet()
        f.sync = False
        with self.assertRaises(up.Stop):
            run(f)
        self.assertEqual(f.calls, [])

    def test_a_failed_check_after_a_host_stops_rolls_back_and_holds(self):
        f = Fleet()
        f.etcd_bad_after_restart_on = "oc-db-1"
        rc, log = run(f)
        self.assertEqual(rc, 1)
        self.assertIn(("downgrade", "oc-db-1", {"etcd-server": "3.5.16-4", "postgresql-17": "17.11-0+deb13u1"}),
                      f.calls)
        self.assertNotIn("oc-core-2", [c[1] for c in f.kinds("install")])  # never got there
        self.assertEqual({c[1] for c in f.kinds("hold")}, {"oc-ldn-1", "oc-db-1", "oc-core-2"})
        self.assertTrue(any(line.startswith("STOPPED") for line in log))

    def test_a_failed_install_stops_rolls_back_and_holds(self):
        f = Fleet()
        f.fail[("install", "oc-core-2")] = 1
        rc, _ = run(f)
        self.assertEqual(rc, 1)
        self.assertEqual(f.kinds("downgrade")[0][1], "oc-core-2")
        self.assertEqual({c[1] for c in f.kinds("hold")}, {"oc-ldn-1", "oc-db-1", "oc-core-2"})


class Transient(unittest.TestCase):
    def test_preflight_waits_out_a_one_off_etcd_reading(self):
        # seen live (2026-10-01): one endpoint-health reading of 2/3 right after
        # another run; the preflight must not refuse on a single blip
        f = Fleet(upgradable=False)
        readings = iter([2, 3, 3, 3, 3, 3])
        f.etcd_healthy = lambda: next(readings, 3)
        rc, log = run(f, restart_only=True)
        self.assertEqual(rc, 0, log)

    def test_preflight_still_refuses_a_lasting_etcd_problem(self):
        f = Fleet(upgradable=False)
        f.etcd = 2
        with self.assertRaises(up.Stop):
            run(f, restart_only=True)
        self.assertEqual(f.calls, [])


class Modes(unittest.TestCase):
    def test_dry_run_changes_nothing_and_shows_the_plan(self):
        f = Fleet()
        rc, log = run(f, dry_run=True)
        self.assertEqual(rc, 0)
        self.assertEqual([c for c in f.calls if c[0] != "hold"], [])
        self.assertTrue(any("oc-db-1: move its leaders" in line for line in log))

    def test_restart_only_installs_nothing_but_runs_the_whole_cycle(self):
        f = Fleet(upgradable=False)
        rc, _ = run(f, restart_only=True)
        self.assertEqual(rc, 0)
        self.assertEqual(f.kinds("install"), [])
        for h in ("oc-db-1", "oc-core-2"):
            self.assertIn(("restart", h, "patroni@oc-east"), f.calls)
        self.assertIn(("restart", "oc-ldn-1", "etcd"), f.calls)
        self.assertEqual(f.leaders, {"oc-east": "oc-db-1", "oc-west": "oc-core-2"})


if __name__ == "__main__":
    unittest.main(verbosity=1)
