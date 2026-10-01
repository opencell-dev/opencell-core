#!/usr/bin/env python3
"""tools/db/oc-db-alert-mail: the rate-limit stamp, backend selection, and the
sendmail fallback end to end (review N1, N2, N5).
usage: test_oc_db_alert_mail.py PATH_TO_OC_DB_ALERT_MAIL"""
import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # no __pycache__ beside the script
PATH = sys.argv.pop(1) if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "..", "tools", "db", "oc-db-alert-mail")
loader = importlib.machinery.SourceFileLoader("oc_db_alert_mail", PATH)
spec = importlib.util.spec_from_loader("oc_db_alert_mail", loader)
mail = importlib.util.module_from_spec(spec)
loader.exec_module(mail)


class Stamp(unittest.TestCase):
    def test_first_failure_always_sends(self):
        send, count, since, stamp = mail.update_stamp(None, 1000)
        self.assertTrue(send)
        self.assertEqual(count, 1)
        self.assertEqual(since, 1000)
        self.assertEqual(stamp, {"since": 1000, "count": 0})

    def test_within_the_window_is_suppressed_and_counted(self):
        send, count, since, stamp = mail.update_stamp({"since": 1000, "count": 0}, 1060)
        self.assertFalse(send)
        self.assertEqual(count, 1)
        self.assertEqual(since, 1000)
        self.assertEqual(stamp, {"since": 1000, "count": 1})
        send, count, since, stamp = mail.update_stamp(stamp, 1120)
        self.assertFalse(send)
        self.assertEqual(count, 2)
        self.assertEqual(stamp, {"since": 1000, "count": 2})

    def test_window_elapsed_sends_the_accumulated_count_and_resets(self):
        stamp = {"since": 1000, "count": 58}  # 59 failures counted; this call is the 60th
        send, count, since, new_stamp = mail.update_stamp(stamp, 1000 + 3600)
        self.assertTrue(send)
        self.assertEqual(count, 59)
        self.assertEqual(since, 1000)
        self.assertEqual(new_stamp, {"since": 1000 + 3600, "count": 0})

    def test_reappearing_before_the_window_elapses_does_not_send(self):
        send, _, _, stamp = mail.update_stamp(None, 0)
        self.assertTrue(send)
        for minute in range(1, 59):
            send, _, _, stamp = mail.update_stamp(stamp, minute * 60)
            self.assertFalse(send, f"unexpected send at minute {minute}")

    def test_ten_runs_a_minute_apart_send_only_the_first(self):
        stamp, sends = None, 0
        for i in range(10):
            send, _, _, stamp = mail.update_stamp(stamp, i * 60)
            sends += send
        self.assertEqual(sends, 1)

    def test_a_full_hour_of_failures_then_one_more_sends_exactly_twice(self):
        # review N1: oc-db-check's own worst case -- failing on every one-a-
        # minute run for over an hour must mail twice, not sixty-two times.
        stamp, sends = None, []
        for i in range(62):
            send, count, since, stamp = mail.update_stamp(stamp, i * 60)
            if send:
                sends.append((i, count, since))
        self.assertEqual(len(sends), 2)
        self.assertEqual(sends[0], (0, 1, 0))
        self.assertEqual(sends[1], (60, 60, 0))  # the second mail reports the whole suppressed hour

    def test_a_real_clear_then_a_fresh_incident_both_send(self):
        send, _, _, stamp = mail.update_stamp(None, 0)
        self.assertTrue(send)
        # nothing fails for a day; a new, unrelated incident an hour+ later
        send, count, since, stamp = mail.update_stamp(stamp, 90000)
        self.assertTrue(send)
        self.assertEqual(count, 1)  # only the one new failure, not the old window's 0


class FindEnv(unittest.TestCase):
    def test_a_systemd_credential_wins_over_the_env_file(self):
        with tempfile.TemporaryDirectory() as d:
            cred_dir = os.path.join(d, "cred")
            os.mkdir(cred_dir)
            cred_file = os.path.join(cred_dir, "smtp")
            open(cred_file, "w").close()
            env_file = os.path.join(d, "env")
            open(env_file, "w").close()
            self.assertEqual(mail.find_env(env_file, cred_dir), cred_file)

    def test_falls_back_to_the_env_file(self):
        with tempfile.TemporaryDirectory() as d:
            env_file = os.path.join(d, "env")
            open(env_file, "w").close()
            self.assertEqual(mail.find_env(env_file, None), env_file)
            self.assertEqual(mail.find_env(env_file, os.path.join(d, "no-such-cred-dir")), env_file)

    def test_neither_present_means_sendmail(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(mail.find_env(os.path.join(d, "no-such-env"), None))
            self.assertIsNone(mail.find_env(os.path.join(d, "no-such-env"),
                                             os.path.join(d, "no-such-cred-dir")))


class Compose(unittest.TestCase):
    def test_subject_and_body_name_the_unit_host_and_count(self):
        subject, body = mail.compose("oc-db-check.service", "oc-ldn-1", 3, 1_800_000_000)
        self.assertEqual(subject, "[OpenCell db] oc-db-check.service failed on oc-ldn-1")
        self.assertIn("3 failure(s) since", body)
        self.assertIn("oc-db-check.service failed on oc-ldn-1", body)


class Main(unittest.TestCase):
    def test_no_env_or_credential_falls_back_to_sendmail(self):
        # review N2: pvelondon has no alert-smtp.env and no systemd credential.
        with tempfile.TemporaryDirectory() as d:
            fake_bin = os.path.join(d, "fake-sendmail")
            calls = os.path.join(d, "calls")
            with open(fake_bin, "w") as f:
                f.write(f'#!/bin/bash\ncat >> "{calls}"\necho called >> "{calls}.log"\n')
            os.chmod(fake_bin, 0o755)
            env = dict(os.environ)
            env["OC_SENDMAIL"] = fake_bin
            env.pop("CREDENTIALS_DIRECTORY", None)
            import subprocess
            r = subprocess.run(
                [sys.executable, PATH, "oc-zfs-snap.service",
                 "--env", os.path.join(d, "no-such-env"),
                 "--state-dir", os.path.join(d, "state")],
                env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(calls), r.stdout + r.stderr)
            with open(calls) as f:
                sent = f.read()
            self.assertIn("To: root", sent)
            self.assertIn("oc-zfs-snap.service failed on", sent)

    def test_second_failure_within_the_hour_is_not_mailed(self):
        with tempfile.TemporaryDirectory() as d:
            fake_bin = os.path.join(d, "fake-sendmail")
            calls = os.path.join(d, "calls")
            with open(fake_bin, "w") as f:
                f.write(f'#!/bin/bash\ncat >> "{calls}"\n')
            os.chmod(fake_bin, 0o755)
            env = dict(os.environ)
            env["OC_SENDMAIL"] = fake_bin
            env.pop("CREDENTIALS_DIRECTORY", None)
            import subprocess
            args = [sys.executable, PATH, "oc-etcd-defrag.service",
                    "--env", os.path.join(d, "no-such-env"), "--state-dir", os.path.join(d, "state")]
            r1 = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(r1.returncode, 0, r1.stderr)
            with open(calls) as f:
                calls_after_first = f.read()
            r2 = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            with open(calls) as f:
                calls_after_second = f.read()
            self.assertEqual(calls_after_first, calls_after_second)  # sendmail not invoked again
            self.assertIn("not mailed", r2.stdout)


UNIT = os.path.join(os.path.dirname(os.path.abspath(PATH)), "systemd", "oc-db-alert-failure@.service")


def systemd_unescape(s):
    """%I: the instance unescaped as systemd does ("-" -> "/", "\\xNN" -> byte)."""
    import shutil
    import subprocess
    if shutil.which("systemd-escape"):
        return subprocess.run(["systemd-escape", "--unescape", s], capture_output=True,
                              text=True, check=True).stdout.strip()
    out, i = [], 0
    while i < len(s):
        if s.startswith("\\x", i):
            out.append(chr(int(s[i + 2:i + 4], 16)))
            i += 4
        else:
            out.append("/" if s[i] == "-" else s[i])
            i += 1
    return "".join(out)


def expand(arg, instance):
    """The two instance specifiers systemd would expand in ExecStart=."""
    return arg.replace("%i", instance).replace("%I", systemd_unescape(instance))


class UnitSubject(unittest.TestCase):
    """The OnFailure= mailer unit must hand the mailer the failed unit's name as
    is: OnFailure=oc-db-alert-failure@%n.service makes the instance
    "oc-db-check.service", and %I would unescape its dashes into
    "oc/db/check.service" (seen live on oc-ldn-1, 2026-09-30)."""

    def exec_args(self):
        with open(UNIT) as f:
            line = next(l for l in f if l.startswith("ExecStart="))
        return line.split("=", 1)[1].split()[1:]

    def test_the_unit_passes_the_raw_instance(self):
        self.assertEqual(self.exec_args(), ["%i"])

    def test_a_dashed_unit_name_reaches_the_subject_intact(self):
        for failed in ("oc-db-check.service", "oc-zfs-snap.service", "oc-etcd-defrag.service",
                       "pga-test.service"):
            args = [expand(a, failed) for a in self.exec_args()]
            self.assertEqual(args, [failed])
            with tempfile.TemporaryDirectory() as d:
                fake_bin = os.path.join(d, "fake-sendmail")
                calls = os.path.join(d, "calls")
                with open(fake_bin, "w") as f:
                    f.write(f'#!/bin/bash\ncat >> "{calls}"\n')
                os.chmod(fake_bin, 0o755)
                env = dict(os.environ)
                env["OC_SENDMAIL"] = fake_bin
                env.pop("CREDENTIALS_DIRECTORY", None)
                import subprocess
                r = subprocess.run(
                    [sys.executable, PATH, *args, "--env", os.path.join(d, "no-such-env"),
                     "--state-dir", os.path.join(d, "state")],
                    env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(r.returncode, 0, r.stderr)
                with open(calls) as f:
                    sent = f.read()
                self.assertIn(f"Subject: [OpenCell db] {failed} failed on ", sent)


if __name__ == "__main__":
    unittest.main(verbosity=1)
