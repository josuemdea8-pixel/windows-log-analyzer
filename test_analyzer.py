import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import windows_log_analyzer as wla  # noqa: E402

BASE = datetime(2026, 10, 1, 9, 0, 0)
SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "security_sample.csv"


def fail(seconds, user="admin", ip="203.0.113.10"):
    return wla.Event(BASE + timedelta(seconds=seconds), 4625, user=user, ip=ip)


def proc(cmd, process="C:\\Windows\\System32\\cmd.exe", parent="C:\\Windows\\explorer.exe"):
    return wla.Event(BASE, 4688, user="maria", process=process, command_line=cmd, parent=parent)


class PasswordAttackTests(unittest.TestCase):
    def test_brute_force_at_threshold(self):
        findings, _ = wla.detect_password_attacks([fail(i * 10) for i in range(5)])
        self.assertEqual([f.technique for f in findings], ["T1110.001"])

    def test_below_threshold_is_ignored(self):
        findings, _ = wla.detect_password_attacks([fail(i * 10) for i in range(4)])
        self.assertEqual(findings, [])

    def test_slow_attempts_outside_window_are_ignored(self):
        events = [fail(i * 600) for i in range(6)]  # 1 falha a cada 10 min
        findings, _ = wla.detect_password_attacks(events)
        self.assertEqual(findings, [])

    def test_password_spraying(self):
        events = [fail(i * 10, user=f"user{i}") for i in range(6)]
        findings, _ = wla.detect_password_attacks(events)
        self.assertEqual([f.technique for f in findings], ["T1110.003"])

    def test_success_after_attack_is_critical(self):
        events = [fail(i * 10) for i in range(6)]
        events.append(wla.Event(BASE + timedelta(seconds=90), 4624, user="admin",
                                ip="203.0.113.10", logon_type="10"))
        findings = wla.analyze(events)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_success_from_other_ip_is_not_flagged(self):
        events = [fail(i * 10) for i in range(6)]
        events.append(wla.Event(BASE + timedelta(seconds=90), 4624, user="admin", ip="10.0.0.5"))
        severities = [f.severity for f in wla.analyze(events)]
        self.assertNotIn("CRITICAL", severities)


class ProcessTests(unittest.TestCase):
    def test_encoded_powershell(self):
        f = wla.detect_suspicious_processes(
            [proc("powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi")])
        self.assertEqual(f[0].technique, "T1059.001")

    def test_benign_process_is_not_flagged(self):
        self.assertEqual(wla.detect_suspicious_processes([proc("notepad.exe")]), [])

    def test_office_spawning_shell(self):
        f = wla.detect_suspicious_processes(
            [proc("cmd.exe /c dir", parent="C:\\Office\\WINWORD.EXE")])
        self.assertIn("T1204.002", [x.technique for x in f])

    def test_shadow_copy_deletion_is_critical(self):
        f = wla.detect_suspicious_processes([proc("vssadmin delete shadows /all /quiet")])
        self.assertEqual(f[0].severity, "CRITICAL")


class LoaderTests(unittest.TestCase):
    def test_parse_time_with_z_and_offset(self):
        self.assertEqual(wla.parse_time("2026-10-01T09:00:00Z"), datetime(2026, 10, 1, 9, 0))
        self.assertEqual(wla.parse_time("2026-10-01T06:00:00-03:00"), datetime(2026, 10, 1, 9, 0))

    def test_sample_file_end_to_end(self):
        events = wla.load_events(str(SAMPLE))
        findings = wla.analyze(events)
        self.assertEqual(len(events), 24)
        self.assertEqual(findings[0].severity, "CRITICAL")
        techniques = {f.technique for f in findings}
        self.assertTrue({"T1110.001", "T1110.003", "T1059.001", "T1105"} <= techniques)


if __name__ == "__main__":
    unittest.main()
