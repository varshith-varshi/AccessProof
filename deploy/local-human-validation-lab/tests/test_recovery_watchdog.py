"""Lab boot recovery test with mocked Docker, no real shutdown or document edits."""
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

FILE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "recover_lab.py"
spec = importlib.util.spec_from_file_location("recover_lab", FILE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RecoveryWatchdogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig_state, self.orig_cooldown = m.STATE, m.COOLDOWN
        m.STATE = pathlib.Path(self.tmp.name)
        m.COOLDOWN = m.STATE / "cooldown"

    def tearDown(self):
        m.STATE, m.COOLDOWN = self.orig_state, self.orig_cooldown
        self.tmp.cleanup()

    def test_healthy_index_never_restarts_ingester(self):
        with patch.object(m, "shell") as shell:
            self.assertEqual(m.attempt_trusted_refresh(
                recover=True, result={"ready": True, "reason": "OK"}), "NOT_NEEDED")
            shell.assert_not_called()

    def test_dry_run_never_restarts_ingester(self):
        with patch.object(m, "shell") as shell:
            self.assertEqual(m.attempt_trusted_refresh(
                recover=False, result={"ready": False, "reason": "SOURCE_SYNC_STALE"}), "DRY_RUN")
            shell.assert_not_called()

    def test_unknown_critical_failure_requires_investigation_not_restart(self):
        with patch.object(m, "shell") as shell:
            text = m.attempt_trusted_refresh(
                recover=True, result={"ready": False, "reason": "UNRECOGNIZED_SIGNING_KEY"})
            self.assertIn("REQUIRES_INVESTIGATION", text)
            shell.assert_not_called()

    def test_stale_index_requests_trusted_ingester_and_recovers(self):
        result = subprocess.CompletedProcess(["docker"], 0, stdout="", stderr="")
        with (patch.object(m, "container_state", return_value=(True, "unless-stopped")),
              patch.object(m, "shell", return_value=result) as shell,
              patch.object(m, "signed_index", return_value={"ready": True}),
              patch.object(m.time, "sleep")):
            answer = m.attempt_trusted_refresh(
                recover=True, result={"ready": False, "reason": "SOURCE_SYNC_STALE"})
            self.assertEqual(answer, "SIGNED_INDEX_REFRESH_RECOVERED")
            self.assertTrue(any(call.args[:3] == ("docker", "restart", "--time")
                                for call in shell.call_args_list))
            self.assertTrue(m.COOLDOWN.exists())

    def test_cooldown_prevents_repeated_automatic_ingester_restart(self):
        m.COOLDOWN.write_text(str(m.time.time()))
        with (patch.object(m, "container_state", return_value=(True, "unless-stopped")),
              patch.object(m, "shell") as shell):
            self.assertEqual(m.attempt_trusted_refresh(
                recover=True, result={"ready": False, "reason": "SOURCE_SYNC_STALE"}),
                "INGESTER_RESTART_COOLDOWN")
            shell.assert_not_called()

    def test_stopped_container_is_not_started_in_check_mode(self):
        completed = subprocess.CompletedProcess(["inspect"], 0, stdout="false|unless-stopped", stderr="")
        with patch.object(m, "shell", return_value=completed) as shell:
            states, started = m.start_known_stopped_containers(recover=False)
            self.assertFalse(started)
            self.assertTrue(all(x == "STOPPED" for x in states.values()))
            self.assertFalse(any(call.args[:2] == ("docker", "start")
                                 for call in shell.call_args_list))

    def test_missing_customer_container_never_autoreinstalled(self):
        failed = subprocess.CompletedProcess(["inspect"], 1, stdout="", stderr="")
        with patch.object(m, "shell", return_value=failed) as shell:
            states, started = m.start_known_stopped_containers(recover=True)
            self.assertFalse(started)
            self.assertTrue(all(x == "MISSING_NOT_AUTOREINSTALLED" for x in states.values()))
            self.assertFalse(any(call.args[:2] == ("docker", "start")
                                 for call in shell.call_args_list))


if __name__ == "__main__":
    unittest.main()
