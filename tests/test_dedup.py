"""Dedup key normalization and fuzzy matching against already-reported findings."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import watchdog  # noqa: E402

NOW = time.time()


class FindingKeyTest(unittest.TestCase):
    def test_id_is_normalized(self):
        self.assertEqual(watchdog.finding_key({"id": "APT Update Failures!"}),
                         "apt-update-failures")

    def test_kebab_id_passes_through(self):
        self.assertEqual(watchdog.finding_key({"id": "apt-update-failures"}),
                         "apt-update-failures")

    def test_punctuation_runs_collapse(self):
        self.assertEqual(watchdog.finding_key({"id": "rootfs (pve) > 85%"}),
                         "rootfs-pve-85")

    def test_falls_back_to_title(self):
        self.assertEqual(watchdog.finding_key({"title": "Node pve offline"}),
                         "node-pve-offline")

    def test_empty_finding_never_crashes(self):
        self.assertEqual(watchdog.finding_key({}), "untitled")
        self.assertEqual(watchdog.finding_key({"id": "???"}), "untitled")


class ResolveKeyTest(unittest.TestCase):
    def test_exact_key_wins(self):
        reported = {"apt-update-failures": NOW}
        self.assertEqual(watchdog.resolve_key("apt-update-failures", reported),
                         "apt-update-failures")

    def test_drifted_id_maps_to_existing_key(self):
        # The canonical drift case: same ongoing apt issue, rephrased id.
        reported = {"apt-update-failures": NOW, "disk-full": NOW}
        self.assertEqual(watchdog.resolve_key("apt-get-failures-persist", reported),
                         "apt-update-failures")

    def test_distinct_issues_do_not_match(self):
        reported = {"disk-full": NOW}
        self.assertEqual(watchdog.resolve_key("backup-failed", reported),
                         "backup-failed")

    def test_distinct_issues_on_same_host_do_not_match(self):
        reported = {"vm104-backup-failed": NOW}
        self.assertEqual(watchdog.resolve_key("vm104-rootfs-full", reported),
                         "vm104-rootfs-full")

    def test_different_digits_never_merge(self):
        # Near-identical wording but another guest: merging would silently
        # swallow a genuinely new finding.
        reported = {"backup-vm104-failed": NOW}
        self.assertEqual(watchdog.resolve_key("backup-vm105-failed", reported),
                         "backup-vm105-failed")

    def test_same_digits_may_merge(self):
        reported = {"vzdump-999999-failed": NOW}
        self.assertEqual(watchdog.resolve_key("vzdump-999999-failed-again", reported),
                         "vzdump-999999-failed")

    def test_empty_reported_returns_key(self):
        self.assertEqual(watchdog.resolve_key("apt-update-failures", {}),
                         "apt-update-failures")


class CooldownIntegrationTest(unittest.TestCase):
    """The property the feature exists for: a drifted id inherits the cooldown."""

    def test_drifted_id_is_suppressed_within_cooldown(self):
        renotify_s = 24 * 3600
        reported = {"apt-update-failures": NOW - 3600}  # notified an hour ago
        finding = {"id": "apt-get-failures-persist", "severity": "warning",
                   "title": "APT failures persist", "detail": "d", "suggested_action": "a"}
        key = watchdog.resolve_key(watchdog.finding_key(finding), reported)
        self.assertEqual(key, "apt-update-failures")
        self.assertLess(NOW - reported[key], renotify_s)  # -> stays quiet

    def test_drifted_id_renotifies_after_cooldown_under_original_key(self):
        renotify_s = 24 * 3600
        reported = {"apt-update-failures": NOW - 25 * 3600}
        finding = {"id": "apt-get-failures-persist"}
        key = watchdog.resolve_key(watchdog.finding_key(finding), reported)
        self.assertEqual(key, "apt-update-failures")  # canonical key stays stable
        self.assertGreaterEqual(NOW - reported[key], renotify_s)  # -> notifies


if __name__ == "__main__":
    unittest.main()
