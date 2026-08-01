#!/usr/bin/env python3
"""homelab-ai-watchdog: Proxmox snapshot -> Claude triage -> chat notification.

Runs once and exits (drive it with a systemd timer or cron). Silence means
everything is fine — it only speaks when something actually matters.

State only advances after an alert has actually been delivered: if every
notifier fails, the run exits non-zero and the same findings regenerate on
the next run instead of being silently lost.
"""

import difflib
import hashlib
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

import yaml

import notifiers
import proxmox_collector
import triage as triage_mod

log = logging.getLogger("watchdog")

SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
# Repeated watchdog errors of the same kind notify at most once per cooldown,
# so a dead Proxmox host doesn't page you every 15 minutes all night.
ERROR_COOLDOWN_S = 24 * 3600
# Same idea for findings: an ongoing issue (failed backup still failed) is
# notified once per cooldown, not on every timer tick. Configurable via
# `renotify_after_hours` in config.yaml.
DEFAULT_RENOTIFY_HOURS = 24
REPORTED_PRUNE_S = 30 * 24 * 3600
# A drifting model id ("apt-update-failures" -> "apt-get-failures-persist")
# must still count as the same ongoing issue. That very pair scores 0.65 on
# SequenceMatcher, so 0.7 would reject it; distinct issues stay well below
# (worst observed ~0.50, e.g. "vm104-backup-failed" vs "vm104-rootfs-full").
FUZZY_MATCH_CUTOFF = 0.6


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    # A YAML key with all children commented out parses as None — normalize,
    # so env-only setups don't crash before the error handler exists.
    for section in ("proxmox", "triage", "notifiers"):
        cfg[section] = cfg.get(section) or {}

    # Environment variables override file values for the two real secrets.
    if os.environ.get("PROXMOX_TOKEN_VALUE"):
        cfg["proxmox"]["token_value"] = os.environ["PROXMOX_TOKEN_VALUE"]
    if os.environ.get("ANTHROPIC_API_KEY"):
        cfg["triage"]["api_key"] = os.environ["ANTHROPIC_API_KEY"]
    return cfg


def load_previous(state_file):
    try:
        return json.loads(Path(state_file).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_snapshot(state_file, snapshot):
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: a power cut mid-write must not corrupt the previous state.
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(snapshot), encoding="utf-8")
    tmp.replace(path)


def _save_or_log(state_file, snapshot):
    try:
        save_snapshot(state_file, snapshot)
    except OSError as exc:
        log.error("could not save state (alert was already delivered): %s", exc)


def _error_state_path(state_file):
    p = Path(state_file)
    return p.with_name(p.stem + ".error.json")


def _reported_path(state_file):
    p = Path(state_file)
    return p.with_name(p.stem + ".reported.json")


def load_reported(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_reported(path, reported):
    now = time.time()
    reported = {k: ts for k, ts in reported.items() if now - ts < REPORTED_PRUNE_S}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(reported), encoding="utf-8")
    except OSError as exc:
        log.error("could not save reported-findings state: %s", exc)


def finding_key(f):
    # The model provides a stable id per underlying issue; fall back to the
    # title for robustness if it ever omits one. Normalize so cosmetic
    # variants ("APT Update Failures" vs "apt-update-failures") collapse
    # into one key.
    raw = f.get("id") or f.get("title") or "untitled"
    key = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return key or "untitled"


def resolve_key(key, reported, severity="warning"):
    """Map a finding key onto an already-reported one when they are close enough.

    Model-generated ids drift between runs despite the stable-id prompt. An
    exact miss falls back to fuzzy matching so a rephrased id doesn't re-page
    for the same ongoing issue. Two hard limits, because swallowing a genuine
    finding is a silent failure while an extra alert is only noise:
      - digit runs (vmids, task ids) are identity: differing numbers never merge;
      - critical findings never fuzzy-match. Nearby ids can mean opposite
        things ("disk-full" vs "disk-slow" scores 0.67), and delaying a
        critical alert by a cooldown is not a trade worth making.
    """
    if key in reported:
        return key
    if severity == "critical":
        return key
    digits = re.findall(r"\d+", key)
    candidates = [k for k in reported if re.findall(r"\d+", k) == digits]
    close = difflib.get_close_matches(key, candidates, n=1, cutoff=FUZZY_MATCH_CUTOFF)
    if close:
        log.info("finding id %r fuzzy-matched onto reported %r", key, close[0])
        return close[0]
    return key


def should_notify_error(path, exc):
    """True if this error kind hasn't been notified within the cooldown window."""
    # Signature = exception type only: messages often carry variable parts
    # (request ids, timestamps) that would defeat deduplication.
    sig = hashlib.sha256(type(exc).__name__.encode()).hexdigest()
    try:
        prev = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        prev = None
    now = time.time()
    if prev and prev.get("sig") == sig and now - prev.get("ts", 0) < ERROR_COOLDOWN_S:
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"sig": sig, "ts": now}), encoding="utf-8")
    except OSError:
        pass  # worst case: the error notifies again next run
    return True


def clear_error_state(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    cfg = load_config(config_path)
    state_file = cfg.get("state_file", "state/last_snapshot.json")
    error_state = _error_state_path(state_file)

    try:
        snapshot = proxmox_collector.collect(cfg["proxmox"])
        previous = load_previous(state_file)
        findings = triage_mod.triage(cfg["triage"], snapshot, previous)
    except Exception as exc:  # noqa: BLE001 — a silent watchdog is worse than a noisy one
        log.error("watchdog run failed: %s", exc)
        if cfg.get("notify_on_watchdog_error", True) and should_notify_error(error_state, exc):
            notifiers.dispatch(
                cfg["notifiers"],
                f"⚠️ Watchdog error (the watchdog itself, not your lab): {exc}",
            )
        sys.exit(1)

    # Healthy run: forget past errors so the next new one notifies immediately.
    clear_error_state(error_state)

    min_sev = SEVERITY_RANK.get(cfg["triage"].get("notify_min_severity", "warning"), 1)
    to_report = [
        f for f in findings
        if SEVERITY_RANK.get(f.get("severity", "info"), 0) >= min_sev
    ]

    if not to_report:
        log.info("all clear (%d finding(s) below threshold)", len(findings))
        _save_or_log(state_file, snapshot)
        return

    # An ongoing issue is notified once per cooldown, not on every timer tick.
    reported_path = _reported_path(state_file)
    reported = load_reported(reported_path)
    renotify_s = float(cfg.get("renotify_after_hours", DEFAULT_RENOTIFY_HOURS)) * 3600
    now = time.time()
    # Resolve each finding onto an existing reported key first, so a drifted
    # id inherits the original key's cooldown instead of re-paging.
    keyed = [(resolve_key(finding_key(f), reported, f.get("severity", "warning")), f)
             for f in to_report]
    fresh = [(k, f) for k, f in keyed if now - reported.get(k, 0) >= renotify_s]

    if not fresh:
        log.info("%d finding(s) present but all notified recently — staying quiet",
                 len(to_report))
        _save_or_log(state_file, snapshot)
        return

    source = cfg["proxmox"].get("host", "homelab")
    text = notifiers.format_report([f for _, f in fresh], source=source)
    sent = notifiers.dispatch(cfg["notifiers"], text)
    if sent == 0:
        # Do NOT advance state and do NOT mark findings as reported: the same
        # findings must regenerate next run, and systemd must see a failed unit.
        log.error("alert NOT delivered — state not advanced, will retry next run")
        sys.exit(1)

    for key, _ in fresh:
        reported[key] = now
    save_reported(reported_path, reported)
    _save_or_log(state_file, snapshot)


if __name__ == "__main__":
    main()
