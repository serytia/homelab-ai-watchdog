"""Ask Claude whether anything in the snapshot is abnormal. Structured output, JSON guaranteed."""

import json
import logging

import anthropic

log = logging.getLogger("watchdog.triage")

# Guard against huge clusters blowing past the model's context window.
MAX_PAYLOAD_CHARS = 300_000

# The schema is enforced server-side (structured outputs), so the response is
# always valid JSON matching this shape — no fragile parsing.
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "warning", "critical"]},
                    "title": {"type": "string"},
                    "detail": {"type": "string"},
                    "suggested_action": {"type": "string"},
                },
                "required": ["id", "severity", "title", "detail", "suggested_action"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

# The system prompt is the whole design: an agent that is allowed to say
# "nothing to report" is an agent you can trust when it does speak.
SYSTEM_PROMPT = """You are a homelab watchdog. You receive a JSON snapshot of a Proxmox \
cluster (nodes, guests, storage, recent tasks) and, when available, the previous snapshot \
for comparison.

Report ONLY genuine anomalies:
- failed or errored tasks (backups, migrations, snapshots)
- degraded states: stopped guests that were running before, offline nodes, inactive storage
- resources trending toward exhaustion (disk/rootfs > 85%, sustained high memory)
- meaningful changes since the previous snapshot (task duration doubling, uptime reset = \
unexpected reboot)

Do NOT report: normal operation, guests already stopped in the previous snapshot, \
minor fluctuations. But a guest (VM or container) that was RUNNING in the previous \
snapshot and is now stopped is ALWAYS a finding — never assume an observed stop was \
expected.
If everything is fine, return an empty findings list. Severity: "critical" = data or \
availability at risk now; "warning" = needs attention soon; "info" = worth knowing.
Suggested actions must be a single safe shell command or a one-line manual step, never \
destructive without saying so.

Each finding carries an "id": a short stable kebab-case identifier derived from the \
UNDERLYING issue, not its wording — e.g. the failing task id ("vzdump-999999-failed"), \
"apt-update-failures", "rootfs-trending-full-pve". The same ongoing issue MUST produce \
the same id on every run, so repeated alerts can be deduplicated."""

DEEP_PROMPT = """You are a senior sysadmin. For each finding below from a Proxmox homelab, \
give a sharper root-cause hypothesis and a concrete fix, using the snapshot as evidence. \
Keep each diagnosis to 2-3 sentences. Return the same findings structure with improved \
detail and suggested_action fields."""


class TriageError(Exception):
    pass


def _call(client, model, system, payload_text, max_tokens=2000):
    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": payload_text}],
        output_config={"format": {"type": "json_schema", "schema": FINDINGS_SCHEMA}},
    )
    if response.stop_reason == "refusal":
        raise TriageError("model declined the request (stop_reason=refusal)")
    if response.stop_reason == "max_tokens":
        raise TriageError("triage output truncated (max_tokens hit)")
    # Models with thinking enabled (e.g. claude-opus-5 as deep_model) put a
    # thinking block before the text block — never index content[0] blindly.
    text = next((b.text for b in response.content if b.type == "text"), None)
    if text is None:
        raise TriageError("no text block in model response")
    return json.loads(text)["findings"]


def triage(cfg, snapshot, previous=None):
    """Return a list of findings dicts (possibly empty)."""
    client = anthropic.Anthropic(api_key=cfg.get("api_key") or None)

    payload = {"current": snapshot}
    if previous:
        payload["previous"] = previous
    payload_text = json.dumps(payload, separators=(",", ":"))
    if len(payload_text) > MAX_PAYLOAD_CHARS:
        log.warning("payload too large (%d chars) — dropping previous snapshot", len(payload_text))
        payload_text = json.dumps({"current": snapshot}, separators=(",", ":"))
        if len(payload_text) > MAX_PAYLOAD_CHARS:
            raise TriageError(f"snapshot too large for triage ({len(payload_text)} chars)")

    findings = _call(client, cfg.get("model", "claude-haiku-4-5"), SYSTEM_PROMPT, payload_text)

    # Optional second pass: cheap eyes found something, smart brain diagnoses it.
    # The deep pass may only ENRICH findings (detail, suggested_action) — it can
    # never drop, downgrade or add alerts, so a bad second pass costs nothing.
    deep_model = cfg.get("deep_model")
    if findings and deep_model:
        deep_payload = json.dumps({"findings": findings, "snapshot": snapshot},
                                  separators=(",", ":"))
        try:
            deep = _call(client, deep_model, DEEP_PROMPT, deep_payload, max_tokens=3000)
            # Match enrichments by stable id, never by position: a reordered
            # deep response must not cross-wire details between findings.
            by_id = {d.get("id"): d for d in deep}
            findings = [
                {**f, "detail": by_id[f["id"]]["detail"],
                 "suggested_action": by_id[f["id"]]["suggested_action"]}
                if f.get("id") in by_id else f
                for f in findings
            ]
        except (TriageError, anthropic.APIError) as exc:
            log.warning("deep pass failed, keeping first-pass findings: %s", exc)

    return findings
