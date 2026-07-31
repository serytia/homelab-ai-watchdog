"""Collect a compact snapshot of a Proxmox cluster: nodes, guests, storage, recent tasks."""

from proxmoxer import ProxmoxAPI

TASK_LIMIT = 20


def _pct(used, total):
    if used is None or not total:
        return None
    return round(100.0 * used / total, 1)


def connect(cfg):
    if not cfg.get("verify_ssl", False):
        # Self-signed PVE certs are the norm in homelabs; without this every
        # run spams an InsecureRequestWarning into the journal.
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return ProxmoxAPI(
        cfg["host"],
        port=cfg.get("port", 8006),
        user=cfg["user"],
        token_name=cfg["token_name"],
        token_value=cfg["token_value"],
        verify_ssl=cfg.get("verify_ssl", False),
    )


def collect(cfg):
    """Return a JSON-serializable snapshot, trimmed to what triage needs."""
    px = connect(cfg)
    snapshot = {"nodes": [], "guests": [], "storage": [], "recent_tasks": []}

    for node in px.nodes.get():
        name = node["node"]
        if node.get("status") != "online":
            snapshot["nodes"].append({"node": name, "status": node.get("status", "unknown")})
            continue

        status = px.nodes(name).status.get()
        mem, root = status.get("memory", {}), status.get("rootfs", {})
        snapshot["nodes"].append({
            "node": name,
            "status": "online",
            "uptime_h": round(status.get("uptime", 0) / 3600, 1),
            "cpu_pct": round(100.0 * status.get("cpu", 0), 1),
            "mem_pct": _pct(mem.get("used"), mem.get("total")),
            "rootfs_pct": _pct(root.get("used"), root.get("total")),
            "loadavg": status.get("loadavg"),
        })

        for kind in ("qemu", "lxc"):
            for guest in getattr(px.nodes(name), kind).get():
                # PVE reports disk=0 for QEMU VMs without a guest agent — that
                # is "unknown", not "0% full"; don't feed it to triage as fact.
                disk = guest.get("disk")
                snapshot["guests"].append({
                    "node": name,
                    "type": kind,
                    "vmid": guest.get("vmid"),
                    "name": guest.get("name"),
                    "status": guest.get("status"),
                    "uptime_h": round(guest.get("uptime", 0) / 3600, 1),
                    "cpu_pct": round(100.0 * guest.get("cpu", 0), 1),
                    "mem_pct": _pct(guest.get("mem"), guest.get("maxmem")),
                    "disk_pct": _pct(disk, guest.get("maxdisk")) if disk else None,
                })

        for store in px.nodes(name).storage.get():
            snapshot["storage"].append({
                "node": name,
                "storage": store.get("storage"),
                "type": store.get("type"),
                "active": store.get("active"),
                "used_pct": _pct(store.get("used"), store.get("total")),
            })

        # The task log is where problems leave footprints: backups, migrations, snapshots.
        for task in px.nodes(name).tasks.get(limit=TASK_LIMIT):
            snapshot["recent_tasks"].append({
                "node": name,
                "type": task.get("type"),
                "id": task.get("id"),
                "user": task.get("user"),
                "starttime": task.get("starttime"),
                "duration_s": (task["endtime"] - task["starttime"])
                if task.get("endtime") and task.get("starttime") else None,
                "status": task.get("status"),
            })

    return snapshot
