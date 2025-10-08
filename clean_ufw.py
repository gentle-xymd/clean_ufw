#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from typing import List

RULE_RE = re.compile(
    r"^\[\s*(?P<idx>\d+)\]\s+(?P<to>.+?)\s+(?P<action>ALLOW|DENY)\s+(?P<dir>IN|OUT)\s+(?P<from>.+)$"
)
ANYWHERE_PATTERNS = ("Anywhere", "Anywhere (v6)")
SSH_PORT_PATTERN = re.compile(r"\b22(?:/tcp)?\b")
PROTECTED_DENY_PORTS = {
    "21/tcp", "25/tcp", "3306/tcp", "33060/tcp", "6081/tcp", "20201/tcp", "20202/tcp",
}

def ensure_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return
    try:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except FileNotFoundError:
        sys.exit("[!] This script must be run as root.")

def find_ufw() -> str:
    for candidate in (shutil.which("ufw"), "/usr/sbin/ufw", "/sbin/ufw"):
        if candidate and os.path.exists(candidate):
            return candidate
    sys.exit("[!] 'ufw' not found. Is UFW installed?")

def parse_ufw_status(ufw_bin: str, warn_protected: bool = False) -> List[int]:
    try:
        output = subprocess.check_output([ufw_bin, "status", "numbered"], text=True)
    except subprocess.CalledProcessError as exc:
        sys.exit(f"[!] Failed to execute 'ufw': {exc}")

    rules_to_delete: List[int] = []
    for raw in output.splitlines():
        m = RULE_RE.match(raw.strip())
        if not m:
            continue

        idx = int(m["idx"])
        to_field = m["to"].strip()
        action = m["action"].strip()
        direction = m["dir"].strip()
        from_field = m["from"].strip()

        # Only touch ALLOW IN rules from Anywhere / Anywhere (v6)
        if action != "ALLOW" or direction != "IN" or from_field not in ANYWHERE_PATTERNS:
            continue

        # Keep ALLOW 22/tcp from Anywhere (SSH)
        if SSH_PORT_PATTERN.search(to_field):
            continue

        # Optional warning if a protected port is ALLOWed (we will delete it anyway)
        if warn_protected:
            leading = to_field.split()[0]
            if leading in PROTECTED_DENY_PORTS:
                print(f"[!] ALLOW found for protected port (will delete): {to_field}")

        rules_to_delete.append(idx)

    return rules_to_delete

def delete_rules(ufw_bin: str, rule_numbers: List[int]) -> None:
    for idx in sorted(rule_numbers, reverse=True):
        try:
            subprocess.check_call([ufw_bin, "--force", "delete", str(idx)])
            print(f"[✓] Deleted rule #{idx}")
        except subprocess.CalledProcessError as exc:
            print(f"[!] Failed to delete rule {idx}: {exc}")

def enforce_once(ufw_bin: str, dry_run: bool) -> None:
    rules = parse_ufw_status(ufw_bin)
    if not rules:
        print("[i] No matching rules found.")
        return
    print("[i] Targeted for deletion:", ", ".join(map(str, sorted(rules))))
    if dry_run:
        print("[i] Dry-run. No changes made.")
        return
    delete_rules(ufw_bin, rules)

def watch_loop(ufw_bin: str, interval: int, dry_run: bool) -> None:
    print(f"[i] Watch mode every {interval}s. Ctrl+C to exit.")
    try:
        while True:
            rules = parse_ufw_status(ufw_bin)
            if rules:
                print("[i] Targeted:", ", ".join(map(str, sorted(rules))))
                if not dry_run:
                    delete_rules(ufw_bin, rules)
                else:
                    print("[i] Dry-run. Would delete above.")
            else:
                print("[i] Nothing to delete.")
            if interval <= 0:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[i] Exiting watch.")

def main() -> None:
    p = argparse.ArgumentParser(description="Immediately delete ALLOW-from-Anywhere UFW rules except SSH (22/tcp).")
    p.add_argument("--dry-run", action="store_true", help="Preview only (no changes)")
    p.add_argument("--watch", "-w", nargs="?", const=5, type=int, metavar="SECONDS",
                   help="Continuously enforce every SECONDS (default 5s if flag given without value)")
    args = p.parse_args()

    ensure_root()
    ufw_bin = find_ufw()

    if args.watch is not None:
        watch_loop(ufw_bin, args.watch, args.dry_run)
    else:
        enforce_once(ufw_bin, args.dry_run)

if __name__ == "__main__":
    main()
