#!/usr/bin/env python3
"""
clean_ufw.py – Smart UFW cleanup utility

Removes any UFW rules that allow connections from *anywhere* (i.e. the rule's
"From" column is "Anywhere" or "Anywhere (v6)") except for SSH (port 22).

Features:
1. Dry-run mode (default) so that you can see what would be removed.
2. Confirmation prompt unless --yes is supplied.
3. Works with both IPv4 and IPv6 rule listings.
4. Requires root; will automatically re-exec with sudo if necessary.

Usage examples
--------------
# See what would be deleted, without actually deleting it
sudo python3 clean_ufw.py --dry-run

# Delete the rules (you will be prompted to confirm)
sudo python3 clean_ufw.py

# Delete without a confirmation prompt
sudo python3 clean_ufw.py --yes
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from typing import List
from datetime import datetime
import time

RULE_RE = re.compile(r"^\[\s*(?P<idx>\d+)\]\s+(?P<to>.+?)\s+ALLOW IN\s+(?P<from>.+)$")
ANYWHERE_PATTERNS = ("Anywhere", "Anywhere (v6)")
SSH_PORT_PATTERN = re.compile(r"\b22(/tcp)?\b")


def ensure_root() -> None:
    """Re-exec the script with sudo if the effective UID is not root."""
    if os.geteuid() == 0:
        return
    try:
        print("[i] Elevating privileges with sudo…", file=sys.stderr)
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except FileNotFoundError:  # sudo not available or not in PATH
        sys.exit("[!] This script must be run as root.")


def parse_ufw_status() -> List[int]:
    """Return a list of rule numbers that should be removed."""
    try:
        output = subprocess.check_output(["ufw", "status", "numbered"], text=True)
    except subprocess.CalledProcessError as exc:
        sys.exit(f"[!] Failed to execute 'ufw': {exc}")

    rules_to_delete: List[int] = []
    for line in output.splitlines():
        m = RULE_RE.match(line.strip())
        if not m:
            continue  # Skip headers/blank lines
        idx = int(m["idx"])
        to_field = m["to"].strip()
        from_field = m["from"].strip()

        # Keep port 22 rules from anywhere; delete the rest
        if from_field in ANYWHERE_PATTERNS and not SSH_PORT_PATTERN.search(to_field):
            rules_to_delete.append(idx)
    return rules_to_delete


def delete_rules(rule_numbers: List[int]) -> None:
    """Delete the given rule numbers *in descending order* to keep indices stable."""
    for idx in sorted(rule_numbers, reverse=True):
        print(f"[+] Deleting rule #{idx}")
        try:
            subprocess.check_call(["ufw", "--force", "delete", str(idx)])
        except subprocess.CalledProcessError as exc:
            print(f"[!] Failed to delete rule {idx}: {exc}")


def single_cleanup(dry_run: bool, assume_yes: bool) -> None:
    """Perform a single cleanup pass."""
    rules = parse_ufw_status()
    if not rules:
        print("[i] No matching rules found. Nothing to do.")
        return

    print("[i] The following rule numbers will be deleted:", ", ".join(map(str, sorted(rules))))

    if dry_run:
        print("[i] Dry-run mode active. No changes have been made.")
        return

    if not assume_yes:
        confirm = input("Proceed with deletion? [y/N]: ").lower().strip()
        if confirm != "y":
            print("[i] Aborted by user. No changes made.")
            return

    delete_rules(rules)
    print("[✓] Cleanup completed.")


def watch_loop(interval: int, dry_run: bool, assume_yes: bool) -> None:
    """Continuously monitor UFW and delete matching rules as soon as they appear."""
    mode_msg = "continuously (no delay)" if interval == 0 else f"every {interval}s"
    print(f"[i] Entering watch mode – checking {mode_msg}. Press Ctrl+C to exit.")

    try:
        while True:
            rules = parse_ufw_status()
            if not rules:
                print("[✓] No matching 'Anywhere' rules remain. Exiting.")
                break

            # Rules present – attempt deletion
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[i] {ts}: found {len(rules)} rule(s) ->", ", ".join(map(str, rules)))
            if dry_run:
                print("[i] Dry-run mode active – would delete these rules.")
            else:

                if not assume_yes:
                    confirm = input("Proceed with deletion? [y/N]: ").lower().strip()
                    if confirm == "y":
                        delete_rules(rules)
                        deleted = True
                    else:
                        print("[i] Skipping deletion this cycle.")
                else:
                    delete_rules(rules)
                    deleted = True

            if interval > 0:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[i] Watch mode interrupted by user. Exiting.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Remove UFW 'Anywhere' rules except SSH (22/tcp)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be removed but do NOT remove it")
    parser.add_argument("--yes", "-y", action="store_true", help="Do not prompt for confirmation")
    parser.add_argument("--watch", "-w", nargs="?", const=0, type=int, metavar="SECONDS", help="Continuously monitor every SECONDS; 0 (default) = as fast as possible. If flag given without value, 0 is used.")

    args = parser.parse_args()

    ensure_root()

    if args.watch is not None:
        watch_loop(args.watch, args.dry_run, args.yes)
    else:
        single_cleanup(args.dry_run, args.yes)


if __name__ == "__main__":
    main()
