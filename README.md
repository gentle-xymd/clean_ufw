# clean_ufw.py – Automatic UFW "Anywhere" Rule Cleanup

`clean_ufw.py` is a tiny utility that keeps your Ubuntu firewall (UFW) tidy:

* Deletes **all** rules that allow traffic from `Anywhere` or `Anywhere (v6)` except for **SSH (22/tcp)**.
* Can run once or watch continuously.
* Handles both IPv4 and IPv6.
* Re-executes itself with `sudo` if required.

---

## Features

| Feature | Description |
|---------|-------------|
| **Dry-run** | `--dry-run` shows what would be deleted without touching the firewall |
| **Non-interactive** | `--yes` answers *Yes* to all prompts – perfect for cron |
| **Watch mode** | `--watch [SEC]` keeps checking until no matching rules remain; `--watch` alone means "check as fast as possible" |
| **Safe deletes** | Rules are removed in descending order so numbering stays valid |

---

## Installation

```bash
# Clone or copy the script somewhere, then make it executable
chmod +x clean_ufw.py
# (Optional) create a virtualenv & install nothing – the script uses only stdlib
```

No external Python packages are required.

---

## Usage

### One-off cleanup (interactive)
```bash
sudo ./clean_ufw.py
```

### One-off cleanup (no prompt)
```bash
sudo ./clean_ufw.py --yes
```

### Dry-run (no changes)
```bash
sudo ./clean_ufw.py --dry-run
```

### Continuous watch until clean
```bash
sudo ./clean_ufw.py --watch       # check as fast as possible
sudo ./clean_ufw.py --watch 10    # check every 10 seconds
```

Combine flags freely, e.g. `--watch --yes` for unattended operation.

---

## Example Cron Job

Run every day at 03:15, first updating Cloudflare IP ranges, then cleaning UFW; log output to `/var/log/cloudflare-ufw.log`:

```cron
15 3 * * * /bin/sh /home/miteldream/cloudflare-ufw.sh && \
           /usr/bin/python3 /home/miteldream/clean_ufw.py --yes >> /var/log/cloudflare-ufw.log 2>&1
```
## create cron job with this command:

**15 3 * * * /bin/sh /home/miteldream/cloudflare-ufw.sh && /usr/bin/python3 /home/miteldream/clean_ufw.py >> /var/log/cloudflare-ufw.log 2>&1**

**What it means**
* `15 3 * * *` – run at **03:15 AM every day** (minute 15, hour 3, any day-of-month, any month, any weekday).
* First command: `/bin/sh /home/miteldream/cloudflare-ufw.sh`
  * Typically downloads the latest Cloudflare IP ranges and inserts them into UFW.
* `&&` ensures the second command only runs if the first succeeds.
* Second command: `/usr/bin/python3 /home/miteldream/clean_ufw.py --yes`
  * Executes this cleanup script in non-interactive mode, deleting any leftover `Anywhere` rules.
* `>> /var/log/cloudflare-ufw.log 2>&1` appends both stdout and stderr from the *whole pipeline* to a log file for auditing.

---

## Contributing
Pull requests & issues are welcome. Please run `shellcheck`/`flake8` before submitting.

---

## License
MIT License – see `LICENSE` (create if you need one).
