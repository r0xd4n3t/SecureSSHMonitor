# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2025-04-25

### 🚀 Added
- Persistent IP ban tracking using SQLite database (`bans.db`)
- Automatic unban logic for expired IP bans
- Real-time SSH log monitoring using `watchdog`
- Telegram alerts include `Server: [hostname]` for multi-server environments
- Duplicate ban prevention using `is_already_banned()`
- IP validation using Python’s `ipaddress` module
- Full systemd support and guide for background service setup
- Compatibility with `iptables-persistent` to preserve bans across reboots
- `requirements.txt` with `requests` and `watchdog`
- Updated `README.md` with full instructions and screenshots

### 🔁 Changed
- Replaced in-memory ban tracking and `Timer()` with persistent SQLite + looped unban checks
- Improved log parsing and error handling
- Log output now includes structured entries with consistent timestamping

---

## [1.0.0] - 2024-05-20

### 🎉 Initial Release
- SSH login monitor with in-memory brute force detection
- Telegram alerting for successful and failed SSH logins
- Randomized IP ban durations (1–30 days)
- `iptables` and `ip6tables` support
- Periodic check for unbanning IPs using `threading.Timer`
- Log file and lock file management
