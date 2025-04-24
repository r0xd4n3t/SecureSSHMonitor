<a id="top"></a>

#

<h1 align="center">
SSH Login Monitor
</h1>

<p align="center"> 
  <kbd>
<img src="https://raw.githubusercontent.com/r0xd4n3t/SecureSSHMonitor/main/img/ssh-login-monitor.jpeg"></img>
  </kbd>
</p>

<p align="center">
<img src="https://img.shields.io/github/last-commit/r0xd4n3t/SecureSSHMonitor?style=flat">
<img src="https://img.shields.io/github/stars/r0xd4n3t/SecureSSHMonitor?color=brightgreen">
<img src="https://img.shields.io/github/forks/r0xd4n3t/SecureSSHMonitor?color=brightgreen">
</p>

A Python-based SSH login monitoring tool that detects and alerts on successful and failed/bruteforce login attempts via Telegram. Includes persistent IP banning with unban logic and multi-server support.

---

## 📜 Introduction

SSH Login Monitor provides real-time protection for your Linux server by watching SSH login events:

- 🚨 Detects failed logins and brute force attempts  
- ✅ Alerts on successful logins  
- 🔐 Bans IPs using `iptables` (IPv4/IPv6 supported)  
- 🔁 Automatically unbans when the time expires  
- 💾 Stores ban history in SQLite (`bans.db`)  
- 🔔 Sends real-time Telegram alerts with hostname  
- ⚙️ Runs continuously as a systemd service  
- 💥 Supports log persistence via `iptables-persistent`

> Sample alert: Brute force detection  
> ![](https://raw.githubusercontent.com/r0xd4n3t/SecureSSHMonitor/main/img/1.png)

> Sample alert: SSH Login Notification  
> ![](https://raw.githubusercontent.com/r0xd4n3t/SecureSSHMonitor/main/img/2.png)

> Sample alert: IP Banned / Unbanned  
> ![](https://raw.githubusercontent.com/r0xd4n3t/SecureSSHMonitor/main/img/3.png)

---

## 🧰 Features

- Real-time SSH log monitoring using `watchdog`
- IP address validation (IPv4 + IPv6)
- Randomized ban durations (1 to 30 days)
- Persistent tracking of bans in SQLite
- Automatic unban of expired entries
- Duplicate ban prevention
- Telegram alerts with hostname
- Compatible with systemd and `iptables-persistent`

---

## 📝 Prerequisites

- Python 3.8+
- `iptables` and/or `ip6tables`
- `iptables-persistent` for ban persistence across reboot
- Access to `/var/log/auth.log` or equivalent SSH log
- A Telegram Bot Token and Chat ID
- Required Python packages:

```bash
pip install -r requirements.txt
```

---

## 📦 Installation

1. Clone the repository:

```bash
git clone https://github.com/r0xd4n3t/SecureSSHMonitor.git
cd SecureSSHMonitor
```
2. Install dependencies:

```bash
pip install -r requirements.txt
```
3. Create .ssh_monitor directory:

```bash
mkdir -p /root/.ssh_monitor
touch /root/.ssh_monitor/.ssh_login_monitor.log
sqlite3 /root/.ssh_monitor/bans.db "VACUUM;"
```
4. Update the script config:

Edit your Python script:

```python
bot_token = 'YOUR_BOT_TOKEN'
chat_id = 'YOUR_CHAT_ID'
message_thread_id = 'YOUR_MESSAGE_THREAD_ID'
log_path = '/root/.ssh_monitor/.ssh_login_monitor.log'
ssh_log_path = '/var/log/auth.log'
lockfile = '/root/.ssh_monitor/.ssh_login_monitor.lock'
```
---

## 📜 requirements.txt

```txt
requests
watchdog
```
Install with:

```bash
pip install -r requirements.txt
```

### ▶ Running the Script (Manual)

```bash
python3 ssh_login_monitor.py
```
### 🔄 Setting Up as a Systemd Service

1. Create the systemd service file:

```bash
nano /etc/systemd/system/ssh_login_monitor.service
```
2.Add:

```bash
[Unit]
Description=SSH Login Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/SecureSSHMonitor/ssh_login_monitor.py
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/root
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ssh_login_monitor
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
3. Enable and start:

```bash
systemctl daemon-reload
systemctl enable ssh_login_monitor
systemctl start ssh_login_monitor
```

---

### 🛡 Persistent Ban Across Reboot

Install `iptables-persistent` to preserve rules:

```bash
sudo apt install iptables-persistent
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6
```
Now, banned IPs remain blocked even after reboot.

---

## 📂 Log Rotation

```bash
nano /etc/logrotate.d/ssh_login_monitor
```
Add:

```bash
/root/.ssh_monitor/.ssh_login_monitor.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root root
    sharedscripts
    postrotate
        systemctl restart ssh_login_monitor
    endscript
}
```

## 🙌 Contributions

Feel free to fork and submit pull requests or open issues.

Stay secure. Stay notified. 🚀
Happy monitoring!

<p align="center"><a href="#top">Back to Top</a></p> 

