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

"A Python-based SSH login monitoring tool that detects and alerts on successful and failed/bruteforce login attempts via Telegram."

# 📜 Introduction
This repository contains a Python script for monitoring SSH login attempts on a Linux server. 
The script detects both successful and failed login attempts and sends alerts via Telegram to a specified chat group. 
This helps in identifying unauthorized access attempts and potential brute force attacks in real-time.

> Sample alert: Potential brute force attack detection

![](https://raw.githubusercontent.com/r0xd4n3t/SecureSSHMonitor/main/img/1.png)

> Sample alert: SSH Login Alert

![](https://raw.githubusercontent.com/r0xd4n3t/SecureSSHMonitor/main/img/2.png)

## 📝 Prerequisites
Before running this script, ensure that you have the following:

- Python 3.x installed on your system
- `requests` library (`pip install requests`)
- Access to the SSH log file (`/var/log/auth.log` or equivalent)
- A Telegram bot token and chat ID for sending alerts
- Appropriate permissions to read the SSH log file and write log files

### 🔄 Installation

1. Clone this repository:
```
git clone https://github.com/r0xd4n3t/SecureSSHMonitor.git
cd ssh-login-monitor
```

2. Install the required Python package:
```
pip3.10 install requests
```

3. Update the script with your Telegram bot token, chat ID, and other necessary configurations:
```
bot_token = 'YOUR_BOT_TOKEN'
chat_id = 'YOUR_CHAT_ID'
message_thread_id = 'YOUR_MESSAGE_THREAD_ID'
log_path = '/root/ssh-login-monitor/.ssh_login_monitor.log'
ssh_log_path = '/var/log/auth.log'  # Adjust if different on your system
lockfile = '/root/ssh-login-monitor/.ssh_login_monitor.lock'
```

### ▶ Running the Script

To run the SSH login monitor script, use the following command:
```
python3.10 ssh_login_monitor.py
```
Ensure that the script has the necessary permissions to read the SSH log file and write the log and lock files.

### 🔄 Setting Up as a Service

1. Create a systemd service file:
```
nano /etc/systemd/system/ssh_login_monitor.service
```

2. Add the following content to the service file:
```
[Unit]
Description=SSH Login Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3.10 /root/ssh-login-monitor/ssh_login_monitor.py
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

3. Make the script executable:
```
chmod +x /root/ssh-login-monitor/ssh_login_monitor.py
```

4. Create the log file and set permissions:
```
touch /root/ssh-login-monitor/.ssh_login_monitor.log
chmod 644 /root/ssh-login-monitor/.ssh_login_monitor.log
chown root:root /root/ssh-login-monitor/.ssh_login_monitor.log
```

5. Reload systemd, enable and start the service:
```
systemctl daemon-reload
systemctl enable ssh-login-monitor
systemctl start ssh-login-monitor
```

## 🕹️ Log Rotation

To manage log rotation for the SSH login monitor logs, use the logrotate tool. Create a configuration file for logrotate:

1. Create a new logrotate configuration file:
```
nano /etc/logrotate.d/ssh_login_monitor
```

Add the following content:
```
/root/ssh-login-monitor/.ssh_login_monitor.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root root
    sharedscripts
    postrotate
        systemctl restart ssh-login-monitor
    endscript
}
```
This configuration rotates the logs daily, keeps 7 days of logs, compresses old logs, and restarts the service after rotation.

## **Contributions**

Contributions to SSH Login Monitor are welcome! If you find any issues or have ideas for improvements, feel free to open an issue 
or submit a pull request.

🔆 Happy Monitoring! 🔆


<p align="center"><a href=#top>Back to Top</a></p>
