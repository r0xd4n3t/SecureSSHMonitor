import os
import re
import time
import logging
import random
import socket
import ipaddress
import requests
import subprocess
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import fcntl
import atexit
import signal

DB_FILE = '/root/.ssh_monitor/bans.db'

class SSHLoginMonitor:
    def __init__(self, log_path, bot_token, chat_id, message_thread_id, ssh_log_path, lockfile):
        self.log_path = log_path
        self.BOT_TOKEN = bot_token
        self.CHAT_ID = chat_id
        self.MESSAGE_THREAD_ID = message_thread_id
        self.SSH_LOG_PATH = ssh_log_path
        self.lockfile = lockfile
        self.hostname = socket.gethostname()
        self.failed_login_attempts = {}
        self.lockfile_handle = None
        self.observer = None
        self.setup_logging()
        logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)
        self.create_lock_file()
        self.init_db()
        self.register_signals()
        self.load_existing_bans()

    def setup_logging(self):
        logging.basicConfig(
            filename=self.log_path,
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)
    
        # Silence noisy libraries:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("watchdog.observers.inotify_buffer").setLevel(logging.WARNING)

    def create_lock_file(self):
        if os.path.exists(self.lockfile):
            logging.error("Script is already running.")
            exit(1)
        self.lockfile_handle = open(self.lockfile, "w")
        try:
            fcntl.flock(self.lockfile_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logging.error("Another instance is already running.")
            exit(1)
        atexit.register(self.cleanup_lock_file)

    def cleanup_lock_file(self):
        if self.lockfile_handle:
            try:
                fcntl.flock(self.lockfile_handle, fcntl.LOCK_UN)
                self.lockfile_handle.close()
                os.remove(self.lockfile)
                logging.info("Lock file cleaned up successfully.")
            except Exception as e:
                logging.error(f"Failed to clean up lock file: {str(e)}")
            finally:
                self.lockfile_handle = None

    def register_signals(self):
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)

    def handle_signal(self, signum, frame):
        logging.info(f"Received termination signal {signum}")
        self.stop_observer()
        self.cleanup_lock_file()
        exit(0)

    def init_db(self):
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bans (
                    ip TEXT PRIMARY KEY,
                    banned_at TEXT,
                    ban_until TEXT
                )
            """)
            conn.commit()

    def load_existing_bans(self):
        now = datetime.now()
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, ban_until FROM bans")
            for ip, ban_until_str in cursor.fetchall():
                ban_until = datetime.fromisoformat(ban_until_str)
                if now >= ban_until:
                    self.unban_ip(ip)
                else:
                    remaining = ban_until - now
                    human_until = ban_until.strftime("%B %d, %Y at %I:%M %p")
                    days = remaining.days
                    hours = remaining.seconds // 3600
                    mins = (remaining.seconds % 3600) // 60
                    time_left = f"{days}d {hours}h {mins}m" if days > 0 else f"{hours}h {mins}m"
                    logging.info(f"🔒 IP {ip} is still banned until {human_until} (⏳ {time_left} left)")

    def check_unban_expired(self):
        now = datetime.now()
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, ban_until FROM bans")
            for ip, ban_until_str in cursor.fetchall():
                ban_until = datetime.fromisoformat(ban_until_str)
                if now >= ban_until:
                    self.unban_ip(ip)

    def send_telegram_message(self, message):
        url = f'https://api.telegram.org/bot{self.BOT_TOKEN}/sendMessage'
        data = {'chat_id': self.CHAT_ID, 'message_thread_id': self.MESSAGE_THREAD_ID, 'text': message}
        try:
            requests.post(url, data=data, timeout=10)
        except Exception as e:
            logging.error(f"Telegram error: {e}")
        time.sleep(1.5)

    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def is_already_banned(self, ip):
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM bans WHERE ip = ?", (ip,))
            return cur.fetchone() is not None

    def ban_ip(self, ip):
        if not self.is_valid_ip(ip) or self.is_already_banned(ip):
            return

        ban_days = random.randint(1, 30)
        banned_at = datetime.now()
        ban_until = banned_at + timedelta(days=ban_days)

        is_ipv6 = ':' in ip
        ban_cmd = f"ip6tables -A INPUT -s {ip} -j DROP" if is_ipv6 else f"iptables -A INPUT -s {ip} -j DROP"

        try:
            subprocess.run(ban_cmd, shell=True, check=True)
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("INSERT INTO bans (ip, banned_at, ban_until) VALUES (?, ?, ?)",
                             (ip, banned_at.isoformat(), ban_until.isoformat()))
                conn.commit()
            logging.info(f"IP {ip} banned for {ban_days} days")
            self.send_telegram_message(
                f"Server: [{self.hostname}] 🚫 IP [{ip}] banned for [{ban_days}] day(s)."
            )
        except subprocess.CalledProcessError as e:
            logging.error(f"Ban failed: {e}")

    def unban_ip(self, ip):
        is_ipv6 = ':' in ip
        unban_cmd = f"ip6tables -D INPUT -s {ip} -j DROP" if is_ipv6 else f"iptables -D INPUT -s {ip} -j DROP"
    
        try:
            subprocess.run(unban_cmd, shell=True, check=True)
    
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT banned_at, ban_until FROM bans WHERE ip = ?", (ip,))
                row = cursor.fetchone()
    
                if row:
                    banned_at = datetime.fromisoformat(row[0])
                    ban_until = datetime.fromisoformat(row[1])
                    duration_days = (ban_until - banned_at).days
                    conn.execute("DELETE FROM bans WHERE ip = ?", (ip,))
                    conn.commit()
    
                    logging.info(f"IP {ip} unbanned (Duration: {duration_days} days)")
                    self.send_telegram_message(
                        f"Server: [{self.hostname}] ✅ IP [{ip}] unbanned (Ban Duration : [{duration_days}] day(s))."
                    )
                else:
                    logging.warning(f"IP {ip} unbanned but not found in DB.")
    
        except subprocess.CalledProcessError as e:
            logging.error(f"Unban failed for {ip}: {e}")

    def parse_ssh_log(self, line):
        ip_regex = r'(\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b)'
        match_success = re.search(rf'Accepted password for (.+?) from {ip_regex}', line)
        match_failed = re.search(rf'Failed password for (.+?) from {ip_regex}', line)

        if match_success:
            user, ip = match_success.group(1), match_success.group(2)
            if self.is_valid_ip(ip):
                key = f"{user}@{ip}"
                now = datetime.now()
        
                # Only alert again if more than 15 minutes since last success from same user@ip
                if not hasattr(self, 'last_success_logins'):
                    self.last_success_logins = {}
        
                last_seen = self.last_success_logins.get(key)
                if not last_seen or (now - last_seen).total_seconds() > 900:  # 15 minutes
                    self.send_telegram_message(
                        f"Server: [{self.hostname}] ⚠️ Login success: [{user}] from [{ip}]"
                    )
                    self.last_success_logins[key] = now

        elif match_failed:
            user, ip = match_failed.group(1), match_failed.group(2)
            if self.is_valid_ip(ip):
        
                # ✅ Skip banned IPs
                if self.is_already_banned(ip):
                    return
        
                self.failed_login_attempts[ip] = self.failed_login_attempts.get(ip, 0) + 1
        
                if self.failed_login_attempts[ip] >= 3:
                    self.send_telegram_message(
                        f"Server: [{self.hostname}] 🚨 Brute force alert: {ip} triggered 3 failed attempts!"
                    )
                    self.ban_ip(ip)
                    self.failed_login_attempts[ip] = 0

    def on_modified(self, event):
        if event.src_path == self.SSH_LOG_PATH:
            try:
                with open(event.src_path, "r") as f:
                    lines = f.readlines()[-10:]
                    for line in lines:
                        self.parse_ssh_log(line)
            except Exception as e:
                logging.error(f"Log read failed: {str(e)}")

    def start_watchdog(self):
        event_handler = PatternMatchingEventHandler(patterns=[self.SSH_LOG_PATH])
        event_handler.on_modified = self.on_modified
        self.observer = Observer()
        self.observer.schedule(event_handler, path=os.path.dirname(self.SSH_LOG_PATH), recursive=False)
        self.observer.start()
        logging.info("Started SSH log observer.")

    def stop_observer(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

    def ensure_log_file_exists(self):
        log_file = Path(self.log_path)
        if not log_file.exists():
            try:
                log_file.touch()
                log_file.chmod(0o640)
                logging.info(f"Log file created: {self.log_path}")
            except PermissionError as e:
                logging.error(f"Failed to create log file: {str(e)}")

if __name__ == "__main__":
    bot_token = 'BOT_TOKEN_HERE'
    chat_id = 'GROUP_ID_HERE'
    message_thread_id = 'SUB_TOPIC_ID'
    log_path = '/root/.ssh_monitor/.ssh_login_monitor.log'
    ssh_log_path = '/var/log/auth.log'
    lockfile = '/root/.ssh_monitor/.ssh_login_monitor.lock'

    monitor = SSHLoginMonitor(log_path, bot_token, chat_id, message_thread_id, ssh_log_path, lockfile)
    monitor.ensure_log_file_exists()
    monitor.start_watchdog()

    try:
        while True:
            monitor.check_unban_expired()
            time.sleep(60)
    except KeyboardInterrupt:
        monitor.handle_signal(signal.SIGINT, None)
