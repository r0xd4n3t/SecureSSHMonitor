import os
import re
import time
import logging
from datetime import datetime
from pathlib import Path
import socket
import fcntl
import atexit
import requests

class SSHLoginMonitor:
    def __init__(self, log_path, bot_token, chat_id, message_thread_id, ssh_log_path, lockfile):
        self.log_path = log_path
        self.BOT_TOKEN = bot_token
        self.CHAT_ID = chat_id
        self.MESSAGE_THREAD_ID = message_thread_id
        self.SSH_LOG_PATH = ssh_log_path
        self.lockfile = lockfile
        self.last_alert_time = None
        self.hostname = socket.gethostname()
        self.failed_login_attempts = {}
        self.setup_logging()
        self.create_lock_file()

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
        try:
            fcntl.flock(self.lockfile_handle, fcntl.LOCK_UN)
            self.lockfile_handle.close()
            os.remove(self.lockfile)
            logging.info("Lock file cleaned up successfully.")
        except Exception as e:
            logging.error(f"Failed to clean up lock file: {str(e)}")

    def tail_file(self, file, delay=1):
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(delay)
                continue
            yield line

    def send_telegram_message(self, message):
        url = f'https://api.telegram.org/bot{self.BOT_TOKEN}/sendMessage'
        data = {'chat_id': self.CHAT_ID, 'message_thread_id': self.MESSAGE_THREAD_ID, 'text': message}
        try:
            response = requests.post(url, data=data)
            response.raise_for_status()
            logging.info(f"Message sent to Telegram: {message}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to send message to Telegram: {str(e)}")

    def parse_ssh_log(self, line):
        timestamp = datetime.now().strftime("%d/%m/%Y %I:%M:%S%p")
        match_successful = re.search(r'Accepted password for (.+?) from (\S+)', line)
        match_failed = re.search(r'Failed password for (.+?) from (\S+)', line)

        if match_successful:
            login_user, login_ip = match_successful.group(1), match_successful.group(2)
            alert_message = f"⚠️ Login Alert ⚠️ Server [{self.hostname}] User [{login_user}] login from {login_ip} on {timestamp}"

            if self.last_alert_time != timestamp:
                self.send_telegram_message(alert_message)
                self.last_alert_time = timestamp

        elif match_failed:
            login_user, login_ip = match_failed.group(1), match_failed.group(2)
            self.failed_login_attempts[login_ip] = self.failed_login_attempts.get(login_ip, 0) + 1

            if self.failed_login_attempts[login_ip] >= 3:
                alert_message = f"🚨 Potential brute force attack detected from {login_ip} on server [{self.hostname}]"
                self.send_telegram_message(alert_message)
                self.failed_login_attempts[login_ip] = 0

    def monitor_ssh_log(self):
        try:
            with open(self.SSH_LOG_PATH, 'r') as log_file:
                for line in self.tail_file(log_file):
                    self.parse_ssh_log(line)
        except FileNotFoundError as e:
            logging.error(f"SSH log file not found: {str(e)}")
        except PermissionError as e:
            logging.error(f"Permission denied accessing SSH log file: {str(e)}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {str(e)}")

    def ensure_log_file_exists(self):
        log_file = Path(self.log_path)
        try:
            if not log_file.exists():
                log_file.touch()
                log_file.chmod(0o640)
                logging.info(f"Log file created: {self.log_path}")
        except PermissionError as e:
            logging.error(f"Failed to create log file: {str(e)}")

if __name__ == "__main__":
    bot_token = 'BOT_TOKEN_HERE'
    chat_id = 'GROUP_ID_HERE'
    message_thread_id = 'SUB_TOPIC_ID'
    log_path = '/root/ssh_monitor/.ssh_login_monitor.log'
    ssh_log_path = '/var/log/auth.log'
    lockfile = '/root/ssh_monitor/.ssh_login_monitor.lock'

    monitor = SSHLoginMonitor(log_path, bot_token, chat_id, message_thread_id, ssh_log_path, lockfile)

    try:
        monitor.ensure_log_file_exists()
        monitor.monitor_ssh_log()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
