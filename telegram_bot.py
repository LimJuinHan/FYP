"""
Telegram bot module for sending alerts and processing updates.
"""
import requests
import time
import re
import os
import threading
from ids_runner import alert_queue
from config import TELEGRAM_API_URL, PHONE_FILE, ALERT_COOLDOWN

class TelegramBot:
    """Class for managing Telegram bot functionality."""
    
    def __init__(self):
        """Initialize the Telegram bot."""
        self.alert_cache = {}  # key: alert_key, value: {'count': int, 'last_time': float}
        self.phone_chat_map = {}
        self.chat_id_var = {"chat_id": None}
        
        # Load existing mappings
        if os.path.exists(PHONE_FILE):
            with open(PHONE_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        phone, chat_id = line.split(",")
                        self.phone_chat_map[phone] = int(chat_id)
    
    def save_phone_to_file(self, phone, chat_id):
        """Append a new phone→chat mapping to file."""
        with open(PHONE_FILE, "a") as f:
            f.write(f"{phone},{chat_id}\n")
        self.phone_chat_map[phone] = chat_id
    
    def get_phone_chat_id(self, phone_number):
        """Return chat ID if phone number exists, else None."""
        try:
            with open(PHONE_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    phone, chat_id = line.split(",")
                    if phone == phone_number:
                        return chat_id
            return None
        except FileNotFoundError:
            return None
    
    def set_chat_id(self, chat_id):
        """Set the current chat ID for alerts."""
        self.chat_id_var["chat_id"] = chat_id
    
    def get_chat_id(self):
        """Get the current chat ID for alerts."""
        return self.chat_id_var["chat_id"]
    
    def send_message(self, chat_id, text):
        """Send a message to the specified chat ID."""
        payload = {"chat_id": chat_id, "text": text}
        try:
            resp = requests.post(f"{TELEGRAM_API_URL}/sendMessage", json=payload, timeout=5)
            print(f"[Telegram] Response: {resp.json()}")
        except Exception as e:
            print(f"[Telegram] Failed to send message: {e}")
    
    def make_alert_key(self, alert):
        """Generate a key to identify duplicate alerts (for fatigue mitigation)."""
        src_ip = alert['src'].split(":")[0]
        dst_ip = alert['dst'].split(":")[0]
        signature = alert['message'].split("(")[0].strip()
        return f"{src_ip}->{dst_ip}-{alert['severity']}-{signature}"
    
    def alert_sender(self):
        """Thread to send IDS alerts to Telegram."""
        while True:
            try:
                alert = alert_queue.get(timeout=1)
                print(f"[DEBUG] Got alert from queue: {alert}")
            except Exception:
                time.sleep(0.5)
                continue

            chat_id = self.chat_id_var["chat_id"]  # <- always get the latest value
            if chat_id is None:
                print("[DEBUG] chat_id_var['chat_id'] is None, skipping alert")
                continue  # no verified chat ID yet

            key = self.make_alert_key(alert)
            now = time.time()

            cache_entry = self.alert_cache.get(key)
            if cache_entry and (now - cache_entry['last_time'] < ALERT_COOLDOWN):
                cache_entry['count'] += 1
                cache_entry['last_time'] = now
                print(f"[DEBUG] Alert key {key} in cooldown, skipping")
                continue
            else:
                self.alert_cache[key] = {'count': 1, 'last_time': now}

            msg = (
                f"[{alert['severity']}] {alert['message']}\n"
                f"{alert['src']} → {alert['dst']}\n"
                f"Time: {alert['time']}"
            )
            print(f"[DEBUG] Sending alert to chat_id {chat_id}: {msg}")
            self.send_message(chat_id, msg)
    
    def process_updates(self):
        """Thread to process Telegram updates."""
        offset = None
        phone_pattern = re.compile(r"^01\d{8,9}$")  # Malaysian phone numbers

        while True:
            try:
                resp = requests.get(
                    f"{TELEGRAM_API_URL}/getUpdates",
                    params={"offset": offset, "timeout": 20},
                    timeout=30
                )
                data = resp.json()

                if not data.get("ok"):
                    continue

                for update in data.get("result", []):
                    offset = update["update_id"] + 1
                    msg = update.get("message")
                    if not msg or "text" not in msg:
                        continue

                    chat_id = msg["chat"]["id"]
                    text = msg["text"].strip()

                    if text.lower() == "/start":
                        self.send_message(chat_id, "Welcome!\nPlease type your phone number:")
                    else:
                        if phone_pattern.match(text):
                            self.phone_chat_map[text] = chat_id
                            self.save_phone_to_file(text, chat_id)
                            self.send_message(chat_id, f"Thanks! Phone {text} registered.")
                            print(f"Mapped phone {text} → chat {chat_id}")
                        else:
                            self.send_message(chat_id, "Invalid phone number format. Please try again.")

            except Exception as e:
                print(f"Error in update loop: {e}")
                time.sleep(5)
    
    def start_bot(self):
        """Start Telegram alert sender and update processor in background threads."""
        print("Starting Telegram bot...")

        # Start alert sender thread
        threading.Thread(target=self.alert_sender, daemon=True).start()

        # Start update polling thread
        threading.Thread(target=self.process_updates, daemon=True).start()