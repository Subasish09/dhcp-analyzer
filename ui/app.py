# app.py
from flask import Flask, render_template, jsonify
import json
import os
import time

# -----------------------------
# Paths (absolute, safe)
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DHCP_LOG = os.path.join(BASE_DIR, "..", "events.log")
ARP_LOG  = os.path.join(BASE_DIR, "..", "arp_events.log")

OUI_DB = {}
OUI_FILE = os.path.join(BASE_DIR, "..", "oui.txt")

# -----------------------------
# Oui lookup
# -----------------------------
def load_oui_db():
    if not os.path.exists(OUI_FILE):
        return

    with open(OUI_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(None, 1)
            if len(parts) != 2:
                continue

            prefix, vendor = parts
            OUI_DB[prefix.upper()] = vendor


def lookup_vendor(mac):
    if not mac or len(mac) < 8:
        return "-"

    prefix = mac.upper()[0:8]  # XX:XX:XX
    return OUI_DB.get(prefix, "Unknown")


# -----------------------------
# Flask setup
# -----------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")

# MAC → device info
devices = {}

# -----------------------------
# Helpers
# -----------------------------
def tail_dhcp_events(n=500):
    events = []
    if not os.path.exists(DHCP_LOG):
        return events

    with open(DHCP_LOG, "r") as f:
        lines = f.readlines()[-n:]

    for line in lines:
        try:
            events.append(json.loads(line))
        except:
            continue

    return events


def load_dhcp_into_devices():
    if not os.path.exists(DHCP_LOG):
        return

    with open(DHCP_LOG, "r") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except:
                continue

            mac = ev.get("mac")
            if not mac:
                continue

            devices.setdefault(mac, {})

            # hostname (option 12 / 81)
            if "hostname" in ev:
                devices[mac]["hostname"] = ev["hostname"]

            # assigned IP
            yi = ev.get("yiaddr")
            if yi and yi != "0.0.0.0":
                devices[mac]["ip"] = yi

            devices[mac]["last_seen"] = time.time()


def load_arp_into_devices():
    if not os.path.exists(ARP_LOG):
        return

    with open(ARP_LOG, "r") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except:
                continue

            mac = ev.get("mac")
            ip  = ev.get("ip")

            if not mac or not ip:
                continue

            devices.setdefault(mac, {})
            devices[mac]["ip"] = ip
            devices[mac]["last_seen"] = time.time()


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    return jsonify(tail_dhcp_events())


@app.route("/api/devices")
def api_devices():
    devices.clear()

    load_dhcp_into_devices()
    load_arp_into_devices()

    now = time.time()
    out = []

    for mac, info in devices.items():
        out.append({
            "mac": mac,
            "ip": info.get("ip", "-"),
            "hostname": info.get("hostname", "-"),
            "vendor": lookup_vendor(mac),
            "last_seen": int(now - info.get("last_seen", now))
        })


    # sort by recent activity
    out.sort(key=lambda x: x["last_seen"])

    return jsonify(out)


# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    load_oui_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
