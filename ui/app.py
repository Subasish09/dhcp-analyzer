# app.py
from flask import Flask, render_template, jsonify
import json
import os

EVENT_FILE = os.path.join(os.path.dirname(__file__), "..", "events.log")

app = Flask(__name__, template_folder='templates', static_folder='static')

def tail_events(n=200):
    events = []
    if not os.path.exists(EVENT_FILE):
        return events
    with open(EVENT_FILE, 'r') as f:
        lines = f.readlines()[-n:]
        for L in lines:
            L = L.strip()
            if not L: continue
            try:
                obj = json.loads(L)
                events.append(obj)
            except:
                continue
    return events

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/events")
def api_events():
    ev = tail_events(500)
    return jsonify(ev)

if __name__ == "__main__":
    app.run(debug=True, port=5000)

