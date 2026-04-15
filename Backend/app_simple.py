from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import threading
import time
from datetime import datetime
from collections import defaultdict
import psutil
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP

app = Flask(__name__, static_folder='../Frontend')
CORS(app)

capturing = False
results = []
flow_stats = defaultdict(lambda: {'start': time.time(), 'pkts_fwd': 0, 'bytes_fwd': 0, 'pkts_bwd': 0, 'bytes_bwd': 0, 'duration': 0})

@app.route('/')
def status():
    return jsonify({'status': 'Live NIDS ready', 'capturing': capturing})

@app.route('/interfaces')
def get_interfaces():
    interfaces = []
    try:
        for iface in psutil.net_if_addrs():
            if 'lo' not in iface.lower():
                interfaces.append(iface)
    except:
        interfaces = ['Wi-Fi', 'Ethernet', 'Local Area Connection']  # dummy if fail
    return jsonify({'interfaces': interfaces})

@app.route('/start', methods=['POST'])
def start_capture():
    global capturing
    if capturing:
        return jsonify({'error': 'Already capturing'}), 400
    iface = request.json.get('iface', 'eth0')
    capturing = True
    flow_stats.clear()
    threading.Thread(target=capture_loop, args=(iface,), daemon=True).start()
    return jsonify({'status': 'started', 'iface': iface})

def capture_loop(iface):
    global capturing, results
    while capturing:
        try:
            pkts
