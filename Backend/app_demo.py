from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import time
from datetime import datetime
import threading

app = Flask(__name__)
CORS(app)

capturing = False
results = []

@app.route('/')
def status():
    return jsonify({'status': 'Demo NIDS ready', 'capturing': capturing})

@app.route('/interfaces')
def get_interfaces():
    return jsonify({'interfaces': ['Wi-Fi', 'Ethernet', 'Local Area Connection']})

@app.route('/start', methods=['POST'])
def start_capture():
    global capturing
    if capturing:
        return jsonify({'error': 'Already capturing'}), 400
    iface = request.json.get('iface')
    capturing
