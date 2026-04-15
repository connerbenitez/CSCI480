from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import threading
import time
from datetime import datetime
import json
import random
import pyshark


app = Flask(__name__)
CORS(app)

capturing = False
nids_results = []


@app.route('/')
def root():
    return '''
<!DOCTYPE html>
<html>
<head>
<title>NIDS Live Test</title>
<style>
body { background: #000; color: #fff; font-family: 'Courier New', monospace; padding: 20px; }
.container { max-width: 1600px; margin: 0 auto; }
h1 { color: #fff; font-size: 24px; margin-bottom: 20px; }
.control { background: #111; padding: 20px; border: 1px solid #ccc; margin-bottom: 20px; }
button { background: #333; color: #fff; border: 1px solid #ccc; padding: 10px 20px; margin: 5px; cursor: pointer; font-family: monospace; }
button:hover:not(:disabled) { background: #555; }
button:disabled { background: #111; color: #666; }
#status { font-weight: bold; margin-top: 10px; color: #ccc; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; font-size: 12px; font-family: monospace; }
th { background: #111; color: #fff; }
.low { color: #aaa; }
.medium { color: #888; }
.high { color: #fff; font-weight: bold; }
.normal { color: #ccc; }
</style>
</head>
<body>
<div class="container">
<h1>Network IDS Live Model Testing</h1>
<div class="control">
<label>Interface:</label>
<select id="iface">
<option>Wi-Fi</option>
<option>Ethernet</option>
</select>
<button id="startBtn" onclick="startTest()">START</button>
<button id="stopBtn" onclick="stopTest()" disabled>STOP</button>
<div id="status">READY</div>
</div>
<table>
<thead>
<tr>
<th>Time</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>Dport</th><th>Pkts</th><th>Bytes</th><th>AE</th><th>Iso</th><th>KMeans</th><th>RF</th><th>Ensemble</th>
</tr>
</thead>
<tbody id="tableBody"></tbody>
</table>
<a href="/results.json" style="color: #ccc;">Download JSON</a>
</div>
<script>
let poll = null;
async function startTest() {
  const iface = document.getElementById('iface').value;
  await fetch('/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({iface})
  });
  document.getElementById('startBtn').disabled = true;
  document.getElementById('stopBtn').disabled = false;
  document.getElementById('status').innerText = `Capturing ${iface}...`;
  poll = setInterval(updateTable, 1000);
  updateTable();
}
async function stopTest() {
  await fetch('/stop', {method: 'POST'});
  clearInterval(poll);
  document.getElementById('startBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
  document.getElementById('status').innerText = 'Stopped - JSON saved';
}
async function updateTable() {
  try {
    const res = await fetch('/results');
    const data = await res.json();
    const tbody = document.getElementById('tableBody');
    tbody.innerHTML = '';
    data.results.slice(-20).reverse().forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
<td>${r.timestamp.slice(11,19)}</td>
<td>${r.flow_key.src_ip.slice(0,12)}...</td>
<td>${r.flow_key.dst_ip}</td>
<td>${r.flow_key.proto || ''}</td>
<td>${r.flow_key.dport}</td>
<td>${r.pkt_count}</td>
<td>${r.bytes_fwd.toLocaleString()}</td>
<td>${r.ae_anomaly ? 'HIGH' : 'OK'}</td>
<td>${r.iso_risk}</td>
<td>${r.kmeans_risk}</td>
<td>${r.rf_labels}</td>
<td class="${r.ensemble_risk}">${r.ensemble_risk}</td>`;
      tbody.appendChild(tr);
    });
  } catch(e) {}
}
</script>
</body>
</html>'''

@app.route('/start', methods=['POST'])
def start():
    global capturing
    capturing = True
    threading.Thread(target=live_data, daemon=True).start()
    return jsonify({'status': 'started'})

def live_data():
    global capturing, nids_results
    iface = 'Ethernet'  # default
    cap = pyshark.LiveCapture(interface=iface, display_filter='tcp or udp')
    for packet in cap.sniff_continuously(packet_count=5):  # batch 5 pkts
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            proto = packet.transport_layer
            dport = packet[packet.transport_layer].dstport
            pkt_len = int(packet.length)
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'flow_key': {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'proto': proto,
                    'dport': dport
                },
                'pkt_count': 1,  # aggregate later
                'bytes_fwd': pkt_len,
                'ae_anomaly': random.random() < 0.08,  # replace with ML
                'iso_risk': random.choices(['normal', 'low', 'medium', 'high'], weights=[0.7, 0.2, 0.08, 0.02])[0],
                'kmeans_risk': random.choices(['normal', 'low', 'medium', 'high'], weights=[0.7, 0.2, 0.08, 0.02])[0],
                'rf_labels': random.choices(['BENIGN', 'DDoS', 'SCAN', 'Bot'], weights=[0.85, 0.08, 0.05, 0.02])[0],
                'ensemble_risk': 'high' if random.random() < 0.05 else 'normal'
            }
            nids_results.append(result)
        if len(nids_results) > 100:
            nids_results = nids_results[-100:]
        if not capturing:
            break
    cap.close()



@app.route('/stop', methods=['POST'])
def stop():
    global capturing
    capturing = False
    try:
        with open('results.json', 'w') as f:
            json.dump(nids_results, f, indent=2)
    except:
        pass
    return jsonify({'status': 'stopped'})


@app.route('/results')
def results():
    return jsonify({'results': nids_results})


@app.route('/results.json')
def download_json():
    try:
        with open('results.json', 'w') as f:
            json.dump(nids_results, f, indent=2)
        return send_from_directory('.', 'results.json')
    except:
        return jsonify({'error': 'JSON save failed'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

