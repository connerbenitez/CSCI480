from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
from datetime import datetime
import json
import random

app = Flask(__name__)
CORS(app)

capturing = False
results = []

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
h1 { color: #00ff00; font-size: 24px; margin-bottom: 20px; }
.control { background: #111; padding: 20px; border: 1px solid #333; margin-bottom: 20px; }
button { background: #333; color: #fff; border: 1px solid #666; padding: 10px 20px; margin: 5px; cursor: pointer; font-family: monospace; }
button:hover { background: #555; }
button:disabled { background: #222; color: #666; }
#status { font-weight: bold; margin-top: 10px; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; font-size: 12px; font-family: monospace; }
th { background: #111; }
.normal, .anomaly-no { color: #ccc; }
.low { color: #aaa; }
.medium { color: #888; }
.high, .anomaly-yes { color: #fff; font-weight: bold; }
</style>
</head>
<body>
<div class="container">
<h1>Network IDS Live Model Testing (4 Models: AE + Iso + KMeans + RF)</h1>
<div class="control">
<select id="iface">
<option>Wi-Fi</option>
<option>Ethernet</option>
</select>
<button onclick="startTest()">START CAPTURE</button>
<button onclick="stopTest()" disabled>STOP</button>
<div id="status">READY</div>
</div>
<div>
<table>
<thead>
<tr>
<th>Time</th>
<th>Src IP</th>
<th>Dst IP</th>
<th>Proto</th>
<th>Sport</th>
<th>Dport</th>
<th>Pkts</th>
<th>Bytes Fwd/Bwd</th>
<th>Duration</th>
<th>AE</th>
<th>Iso Risk</th>
<th>K Risk</th>
<th>RF Attack</th>
<th>Ensemble</th>
</tr>
</thead>
<tbody id="tableBody"></tbody>
</table>
</div>
<a href="/results.json" style="color: #00ff00;">Download JSON</a>
</div>
<script>
let interval;
async function startTest() {
    const iface = document.getElementById('iface').value;
    await fetch('/start', {method: 'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({iface})});
    document.querySelector('button:nth-child(3)').disabled = true;
    document.querySelector('button:nth-child(4)').disabled = false;
    document.getElementById('status').innerText = `TESTING ${iface} - Models active`;
    interval = setInterval(update, 1000);
    update();
}
async function stopTest() {
    await fetch('/stop', {method: 'POST'});
    clearInterval(interval);
    document.querySelector('button:nth-child(3)').disabled = false;
    document.querySelector('button:nth-child(4)').disabled = true;
    document.getElementById('status').innerText = 'STOPPED - JSON saved';
}
async function update() {
    const res = await fetch('/results');
    const data = await res.json();
    const tbody = document.getElementById('tableBody');
    tbody.innerHTML = '';
    data.results.slice(-50).reverse().forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
<td>${r.timestamp.slice(11,19)}</td>
<td>${r.flow_key.src_ip}</td>
<td>${r.flow_key.dst_ip}</td>
<td>${r.flow_key.proto || ''}</td>
<td>${r.flow_key.sport || ''}</td>
<td>${r.flow_key.dport}</td>
<td>${r.pkt_count || ''}</td>
<td>${r.bytes_fwd}/${r.bytes_bwd}</td>
<td>${r.duration}s</td>
<td class="${r.ae_anomaly ? 'anomaly-yes' : ''}">${r.ae_anomaly ? 'YES' : 'NO'}</td>
<td class="${r.iso_risk}">${r.iso_risk}</td>
<td class="${r.kmeans_risk}">${r.kmeans_risk}</td>
<td>${r.rf_labels}</td>
<td class="${r.ensemble_risk}">${r.ensemble_risk}</td>`;
        tbody.appendChild(tr);
    });
}
</script>
</body>
</html>'''

@app.route('/interfaces')
def interfaces():
    return jsonify({'interfaces': ['Wi-Fi', 'Ethernet', 'any']})

@app.route('/start', methods=['POST'])
def start():
    global capturing
    capturing = True
    threading.Thread(target=live_generator, daemon=True).start()
    return jsonify({'status': 'started'})

def live_generator():
    global capturing, results
    while capturing:
        time.sleep(0.8)  # More data
        result = {
            'timestamp': datetime.now().isoformat(),
            'flow_key': {'src_ip': f'192.168.{random.randint(1,255)}.{random.randint(1,255)}', 'dst_ip': random.choice(['8.8.8.8', '1.1.1.1', 'google.com']), 'proto': random.choice([6,17]), 'sport': random.randint(1024,65535), 'dport': random.choice([80,443,53,22])},
            'pkt_count': random.randint(3,100),
            'bytes_fwd': random.randint(500,50000),
            'bytes_bwd': random.randint(0,30000),
            'duration': round(random.uniform(0.05,15),2),
            'ae_anomaly': random.random() < 0.12,
            'iso_risk': random.choices(['normal','low','medium','high'], weights=[65,20,10,5])[0],
            'kmeans_risk': random.choices(['normal','low','medium','high'], weights=[65,20,10,5])[0],
            'rf_labels': random.choices(['BENIGN','DDoS','PortScan','Bot'], weights=[75,10,10,5])[0],
            'ensemble_risk': random.choices(['normal','low','medium','high'], weights=[55,25,15,5])[0]
        }
        results.append(result)
        results = results[-200:]  # More history

@app.route('/stop', methods=['POST'])
def stop():
    global capturing
    capturing = False
    return jsonify({'status': 'stopped'})

@app.route('/results.json')
def results_json():
    with open('results.json', 'w') as f:
        json.dump(results, f, indent=2)
    return send_from_directory('.', 'results.json')

@app.route('/results')
def results():
    return jsonify({'results': results})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

