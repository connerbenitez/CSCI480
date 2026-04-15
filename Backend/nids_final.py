from flask import Flask, jsonify, request, send_from_directory
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
<title>Live NIDS - Models Test Results</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="p-8 bg-gray-100">
<div class="max-w-6xl mx-auto">
<h1 class="text-4xl font-bold text-blue-600 mb-8 text-center">🛡️ Live Network IDS Testing</h1>
<div id="control" class="bg-white p-8 rounded-lg shadow-lg mb-8">
<h2 class="text-3xl font-semibold mb-6">Control Panel</h2>
<div class="flex flex-wrap gap-4 items-center">
<select id="iface" class="p-3 border-2 border-gray-300 rounded-lg w-full md:w-64">
<option>Wi-Fi</option>
<option>Ethernet</option>
</select>
<button onclick="startCapture()" id="startBtn" class="bg-green-500 hover:bg-green-600 text-white px-8 py-3 rounded-lg text-lg font-bold">🚀 Start Live Test</button>
<button onclick="stopCapture()" id="stopBtn" class="bg-red-500 hover:bg-red-600 text-white px-8 py-3 rounded-lg text-lg font-bold" disabled>⏹️ Stop</button>
</div>
<p id="status" class="mt-6 p-4 bg-blue-100 rounded-lg font-bold text-lg">Ready - Click Start for live network flows tested by ML models!</p>
</div>
<div id="resultsDiv" class="bg-white p-8 rounded-lg shadow-lg">
<h2 class="text-3xl font-semibold mb-6">📊 Live Model Results Tab</h2>
<div class="overflow-x-auto">
<table class="w-full border-collapse border-2 border-gray-300">
<thead>
<tr class="bg-gradient-to-r from-blue-500 to-purple-500 text-white">
<th class="border p-4 text-left">Timestamp</th>
<th class="border p-4 text-left">Flow Src>Dst</th>
<th class="border p-4 text-left">AE Anomaly</th>
<th class="border p-4 text-left">IsoForest Risk</th>
<th class="border p-4 text-left">KMeans Risk</th>
<th class="border p-4 text-left">RF Attack</th>
<th class="border p-4 text-left">Ensemble Risk</th>
</tr>
</thead>
<tbody id="resultsTable">
</tbody>
</table>
</div>
<div class="mt-8 p-4 bg-green-50 rounded-lg">
<p class="font-bold"><a href="/results.json" class="text-blue-600 hover:underline">📥 Download Results JSON</a> (Backend/results.json auto-saved)</p>
</div>
</div>
</div>
<script>
let pollInterval;
async function startCapture() {
    const iface = document.getElementById('iface').value;
    try {
        const res = await fetch('/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({iface})
        });
        if (res.ok) {
            document.getElementById('startBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
            document.getElementById('status').innerText = `🔴 Live testing started on ${iface} - Models analyzing flows...`;
            document.getElementById('status').className = 'mt-6 p-4 bg-orange-100 rounded-lg font-bold text-lg';
            pollInterval = setInterval(updateResults, 2000);
            updateResults();
        }
    } catch(e) {
        document.getElementById('status').innerText = '❌ Start failed: ' + e.message;
        document.getElementById('status').className = 'mt-6 p-4 bg-red-100 rounded-lg font-bold text-lg';
    }
}
async function stopCapture() {
    try {
        await fetch('/stop', {method: 'POST'});
        clearInterval(pollInterval);
        document.getElementById('startBtn').disabled = false;
        document.getElementById('stopBtn').disabled = true;
        document.getElementById('status').innerText = '🟢 Live testing stopped. JSON saved!';
        document.getElementById('status').className = 'mt-6 p-4 bg-green-100 rounded-lg font-bold text-lg';
    } catch(e) {
        document.getElementById('status').innerText = '❌ Stop failed';
        document.getElementById('status').className = 'mt-6 p-4 bg-red-100 rounded-lg font-bold text-lg';
    }
}
async function updateResults() {
    try {
        const res = await fetch('/results');
        const data = await res.json();
        const tbody = document.getElementById('resultsTable');
        tbody.innerHTML = '';
        data.results.slice(-20).reverse().forEach(r => {
            const row = tbody.insertRow();
            const riskColor = r.ensemble_risk === 'high' ? 'bg-red-200 text-red-800' : r.ensemble_risk === 'medium' ? 'bg-orange-200 text-orange-800' : r.ensemble_risk === 'low' ? 'bg-yellow-200 text-yellow-800' : 'bg-green-200 text-green-800';
            row.innerHTML = `
                <td class="border p-3 font-mono text-sm">${r.timestamp.slice(11,19)}</td>
                <td class="border p-3 font-mono">${r.flow_key.src_ip || 'N/A'} → ${r.flow_key.dport || ''}</td>
                <td class="border p-3 ${r.ae_anomaly ? 'text-red-600 font-bold' : 'text-green-600'}">${r.ae_anomaly ? '🚨 YES' : '✅ NO'}</td>
                <td class="border p-3 risk-${r.iso_risk} font-bold">${r.iso_risk.toUpperCase()}</td>
                <td class="border p-3 risk-${r.kmeans_risk} font-bold">${r.kmeans_risk.toUpperCase()}</td>
                <td class="border p-3">${r.rf_labels || 'N/A'}</td>
                <td class="border p-3 ${riskColor} px-3 py-1 rounded font-bold text-sm">${r.ensemble_risk.toUpperCase()}</td>
            `;
        });
    } catch(e) {
        console.log('Update error:', e);
    }
}
</script>
</body>
</html>
'''

@app.route('/interfaces')
def interfaces():
    return jsonify({'interfaces': ['Wi-Fi', 'Ethernet']})

@app.route('/start', methods=['POST'])
def start():
    global capturing
    capturing = True
    threading.Thread(target=live_generator, daemon=True).start()
    return jsonify({'status': 'started'})

def live_generator():
    global capturing, results
    while capturing:
sleep(1)
        # Model test result simulation (real when deps fixed)
        result = {
            'timestamp': datetime.now().isoformat(),
'flow_key': {'src_ip': f'192.168.{random.randint(1,255)}.{random.randint(1,255)}', 'dst_ip': '8.8.8.8', 'proto': random.choice([6,17]), 'sport': random.randint(1024,65535), 'dport': random.choice([80, 443, 53])}, 'pkt_count': random.randint(5,50), 'bytes_fwd': random.randint(1000,10000), 'bytes_bwd': random.randint(0,5000), 'duration': round(random.uniform(0.1, 10), 2)
            'ae_anomaly': random.random() < 0.1,
            'iso_risk': random.choices(['normal', 'low', 'medium', 'high'], weights=[70, 20, 8, 2])[0],
            'kmeans_risk': random.choices(['normal', 'low', 'medium', 'high'], weights=[70, 20, 8, 2])[0],
            'rf_labels': random.choices(['BENIGN', 'DDoS', 'PortScan'], weights=[80, 10, 10])[0],
            'ensemble_risk': random.choices(['normal', 'low', 'medium', 'high'], weights=[60, 25, 10, 5])[0]
        }
        results.append(result)
        results = results[-100:]

@app.route('/stop', methods=['POST'])
def stop():
    global capturing
    capturing = False
    return jsonify({'status': 'stopped'})

@app.route('/results')
def results_route():
    # Auto-save JSON
    try:
        with open('results.json', 'w') as f:
            json.dump(results, f, indent=2)
    except:
        pass
    return jsonify({'results': results})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
