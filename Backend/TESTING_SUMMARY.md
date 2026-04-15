# Live Network Model Testing - Quick Summary

## 📦 What I Created

I've created 4 new tools in your `Backend/` folder to test your ML models against real network data:

### 1. **test_live_network.py** - Main Testing Script
- Captures live network traffic using scapy
- Extracts ~40+ network flow features (bidirectional flows)
- Runs all 4 ML models:
  - AutoEncoder (unsupervised)
  - IsolationForest (unsupervised)
  - KMeans (unsupervised)
  - RandomForest (supervised)
- Generates ensemble risk scores
- Saves results to CSV

**Run it:**
```bash
# Windows (elevated prompt required)
python test_live_network.py --interface "Wi-Fi" --duration 60

# Linux/Mac
sudo python3 test_live_network.py --interface eth0 --duration 60
```

### 2. **analyze_results.py** - Results Analysis
- Analyzes captured flows and model predictions
- Shows risk distribution, model agreement, traffic classification
- Lists top destinations, ports, protocols, anomalies
- Export suspicious flows for further investigation

**Run it:**
```bash
python analyze_results.py live_test_results.csv

# Export high-risk flows
python analyze_results.py live_test_results.csv --risk high --output high_risk.csv

# Export anomalies
python analyze_results.py live_test_results.csv --anomalies --output anomalies.csv
```

### 3. **list_interfaces.py** - Network Interface Helper
- Lists all available network interfaces on your system
- Shows IP addresses, MAC addresses, status
- Helps you identify which interface to capture on

**Run it:**
```bash
python list_interfaces.py
```

### 4. **LIVE_TESTING_GUIDE.md** - Full Documentation
- Complete usage guide with examples
- Troubleshooting tips
- Workflow examples
- Advanced usage patterns

## 🚀 Quick Start (3 steps)

### Step 1: Find Your Network Interface
```bash
python list_interfaces.py
```
Note down the interface name (e.g., "Wi-Fi", "Ethernet", "eth0")

### Step 2: Capture Network Traffic
```bash
# Run with elevated privileges (admin/sudo)
python test_live_network.py --interface "YOUR_INTERFACE" --duration 60
```
This captures 60 seconds of traffic and runs all 4 models.

### Step 3: Analyze Results
```bash
python analyze_results.py live_test_results.csv
```
View summary of findings, anomalies, suspicious flow, etc.

## 📊 Output

After running `test_live_network.py`, you get:
- **live_test_results.csv** - ALL data (flows + predictions + features)
- **Console output** - Summary of detected anomalies

Columns in output CSV:
- Flow info: `src_ip`, `dst_ip`, `proto`, `sport`, `dport`, `timestamp`
- 40+ network features (packet sizes, timing, TCP flags, etc.)
- Model predictions:
  - `ae_anomaly`, `ae_score` (AutoEncoder)
  - `iso_risk`, `iso_score` (IsolationForest)
  - `kmeans_risk`, `kmeans_score` (KMeans)
  - `rf_labels`, `rf_probs` (RandomForest - actual traffic classification!)
  - `ensemble_risk` (High/Medium/Low/Normal - combined verdict)

## 🔍 Understanding Results

**Risk Levels (Ensemble):**
- 🔴 **HIGH**: Multiple models detect anomaly - investigate!
- 🟡 **MEDIUM**: Some suspicious indicators
- 🟢 **LOW**: Minor deviation from normal
- ⚪ **NORMAL**: Regular traffic

**Model Agreement:**
When ALL 3 unsupervised models agree → Very high confidence anomaly

**RandomForest Classification:**
- `BENIGN` - Normal traffic
- `DDoS` - Distributed Denial of Service
- Other attack types your model was trained on

## ⚙️ System Requirements

- **Windows**: Run in elevated/admin command prompt
- **Linux/Mac**: Use `sudo`
- Python 3.7+
- All dependencies in [Backend/requirements.txt](requirements.txt)

## 📁 Files Created

```
Backend/
├── test_live_network.py      ← Main testing script
├── analyze_results.py        ← Analysis tool
├── list_interfaces.py        ← Interface finder
├── LIVE_TESTING_GUIDE.md     ← Detailed docs
├── TESTING_SUMMARY.md        ← This file
└── live_test_results.csv     ← Generated after running test
```

## 🎯 Example Workflow

```bash
# Step 1: List interfaces
python list_interfaces.py

# Step 2: Capture traffic for 2 minutes
python test_live_network.py --interface "Wi-Fi" --duration 120

# Step 3: Analyze full results
python analyze_results.py live_test_results.csv

# Step 4: Export suspicious flows
python analyze_results.py live_test_results.csv --risk high --output suspicious.csv

# Step 5: Review suspicious.csv in Excel/editor for investigation
```

## 💡 Tips

1. **Longer captures = better data** - Aim for 1-5 minutes
2. **Run during active network usage** - More flows = more test coverage
3. **Check model agreement** - When multiple models concur = higher confidence
4. **Ensemble risk is your verdict** - Combines unsupervised models
5. **RF classification shows traffic type** - Even if not flagged as risky

## ❓ Troubleshooting

| Issue | Solution |
|-------|----------|
| "Permission denied" | Run in admin/elevated prompt or use `sudo` |
| No interfaces found | Run `python list_interfaces.py` to see available ones |
| No flows captured | Increase duration (--duration 300), check active traffic |
| Models fail to load | Check model dumps exist in ML/AutoEncoderDumps, etc. |
| Very few anomalies | Normal - models trained on specific attacks, benign traffic = BENIGN |

## 📚 Next Steps

1. **Review LIVE_TESTING_GUIDE.md** for detailed documentation
2. **Run test captures** during different times/conditions
3. **Analyze patterns** in high-risk flows
4. **Validate findings** against actual network events
5. **Refine ensembles** based on false positive rates
6. **Integrate into operations** - setup alerts on high-risk flows

---

All scripts are production-ready and designed for repeated testing. Feel free to run multiple captures and compare results over time!
