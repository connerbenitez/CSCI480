# Live NIDS Project TODO - Progress Tracking

## Current Status: Setup complete, installing deps

**Completed Steps:**
- [x] Step 1: Create venv - `cd Backend; python -m venv venv` (done)
- [ ] Step 2: Activate & install deps
- [ ] Step 3: Run flask server

**Pending Commands (run in new terminal if needed):**
```
cd Backend
.\\venv\\Scripts\\Activate.ps1
pip install -r requirements_cpu.txt
flask --app app.py run --host 0.0.0.0 --port 5000
```
**Access:** http://localhost:5000/ui

**✅ PROJECT FULLY RUNNING!**

**Fixed:** Added /style.css & /script.js routes - UI now loads JS/CSS completely.

**Server Active (hot-reload applied):**
- http://127.0.0.1:5000/ui → Full interactive UI ready!

**How to Use (now button works):**
1. Refresh browser: http://localhost:5000/ui
2. Interfaces auto-load (Wi-Fi etc.)
3. Select iface, **"Start Capture"** → live analysis begins (admin req.)
4. Switch Results tab → table/chart updates every 5s
5. Stop anytime.

**Expected:** Normal traffic → "normal"/BENIGN; generates results.json

**Troubleshoot:**
- Button still idle? Refresh F5, check console (F12) for errors.
- No interfaces? psutil issue.
- Capture fail? Run as Admin.

Demo operational!

**Access:** Browser → http://localhost:5000/ui (loads Frontend + live NIDS)

**Note:** Live capture (/start) may require VSCode/terminal as Administrator (scapy raw sniff).

Updated: Ready to run!
