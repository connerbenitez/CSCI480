# CSCI480 Layered IDS/IPS

Multi-model intrusion detection and prevention system with:

- live packet capture
- layered ML detection
- active prevention and healing
- real attack simulation
- PCAP replay and upload
- Windows packaging support

## Repository layout

- `Backend/` Flask API, capture engine, prevention/healing logic
- `Frontend/` dashboard UI
- `ML/` trained artifacts and prediction code
- `packaging/` PyInstaller and Inno Setup packaging files
- `run_project.py` main launcher

## Prerequisites

For teammates running from source:

1. Python `3.11`
2. [Npcap](https://npcap.com/) on Windows for packet capture/injection
3. Administrator PowerShell if firewall prevention/healing should work
4. Git LFS installed before cloning, because the large ML artifacts are tracked with LFS

## Clone the project

```powershell
git lfs install
git clone <your-github-repo-url>
cd CSCI480
```

## Run from source

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
cd .\Backend
pip install -r requirements.txt
cd ..
python .\run_project.py
```

The dashboard opens at:

```text
http://127.0.0.1:5000
```

## Run the packaged app

If you want classmates to avoid Python setup, build or share the installer described in:

- [INSTALLER_GUIDE.md](INSTALLER_GUIDE.md)

They should still:

1. install [Npcap](https://npcap.com/)
2. run the app as Administrator for firewall-based blocking/healing

## GitHub push notes

This repo is prepared so GitHub pushes are practical:

- virtual environments are ignored
- build and installer outputs are ignored
- runtime state and logs are ignored
- datasets and downloaded external tool bundles are ignored
- large ML model files are tracked with Git LFS

Before your first push, make sure LFS tracking is active:

```powershell
git lfs install
```

## Recommended first push workflow

```powershell
git add .gitattributes .gitignore README.md
git add Backend Frontend ML packaging run_project.py INSTALLER_GUIDE.md
git status
git commit -m "Prepare layered IDS/IPS project for GitHub"
git remote add origin <your-github-repo-url>
git push -u origin main
```

## Notes for classmates

- The repo may clone slowly the first time because the ML models are large.
- If the dashboard says models are unavailable after cloning, confirm `git lfs pull` completed.
- The `PCAP Replay` tab can use uploaded `.pcap` files even if the repo is cloned without bundled sample PCAPs.
