# Windows Packaging Guide

This project can be packaged into a Windows executable and, optionally, an installer for teammates.

## What the packaged app includes

- Flask dashboard UI
- Frontend assets
- Backend detection and prevention engine
- ML artifacts from `ML/`
- Prevention and healing logic

## Important runtime notes

- Run the installed app as Administrator if you want firewall blocking/healing to work.
- Packet capture and packet injection on Windows work best when [Npcap](https://npcap.com/) is installed.
- Runtime state is stored in `%LOCALAPPDATA%\\CSCI480LayeredIDS` when bundled.

## Build the executable

From the project root:

```powershell
.\packaging\build_windows.ps1
```

That produces:

```text
dist\CSCI480 Layered IDS\CSCI480 Layered IDS.exe
```

## Build the installer

Install Inno Setup first so `iscc` is on `PATH`, then run:

```powershell
.\packaging\build_windows.ps1 -Installer
```

That produces:

```text
dist\CSCI480-Layered-IDS-Installer.exe
```

## Recommended teammate setup

1. Install Npcap on the target machine.
2. Run the generated installer, or launch `CSCI480 Layered IDS.exe` from the bundled folder as Administrator.
3. Select the active interface in the dashboard.
4. Start capture.
5. Use the built-in prevention/healing controls from the `Defense & Prevention` tab.
