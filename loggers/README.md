# 5G Data Collection Setup Guide

Automated capture of PCAP, QMDL modem logs, and G-NetTrack Pro signal logs synchronized with an Ookla speedtest on a rooted OnePlus 11R (Snapdragon 8+ Gen 1).

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Install ADB](#2-install-adb)
   - [Windows](#windows)
   - [Linux](#linux)
3. [Phone Setup (One-Time)](#3-phone-setup-one-time)
4. [Device File Setup (One-Time)](#4-device-file-setup-one-time)
5. [Install G-NetTrack Pro](#5-install-g-nettrack-pro)
6. [Running the Scripts](#6-running-the-scripts)
7. [Output Structure](#7-output-structure)
8. [G-NetTrack Pro Log Files Explained](#8-g-nettrack-pro-log-files-explained)

---

## 1. Prerequisites

- Rooted OnePlus 11R connected via USB
- G-NetTrack Pro installed on the phone
- USB cable (data-capable, not charge-only)
- Scripts from this repository:
  - `capture_diag_pcap_nsg_speedtest.sh` — single capture run
  - `run_scheduled_captures.sh` — runs every 5 minutes continuously

---

## 2. Install ADB

### Windows

**Option A — Official Google Platform Tools (Recommended)**

1. Download from: https://developer.android.com/tools/releases/platform-tools
2. Extract the zip (e.g. to `C:\platform-tools\`)
3. Add to PATH:
   - Search → "Environment Variables" → Edit System Environment Variables
   - Under System Variables → select `Path` → Edit → New
   - Add `C:\platform-tools`
   - Click OK on all dialogs
4. Open a new Command Prompt and verify:
   ```cmd
   adb version
   ```

**Option B — winget (Windows 10/11)**
```cmd
winget install Google.PlatformTools
```

**USB Driver (Windows only)**

If your device is not recognized, install the Google USB Driver:
- Download from: https://developer.android.com/studio/run/win-usb
- Or install via Device Manager → Update Driver → Browse → point to extracted driver folder

---

### Linux

```bash
sudo apt update
sudo apt install adb

# Verify
adb version
```

On some distros you may also need:
```bash
sudo apt install android-tools-adb
```

---

## 3. Phone Setup (One-Time)

**Enable Developer Options:**
1. Settings → About Phone → tap **Build Number** 7 times
2. You will see "You are now a developer"

**Enable USB Debugging:**
1. Settings → Developer Options → **USB Debugging** → ON

**Enable Rooted Debugging:**
1. Settings → Developer Options → **Rooted Debugging** → ON

**Authorize the computer:**
1. Connect the phone via USB
2. A dialog will appear on the phone: **"Allow USB Debugging?"**
3. Tap **Allow** (check "Always allow from this computer" to skip this in future)

**Verify connection:**

Windows (Command Prompt):
```cmd
adb devices
```

Linux (Terminal):
```bash
adb devices
```

Expected output:
```
List of devices attached
XXXXXXXX    device
```

If it shows `unauthorized`, unlock the phone and tap **Allow** on the popup.

**Verify root:**
```bash
adb shell su -c id
```
Expected: `uid=0(root) ...`

---

## 4. Device File Setup (One-Time)

The speedtest binary and CA certificates must be placed on the device once.

### Download the Speedtest CLI (ARM64 for OnePlus 11R)

**Windows (Command Prompt):**
```cmd
curl -L -o speedtest.tgz "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
tar -xzf speedtest.tgz
```

**Linux (Terminal):**
```bash
curl -L -o speedtest.tgz "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
tar -xzf speedtest.tgz
```

### Push files to device

**Windows:**
```cmd
adb push speedtest /data/local/tmp/speedtest
adb shell chmod +x /data/local/tmp/speedtest
curl -o cacert.pem https://curl.se/ca/cacert.pem
adb push cacert.pem /data/local/tmp/cacert.pem
```

**Linux:**
```bash
adb push speedtest /data/local/tmp/speedtest
adb shell chmod +x /data/local/tmp/speedtest
curl -o cacert.pem https://curl.se/ca/cacert.pem
adb push cacert.pem /data/local/tmp/cacert.pem
```

### Verify the binary works
```bash
adb shell su -c "/data/local/tmp/speedtest --version"
```

---

## 5. Install G-NetTrack Pro

1. Install **G-NetTrack Pro** from the Google Play Store on the phone
   - Package name: `com.gyokovsolutions.gnettrackproplus`
2. Open the app once manually and grant all requested permissions (location, phone state)
3. Close the app — the scripts will launch and control it automatically

> **Note:** The scripts use hardcoded tap coordinates calibrated for the OnePlus 11R screen resolution (1080×2400). If you use a different device, you will need to re-calibrate the tap coordinates at the top of `capture_diag_pcap_nsg_speedtest.sh`:
> ```bash
> GNET_THREE_DOTS_X=1160; GNET_THREE_DOTS_Y=175
> GNET_START_LOG_X=818;   GNET_START_LOG_Y=209
> GNET_END_LOG_X=702;     GNET_END_LOG_Y=362
> ```
> To find your coordinates: Settings → Developer Options → **Pointer Location** → ON, then tap each button and note the X,Y shown on screen.

---

## 6. Running the Scripts

> **Windows users:** These are bash scripts. Run them inside **Git Bash**, **WSL (Windows Subsystem for Linux)**, or **Cygwin**. Command Prompt and PowerShell will not work.
>
> Install Git Bash from: https://git-scm.com/download/win
> Or enable WSL: `wsl --install` in an admin PowerShell.

### Single Capture Run

Runs one speedtest with all captures and saves to a timestamped folder:

**Linux:**
```bash
cd /path/to/scripts
bash capture_diag_pcap_nsg_speedtest.sh
```

**Windows (Git Bash / WSL):**
```bash
cd /path/to/scripts
bash capture_diag_pcap_nsg_speedtest.sh
```

Optional — specify a custom output folder:
```bash
bash capture_diag_pcap_nsg_speedtest.sh my_output_folder
```

### Scheduled Run (Every 5 Minutes)

Runs the capture script repeatedly — waits for each speedtest to finish, then waits 5 minutes before starting the next run:

```bash
bash run_scheduled_captures.sh
```

Optional — specify a custom root output folder:
```bash
bash run_scheduled_captures.sh /path/to/my/output
```

Press **Ctrl+C** to stop cleanly.

---

## 7. Output Structure

```
scheduled_captures/
├── run_000_20260614_120000/
│   ├── capture_20260614_120000.pcap       ← Full packet capture (tcpdump)
│   ├── mdm_*.qmdl2                        ← Qualcomm modem DIAG log (primary)
│   ├── mdm2_*.qmdl2                       ← Qualcomm modem DIAG log (RF subsystem)
│   ├── speedtest_results.txt              ← Speedtest summary + raw output
│   └── gnettrack_logs/
│       └── Jio_True5G_2026.06.14_120000/
│           ├── *.txt                      ← Main signal log (timestamped)
│           ├── *_events.txt               ← Network events log
│           ├── *_datatest.txt             ← G-NetTrack data test (unused)
│           └── *.kml                      ← Per-metric KML files (Google Earth)
│
├── run_001_20260614_120845/
│   └── ...
```

**Tools to open logs:**
| File | Tool |
|---|---|
| `.pcap` | Wireshark |
| `.qmdl2` | Qualcomm QXDM or QCAT |
| `.kml` | Google Earth |
| `.txt` | Any text editor |

---

## 8. G-NetTrack Pro Log Files Explained

Each session creates one folder containing the following files:

### Text Logs

| File | Has Data? | Contents |
|---|---|---|
| `*.txt` | Always | Main continuous log — timestamped measurements of all signal parameters (RSRP, SNR, CQI, band, cell ID, technology) sampled throughout the entire session |
| `*_events.txt` | Only if events occurred | Network events such as handovers, cell changes, 4G↔5G technology switches. Empty if the phone stayed on the same cell for the entire session |
| `*_datatest.txt` | Always empty | Only populated when G-NetTrack Pro's own built-in data test is triggered. Since we use an external Ookla speedtest, this file will always be empty |

### KML Files (Google Earth / mapping)

Each KML file contains time-stamped GPS coordinates paired with the metric value — one data point per sample interval:

| File | Metric |
|---|---|
| `*_rxlev.kml` | Received signal level (RSRP) |
| `*_qual.kml` | Signal quality (RSRQ) |
| `*_snr.kml` | Signal-to-Noise Ratio (SNR / SINR) |
| `*_cqi.kml` | Channel Quality Indicator |
| `*_dlbitrate.kml` | Downlink bitrate |
| `*_ulbitrate.kml` | Uplink bitrate |
| `*_speed.kml` | Instantaneous speed |
| `*_band.kml` | Active frequency band (e.g. n78, B3) |
| `*_arfcn.kml` | ARFCN channel number |
| `*_technology.kml` | Radio technology (NR / LTE) |
| `*_cellid.kml` | Serving cell ID |
| `*_phonestate.kml` | Phone state (idle / data active) |
| `*_ping.kml` | Ping / latency |
| `*_pingloss.kml` | Ping loss percentage |
| `*_pc.kml` | Power control |
| `*_testdl.kml` | Download test trace |
| `*_testul.kml` | Upload test trace |
| `*_datatest.kml` | Data test state |
| `*_filemarks.kml` | Manual filemarks placed during session |
| `*_events.kml` | Events mapped to GPS location |
