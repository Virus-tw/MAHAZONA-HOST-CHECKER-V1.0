# 🌐 MAHAZONA HOST CHECKER V1.0

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**MAHAZONA Host Checker** 🌐 Tests VLESS/VMESS SNI and Host Headers. Parses config, checks TCP/TLS success, simulates speed, and generates working VPN configs. Includes a CIDR range IP/Port scanner. Essential for finding and validating fast, working hosts for proxy/VPN use. Requires Python (requests, dnspython) and curl. 🛠️

## 🛠️ Installation & Setup

1.  **Install Prerequisites:** `pkg install python git curl -y`
2.  **Install Python Libraries:** `pip install requests dnspython`
3.  **Grant Storage Access (Termux only):** `termux-setup-storage`
4.  **Fix DNS Error (Termux only):** This is critical for network functions.
    ```bash
    rm /etc/resolv.conf
    ln -s /data/data/com.termux/files/usr/etc/resolv.conf /etc/resolv.conf
    termux-change-repo
    ```

## 🚀 Usage Guide

1. Clone the repository:
   `git clone https://github.com/YOUR_USERNAME/MAHAZONA-Host-Checker.git`
2. Run the script:
   `cd MAHAZONA-Host-Checker`
   `python mahazona_checker.py`
