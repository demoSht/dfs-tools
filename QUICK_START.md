# Quick Start Guide - Dofus Traffic Sniffer

## ✅ Setup Complete!

All dependencies have been installed successfully and the psutil API issue has been fixed. You can now use the complete Dofus traffic sniffer.

**✨ Active Dofus Process Detected!**
The sniffer has automatically detected a running Dofus process with 3 active connections to game servers.

## 🚀 Quick Usage Commands

### 1. Traffic Sniffer Only (Recommended for beginners)

```bash
# Méthode simple - Capture réseau uniquement
sudo python3 launch_simple.py --network

# Méthode simple - SSL uniquement
python3 launch_simple.py --ssl

# Méthode avancée - Both network + SSL
sudo python3 launcher.py --traffic-only --ssl
```

### ⚡ **Méthode Simple (Si problèmes SSL)**

```bash
# Capture réseau Dofus (privilèges root requis)
sudo python3 launch_simple.py --network

# OU interception SSL séparément
python3 launch_simple.py --ssl
```

### 2. All Tools Together

```bash
# Archimonstre tools + Traffic sniffer
sudo python3 launcher.py --traffic --ssl
```

### 3. Direct Usage

```bash
# Network capture with Dofus filtering
sudo python3 dofus_traffic_sniffer.py

# SSL interception with web interface
python3 dofus_traffic_sniffer.py --ssl --no-network
```

## 🔧 For SSL Interception

1. **Start the sniffer with SSL:**
   ```bash
   python3 launcher.py --traffic-only --ssl --no-network
   ```

2. **Configure your system proxy:**
   - Set HTTP/HTTPS proxy to: `localhost:8080`
   - Access web interface: `http://localhost:8081`

3. **Install the certificate:**
   - Navigate to: `http://mitm.it/` (with proxy enabled)
   - Download and install the certificate for macOS
   - Mark as "trusted" in Keychain Access

4. **Launch Dofus** and the traffic will be captured!

## 📁 Output Files

Captures are saved in `captures/` folder:
- `traffic_data_*.json` - Structured packet data
- `traffic_log_*.txt` - Human-readable logs
- `traffic_raw_*.bin` - Raw binary data
- `analysis_report.json` - Summary report
- `dofus_decrypted.json` - SSL-decrypted data

## 🎯 What Gets Captured

- ✅ Network packets to/from Dofus servers
- ✅ SSL/HTTPS traffic (decrypted)
- ✅ Chat messages and coordinates
- ✅ Game protocol messages
- ✅ Server communications

## ⚠️ Important Notes

- **Sudo required** for network capture
- **Personal use only** - respect Dofus ToS
- **Secure storage** of capture files
- **Dofus process** must be running for auto-detection

## 🛑 Stop Capture

Press `Ctrl+C` to stop any running capture session.

---

**Ready to capture Dofus traffic! 🎮📡**