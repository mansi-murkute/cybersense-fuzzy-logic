# 🛡️ CyberSense AI — Fuzzy-Based Intelligent Cyber Threat Detection

A real-time cyber threat detection and risk assessment system built with
**Fuzzy Logic**, **Python**, and **Streamlit**.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
streamlit run app.py
```

---

## 📦 Project Structure
```
cyber_threat_app/
├── app.py                  # Main Streamlit dashboard
├── fuzzy_engine.py         # Fuzzy logic inference engine (scikit-fuzzy)
├── attack_simulator.py     # Synthetic network event generator
├── alert_system.py         # Gmail SMTP email alerts
├── virustotal_scanner.py   # VirusTotal API file scanner
└── requirements.txt
```

---

## 🧩 Features

| Feature | Description |
|---|---|
| **Live Attack Simulation** | Mimics Port Scan, Brute Force, DDoS, Stealth Recon, Zero-Day |
| **Fuzzy Risk Scoring** | 4 input variables → Mamdani FIS → 0–100 risk score |
| **Real-Time Dashboard** | Live gauge, scrolling log, color-coded threat levels |
| **Email Alerts** | Sends Gmail alert when CRITICAL threat is detected |
| **VirusTotal Scanner** | Upload any file → 70+ AV engines → fuzzy threat score |
| **Analytics Tab** | Charts: distribution, timeline, attack frequency |
| **Fuzzy Explainer** | Interactive manual assessor + rule explanation |
| **CSV Export** | Download full session threat log |

---

## 🔧 Configuration

### Email Alerts (Gmail)
1. Enable 2FA on your Gmail account
2. Go to: Google Account → Security → App Passwords
3. Generate a 16-character App Password
4. Enter your Gmail address + App Password in the sidebar

### VirusTotal Scanner
1. Sign up at https://www.virustotal.com (free)
2. Go to your profile → API Key
3. Paste the key in the VirusTotal Scanner tab
- Free tier: **500 lookups/day**, **4 requests/minute**

---

## 🧠 Fuzzy Logic System

### Input Variables
| Variable | Range | Fuzzy Sets |
|---|---|---|
| `packet_rate` | 0–2000 pkt/s | low, medium, high, very_high |
| `failed_logins` | 0–100 | none, few, many, extreme |
| `port_diversity` | 0–1000 ports | single, low, medium, high |
| `connection_duration` | 0–3600 sec | brief, normal, extended, persistent |

### Output Variable
| Score | Level |
|---|---|
| 0–25 | 🟢 LOW |
| 25–50 | 🟡 MEDIUM |
| 50–75 | 🟠 HIGH |
| 75–100 | 🔴 CRITICAL |

### Sample Rules
```
IF packet_rate IS very_high AND port_diversity IS high  → risk IS critical
IF failed_logins IS extreme                             → risk IS critical
IF packet_rate IS high AND failed_logins IS few         → risk IS high
IF packet_rate IS medium AND failed_logins IS none      → risk IS medium
IF packet_rate IS low AND failed_logins IS none         → risk IS low
```

---

## 📸 Demo Flow (for presentations)
1. Launch app → open in browser
2. Select **"DDoS Wave"** scenario, intensity **9** → hit **START**
3. Watch real-time gauge spike to CRITICAL
4. Switch to **"Stealth Recon"** → show LOW/MEDIUM detections
5. Open **Analytics** tab → show distribution chart
6. Open **Fuzzy Explainer** → manually test extreme values
7. Demo **VirusTotal tab** with any test file

---

## 🎓 Academic Notes
- Inference method: **Mamdani** (most interpretable, ideal for academic work)
- Defuzzification: **Centroid** method
- All fuzzy sets use trapezoidal/triangular membership functions
- System is fully explainable — no black-box ML
