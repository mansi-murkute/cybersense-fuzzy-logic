## cybersense ai - cyber threat detection system

cybersense ai is a cyber security project made using python, streamlit, and fuzzy logic. it checks network activity, detects possible cyber attacks, and gives a risk score.

## how to run

install all required files:

```bash
pip install -r requirements.txt
```

run the project:

```bash
streamlit run app.py
```

## project files

* app.py - main dashboard
* fuzzy_engine.py - fuzzy logic calculations
* attack_simulator.py - creates sample attacks
* alert_system.py - sends email alerts
* virustotal_scanner.py - scans files using virustotal
* requirements.txt - required libraries

## features

### attack simulation

can simulate:

* port scan
* brute force attack
* ddos attack
* stealth recon attack
* zero-day attack

### risk score

uses fuzzy logic to calculate a risk score from 0 to 100.

### dashboard

shows:

* risk level
* attack logs
* threat status

### email alerts

sends an email when a critical threat is found.

### virustotal scanner

users can upload a file and check if it is dangerous.

### analytics

shows charts and attack statistics.

### fuzzy explainer

helps users understand how the risk score is calculated.

### csv download

allows users to download the threat log.

## setup

### gmail alerts

* turn on 2-step verification in gmail
* create an app password
* enter gmail and app password in the project

### virustotal

* create a free virustotal account
* copy your api key
* paste it into the scanner tab

free account limits:

* 500 scans per day
* 4 requests per minute

## fuzzy logic inputs

* packet rate (0-2000)
* failed logins (0-100)
* port diversity (0-1000)
* connection duration (0-3600)

## risk levels

* 0-25 = low
* 25-50 = medium
* 50-75 = high
* 75-100 = critical

## sample rules

* very high packet rate + high port diversity = critical risk
* extreme failed logins = critical risk
* high packet rate + few failed logins = high risk
* medium packet rate + no failed logins = medium risk
* low packet rate + no failed logins = low risk

## demo

1. start the app
2. select ddos wave
3. choose intensity 9
4. click start
5. see the risk level increase
6. open analytics to view charts
7. test values in fuzzy explainer
8. scan a file in virustotal

## notes

* uses mamdani fuzzy logic
* uses centroid method
* uses triangular and trapezoidal membership functions
* easy to understand and explain
* does not use machine learning
