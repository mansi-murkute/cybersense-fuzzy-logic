import streamlit as st
import time
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from fuzzy_engine import FuzzyThreatEngine
from attack_simulator import AttackSimulator
from alert_system import send_email_alert
from report_generator import generate_pdf_report

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberSense AI — Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CSS + Alert Sound ─────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600&family=Oxanium:wght@300;500;700&display=swap');

:root {
  --bg0:      #03070d;
  --bg1:      #060f1a;
  --bg2:      #091525;
  --bg3:      #0c1c30;
  --border:   #142840;
  --accent:   #00c8ff;
  --accent2:  #0077aa;
  --muted:    #3a6a8a;
  --text:     #b8d0e0;
  --low:      #00e676;
  --medium:   #ffd600;
  --high:     #ff6d00;
  --critical: #ff1744;
  --mono:     'IBM Plex Mono', monospace;
  --display:  'Oxanium', sans-serif;
}

html, body, [class*="css"] {
  background-color: var(--bg0) !important;
  color: var(--text) !important;
  font-family: var(--mono) !important;
}
.stApp { background: var(--bg0) !important; }

.stApp::before {
  content: '';
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background-image:
    linear-gradient(rgba(0,200,255,0.012) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,200,255,0.012) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}

section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, var(--bg1) 0%, var(--bg0) 100%) !important;
  border-right: 1px solid var(--border) !important;
}

div[data-testid="metric-container"] {
  background: var(--bg2) !important;
  border: 1px solid var(--border) !important;
  border-top: 2px solid var(--accent2) !important;
  border-radius: 4px !important;
  padding: 12px 16px !important;
  position: relative;
  overflow: hidden;
}
div[data-testid="metric-container"]::after {
  content: '';
  position: absolute;
  top: 0; right: 0;
  width: 40px; height: 2px;
  background: var(--accent);
}
div[data-testid="metric-container"] label {
  color: var(--muted) !important;
  font-family: var(--mono) !important;
  font-size: 10px !important;
  letter-spacing: 2px !important;
  text-transform: uppercase !important;
}
div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
  color: var(--accent) !important;
  font-family: var(--display) !important;
  font-size: 1.6rem !important;
  font-weight: 700 !important;
}

.stTabs [data-baseweb="tab-list"] {
  background: var(--bg1) !important;
  border-bottom: 1px solid var(--border) !important;
  gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
  color: var(--muted) !important;
  font-family: var(--mono) !important;
  font-size: 11px !important;
  letter-spacing: 2px !important;
  text-transform: uppercase !important;
  padding: 12px 20px !important;
  border-radius: 0 !important;
  border-right: 1px solid var(--border) !important;
}
.stTabs [aria-selected="true"] {
  color: var(--accent) !important;
  background: var(--bg2) !important;
  border-bottom: 2px solid var(--accent) !important;
}

.stButton > button {
  background: transparent !important;
  color: var(--accent) !important;
  border: 1px solid var(--accent2) !important;
  border-radius: 3px !important;
  font-family: var(--mono) !important;
  font-size: 11px !important;
  letter-spacing: 2px !important;
  text-transform: uppercase !important;
  transition: all 0.15s !important;
}
.stButton > button:hover {
  background: rgba(0,200,255,0.08) !important;
  border-color: var(--accent) !important;
  box-shadow: 0 0 12px rgba(0,200,255,0.2) !important;
}

.stTextInput > div > div > input,
.stSelectbox > div > div,
.stNumberInput > div > div > input {
  background: var(--bg2) !important;
  color: var(--text) !important;
  border: 1px solid var(--border) !important;
  border-radius: 3px !important;
  font-family: var(--mono) !important;
  font-size: 12px !important;
}

::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--bg0); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

.panel {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 16px 20px;
  margin: 6px 0;
  position: relative;
}
.panel::before {
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 3px;
  border-radius: 3px 0 0 3px;
}
.panel-low::before      { background: #00e676; }
.panel-medium::before   { background: #ffd600; }
.panel-high::before     { background: #ff6d00; }
.panel-critical::before { background: #ff1744; }
.panel-normal::before   { background: #00c8ff; }

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 2px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1px;
}
.badge-LOW      { color:#00e676; border:1px solid #00e676; background:rgba(0,230,118,0.08); }
.badge-MEDIUM   { color:#ffd600; border:1px solid #ffd600; background:rgba(255,214,0,0.08); }
.badge-HIGH     { color:#ff6d00; border:1px solid #ff6d00; background:rgba(255,109,0,0.08); }
.badge-CRITICAL { color:#ff1744; border:1px solid #ff1744; background:rgba(255,23,68,0.1); animation:blink 0.9s infinite; }

@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

.critical-banner {
  background: linear-gradient(90deg,rgba(255,23,68,0.15),rgba(255,23,68,0.03));
  border: 1px solid #ff1744;
  border-left: 4px solid #ff1744;
  border-radius: 3px;
  padding: 10px 18px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: #ff1744;
  animation: blink 1s infinite;
  margin: 6px 0;
}
.normal-banner {
  background: linear-gradient(90deg,rgba(0,200,255,0.07),rgba(0,200,255,0.01));
  border: 1px solid #0077aa;
  border-left: 4px solid #00c8ff;
  border-radius: 3px;
  padding: 10px 18px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  color: #00c8ff;
  margin: 6px 0;
}
.section-label {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9px;
  color: #3a6a8a;
  letter-spacing: 3px;
  text-transform: uppercase;
  margin-bottom: 6px;
}
</style>

<script>
window._alertPlayed = window._alertPlayed || {};
function playAlert(level, eventId) {
  if (window._alertPlayed[eventId]) return;
  window._alertPlayed[eventId] = true;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const sequences = {
      CRITICAL: [{f:880,t:0},{f:660,t:0.13},{f:880,t:0.26},{f:440,t:0.39}],
      HIGH:     [{f:550,t:0},{f:440,t:0.18}]
    };
    (sequences[level] || sequences.HIGH).forEach(({f,t}) => {
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.connect(g); g.connect(ctx.destination);
      o.type = level === 'CRITICAL' ? 'sawtooth' : 'sine';
      o.frequency.value = f;
      const start = ctx.currentTime + t;
      g.gain.setValueAtTime(0, start);
      g.gain.linearRampToValueAtTime(0.3, start + 0.01);
      g.gain.exponentialRampToValueAtTime(0.001, start + 0.12);
      o.start(start);
      o.stop(start + 0.13);
    });
  } catch(e) {}
}
</script>
""", unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
for k, v in {
    "running":False,"events":[],"alert_email":"","smtp_user":"","smtp_pass":"",
    "email_sent":set(),"total_events":0,"critical_count":0,"high_count":0,
    "sound_enabled":True,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

fuzzy = FuzzyThreatEngine()
sim   = AttackSimulator()
LEVEL_COLOR = {"LOW":"#00e676","MEDIUM":"#ffd600","HIGH":"#ff6d00","CRITICAL":"#ff1744"}

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding:8px 0 4px 0">
      <div style="font-family:'Oxanium',sans-serif;font-size:1.4rem;font-weight:700;
                  color:#00c8ff;letter-spacing:4px;">CYBER<span style="color:#3a6a8a">SENSE</span></div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:8px;color:#3a6a8a;
                  letter-spacing:3px;margin-top:2px;">FUZZY THREAT INTELLIGENCE</div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:7px;color:#142840;
                  margin-top:2px;letter-spacing:1px;">NODE: CS-7743 &nbsp;|&nbsp; FIS v2.1 MAMDANI</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown('<hr style="border:none;border-top:1px solid #142840;margin:8px 0">', unsafe_allow_html=True)

    st.markdown('<div class="section-label">Simulation Parameters</div>', unsafe_allow_html=True)
    scenario  = st.selectbox("Scenario", [
        "Normal Day — No Threats",
        "Random Mix",
        "Port Scan Burst",
        "Brute Force Storm",
        "DDoS Wave",
        "Stealth Recon",
        "Zero-Day Behavior",
    ])
    speed     = st.slider("Event Interval (s)", 0.3, 3.0, 1.0, 0.1)
    intensity = st.slider("Attack Intensity",    1, 10, 5)
    st.session_state.sound_enabled = st.toggle("Alert Sound", value=True)

    st.markdown('<hr style="border:none;border-top:1px solid #142840;margin:8px 0">', unsafe_allow_html=True)
    st.markdown('<div class="section-label">Email Alerts — Critical Only</div>', unsafe_allow_html=True)
    ae = st.text_input("Recipient Email", placeholder="analyst@org.com")
    su = st.text_input("SMTP User (Gmail)",placeholder="sender@gmail.com")
    sp = st.text_input("App Password", type="password")
    if ae: st.session_state.alert_email = ae
    if su: st.session_state.smtp_user   = su
    if sp: st.session_state.smtp_pass   = sp

    st.markdown('<hr style="border:none;border-top:1px solid #142840;margin:8px 0">', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("▶  START", use_container_width=True):
            st.session_state.running        = True
            st.session_state.events         = []
            st.session_state.total_events   = 0
            st.session_state.critical_count = 0
            st.session_state.high_count     = 0
            st.session_state.email_sent     = set()
    with c2:
        if st.button("■  STOP", use_container_width=True):
            st.session_state.running = False
    if st.button("↺  CLEAR LOGS", use_container_width=True):
        st.session_state.events         = []
        st.session_state.total_events   = 0
        st.session_state.critical_count = 0
        st.session_state.high_count     = 0

    st.markdown('<hr style="border:none;border-top:1px solid #142840;margin:8px 0">', unsafe_allow_html=True)
    st.markdown('<div class="section-label">Export</div>', unsafe_allow_html=True)
    if st.session_state.events:
        df_exp = pd.DataFrame(st.session_state.events)
        st.download_button("↓ Export CSV", df_exp.to_csv(index=False),
                           "threat_log.csv", "text/csv", use_container_width=True)
        if st.button("⬡ Generate PDF Report", use_container_width=True):
            with st.spinner("Compiling report..."):
                pdf_bytes = generate_pdf_report(st.session_state.events)
            st.download_button("↓ Download PDF", pdf_bytes,
                f"cybersense_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "application/pdf", use_container_width=True)

# ── Page header ───────────────────────────────────────────────────────────────
hc1, hc2 = st.columns([3,1])
with hc1:
    st.markdown("""
    <div style="padding:4px 0 10px 0">
      <div style="font-family:'Oxanium',sans-serif;font-size:1.3rem;font-weight:700;
                  color:#00c8ff;letter-spacing:4px;text-transform:uppercase;">
        Intelligent Cyber Threat Detection &amp; Risk Assessment
      </div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:#3a6a8a;
                  letter-spacing:3px;margin-top:3px;">
        FUZZY INFERENCE ENGINE &nbsp;·&nbsp; MAMDANI FIS &nbsp;·&nbsp; REAL-TIME MONITORING
      </div>
    </div>""", unsafe_allow_html=True)
with hc2:
    now = datetime.now()
    st.markdown(f"""
    <div style="text-align:right;padding-top:6px;">
      <div style="font-family:'IBM Plex Mono',monospace;font-size:14px;color:#00c8ff;
                  letter-spacing:2px;">{now.strftime('%H:%M:%S')}</div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:#3a6a8a;">
        {now.strftime('%d %b %Y')}</div>
    </div>""", unsafe_allow_html=True)

st.markdown('<hr style="border:none;border-top:1px solid #142840;margin:0 0 10px 0">', unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3 = st.tabs(["◈  LIVE MONITOR", "◉  ANALYTICS", "◎  FUZZY ENGINE"])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — LIVE MONITOR
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    status_ph  = st.empty()
    banner_ph  = st.empty()
    metrics_ph = st.empty()
    sound_ph   = st.empty()

    col_gauge, col_log = st.columns([5, 7])
    with col_gauge:
        gauge_ph  = st.empty()
        params_ph = st.empty()
    with col_log:
        log_ph = st.empty()

    # ── Generate new event ────────────────────────────────────────────────
    if st.session_state.running:
        raw    = sim.generate_event(scenario, intensity)
        result = fuzzy.assess(raw)
        result.update(raw)
        result["timestamp"] = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        st.session_state.events.append(result)
        st.session_state.total_events += 1
        lvl = result["threat_level"]
        if lvl == "CRITICAL": st.session_state.critical_count += 1
        if lvl == "HIGH":     st.session_state.high_count     += 1

        # Email alert
        if (lvl == "CRITICAL" and st.session_state.alert_email
                and st.session_state.smtp_user and st.session_state.smtp_pass
                and result["timestamp"] not in st.session_state.email_sent):
            try:
                send_email_alert(st.session_state.alert_email,
                                 st.session_state.smtp_user,
                                 st.session_state.smtp_pass, result)
                st.session_state.email_sent.add(result["timestamp"])
            except: pass

    events = st.session_state.events

    # ── Status bar ────────────────────────────────────────────────────────
    if st.session_state.running:
        mode = "NORMAL DAY SIMULATION" if scenario == "Normal Day — No Threats" else f"SCENARIO: {scenario.upper()}"
        status_ph.markdown(
            f'<div style="background:rgba(0,200,255,0.04);border:1px solid #142840;'
            f'border-left:3px solid #00c8ff;border-radius:3px;padding:7px 14px;'
            f'font-family:\'IBM Plex Mono\',monospace;font-size:10px;'
            f'display:flex;justify-content:space-between;align-items:center;">'
            f'<span><span style="color:#00e676">●</span>&nbsp; SYSTEM ACTIVE &nbsp;|&nbsp; {mode}</span>'
            f'<span style="color:#142840">{datetime.now().strftime("%H:%M:%S")}</span></div>',
            unsafe_allow_html=True)
    else:
        status_ph.markdown(
            '<div style="background:rgba(20,40,64,0.2);border:1px solid #142840;'
            'border-left:3px solid #142840;border-radius:3px;padding:7px 14px;'
            'font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:#142840;">'
            '○ &nbsp;SYSTEM IDLE — SELECT SCENARIO AND PRESS START</div>',
            unsafe_allow_html=True)

    # ── Alert banner + sound ──────────────────────────────────────────────
    if events:
        last = events[-1]
        lvl  = last.get("threat_level","LOW")
        eid  = last["timestamp"].replace(":","").replace(".","")
        if lvl == "CRITICAL":
            banner_ph.markdown(
                f'<div class="critical-banner">'
                f'⚠ &nbsp;CRITICAL THREAT DETECTED &nbsp;|&nbsp; {last.get("attack_type","?")} &nbsp;|&nbsp; '
                f'SRC: {last.get("source_ip","?")} &nbsp;|&nbsp; '
                f'DST PORT: {last.get("destination_port","?")} &nbsp;|&nbsp; '
                f'SCORE: {last.get("risk_score","?")} / 100</div>',
                unsafe_allow_html=True)
            if st.session_state.sound_enabled:
                sound_ph.markdown(f'<script>playAlert("CRITICAL","{eid}");</script>',
                                  unsafe_allow_html=True)
        elif lvl == "HIGH":
            banner_ph.markdown(
                f'<div style="background:rgba(255,109,0,0.06);border:1px solid #ff6d00;'
                f'border-left:4px solid #ff6d00;border-radius:3px;padding:8px 16px;'
                f'font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:#ff6d00;margin:6px 0;">'
                f'▲ &nbsp;HIGH SEVERITY &nbsp;|&nbsp; {last.get("attack_type","?")} &nbsp;|&nbsp; '
                f'SRC: {last.get("source_ip","?")} &nbsp;|&nbsp; '
                f'SCORE: {last.get("risk_score","?")} / 100</div>',
                unsafe_allow_html=True)
            if st.session_state.sound_enabled:
                sound_ph.markdown(f'<script>playAlert("HIGH","{eid}");</script>',
                                  unsafe_allow_html=True)
        elif scenario == "Normal Day — No Threats":
            banner_ph.markdown(
                '<div class="normal-banner">'
                '✓ &nbsp;NETWORK NOMINAL &nbsp;|&nbsp; '
                'ALL SYSTEMS OPERATING WITHIN NORMAL PARAMETERS &nbsp;|&nbsp; NO THREATS DETECTED'
                '</div>', unsafe_allow_html=True)
        else:
            banner_ph.empty()

    # ── Metrics row ───────────────────────────────────────────────────────
    total  = st.session_state.total_events
    crits  = st.session_state.critical_count
    highs  = st.session_state.high_count
    avg_s  = round(sum(e.get("risk_score",0) for e in events)/len(events),1) if events else 0
    last_s = events[-1]["risk_score"] if events else 0
    last_lv= events[-1]["threat_level"] if events else "—"

    with metrics_ph.container():
        m1,m2,m3,m4,m5 = st.columns(5)
        m1.metric("TOTAL EVENTS",   total)
        m2.metric("CRITICAL",       crits)
        m3.metric("HIGH",           highs)
        m4.metric("AVG SCORE",      avg_s)
        m5.metric("CURRENT SCORE",  last_s)

    # ── Gauge ─────────────────────────────────────────────────────────────
    gc = LEVEL_COLOR.get(last_lv, "#00c8ff")
    fig_g = go.Figure(go.Indicator(
        mode="gauge+number",
        value=last_s,
        domain={"x":[0,1],"y":[0,1]},
        title={"text":"RISK SCORE", "font":{"color":"#3a6a8a","family":"IBM Plex Mono","size":10}},
        number={"font":{"color":gc,"family":"Oxanium","size":46},"suffix":"/100"},
        gauge={
            "axis":{"range":[0,100],"tickcolor":"#142840",
                    "tickfont":{"color":"#3a6a8a","size":8},"nticks":6},
            "bar": {"color":gc,"thickness":0.16},
            "bgcolor":"#060f1a","borderwidth":1,"bordercolor":"#142840",
            "steps":[
                {"range":[0,25],  "color":"#040d07"},
                {"range":[25,50], "color":"#0d0d02"},
                {"range":[50,75], "color":"#0d0600"},
                {"range":[75,100],"color":"#0d0004"},
            ],
            "threshold":{"line":{"color":gc,"width":2},"thickness":0.7,"value":last_s}
        }
    ))
    fig_g.update_layout(
        paper_bgcolor="#03070d", plot_bgcolor="#03070d",
        height=260, margin=dict(l=20,r=20,t=35,b=5)
    )
    gauge_ph.plotly_chart(fig_g, use_container_width=True, key=f"g{total}")

    # Params card
    if events:
        e = events[-1]
        params_ph.markdown(f"""
        <div style="background:#060f1a;border:1px solid #142840;border-radius:3px;
                    padding:10px 14px;font-family:'IBM Plex Mono',monospace;font-size:10px;">
          <div class="section-label" style="margin-bottom:8px;">Last Event Parameters</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:3px 20px;">
            <span><span style="color:#3a6a8a">PKT/S &nbsp;</span><span style="color:#00c8ff">{e.get('packet_rate',0):.0f}</span></span>
            <span><span style="color:#3a6a8a">FAILS &nbsp;</span><span style="color:#00c8ff">{e.get('failed_logins',0):.0f}</span></span>
            <span><span style="color:#3a6a8a">PORTS &nbsp;</span><span style="color:#00c8ff">{e.get('port_diversity',0):.0f}</span></span>
            <span><span style="color:#3a6a8a">CONN &nbsp;&nbsp;</span><span style="color:#00c8ff">{e.get('connection_duration',0):.0f}s</span></span>
            <span><span style="color:#3a6a8a">PROTO &nbsp;</span><span style="color:#b8d0e0">{e.get('protocol','?')}</span></span>
            <span><span style="color:#3a6a8a">PORT &nbsp;&nbsp;</span><span style="color:#b8d0e0">{e.get('destination_port','?')}</span></span>
          </div>
          <div style="margin-top:8px;padding-top:6px;border-top:1px solid #142840;
                      color:#3a6a8a;font-size:9px;line-height:1.5;">
            {e.get('explanation','')[:130]}
          </div>
        </div>""", unsafe_allow_html=True)

    # ── Event log ─────────────────────────────────────────────────────────
    if events:
        log_html = (
            '<div style="height:390px;overflow-y:auto;background:#060f1a;'
            'border:1px solid #142840;border-radius:3px;">'
            '<div style="position:sticky;top:0;padding:7px 14px;background:#091525;'
            'border-bottom:1px solid #142840;font-family:\'IBM Plex Mono\',monospace;'
            'font-size:9px;color:#3a6a8a;letter-spacing:2px;'
            'display:grid;grid-template-columns:90px 85px 150px 120px 55px 75px;">'
            '<span>TIME</span><span>LEVEL</span><span>ATTACK TYPE</span>'
            '<span>SOURCE IP</span><span>SCORE</span><span>PROTO</span></div>'
        )
        for e in reversed(events[-50:]):
            lv = e.get("threat_level","LOW")
            c  = LEVEL_COLOR.get(lv,"#00e676")
            bg = "rgba(255,23,68,0.04)" if lv=="CRITICAL" else \
                 "rgba(255,109,0,0.03)" if lv=="HIGH" else "transparent"
            log_html += (
                f'<div style="padding:5px 14px;border-bottom:1px solid #091525;'
                f'font-family:\'IBM Plex Mono\',monospace;font-size:10px;background:{bg};'
                f'display:grid;grid-template-columns:90px 85px 150px 120px 55px 75px;'
                f'align-items:center;">'
                f'<span style="color:#3a6a8a">{e["timestamp"]}</span>'
                f'<span class="badge badge-{lv}">{lv}</span>'
                f'<span style="color:#b8d0e0">{e.get("attack_type","?")}</span>'
                f'<span style="color:{c}">{e.get("source_ip","?")}</span>'
                f'<span style="color:{c};font-weight:600">{e.get("risk_score","?")}</span>'
                f'<span style="color:#3a6a8a">{e.get("protocol","?")}</span>'
                f'</div>'
            )
        log_html += '</div>'
        log_ph.markdown(log_html, unsafe_allow_html=True)

    if st.session_state.running:
        time.sleep(speed)
        st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    if not events:
        st.markdown(
            '<div style="text-align:center;padding:80px;font-family:\'IBM Plex Mono\',monospace;'
            'font-size:10px;color:#142840;letter-spacing:3px;">'
            'NO SESSION DATA — START SIMULATION FIRST</div>',
            unsafe_allow_html=True)
    else:
        df = pd.DataFrame(events)
        df["idx"] = range(len(df))

        # Timeline
        fig_line = go.Figure()
        fig_line.add_trace(go.Scatter(
            x=df["idx"], y=df["risk_score"], mode="lines",
            line=dict(color="#142840", width=1), showlegend=False))
        for lv, col in [("LOW","#00e676"),("MEDIUM","#ffd600"),("HIGH","#ff6d00"),("CRITICAL","#ff1744")]:
            m = df["threat_level"]==lv
            if m.any():
                fig_line.add_trace(go.Scatter(
                    x=df[m]["idx"], y=df[m]["risk_score"], mode="markers",
                    name=lv, marker=dict(color=col, size=5), showlegend=True))
        fig_line.update_layout(
            title=dict(text="RISK SCORE TIMELINE",
                       font=dict(family="IBM Plex Mono",size=10,color="#3a6a8a"),x=0),
            paper_bgcolor="#03070d", plot_bgcolor="#060f1a",
            font=dict(color="#3a6a8a",family="IBM Plex Mono",size=9),
            height=230, margin=dict(l=10,r=10,t=32,b=10),
            xaxis=dict(gridcolor="#091525",zeroline=False,title="Event #"),
            yaxis=dict(gridcolor="#091525",zeroline=False,range=[0,105],title="Score"),
            legend=dict(bgcolor="#060f1a",bordercolor="#142840",borderwidth=1,
                        font=dict(size=9),orientation="h",y=-0.15),
        )
        st.plotly_chart(fig_line, use_container_width=True)

        ca, cb = st.columns(2)
        with ca:
            lc = df["threat_level"].value_counts().reset_index()
            lc.columns = ["Level","Count"]
            cmap = {"LOW":"#00e676","MEDIUM":"#ffd600","HIGH":"#ff6d00","CRITICAL":"#ff1744"}
            fig_d = go.Figure(go.Pie(
                labels=lc["Level"], values=lc["Count"], hole=0.62,
                marker_colors=[cmap.get(l,"#3a6a8a") for l in lc["Level"]],
                textfont=dict(family="IBM Plex Mono",size=9),
            ))
            fig_d.update_layout(
                title=dict(text="THREAT DISTRIBUTION",
                           font=dict(family="IBM Plex Mono",size=10,color="#3a6a8a"),x=0),
                paper_bgcolor="#03070d", font_color="#3a6a8a",
                height=280, margin=dict(l=10,r=10,t=32,b=10),
                legend=dict(bgcolor="#060f1a",bordercolor="#142840",borderwidth=1,font=dict(size=9)),
                annotations=[dict(text=f"<b>{len(df)}</b><br><span style='font-size:9px'>events</span>",
                                  font=dict(color="#00c8ff",family="Oxanium",size=14),showarrow=False)]
            )
            st.plotly_chart(fig_d, use_container_width=True)

        with cb:
            ac = df["attack_type"].value_counts().reset_index()
            ac.columns = ["Attack","Count"]
            fig_b = go.Figure(go.Bar(
                x=ac["Count"], y=ac["Attack"], orientation="h",
                marker=dict(
                    color=ac["Count"],
                    colorscale=[[0,"#091525"],[0.5,"#005577"],[1,"#00c8ff"]],
                    line=dict(color="#142840",width=0.5)),
                text=ac["Count"], textposition="outside",
                textfont=dict(family="IBM Plex Mono",size=9,color="#3a6a8a"),
            ))
            fig_b.update_layout(
                title=dict(text="ATTACK TYPE FREQUENCY",
                           font=dict(family="IBM Plex Mono",size=10,color="#3a6a8a"),x=0),
                paper_bgcolor="#03070d", plot_bgcolor="#060f1a",
                font=dict(color="#3a6a8a",family="IBM Plex Mono",size=9),
                height=280, margin=dict(l=10,r=10,t=32,b=10),
                xaxis=dict(gridcolor="#091525",zeroline=False),
                yaxis=dict(gridcolor="#091525"),
            )
            st.plotly_chart(fig_b, use_container_width=True)

        st.markdown('<div class="section-label" style="margin-top:4px;">Event Log — Last 20</div>',
                    unsafe_allow_html=True)
        show = [c for c in ["timestamp","attack_type","source_ip","packet_rate",
                             "failed_logins","port_diversity","connection_duration",
                             "risk_score","threat_level"] if c in df.columns]
        st.dataframe(df[show].tail(20).reset_index(drop=True),
                     use_container_width=True, height=280)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — FUZZY ENGINE
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<div class="section-label">System Architecture</div>', unsafe_allow_html=True)
    fc1, fc2 = st.columns(2)

    with fc1:
        st.markdown("""
        <div class="panel panel-normal">
          <div class="section-label" style="margin-bottom:10px;">Input Variables</div>
          <table style="width:100%;font-family:'IBM Plex Mono',monospace;font-size:10px;border-collapse:collapse;">
            <tr style="color:#3a6a8a;font-size:9px;border-bottom:1px solid #142840;">
              <td style="padding:4px 6px">VARIABLE</td>
              <td style="padding:4px 6px">RANGE</td>
              <td style="padding:4px 6px">LINGUISTIC SETS</td>
            </tr>
            <tr><td style="padding:5px 6px;color:#00c8ff">packet_rate</td>
                <td style="padding:5px 6px;color:#b8d0e0">0–2000 pkt/s</td>
                <td style="padding:5px 6px;color:#3a6a8a">low · medium · high · very_high</td></tr>
            <tr style="background:rgba(9,21,37,0.6)">
                <td style="padding:5px 6px;color:#00c8ff">failed_logins</td>
                <td style="padding:5px 6px;color:#b8d0e0">0–100</td>
                <td style="padding:5px 6px;color:#3a6a8a">none · few · many · extreme</td></tr>
            <tr><td style="padding:5px 6px;color:#00c8ff">port_diversity</td>
                <td style="padding:5px 6px;color:#b8d0e0">0–1000 ports</td>
                <td style="padding:5px 6px;color:#3a6a8a">single · low · medium · high</td></tr>
            <tr style="background:rgba(9,21,37,0.6)">
                <td style="padding:5px 6px;color:#00c8ff">conn_duration</td>
                <td style="padding:5px 6px;color:#b8d0e0">0–3600 sec</td>
                <td style="padding:5px 6px;color:#3a6a8a">brief · normal · extended · persistent</td></tr>
          </table>
        </div>""", unsafe_allow_html=True)

    with fc2:
        st.markdown("""
        <div class="panel panel-normal">
          <div class="section-label" style="margin-bottom:10px;">Output Variable &amp; Thresholds</div>
          <table style="width:100%;font-family:'IBM Plex Mono',monospace;font-size:10px;border-collapse:collapse;">
            <tr style="color:#3a6a8a;font-size:9px;border-bottom:1px solid #142840;">
              <td style="padding:4px 6px">SCORE</td>
              <td style="padding:4px 6px">LEVEL</td>
              <td style="padding:4px 6px">RECOMMENDED ACTION</td>
            </tr>
            <tr><td style="padding:5px 6px;color:#b8d0e0">0 – 25</td>
                <td style="padding:5px 6px;color:#00e676;font-weight:600">LOW</td>
                <td style="padding:5px 6px;color:#3a6a8a">Continue monitoring</td></tr>
            <tr style="background:rgba(9,21,37,0.6)">
                <td style="padding:5px 6px;color:#b8d0e0">25 – 50</td>
                <td style="padding:5px 6px;color:#ffd600;font-weight:600">MEDIUM</td>
                <td style="padding:5px 6px;color:#3a6a8a">Log and investigate</td></tr>
            <tr><td style="padding:5px 6px;color:#b8d0e0">50 – 75</td>
                <td style="padding:5px 6px;color:#ff6d00;font-weight:600">HIGH</td>
                <td style="padding:5px 6px;color:#3a6a8a">Alert security team</td></tr>
            <tr style="background:rgba(9,21,37,0.6)">
                <td style="padding:5px 6px;color:#b8d0e0">75 – 100</td>
                <td style="padding:5px 6px;color:#ff1744;font-weight:600">CRITICAL</td>
                <td style="padding:5px 6px;color:#3a6a8a">Immediate response</td></tr>
          </table>
          <div style="margin-top:8px;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#3a6a8a;border-top:1px solid #142840;padding-top:6px;">
            Method: Mamdani FIS &nbsp;·&nbsp; Defuzzification: Centroid &nbsp;·&nbsp; Total Rules: 20
          </div>
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-label" style="margin-top:12px;">Active Inference Rules</div>',
                unsafe_allow_html=True)
    rules = [
        ("CRITICAL","packet_rate IS very_high AND port_diversity IS high",    "risk IS critical"),
        ("CRITICAL","failed_logins IS extreme",                                "risk IS critical"),
        ("CRITICAL","packet_rate IS very_high AND failed_logins IS many",      "risk IS critical"),
        ("CRITICAL","port_diversity IS high AND failed_logins IS many",        "risk IS critical"),
        ("CRITICAL","packet_rate IS very_high AND connection_duration IS brief","risk IS critical"),
        ("HIGH",    "packet_rate IS high AND port_diversity IS medium",        "risk IS high"),
        ("HIGH",    "failed_logins IS many AND packet_rate IS medium",         "risk IS high"),
        ("HIGH",    "failed_logins IS many AND connection_duration IS brief",  "risk IS high"),
        ("HIGH",    "packet_rate IS high AND failed_logins IS few",            "risk IS high"),
        ("MEDIUM",  "packet_rate IS medium AND port_diversity IS low",         "risk IS medium"),
        ("MEDIUM",  "failed_logins IS few AND port_diversity IS low",          "risk IS medium"),
        ("MEDIUM",  "port_diversity IS medium AND failed_logins IS none",      "risk IS medium"),
        ("LOW",     "packet_rate IS low AND failed_logins IS none",            "risk IS low"),
        ("LOW",     "packet_rate IS low AND port_diversity IS single",         "risk IS low"),
    ]
    rhtml = '<div style="background:#060f1a;border:1px solid #142840;border-radius:3px;">'
    for lv, cond, conc in rules:
        c = LEVEL_COLOR.get(lv,"#00c8ff")
        rhtml += (
            f'<div style="padding:6px 14px;border-bottom:1px solid #091525;'
            f'font-family:\'IBM Plex Mono\',monospace;font-size:10px;'
            f'display:grid;grid-template-columns:82px 1fr 160px;align-items:center;">'
            f'<span class="badge badge-{lv}">{lv}</span>'
            f'<span style="color:#b8d0e0">IF &nbsp;{cond}</span>'
            f'<span style="color:{c}">THEN &nbsp;{conc}</span></div>'
        )
    rhtml += '</div>'
    st.markdown(rhtml, unsafe_allow_html=True)

    # Manual assessor
    st.markdown('<div class="section-label" style="margin-top:14px;">Manual Threat Assessment</div>',
                unsafe_allow_html=True)
    ac1,ac2,ac3,ac4 = st.columns(4)
    with ac1: t_pr = st.slider("Packet Rate",       0, 2000, 500, key="tpr")
    with ac2: t_fl = st.slider("Failed Logins",     0, 100,  10,  key="tfl")
    with ac3: t_pd = st.slider("Port Diversity",    0, 1000, 50,  key="tpd")
    with ac4: t_cd = st.slider("Conn Duration (s)", 0, 3600, 120, key="tcd")

    if st.button("▶  RUN ASSESSMENT", key="manual_run"):
        res = fuzzy.assess({"packet_rate":t_pr,"failed_logins":t_fl,
                            "port_diversity":t_pd,"connection_duration":t_cd})
        lv = res["threat_level"]
        c  = LEVEL_COLOR.get(lv,"#00c8ff")
        st.markdown(
            f'<div class="panel panel-{lv.lower()}" style="margin-top:10px;">'
            f'<div style="display:flex;align-items:center;gap:24px;">'
            f'<div style="font-family:\'Oxanium\',sans-serif;font-size:3rem;'
            f'font-weight:700;color:{c};line-height:1;">'
            f'{res["risk_score"]}<span style="font-size:1rem;color:#3a6a8a;">/100</span></div>'
            f'<div>'
            f'<div class="badge badge-{lv}">{lv}</div>'
            f'<div style="font-family:\'IBM Plex Mono\',monospace;font-size:10px;'
            f'color:#3a6a8a;margin-top:8px;max-width:480px;line-height:1.6;">'
            f'{res.get("explanation","")}</div>'
            f'</div></div></div>',
            unsafe_allow_html=True)
