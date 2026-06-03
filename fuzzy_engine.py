"""
Fuzzy Threat Engine
Uses scikit-fuzzy (skfuzzy) to build a Mamdani fuzzy inference system.
Inputs:  packet_rate, failed_logins, port_diversity, connection_duration
Output:  risk_score (0–100)
"""

import numpy as np

try:
    import skfuzzy as fuzz
    from skfuzzy import control as ctrl
    SKFUZZY_AVAILABLE = True
except ImportError:
    SKFUZZY_AVAILABLE = False


class FuzzyThreatEngine:
    def __init__(self):
        if SKFUZZY_AVAILABLE:
            self._build_system()
        else:
            self._system = None

    # ── Build fuzzy control system ─────────────────────────────────────────
    def _build_system(self):
        # ── Universe of discourse ──
        packet_rate         = ctrl.Antecedent(np.arange(0, 2001, 1),  "packet_rate")
        failed_logins       = ctrl.Antecedent(np.arange(0, 101,  1),  "failed_logins")
        port_diversity      = ctrl.Antecedent(np.arange(0, 1001, 1),  "port_diversity")
        connection_duration = ctrl.Antecedent(np.arange(0, 3601, 1),  "connection_duration")
        risk_score          = ctrl.Consequent(np.arange(0, 101,  1),  "risk_score")

        # ── Membership functions ──

        # packet_rate
        packet_rate["low"]       = fuzz.trapmf(packet_rate.universe,   [0,   0,   100, 300])
        packet_rate["medium"]    = fuzz.trimf(packet_rate.universe,    [200, 500,  800])
        packet_rate["high"]      = fuzz.trimf(packet_rate.universe,    [600, 900, 1200])
        packet_rate["very_high"] = fuzz.trapmf(packet_rate.universe,   [1000,1300,2000,2000])

        # failed_logins
        failed_logins["none"]    = fuzz.trapmf(failed_logins.universe, [0,  0,  2,  5])
        failed_logins["few"]     = fuzz.trimf(failed_logins.universe,  [3,  10, 20])
        failed_logins["many"]    = fuzz.trimf(failed_logins.universe,  [15, 30, 50])
        failed_logins["extreme"] = fuzz.trapmf(failed_logins.universe, [40, 60, 100,100])

        # port_diversity
        port_diversity["single"] = fuzz.trapmf(port_diversity.universe,[0,  0,  5,  20])
        port_diversity["low"]    = fuzz.trimf(port_diversity.universe, [10, 50, 150])
        port_diversity["medium"] = fuzz.trimf(port_diversity.universe, [100,250, 500])
        port_diversity["high"]   = fuzz.trapmf(port_diversity.universe,[400,600,1000,1000])

        # connection_duration
        connection_duration["brief"]     = fuzz.trapmf(connection_duration.universe,[0,  0,  10, 30])
        connection_duration["normal"]    = fuzz.trimf(connection_duration.universe, [20, 120,300])
        connection_duration["extended"]  = fuzz.trimf(connection_duration.universe, [200,600,1200])
        connection_duration["persistent"]= fuzz.trapmf(connection_duration.universe,[1000,1800,3600,3600])

        # risk_score
        risk_score["low"]      = fuzz.trapmf(risk_score.universe, [0,  0,  15, 30])
        risk_score["medium"]   = fuzz.trimf(risk_score.universe,  [20, 40, 60])
        risk_score["high"]     = fuzz.trimf(risk_score.universe,  [50, 65, 80])
        risk_score["critical"] = fuzz.trapmf(risk_score.universe, [70, 85, 100,100])

        # ── Fuzzy rules ──
        rules = [
            # CRITICAL
            ctrl.Rule(packet_rate["very_high"] & port_diversity["high"],            risk_score["critical"]),
            ctrl.Rule(failed_logins["extreme"],                                     risk_score["critical"]),
            ctrl.Rule(packet_rate["very_high"] & failed_logins["many"],             risk_score["critical"]),
            ctrl.Rule(port_diversity["high"] & failed_logins["many"],               risk_score["critical"]),
            ctrl.Rule(packet_rate["very_high"] & connection_duration["brief"],      risk_score["critical"]),

            # HIGH
            ctrl.Rule(packet_rate["high"] & port_diversity["medium"],               risk_score["high"]),
            ctrl.Rule(failed_logins["many"] & packet_rate["medium"],                risk_score["high"]),
            ctrl.Rule(port_diversity["high"] & packet_rate["medium"],               risk_score["high"]),
            ctrl.Rule(failed_logins["many"] & connection_duration["brief"],         risk_score["high"]),
            ctrl.Rule(packet_rate["high"] & failed_logins["few"],                   risk_score["high"]),
            ctrl.Rule(connection_duration["persistent"] & packet_rate["high"],      risk_score["high"]),

            # MEDIUM
            ctrl.Rule(packet_rate["medium"] & port_diversity["low"],                risk_score["medium"]),
            ctrl.Rule(failed_logins["few"] & port_diversity["low"],                 risk_score["medium"]),
            ctrl.Rule(packet_rate["high"] & failed_logins["none"],                  risk_score["medium"]),
            ctrl.Rule(connection_duration["extended"] & failed_logins["few"],       risk_score["medium"]),
            ctrl.Rule(port_diversity["medium"] & failed_logins["none"],             risk_score["medium"]),

            # LOW
            ctrl.Rule(packet_rate["low"] & failed_logins["none"],                   risk_score["low"]),
            ctrl.Rule(packet_rate["low"] & port_diversity["single"],                risk_score["low"]),
            ctrl.Rule(failed_logins["none"] & port_diversity["single"],             risk_score["low"]),
            ctrl.Rule(packet_rate["medium"] & failed_logins["none"] & port_diversity["single"], risk_score["low"]),
        ]

        self._ctrl_system = ctrl.ControlSystem(rules)
        self._system      = ctrl.ControlSystemSimulation(self._ctrl_system)

    # ── Public: assess an event dict ──────────────────────────────────────
    def assess(self, event: dict) -> dict:
        pr = float(np.clip(event.get("packet_rate",        100), 0, 2000))
        fl = float(np.clip(event.get("failed_logins",        0), 0, 100))
        pd = float(np.clip(event.get("port_diversity",       1), 0, 1000))
        cd = float(np.clip(event.get("connection_duration", 60), 0, 3600))

        if SKFUZZY_AVAILABLE and self._system:
            try:
                self._system.input["packet_rate"]         = pr
                self._system.input["failed_logins"]       = fl
                self._system.input["port_diversity"]      = pd
                self._system.input["connection_duration"] = cd
                self._system.compute()
                score = round(float(self._system.output["risk_score"]), 1)
            except Exception:
                score = self._fallback_score(pr, fl, pd, cd)
        else:
            score = self._fallback_score(pr, fl, pd, cd)

        score = float(np.clip(score, 0, 100))
        level = self._level(score)
        explanation = self._explain(pr, fl, pd, cd, score)

        return {
            "risk_score":    round(score, 1),
            "threat_level":  level,
            "explanation":   explanation,
        }

    # ── VirusTotal fuzzy score ────────────────────────────────────────────
    def score_from_vt(self, malicious: int, suspicious: int, total: int) -> int:
        if total == 0:
            return 0
        ratio = (malicious + 0.5 * suspicious) / total
        # Fuzzy-style blending
        if malicious >= 10:
            base = 90
        elif malicious >= 5:
            base = 70
        elif malicious >= 2:
            base = 55
        elif malicious == 1:
            base = 40
        elif suspicious >= 3:
            base = 30
        elif suspicious >= 1:
            base = 18
        else:
            base = 5
        score = base + ratio * 10
        return int(np.clip(score, 0, 100))

    # ── Helpers ───────────────────────────────────────────────────────────
    def _level(self, score: float) -> str:
        if score >= 75: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 25: return "MEDIUM"
        return "LOW"

    def _fallback_score(self, pr, fl, pd, cd) -> float:
        """Simple weighted heuristic when skfuzzy is unavailable."""
        s  = min(pr / 2000, 1.0) * 40
        s += min(fl / 100,  1.0) * 30
        s += min(pd / 1000, 1.0) * 20
        s += (1 - min(cd / 3600, 1.0)) * 10   # shorter duration = more suspicious
        return round(s, 1)

    def _explain(self, pr, fl, pd, cd, score) -> str:
        parts = []
        if pr > 1000: parts.append(f"very high packet rate ({pr:.0f} pkt/s)")
        elif pr > 500: parts.append(f"elevated packet rate ({pr:.0f} pkt/s)")
        if fl > 40:  parts.append(f"extreme failed logins ({fl:.0f})")
        elif fl > 15: parts.append(f"many failed login attempts ({fl:.0f})")
        if pd > 400: parts.append(f"high port scan diversity ({pd:.0f} ports)")
        elif pd > 100: parts.append(f"moderate port scanning ({pd:.0f} ports)")
        if cd < 10:  parts.append(f"very short connection ({cd:.0f}s) — typical of automated attacks")
        if not parts:
            return "Traffic parameters within normal ranges. No significant anomalies."
        return "Risk elevated due to: " + "; ".join(parts) + f". Computed score: {score}/100."
