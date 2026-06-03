"""
Attack Simulator
Generates realistic synthetic network events for each attack type.
"""

import random
import ipaddress


def _random_ip():
    return str(ipaddress.IPv4Address(random.randint(0x01000000, 0xFEFFFFFF)))


ATTACK_PROFILES = {
    "Port Scan Burst": {
        "packet_rate":         (300,  900),
        "failed_logins":       (0,    5),
        "port_diversity":      (400,  950),
        "connection_duration": (2,    15),
        "weight": 1,
    },
    "Brute Force Storm": {
        "packet_rate":         (200,  700),
        "failed_logins":       (40,   100),
        "port_diversity":      (1,    20),
        "connection_duration": (30,   300),
        "weight": 1,
    },
    "DDoS Wave": {
        "packet_rate":         (1200, 2000),
        "failed_logins":       (0,    10),
        "port_diversity":      (1,    5),
        "connection_duration": (1,    10),
        "weight": 1,
    },
    "Stealth Recon": {
        "packet_rate":         (10,   150),
        "failed_logins":       (0,    3),
        "port_diversity":      (100,  400),
        "connection_duration": (300,  1800),
        "weight": 1,
    },
    "Zero-Day Behavior": {
        "packet_rate":         (500,  1500),
        "failed_logins":       (20,   80),
        "port_diversity":      (200,  700),
        "connection_duration": (5,    60),
        "weight": 1,
    },
    "Normal Traffic": {
        "packet_rate":         (10,   200),
        "failed_logins":       (0,    2),
        "port_diversity":      (1,    10),
        "connection_duration": (60,   600),
        "weight": 1,
    },
}

# In Random Mix mode, Normal traffic appears ~30 % of the time
ATTACK_PROFILES["Normal Day Traffic"] = {
    "packet_rate":         (5,    120),
    "failed_logins":       (0,    1),
    "port_diversity":      (1,    8),
    "connection_duration": (60,   900),
    "weight": 1,
}

RANDOM_MIX_WEIGHTS = {
    "Port Scan Burst":    2,
    "Brute Force Storm":  2,
    "DDoS Wave":          2,
    "Stealth Recon":      2,
    "Zero-Day Behavior":  1,
    "Normal Traffic":     3,
}


class AttackSimulator:
    def generate_event(self, scenario: str, intensity: int = 5) -> dict:
        """
        Generate a single synthetic network event.

        Parameters
        ----------
        scenario  : one of the keys in ATTACK_PROFILES, or "Random Mix"
        intensity : 1–10, scales the upper bound of numeric ranges
        """
        multiplier = 0.5 + (intensity / 10) * 1.5   # 0.65 … 2.0

        if scenario == "Random Mix":
            keys    = list(RANDOM_MIX_WEIGHTS.keys())
            weights = [RANDOM_MIX_WEIGHTS[k] for k in keys]
            profile_name = random.choices(keys, weights=weights, k=1)[0]
        elif scenario == "Normal Day — No Threats":
            profile_name = "Normal Day Traffic"
        elif scenario in ATTACK_PROFILES:
            profile_name = scenario
        else:
            profile_name = "Normal Traffic"

        profile = ATTACK_PROFILES[profile_name]

        def _sample(key):
            lo, hi = profile[key]
            if key in ("packet_rate", "port_diversity"):
                hi = min(hi * multiplier, {"packet_rate":2000,"port_diversity":1000}[key])
            elif key == "failed_logins":
                hi = min(hi * multiplier, 100)
            return random.uniform(lo, hi)

        return {
            "attack_type":          profile_name,
            "source_ip":            _random_ip(),
            "destination_ip":       _random_ip(),
            "packet_rate":          round(_sample("packet_rate"),         1),
            "failed_logins":        round(_sample("failed_logins"),        1),
            "port_diversity":       round(_sample("port_diversity"),       1),
            "connection_duration":  round(_sample("connection_duration"),  1),
            "protocol":             random.choice(["TCP","UDP","ICMP","HTTP","HTTPS","SSH","FTP"]),
            "destination_port":     random.choice([22,23,25,53,80,443,445,3389,8080,8443,
                                                   random.randint(1024,65535)]),
        }
