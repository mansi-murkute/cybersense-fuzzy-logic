"""
VirusTotal File Scanner
Uploads a file to VirusTotal v3 API and retrieves scan results.
Free tier: 500 requests/day, 4 requests/minute.
"""

import time
import requests


def scan_file_virustotal(uploaded_file, api_key: str) -> dict:
    """
    Upload a file to VirusTotal and return parsed results.

    Parameters
    ----------
    uploaded_file : Streamlit UploadedFile object
    api_key       : VirusTotal API v3 key

    Returns
    -------
    dict with keys: malicious, suspicious, harmless, undetected, total,
                    file_name, sha256, engine_details, error (on failure)
    """
    headers = {"x-apikey": api_key}

    # ── Step 1: Upload file ───────────────────────────────────────────────
    files = {"file": (uploaded_file.name, uploaded_file.read())}
    try:
        upload_resp = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files,
            timeout=60,
        )
        upload_resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"error": f"Upload failed: {str(e)}"}

    upload_data = upload_resp.json()
    analysis_id = upload_data.get("data", {}).get("id")
    if not analysis_id:
        return {"error": "No analysis ID returned from VirusTotal."}

    # ── Step 2: Poll for results (max 60 s) ───────────────────────────────
    for attempt in range(12):
        time.sleep(5)
        try:
            analysis_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=30,
            )
            analysis_resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            return {"error": f"Analysis poll failed: {str(e)}"}

        analysis_data = analysis_resp.json()
        status = analysis_data.get("data", {}).get("attributes", {}).get("status")

        if status == "completed":
            attrs   = analysis_data["data"]["attributes"]
            stats   = attrs.get("stats", {})
            results = attrs.get("results", {})

            engine_details = {
                engine: {
                    "category": info.get("category"),
                    "result":   info.get("result"),
                }
                for engine, info in results.items()
                if info.get("category") not in ("undetected", "type-unsupported")
            }

            # Try to get SHA256 from file report
            sha256 = "N/A"
            file_id = analysis_data.get("meta", {}).get("file_info", {}).get("sha256")
            if file_id:
                sha256 = file_id

            return {
                "malicious":      stats.get("malicious",      0),
                "suspicious":     stats.get("suspicious",     0),
                "harmless":       stats.get("harmless",       0),
                "undetected":     stats.get("undetected",     0),
                "total":          sum(stats.values()),
                "file_name":      uploaded_file.name,
                "sha256":         sha256,
                "engine_details": engine_details,
            }

    return {"error": "Analysis timed out. Please try again in a moment."}
