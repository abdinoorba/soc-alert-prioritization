# enrich_iocs.py
import os
import time
import requests

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_DELAY = 16          # seconds between VT requests (free tier)
ABUSE_DELAY = 1        # light delay for AbuseIPDB


def vt_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as e:
        return {"error": f"VT request error: {e}"}
    if r.status_code != 200:
        return {"error": f"VT status {r.status_code}"}

    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
    }


def abuse_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=20)
    except requests.RequestException as e:
        return {"error": f"AbuseIPDB request error: {e}"}
    if r.status_code != 200:
        return {"error": f"AbuseIPDB status {r.status_code}"}

    data = r.json().get("data", {})
    return {
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
    }


def score(vt, abuse):
    if "error" in vt and "error" in abuse:
        return 0.0
    vt_part = 0.0
    if "error" not in vt:
        vt_part = vt["malicious"] * 3.0 + vt["suspicious"] * 1.5
    abuse_part = 0.0
    if "error" not in abuse:
        abuse_part = abuse["abuse_confidence"] / 5.0
    return round(vt_part + abuse_part, 1)


def main():
    if not VT_API_KEY or not ABUSE_API_KEY:
        raise SystemExit("Set VT_API_KEY and ABUSEIPDB_API_KEY env vars first.")

    with open("iocs.txt") as f:
        ips = [line.strip() for line in f if line.strip()]

    results = []

    for i, ip in enumerate(ips, start=1):
        print(f"[{i}/{len(ips)}] {ip}")
        vt = vt_lookup(ip)
        print("  VT:", vt)
        time.sleep(VT_DELAY)

        abuse = abuse_lookup(ip)
        print("  AbuseIPDB:", abuse)
        time.sleep(ABUSE_DELAY)

        results.append((ip, vt, abuse, score(vt, abuse)))
        print()

    # sort by score descending
    results.sort(key=lambda x: x[3], reverse=True)

    print("=== Combined priority ranking ===")
    for ip, vt, abuse, s in results:
        print(
            f"{s:5.1f}  {ip}  "
            f"(VT mal={vt.get('malicious')} susp={vt.get('suspicious')} ; "
            f"Abuse score={abuse.get('abuse_confidence')} reports={abuse.get('total_reports')})"
        )


if __name__ == "__main__":
    main()

