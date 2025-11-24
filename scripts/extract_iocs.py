# extract_iocs.py
import json
from collections import Counter
from pathlib import Path

EVE_PATH = Path("suricata_output/eve.json")
OUTPUT = Path("iocs.txt")
TOP_N = 10   # extract top 10 most active attacker IPs

def main():
    if not EVE_PATH.exists():
        raise SystemExit(f"Cannot find {EVE_PATH}")

    ip_counts = Counter()

    # Count how many alerts each IP generated
    with EVE_PATH.open() as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            src_ip = event.get("src_ip")
            if src_ip:
                ip_counts[src_ip] += 1

    # Get top N IPs
    top_ips = [ip for ip, _ in ip_counts.most_common(TOP_N)]

    # Write them to iocs.txt
    with OUTPUT.open("w") as f:
        for ip in top_ips:
            f.write(ip + "\n")

    print(f"Extracted top {TOP_N} IPs by alert volume:")
    for ip, count in ip_counts.most_common(TOP_N):
        print(f"{count:5}  {ip}")

    print(f"\nSaved to {OUTPUT}")

if __name__ == "__main__":
    main()
