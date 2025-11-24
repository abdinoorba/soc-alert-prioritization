import json
from collections import Counter, defaultdict
from pathlib import Path

EVE_PATH = Path("suricata_output/eve.json")

def load_alerts(path: Path):
    alerts = []
    with path.open() as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts

def main():
    alerts = load_alerts(EVE_PATH)
    print(f"Total alerts: {len(alerts)}")

    # Top 10 signatures
    sig_counts = Counter(a["alert"]["signature"] for a in alerts)
    print("\nTop 10 alert signatures:")
    for sig, count in sig_counts.most_common(10):
        print(f"{count:5}  {sig}")

    # Top 10 source IPs
    src_counts = Counter(a["src_ip"] for a in alerts)
    print("\nTop 10 source IPs:")
    for ip, count in src_counts.most_common(10):
        print(f"{count:5}  {ip}")

    # Simple priority scoring: severity + frequency
    scores = defaultdict(float)
    severity_weight = {1: 3.0, 2: 2.0, 3: 1.0}

    for a in alerts:
        sev = a["alert"].get("severity", 3)
        key = (a["src_ip"], a["dest_ip"])
        scores[key] += severity_weight.get(sev, 1.0)

    print("\nTop 10 (src_ip, dest_ip) by priority score:")
    for (src, dst), score in sorted(scores.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{score:6.1f}  {src} -> {dst}")

if __name__ == "__main__":
    main()

