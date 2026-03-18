import sys
from colorama import Fore, init

init(autoreset=True)

known_ips = ["192.168.1.5", "192.168.1.7"]

# Read logs from file
def read_logs(file_name):
    try:
        with open(file_name) as file:
            return file.readlines()
    except:
        print(Fore.RED + "Error: File not found!")
        sys.exit()

# Analyze logs
def analyze_logs(logs):
    failed_attempts = {}
    alerts = []

    for log in logs:
        parts = log.strip().split("-")

        if len(parts) < 3:
            continue

        status = parts[0].strip()
        ip = parts[1].strip()
        time = parts[2].strip()

        # Unknown IP detection
        if ip not in known_ips:
            alerts.append(("MEDIUM", f"{time} - Unknown IP: {ip}"))

        # Failed login tracking
        if "failed" in status:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # Brute force detection
    for ip, count in failed_attempts.items():
        if count >= 3:
            alerts.append(("HIGH", f"Brute force attack from {ip}"))

    return alerts

# Display alerts (FINAL VERSION)
def display_alerts(alerts):
    print("="*40)
    print(" CLOUD SECURITY LOG ANALYZER ")
    print("="*40)

    high, medium = 0, 0
    shown_ips = set()

    print("\n=== CLOUD SECURITY ALERTS ===\n")

    for level, msg in alerts:
        ip = msg.split()[-1]

        # Avoid duplicate alerts
        if ip in shown_ips:
            continue
        shown_ips.add(ip)

        if level == "HIGH":
            print(Fore.RED + f"[HIGH] {msg}")
            high += 1
        elif level == "MEDIUM":
            print(Fore.YELLOW + f"[MEDIUM] {msg}")
            medium += 1

    print("\n=== SUMMARY ===")
    print(f"High Alerts: {high}")
    print(f"Medium Alerts: {medium}")

    print("\nScan completed successfully ✅")

# Save report
def save_report(alerts):
    with open("report.txt", "w") as file:
        for level, msg in alerts:
            file.write(f"[{level}] {msg}\n")

    print("\nReport saved as report.txt")

# MAIN
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py logs.txt")
        sys.exit()

    file_name = sys.argv[1]

    logs = read_logs(file_name)
    alerts = analyze_logs(logs)

    display_alerts(alerts)
    save_report(alerts)
    



