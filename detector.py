import re

# Load IOC list
with open("ioc_list.txt", "r") as file:
    iocs = [line.strip() for line in file]

# Read logs
with open("sample_logs.txt", "r") as file:
    logs = file.readlines()

alerts = []

# Detection patterns
powershell_pattern =  r"powershell"
failed_login_pattern = r"Failed password"

# Check logs
for line in logs:

    # IOC matching
    for ioc in iocs:
        if ioc in line:
            alerts.append(f"[IOC DETECTED] {ioc} -> {line.strip()}")

    # Detect encoded PowerShell
    if re.search(powershell_pattern, line, re.IGNORECASE):
        alerts.append(f"[ENCODED POWERSHELL] -> {line.strip()}")

    # Detect failed login
    if re.search(failed_login_pattern, line, re.IGNORECASE):
        alerts.append(f"[FAILED LOGIN] -> {line.strip()}")

# Print alerts
print("\n=== ALERTS ===\n")

for alert in alerts:
    print(alert)

# Save report
with open("report.txt", "w") as report:
    for alert in alerts:
        report.write(alert + "\n")

print("\nReport saved as report.txt")