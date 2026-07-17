from pathlib import Path
import pandas as pd

from config.settings import WINDOWS_LOG, IOC_REPORT

# ==========================
# Indicators of Compromise
# ==========================

IOC_EVENTS = {
    4672: ("Special Privileges Assigned", "High"),
    4720: ("User Account Created", "Critical"),
    4728: ("User Added to Administrators", "Critical"),
}

SUSPICIOUS_PROCESSES = {
    "powershell.exe": "High",
    "cmd.exe": "Medium",
}


def load_events():
    """Load Windows Security Events."""
    return pd.read_csv(WINDOWS_LOG)


def detect_iocs(df):
    """
    Detect basic Indicators of Compromise.
    """

    findings = []

    for _, row in df.iterrows():

        event = row["EventID"]

        if event in IOC_EVENTS:

            description, risk = IOC_EVENTS[event]

            findings.append({
                "Timestamp": row["Timestamp"],
                "EventID": event,
                "Username": row["Username"],
                "SourceIP": row["SourceIP"],
                "Indicator": description,
                "Risk": risk
            })

        elif event == 4688:

            process = str(row["Description"]).lower()

            for executable, risk in SUSPICIOUS_PROCESSES.items():

                if executable in process:

                    findings.append({
                        "Timestamp": row["Timestamp"],
                        "EventID": event,
                        "Username": row["Username"],
                        "SourceIP": row["SourceIP"],
                        "Indicator": f"Execution of {executable}",
                        "Risk": risk
                    })

    return pd.DataFrame(findings)


def print_results(df):

    print("=" * 60)
    print("IOC DETECTOR")
    print("=" * 60)

    if df.empty:

        print("\nNo Indicators of Compromise detected.")
        return

    print("\nIndicators Found:\n")

    print(df.to_string(index=False))


def security_observation(events):

    print("\n" + "=" * 60)
    print("SECURITY OBSERVATION")
    print("=" * 60)

    failed = len(events[events["EventID"] == 4625])
    privileged = len(events[events["EventID"] == 4672])
    admin_group = len(events[events["EventID"] == 4728])

    if failed >= 3 and privileged > 0 and admin_group > 0:

        print("""
Potential attack sequence identified.

Indicators observed:

✓ Multiple failed logon attempts
✓ Privileged account activity
✓ Administrative group modification

Recommendation:

Review the affected account and verify
whether the activity was authorized.
""")

    else:

        print("No suspicious attack sequence identified.")


def save_report(df):

    df.to_csv(IOC_REPORT, index=False)

    print("\nReport generated successfully.")
    print(f"Location: {IOC_REPORT}")


def main():

    try:

        events = load_events()

        findings = detect_iocs(events)

        print_results(findings)

        security_observation(events)

        save_report(findings)

    except FileNotFoundError:
        print("Error: windows_security.csv was not found.")

    except Exception as error:
        print(f"Unexpected error: {error}")


if __name__ == "__main__":
    main()
