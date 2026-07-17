
from pathlib import Path
import pandas as pd

from config.settings import WINDOWS_LOG, CLASSIFIED_REPORT



# ==========================
# Event Severity Mapping
# ==========================

SEVERITY = {
    4624: "Low",
    4625: "Medium",
    4672: "High",
    4688: "Medium",
    4720: "Critical",
    4728: "Critical",
}


def load_events():
    """
    Load Windows Security Events from CSV.
    """
    return pd.read_csv(WINDOWS_LOG)


def classify_events(df):
    """
    Assign a severity level based on the Windows Event ID.
    """
    df["Severity"] = df["EventID"].map(SEVERITY)
    return df


def print_summary(df):
    """
    Display event summary and critical alerts.
    """

    print("=" * 60)
    print("SOC ALERT TRIAGE")
    print("=" * 60)

    print(f"\nTotal Events: {len(df)}")

    print("\nAnalyzed Events:\n")

    print(
        df[
            [
                "Timestamp",
                "EventID",
                "Severity",
                "Username",
                "SourceIP",
            ]
        ]
    )

    print("\n" + "=" * 60)
    print("ALERT SUMMARY")
    print("=" * 60)

    summary = df["Severity"].value_counts()

    for level in ["Critical", "High", "Medium", "Low"]:
        print(f"{level:<10}: {summary.get(level, 0)}")

    print("\n" + "=" * 60)
    print("CRITICAL ALERTS")
    print("=" * 60)

    critical = df[df["Severity"] == "Critical"]

    if critical.empty:
        print("No critical alerts detected.")

    else:
        print(
            critical[
                [
                    "Timestamp",
                    "EventID",
                    "Username",
                    "SourceIP",
                    "Description",
                ]
            ]
        )


def generate_report(df):
    """
    Save classified events into a CSV report.
    """

    df.to_csv(CLASSIFIED_REPORT, index=False)

    print("\nReport generated successfully.")
    print(f"Location: {CLASSIFIED_REPORT}")


def main():

    try:

        events = load_events()

        events = classify_events(events)

        print_summary(events)

        generate_report(events)

    except FileNotFoundError:
        print("Error: windows_security.csv was not found.")

    except Exception as error:
        print(f"Unexpected error: {error}")


if __name__ == "__main__":
    main()
