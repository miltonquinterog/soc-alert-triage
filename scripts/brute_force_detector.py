from pathlib import Path
import pandas as pd

from config.settings import WINDOWS_LOG, BRUTE_FORCE_REPORT     


# Windows Event ID for Failed Logon
FAILED_LOGON_EVENT = 4625

# Minimum failed attempts to consider suspicious
THRESHOLD = 3


def load_events():
    """
    Load Windows Security Events from CSV.

    Returns:
        pandas.DataFrame
    """
    return pd.read_csv(WINDOWS_LOG)


def detect_brute_force(df):
    """
    Detect repeated failed logon attempts from the same
    source IP and target user.

    Returns:
        pandas.DataFrame
    """

    failed_events = df[df["EventID"] == FAILED_LOGON_EVENT]

    grouped = (
        failed_events
        .groupby(["SourceIP", "Username"])
        .size()
        .reset_index(name="FailedAttempts")
    )

    suspicious = grouped[grouped["FailedAttempts"] >= THRESHOLD].copy()

    return suspicious


def assign_risk(df):
    """
    Assign a risk level according to the number of failed attempts.

    Returns:
        pandas.DataFrame
    """

    if df.empty:
        return df

    def calculate_risk(attempts):

        if attempts >= 5:
            return "High"

        elif attempts >= 3:
            return "Medium"

        return "Low"

    df["Risk"] = df["FailedAttempts"].apply(calculate_risk)

    return df


def print_results(df):
    """
    Display suspicious brute-force activity.
    """

    print("=" * 60)
    print("BRUTE FORCE DETECTOR")
    print("=" * 60)

    if df.empty:

        print("\nNo suspicious activity detected.")
        return

    print("\nSuspicious activity detected:\n")

    print(
        df[
            [
                "SourceIP",
                "Username",
                "FailedAttempts",
                "Risk",
            ]
        ].to_string(index=False)
    )

    print("\n" + "=" * 60)
    print(f"Total Suspicious IPs: {len(df)}")


def save_report(df):
    """
    Save brute-force report to CSV.
    """

    df.to_csv(BRUTE_FORCE_REPORT, index=False)

    print("\nReport generated successfully.")
    print(f"Location: {BRUTE_FORCE_REPORT}")


def main():

    try:

        events = load_events()

        suspicious = detect_brute_force(events)

        suspicious = assign_risk(suspicious)

        print_results(suspicious)

        save_report(suspicious)

    except FileNotFoundError:
        print("Error: windows_security.csv was not found.")

    except Exception as error:
        print(f"Unexpected error: {error}")


if __name__ == "__main__":
    main()
