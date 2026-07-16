from pathlib import Path
import pandas as pd

# ==========================
# Project Paths
# ==========================

BASE_DIR = Path(__file__).resolve().parent.parent

CSV_FILE = BASE_DIR / "data" / "windows_security.csv"
OUTPUT_FILE = BASE_DIR / "reports" / "brute_force_report.csv"

FAILED_LOGON = 4625
THRESHOLD = 3


def load_events():
    """Load Windows Security Events."""
    return pd.read_csv(CSV_FILE)


def detect_brute_force(df):
    """Detect IP addresses with multiple failed logon attempts."""

    failed = df[df["EventID"] == FAILED_LOGON]

    grouped = (
        failed.groupby("SourceIP")
        .size()
        .reset_index(name="FailedAttempts")
    )

    suspicious = grouped[grouped["FailedAttempts"] >= THRESHOLD]

    return suspicious


def print_results(df):

    print("=" * 60)
    print("BRUTE FORCE DETECTOR")
    print("=" * 60)

    if df.empty:
        print("\nNo suspicious activity detected.")

    else:
        print("\nSuspicious IP addresses:\n")
        print(df)


def save_report(df):

    df.to_csv(OUTPUT_FILE, index=False)

    print("\nReport generated successfully.")
    print(f"Location: {OUTPUT_FILE}")


def main():

    try:

        events = load_events()

        suspicious = detect_brute_force(events)

        print_results(suspicious)

        save_report(suspicious)

    except FileNotFoundError:
        print("CSV file not found.")

    except Exception as error:
        print(f"Unexpected error: {error}")


if __name__ == "__main__":
    main()
