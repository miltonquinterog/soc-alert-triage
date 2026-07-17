from pathlib import Path
import subprocess
import sys

# ==========================
# Project Paths
# ==========================

BASE_DIR = Path(__file__).resolve().parent

from config.settings import SCRIPTS_DIR

SCRIPTS = {
    "1": SCRIPTS_DIR / "alert_classifier.py",
    "2": SCRIPTS_DIR / "brute_force_detector.py",
    "3": SCRIPTS_DIR / "ioc_detector.py",
}


def clear_screen():
    """Print blank lines to separate analyses."""
    print("\n" * 3)


def run_script(script_path):
    """Execute a Python script."""

    try:

        module_name = f"scripts.{script_path.stem}"

        print(f"Executing module: {module_name}")

        subprocess.run(
            [sys.executable, "-m", module_name],
            cwd=BASE_DIR,
            check=True
        )

    except subprocess.CalledProcessError as error:

        print(f"\nError while executing {module_name}:")
        print(error)

def run_full_analysis():

    clear_screen()

    print("=" * 60)
    print("RUNNING FULL SOC ANALYSIS")
    print("=" * 60)

    for script in SCRIPTS.values():

        print(f"\nExecuting: {script.name}\n")

        run_script(script)

    print("\n" + "=" * 60)
    print("Analysis completed successfully.")
    print("=" * 60)


def menu():

    while True:

        print("\n" + "=" * 60)
        print("SOC ALERT TRIAGE TOOLKIT")
        print("=" * 60)

        print("1. Alert Classifier")
        print("2. Brute Force Detector")
        print("3. IOC Detector")
        print("4. Run Full Analysis")
        print("0. Exit")

        option = input("\nSelect an option: ")

        if option == "1":

            clear_screen()
            run_script(SCRIPTS["1"])

        elif option == "2":

            clear_screen()
            run_script(SCRIPTS["2"])

        elif option == "3":

            clear_screen()
            run_script(SCRIPTS["3"])

        elif option == "4":

            run_full_analysis()

        elif option == "0":

            print("\nGoodbye!")
            break

        else:

            print("\nInvalid option.")


if __name__ == "__main__":
    menu()
