import re
import sys
from collections import Counter


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password.*?from (\d+\.\d+\.\d+\.\d+)"
)


def analyze_log(filename):
    failed_attempts = Counter()

    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                match = FAILED_LOGIN_PATTERN.search(line)

                if match:
                    ip_address = match.group(1)
                    failed_attempts[ip_address] += 1

    except FileNotFoundError:
        print(f"[!] File not found: {filename}")
        return

    except PermissionError:
        print(f"[!] Permission denied: {filename}")
        return

    if not failed_attempts:
        print("[+] No failed SSH login attempts detected.")
        return

    print("=" * 60)
    print("             SECURITY LOG ANALYZER")
    print("=" * 60)

    print("\nFailed login attempts by source IP:")
    print("-" * 60)

    for ip, attempts in failed_attempts.most_common():
        status = "REVIEW" if attempts >= 5 else "MONITOR"

        print(
            f"{ip:<20} "
            f"Attempts: {attempts:<5} "
            f"Status: {status}"
        )

    print("\n" + "-" * 60)
    print(f"Unique source IPs: {len(failed_attempts)}")
    print(f"Total failed attempts: {sum(failed_attempts.values())}")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <log-file>")
        sys.exit(1)

    analyze_log(sys.argv[1])


if __name__ == "__main__":
    main()
