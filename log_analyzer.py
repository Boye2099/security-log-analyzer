import argparse
import csv
import json
from collections import Counter


def analyze_log(file_path, threshold):
    failed_logins = Counter()
    successful_logins = 0
    total_events = 0

    with open(file_path, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required_fields = {
            "timestamp",
            "username",
            "event",
            "source_ip"
        }

        if not required_fields.issubset(reader.fieldnames or set()):
            raise ValueError(
                "Log file is missing required columns."
            )

        for row in reader:
            total_events += 1

            event = row["event"].strip().lower()

            if event == "failed_login":
                failed_logins[row["source_ip"]] += 1

            elif event == "successful_login":
                successful_logins += 1

    flagged_sources = [
        {
            "source_ip": ip,
            "failed_attempts": count
        }
        for ip, count in failed_logins.items()
        if count >= threshold
    ]

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": sum(failed_logins.values()),
        "failed_logins_by_ip": dict(failed_logins),
        "flagged_sources": flagged_sources,
        "threshold": threshold
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs."
    )

    parser.add_argument(
        "logfile",
        help="Path to the authentication log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required to flag an IP"
    )

    parser.add_argument(
        "--output",
        default="report.json",
        help="Output JSON report"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error(
            "Threshold must be at least 1."
        )

    try:
        report = analyze_log(
            args.logfile,
            args.threshold
        )

    except (OSError, ValueError) as error:
        parser.error(str(error))

    with open(
        args.output,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )

    print(
        f"Events analyzed: "
        f"{report['total_events']}"
    )

    print(
        f"Failed logins: "
        f"{report['failed_logins']}"
    )

    print(
        f"Flagged sources: "
        f"{len(report['flagged_sources'])}"
    )

    print(
        f"Report saved to: "
        f"{args.output}"
    )


if __name__ == "__main__":
    main()    print("=" * 60)

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
