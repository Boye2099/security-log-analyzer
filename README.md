# Security Log Analyzer

A Python-based defensive security tool for analyzing authentication logs and identifying repeated failed-login activity.

## Overview

This project analyzes synthetic authentication logs, summarizes login activity, and flags source IP addresses that exceed a configurable failed-login threshold.

It was built to practice security monitoring, log analysis, Python data processing, and basic detection logic.

## Features

- Authentication log parsing
- Successful and failed login statistics
- Failed-login aggregation by source IP
- Configurable detection threshold
- JSON report generation
- Synthetic security dataset
- Unit testing

## Usage

Run the analyzer with:

python analyzer.py sample_auth.log

Use a custom detection threshold:

python analyzer.py sample_auth.log --threshold 3

Specify a custom output file:

python analyzer.py sample_auth.log --output report.json

## Example Output

Events analyzed: 7
Failed logins: 5
Flagged sources: 1
Report saved to: report.json

## Project Structure

security-log-analyzer/
├── analyzer.py
├── sample_auth.log
├── tests/
│   └── test_analyzer.py
├── requirements.txt
├── .gitignore
└── README.md

## Skills Demonstrated

- Python
- Security log analysis
- Authentication monitoring
- Detection logic
- CSV processing
- JSON reporting
- Unit testing

## Security Concepts

The project demonstrates a simple approach to identifying repeated authentication failures that could warrant further investigation.

This is a learning project and does not replace a production SIEM or security monitoring platform.

## Data Privacy

The included authentication data is synthetic and contains no real credentials or personal information.

## Future Improvements

- Time-window based detection
- Additional authentication event types
- Severity classification
- CSV report export
- Dashboard visualization
- Integration with a SIEM-style workflow
## Technologies

- Python 3
- Regular expressions
- File handling
- Data structures
- Linux authentication logs
- Git & GitHub

## Example

Using the included sample log:

```text
============================================================
             SECURITY LOG ANALYZER
============================================================

Failed login attempts by source IP:
------------------------------------------------------------
10.0.0.25            Attempts: 5     Status: REVIEW
192.168.1.15         Attempts: 3     Status: MONITOR
172.16.0.8           Attempts: 1     Status: MONITOR

------------------------------------------------------------
Unique source IPs: 3
Total failed attempts: 9
