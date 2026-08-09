# Security Log Analyzer

A Python-based tool for analyzing authentication logs and identifying repeated failed login attempts.

## About

I built this project to practice a common security monitoring task: reviewing authentication events and identifying patterns that may deserve further investigation.

The analyzer reads a log file, extracts failed SSH login attempts, groups them by source IP address, and highlights IPs with repeated failures.

## Features

- Parses authentication log files
- Detects failed SSH login attempts
- Extracts source IP addresses
- Counts failed attempts by IP
- Flags repeated failed-login activity for review
- Handles missing and inaccessible log files
- Produces simple, readable terminal output

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
