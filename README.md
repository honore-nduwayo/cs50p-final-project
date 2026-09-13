Report Sample


============================================================
 INTRUSION DETECTION REPORT
 Generated: 2026-09-01T09:42:11
 Log file: sample.log
============================================================

SUMMARY
  Total findings: 4
  CRITICAL: 0   HIGH: 2   MEDIUM: 1   LOW: 1

------------------------------------------------------------
[HIGH] BRUTE-FORCE ATTACK
------------------------------------------------------------
  IP Address     : 203.0.113.45
  Failed Attempts: 8  (threshold: 4)
  Targeted User  : root
  Time Window    : 2026-09-01T08:12:03 → 2026-09-01T08:12:24

------------------------------------------------------------
[HIGH] PORT SCAN
------------------------------------------------------------
  IP Address     : 198.51.100.23
  Distinct Ports : 12  (threshold: 5)
  Ports Touched  : 22, 23, 25, 80, 443, 3389, ...
  Time Window    : 2026-09-01T08:15:00 → 2026-09-01T08:15:14

------------------------------------------------------------
[MEDIUM] BRUTE-FORCE ATTACK
------------------------------------------------------------
  IP Address     : 203.0.113.99
  Failed Attempts: 5  (threshold: 4)
  Targeted User  : root
  Time Window    : 2026-09-01T08:16:02 → 2026-09-01T08:16:09

------------------------------------------------------------
[LOW] UNUSUAL-HOUR LOGIN
------------------------------------------------------------
  IP Address     : 192.168.1.10
  User           : admin
  Timestamp      : 2026-09-01T03:24:00

============================================================
 END OF REPORT
============================================================



Pseudocode for project.py (yours to implement)
main()

Purpose: Orchestrates the whole program.

Call get_args() to read command-line arguments.
Call load_log_file(args.logfile) → get list of parsed entries.
Call each detection function on the entries: detect_brute_force(), detect_port_scan(), detect_unusual_hours().
Combine all findings into one list.
Call generate_report(findings) → get report text.
If args.output was given, call save_report(); otherwise print the report to console.
Exit with code 0 if no critical findings, or a non-zero code if critical findings exist (nice touch for scripting/automation use).
get_args()

Purpose: Define and parse CLI arguments.
Returns: parsed arguments object.
Logic:

Create an argument parser with a description.
Add required positional argument: logfile (path to the log file to analyze).
Add optional argument --failed-login-threshold (int, default 4) — how many failed logins from one IP within the time window counts as brute force.
Add optional argument --port-scan-threshold (int, default 5) — how many distinct ports from one IP within the time window counts as a scan.
Add optional argument --time-window (int, seconds, default 60) — the sliding window used for both detections.
Add optional argument --output (path, default None) — if given, save report to this file instead of just printing.
Return the parsed arguments.
parse_log_line(line)

Purpose: Convert one raw log line into a structured record, or None if it doesn't match a known pattern. This is your core regex/string-parsing function — a great one to unit test.
Input: one string (a single log line).
Returns: a dictionary like {"timestamp": <datetime>, "ip": <str>, "event_type": <str>, "port": <int or None>, "user": <str or None>}, or None.
Logic:

Try to match the line against a "Failed password" pattern → extract timestamp, username, IP, port. If matched, set event_type = "failed_login".
Else try to match against an "Accepted password" pattern → same fields, event_type = "success_login".
Else try to match against a "Connection attempt" pattern → extract timestamp, IP, port only (no username). event_type = "connection_attempt".
If none match, return None (skip malformed/unknown lines).
Convert the extracted timestamp string into an actual datetime object before returning.
load_log_file(filepath)

Purpose: Read the whole file and parse every line.
Input: file path string.
Returns: list of parsed entry dictionaries (skipping any lines that failed to parse).
Logic:

Open the file for reading.
For each line, call parse_log_line().
If the result isn't None, append it to a results list.
Optionally, keep a count of skipped/unparseable lines and print a warning at the end if any were skipped.
Return the results list.
detect_brute_force(entries, threshold, time_window_seconds)

Purpose: Flag IPs with too many failed logins in a short window. Good candidate for unit testing with hand-crafted entry lists.
Input: list of parsed entries, threshold int, time window int.
Returns: list of finding dictionaries.
Logic:

Filter entries to only those where event_type == "failed_login".
Group these by IP address (a dictionary mapping IP → list of timestamps).
For each IP's list of timestamps, sort them chronologically.
Use a sliding-window approach: for each timestamp, count how many other timestamps from the same IP fall within time_window_seconds after it.
If that count reaches or exceeds threshold, flag this IP as a brute-force finding — record IP, total failed attempts, first and last timestamp in the burst.
Avoid flagging the same IP multiple times for overlapping windows — once flagged, move to the next IP.
Return the list of findings.
detect_port_scan(entries, threshold, time_window_seconds)

Purpose: Flag IPs that touch many distinct ports in a short window.
Input/Returns: same shape as above.
Logic:

Filter entries to event_type == "connection_attempt".
Group by IP → list of (timestamp, port) tuples.
Sort each IP's list by timestamp.
Using a sliding time window, count the number of distinct ports touched by that IP within any time_window_seconds span.
If distinct port count reaches or exceeds threshold, flag as a port-scan finding — record IP, list of ports involved, first/last timestamp.
Return the list of findings.
detect_unusual_hours(entries, normal_start_hour, normal_end_hour)

Purpose: Flag successful logins that happen outside normal hours (default suggestion: before 6am or after 10pm).
Logic:

Filter entries to event_type == "success_login".
For each, extract the hour from its timestamp.
If the hour falls outside [normal_start_hour, normal_end_hour], flag it as an unusual-hours finding — record IP, user, timestamp.
Return the list of findings.
calculate_severity(finding)

Purpose: Pure helper — assigns a severity label based on finding type and magnitude. Simple, very testable pure function.
Input: one finding dictionary.
Returns: a string, e.g. "LOW", "MEDIUM", "HIGH", "CRITICAL".
Logic (example thresholds, tune as you like):

If finding["type"] == "brute_force": attempts ≥ 15 → CRITICAL; ≥ 8 → HIGH; else MEDIUM.
If finding["type"] == "port_scan": distinct ports ≥ 20 → CRITICAL; ≥ 10 → HIGH; else MEDIUM.
If finding["type"] == "unusual_hours": always LOW (it's a soft signal, not a hard attack indicator).
Return the resulting label.
generate_report(findings)

Purpose: Turn the list of findings into a readable report string.
Logic:

If findings is empty, return a simple "No suspicious activity detected" message.
Otherwise, call calculate_severity() on each finding and attach the label.
Sort findings by severity (CRITICAL first, then HIGH, MEDIUM, LOW).
Build a header summarizing total findings and counts per severity level.
For each finding, format a readable line/block: type, IP, key details (attempt count / ports / timestamp), and severity.
Join everything into one multi-line string and return it.
save_report(report_text, output_path)

Purpose: Write the report string to a file.
Logic:

Open output_path for writing.
Write report_text to it.
Close the file (or use a context manager).
CS50P testing requirement — which functions to test in test_project.py

You need at least 3 functions besides main() tested. Best candidates, roughly by ease:

parse_log_line() — feed it hand-written sample lines (one of each event type, plus one garbage line), assert the returned dict fields or None.
calculate_severity() — feed it hand-built finding dicts, assert the returned label.
detect_brute_force() — feed it a small hand-crafted list of entries (some clustered failed logins from one IP, some spread out), assert it correctly flags or doesn't flag.