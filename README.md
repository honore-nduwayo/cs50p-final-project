# Log Analyzer & Intrusion Detection Script

#### Video Demo: <>

#### Description:

This is my CS50P final project. It is a command line tool that reads a server log file and tries to find signs of an attack, so a person does not have to scroll through thousands of lines by hand.

Every time something happens on a server, like someone logging in or someone trying to log in and failing, it gets written as one line in a log file. On a busy server this can be thousands of lines in a single day. Somewhere inside all that text there might be real evidence that someone is attacking the server, but no human is going to read all of it line by line. That is the problem this program solves.

The program looks for three things.

1. Brute force attacks. This is when one IP address fails to log in many times in a short amount of time, like someone guessing passwords over and over.
2. Port scans. This is when one IP address touches many different ports very fast, like someone checking every door on a house to see which one is unlocked.
3. Unusual hour logins. This is when someone actually succeeds in logging in, but at a strange hour, like 3am. It is not proof of anything bad on its own, it is just something worth a second look.

Once it finds these things it prints a report, sorted so the worst stuff shows up first.

## How it works, roughly

The program reads the log file one line at a time. Each line gets checked against three different patterns, one for a failed login, one for a successful login, and one for a generic connection attempt. If a line does not match any of the three, it just gets skipped, nothing breaks.

Every line that does match turns into a small dictionary with the timestamp, the ip, what kind of event it was, the port, and the username if there is one. Once the whole file has been read this way, three separate functions go through that list looking for their own pattern. They group everything by ip address and check if enough suspicious stuff happened close together in time.

Anything that gets flagged is called a finding. Each finding gets a severity, LOW, MEDIUM, HIGH or CRITICAL, depending on how bad it looks. All the findings get sorted worst first and turned into one readable report, which either prints straight to the terminal or gets saved to a file if you ask for that.

Here is roughly what the report looks like once it runs.

```
============================================================
 INTRUSION DETECTION REPORT
 Generated: 2026-09-01T09:42:11
 Log file: sample.log
============================================================

SUMMARY
  Total findings: 4
  CRITICAL: 0   HIGH: 2   MEDIUM: 1   LOW: 1

[HIGH] BRUTE-FORCE ATTACK
  IP Address     : 203.0.113.45
  Failed Attempts: 8  (threshold: 4)
  Targeted User  : root
  Time Window    : 2026-09-01T08:12:03 to 2026-09-01T08:12:24

[HIGH] PORT SCAN
  IP Address     : 198.51.100.23
  Distinct Ports : 12  (threshold: 5)
  Ports Touched  : 22, 23, 25, 80, 443, 3389, ...
  Time Window    : 2026-09-01T08:15:00 to 2026-09-01T08:15:14

[MEDIUM] BRUTE-FORCE ATTACK
  IP Address     : 203.0.113.99
  Failed Attempts: 5  (threshold: 4)
  Targeted User  : root
  Time Window    : 2026-09-01T08:16:02 to 2026-09-01T08:16:09

[LOW] UNUSUAL-HOUR LOGIN
  IP Address     : 192.168.1.10
  User           : admin
  Timestamp      : 2026-09-01T03:24:00

============================================================
 END OF REPORT
============================================================
```
## Commands

NOTE: THESE COMMANDS USING "python3" as a requirement for macs, for other, you might not need the "3" and simply use "python"

Running the program:

1. python3 project.py sample.log

2. python3 project.py sample.log --failed-login-threshold 4 --port-scan-threshold 5 --time-window 60

3. python3 project.py sample.log --output report.txt


Regenerating test data:

1. python3 generate_test_data.py --output sample.log --lines 200

Running the tests:

1. python3 -m pytest test_project.py

2. python3 -m pytest test_project.py -v

`-v` shows each test name individually, pass or fail, instead of just a summary count.

3. python3 -m pytest test_project.py -v -k parse_log_line

`-k` runs only tests whose name contains that text — useful for rerunning one function's tests while debugging without running the whole suite.


Anything specific among these you want to run right now and check the output of?
## Files in this project

`project.py` is the whole program. It has these functions inside it.

`main()` runs everything in order. It calls `get_args()` to read what the user typed, then `load_log_file()` to read the log, then all three detection functions, then it builds the report and either prints it or saves it depending on what the user asked for.

`get_args()` sets up all the command line flags using argparse. The log file itself is required, everything else like the thresholds has a default value so you do not have to type them every time.

`parse_log_line(line)` takes one single line of text and turns it into a dictionary, or returns None if the line does not match anything we know about. This is the function that uses regex to actually pull the timestamp, ip, user and port out of the raw text.

`load_log_file(filepath)` opens the file and calls `parse_log_line()` on every line, collecting all the ones that worked into one big list.

`detect_brute_force(entries, threshold, time_window_seconds)` looks for ip addresses with too many failed logins close together in time.

`detect_port_scan(entries, threshold, time_window_seconds)` looks for ip addresses touching too many different ports close together in time.

`detect_unusual_hours(entries, normal_start_hour, normal_end_hour)` looks for successful logins that happened outside of normal working hours.

`calculate_severity(finding)` looks at one finding and decides if it is LOW, MEDIUM, HIGH or CRITICAL based on how big the numbers are.

`generate_report(findings)` takes the whole list of findings, sorts them worst first, and turns them into the readable text report shown above.

`save_report(report_text, output_path)` just writes the report text out to a file if the user asked for that.

`test_project.py` has the pytest tests. I tested `parse_log_line`, `calculate_severity` and `detect_brute_force`, since those three do not need any files or setup to test, you can just hand them made up data and check what comes back.

`generate_test_data.py` is a script I wrote to make a fake log file called sample.log, with some normal traffic and some attacks mixed in on purpose, so I would have something real to test the program against while I was building it. It is not part of the actual graded project, just a helper.

`requirements.txt` only has pytest in it. Everything else the program uses, like re, argparse and datetime, is already built into python so there is nothing else to install.

## How to run it

1. First make a test log file if you do not have one already.


python3 generate_test_data.py --output sample.log --lines 200


2. Then run the analyzer on it.


python3 project.py sample.log


3. You can also change the settings if you want.

python3 project.py sample.log --failed-login-threshold 4 --port-scan-threshold 5 --time-window 60 --output report.txt


`failed-login-threshold` is how many failed logins from one ip counts as brute force, default is 4.

`port-scan-threshold` is how many different ports counts as a scan, default is 5.

`time-window` is the number of seconds the program checks within, default is 60.

`output` lets you save the report to a file instead of just printing it in the terminal.

4. To run the tests.


python3 -m pytest test_project.py -v


## A few things I want to mention

I only used the python standard library for the actual program, pytest is only used for testing, nothing else needed to be installed.

I used plain dictionaries instead of a class for the findings and the parsed log entries, mostly to keep things simple while I was still learning how regex and functions fit together. It also made the functions easier to test on their own since a dictionary is just data, nothing hidden inside it.

The time window matters a lot here. Ten failed logins spread out over a whole week is not really an attack, but ten failed logins in eight seconds definitely is. Same total count, very different meaning, so the program checks the time gap between attempts, not just the total.

This project genuinely took me a long time to get right, especially the regex part. My first few attempts at the patterns did not work at all and I had to learn a lot about how regex actually reads a string character by character before it started making sense.

## Author

Honore Nduwayo
Burundi