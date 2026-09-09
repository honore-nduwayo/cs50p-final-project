"""
CS50 Final Project
Name: Honoré Nduwayo
Country: Burundi

"""
# Importing libraries/requirements
import re
import argparse
import datetime
import collections
import sys
from dataclasses import dataclass
import datetime

#{"timestamp": some_datetime, "ip": "203.0.113.45", "event_type": "failed_login", "port": 51422, "user": None}
line =  "2026-09-01T12:33:39 webserver01 sshd[5369]: Failed password for invalid user root from 203.0.113.45 port 57478 ssh2"
line1= "2026-09-01T09:32:07 webserver01 sshd[8362]: Accepted password for admin from 192.168.1.22 port 54061 ssh2"
line2 = "2026-09-01T10:41:35 webserver01 sshd[10830]: Accepted password for svc_web from 10.0.0.8 port 52144 ssh2"

#### Reg Exes for diffrent incidents, by the help of stuck overflow

FAILED   = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*\buser\s+(\w+)\s+from\b\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(\d+)"
ACCEPTED = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*\bfor\s+(\w+)\s+from\b\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(\d+)"
ATTEMPT  = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*\bfrom\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+to\s+port\s+(\d+)"


TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

def main():
    ...
def get_args():
    ...

def parse_log_line(line):
    if "Failed" in line:
        result = re.search(FAILED, line)
        if result:
            return {"timestamp": datetime.strptime(result.group(1), TIME_FORMAT), "ip": result.group(3), "event_type": "failed_login", "port": int(result.group(4)), "user": result.group(2)}
    elif "Accepted" in line:
        result = re.search(ACCEPTED, line)
        if result:
            return {"timestamp": datetime.strptime(result.group(1), TIME_FORMAT), "ip": result.group(3), "event_type": "success_login", "port": int(result.group(4)), "user": result.group(2)}
    else:
        result = re.search(ATTEMPT, line)
        if result:
            return {"timestamp": datetime.strptime(result.group(1), TIME_FORMAT), "ip": result.group(2), "event_type": "connection_attempt", "port": int(result.group(3)), "user": None}
    return None

def load_log_file(filepath):
    ...
def detect_brute_force(entries, threshold, time_window_seconds):
    ...
def detect_port_scan(entries, threshold, time_window_seconds):
    ...

def detect_unusual_hours(entries, normal_start_hour, normal_end_hour):
    ...
def calculate_severity(finding):
    ...

def generate_report(findings):
    ...

def save_report(report_text, output_path):
    ...
    

if __name__ == "__main__":
    main()


