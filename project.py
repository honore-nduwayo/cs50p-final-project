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

##### Project starts here #####

class EntryLog:
    def __init__(self, timestamp, ip, event_type, port, user):
        self.timestamp = timestamp
        self.ip = ip
        self.event_type = event_type
        self.port = port
        self.user = user

    def is_failed_login(self):
        return self.event_type == "failed_login"
    
    def is_success_login(self):
        return self.event_type == "success_login"
    
    def is_connection_attempt(self):
        return self.event_type == "connection_attempt"


entry1 = EntryLog(20, "203.0.113.45", "failed_login", 51422, None)
entry2 = EntryLog(30, "255.255.255.01", "success_login", 4545, None)

print(f"Event1: {entry1.ip}:{entry1.event_type} ({entry1.is_failed_login})")
print(f"Event2: {entry2.ip}:{entry2.event_type} ({entry2.is_failed_login})")

#{"timestamp": some_datetime, "ip": "203.0.113.45", "event_type": "failed_login", "port": 51422, "user": None}

def main():
    ...
def get_args():
    ...

def parse_log_line(line):
    ...
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


