import pytest
from datetime import datetime
from project import parse_log_line, calculate_severity, detect_brute_force


def test_parse_log_line_failed():
    line = "2026-09-01T12:33:39 webserver01 sshd[5369]: Failed password for invalid user root from 203.0.113.45 port 57478 ssh2"
    result = parse_log_line(line)
    assert result == {
        "timestamp": datetime(2026, 9, 1, 12, 33, 39),
        "ip": "203.0.113.45",
        "event_type": "failed_login",
        "port": 57478,
        "user": "root",
    }


def test_parse_log_line_accepted():
    line = "2026-09-01T09:32:07 webserver01 sshd[8362]: Accepted password for admin from 192.168.1.22 port 54061 ssh2"
    result = parse_log_line(line)
    assert result == {
        "timestamp": datetime(2026, 9, 1, 9, 32, 7),
        "ip": "192.168.1.22",
        "event_type": "success_login",
        "port": 54061,
        "user": "admin",
    }


def test_parse_log_line_connection_attempt():
    line = "2026-09-01T12:34:07 webserver01 kernel: Connection attempt from 198.51.100.23 to port 5281"
    result = parse_log_line(line)
    assert result == {
        "timestamp": datetime(2026, 9, 1, 12, 34, 7),
        "ip": "198.51.100.23",
        "event_type": "connection_attempt",
        "port": 5281,
        "user": None,
    }


def test_parse_log_line_no_match():
    line = "2026-09-01T08:00:00 webserver01 systemd[1]: Started something unrelated"
    assert parse_log_line(line) is None


def test_calculate_severity_brute_force():
    assert calculate_severity({"type": "brute_force", "count": 20}) == "CRITICAL"
    assert calculate_severity({"type": "brute_force", "count": 8}) == "HIGH"
    assert calculate_severity({"type": "brute_force", "count": 5}) == "MEDIUM"


def test_calculate_severity_port_scan():
    assert calculate_severity({"type": "port_scan", "port_count": 25}) == "CRITICAL"
    assert calculate_severity({"type": "port_scan", "port_count": 12}) == "HIGH"
    assert calculate_severity({"type": "port_scan", "port_count": 6}) == "MEDIUM"


def test_calculate_severity_unusual_hours():
    assert calculate_severity({"type": "unusual_hours"}) == "LOW"


def test_detect_brute_force_flags_burst():
    entries = [
        {"timestamp": datetime(2026, 9, 1, 12, 0, 0), "ip": "1.2.3.4", "event_type": "failed_login", "port": 1, "user": "root"},
        {"timestamp": datetime(2026, 9, 1, 12, 0, 5), "ip": "1.2.3.4", "event_type": "failed_login", "port": 2, "user": "root"},
        {"timestamp": datetime(2026, 9, 1, 12, 0, 10), "ip": "1.2.3.4", "event_type": "failed_login", "port": 3, "user": "root"},
        {"timestamp": datetime(2026, 9, 1, 12, 0, 15), "ip": "1.2.3.4", "event_type": "failed_login", "port": 4, "user": "root"},
    ]
    findings = detect_brute_force(entries, threshold=4, time_window_seconds=60)
    assert len(findings) == 1
    assert findings[0]["ip"] == "1.2.3.4"
    assert findings[0]["count"] == 4


def test_detect_brute_force_ignores_spread_out_attempts():
    entries = [
        {"timestamp": datetime(2026, 9, 1, 8, 0, 0), "ip": "1.2.3.4", "event_type": "failed_login", "port": 1, "user": "root"},
        {"timestamp": datetime(2026, 9, 1, 10, 0, 0), "ip": "1.2.3.4", "event_type": "failed_login", "port": 2, "user": "root"},
        {"timestamp": datetime(2026, 9, 1, 12, 0, 0), "ip": "1.2.3.4", "event_type": "failed_login", "port": 3, "user": "root"},
        {"timestamp": datetime(2026, 9, 1, 14, 0, 0), "ip": "1.2.3.4", "event_type": "failed_login", "port": 4, "user": "root"},
    ]
    findings = detect_brute_force(entries, threshold=4, time_window_seconds=60)
    assert findings == []


def test_detect_brute_force_ignores_success_logins():
    entries = [
        {"timestamp": datetime(2026, 9, 1, 12, 0, 0), "ip": "1.2.3.4", "event_type": "success_login", "port": 1, "user": "root"},
        {"timestamp": datetime(2026, 9, 1, 12, 0, 5), "ip": "1.2.3.4", "event_type": "success_login", "port": 2, "user": "root"},
    ]
    findings = detect_brute_force(entries, threshold=2, time_window_seconds=60)
    assert findings == []