"""
generate_test_data.py
Generates a synthetic log file with normal traffic plus injected
brute-force and port-scan attack patterns, for testing the
Log Analyzer & Intrusion Detection Script.

Usage:
    python generate_test_data.py
    python generate_test_data.py --output sample.log --lines 300
"""

import argparse
import random
from datetime import datetime, timedelta

NORMAL_USERS = ["admin", "deploy", "backup", "svc_web", "jsmith"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.14", "10.0.0.8", "192.168.1.22"]
ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "203.0.113.99"]
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3389, 8080]


def get_args():
    parser = argparse.ArgumentParser(description="Generate synthetic IDS test log data")
    parser.add_argument("--output", default="sample.log", help="Output log file path")
    parser.add_argument("--lines", type=int, default=200, help="Approx. number of normal traffic lines")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    return parser.parse_args()


def format_timestamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def generate_normal_traffic(start_time, count):
    lines = []
    current_time = start_time
    for _ in range(count):
        current_time += timedelta(seconds=random.randint(5, 300))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(NORMAL_USERS)
        port = random.randint(50000, 60000)
        lines.append(
            f"{format_timestamp(current_time)} webserver01 sshd[{random.randint(1000,20000)}]: "
            f"Accepted password for {user} from {ip} port {port} ssh2"
        )
    return lines, current_time


def generate_brute_force_attack(start_time, attacker_ip, attempts=8):
    lines = []
    current_time = start_time
    fake_user = "root"
    for i in range(attempts):
        current_time += timedelta(seconds=random.randint(1, 4))
        port = random.randint(50000, 60000)
        lines.append(
            f"{format_timestamp(current_time)} webserver01 sshd[{random.randint(1000,20000)}]: "
            f"Failed password for invalid user {fake_user} from {attacker_ip} port {port} ssh2"
        )
    return lines, current_time


def generate_port_scan(start_time, attacker_ip, num_ports=10):
    lines = []
    current_time = start_time
    ports = random.sample(range(1, 65535), num_ports)
    for port in ports:
        current_time += timedelta(seconds=random.uniform(0.2, 1.5))
        lines.append(
            f"{format_timestamp(current_time)} webserver01 kernel: "
            f"Connection attempt from {attacker_ip} to port {port}"
        )
    return lines, current_time


def generate_unusual_hour_login(start_time):
    odd_hour_time = start_time.replace(hour=3, minute=random.randint(0, 59))
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    port = random.randint(50000, 60000)
    line = (
        f"{format_timestamp(odd_hour_time)} webserver01 sshd[{random.randint(1000,20000)}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )
    return line


def main():
    args = get_args()
    random.seed(args.seed)

    all_lines = []
    current_time = datetime(2026, 9, 1, 8, 0, 0)

    # Normal traffic, first half
    normal_lines, current_time = generate_normal_traffic(current_time, args.lines // 2)
    all_lines.extend(normal_lines)

    # Injected brute-force attack
    bf_lines, current_time = generate_brute_force_attack(current_time, ATTACKER_IPS[0], attempts=8)
    all_lines.extend(bf_lines)

    # Injected port scan
    ps_lines, current_time = generate_port_scan(current_time, ATTACKER_IPS[1], num_ports=12)
    all_lines.extend(ps_lines)

    # A second, smaller brute-force burst from a different IP
    bf_lines2, current_time = generate_brute_force_attack(current_time, ATTACKER_IPS[2], attempts=5)
    all_lines.extend(bf_lines2)

    # Normal traffic, second half
    normal_lines2, current_time = generate_normal_traffic(current_time, args.lines // 2)
    all_lines.extend(normal_lines2)

    # A login at an unusual hour (not tied to an attack, just a lone anomaly)
    all_lines.append(generate_unusual_hour_login(current_time))

    # Shuffle only the normal traffic blocks lightly isn't realistic for real logs
    # (real logs are chronological) so we sort everything by timestamp instead
    all_lines.sort(key=lambda line: line.split(" ", 1)[0])

    with open(args.output, "w") as f:
        f.write("\n".join(all_lines) + "\n")

    print(f"Generated {len(all_lines)} log lines → {args.output}")
    print(f"Injected: brute-force from {ATTACKER_IPS[0]} and {ATTACKER_IPS[2]}, port scan from {ATTACKER_IPS[1]}")


if __name__ == "__main__":
    main()