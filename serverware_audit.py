#!/usr/bin/env python3
"""
SERVERware LXC Nginx Cluster Audit Tool
Probes SSH keys prior to requesting passwords, dynamically discovers
running VPS instances, and extracts Nginx build versions concurrently.
"""

import concurrent.futures
import csv
import getpass
import os
import re
import shutil
import subprocess
import sys

print("=== SERVERware Cluster Nginx Audit ===")

# 1. Configuration & Prompts
cluster_name = input("Enter Cluster Name: ").strip() or "Cluster-1"
host_ip = input("Enter Host IP: ").strip()
ssh_port = input("Enter SSH Port [22]: ").strip() or "22"
ssh_user = input("Enter SSH User: ").strip() or "root"

use_ssh_keys = False
use_sudo_nopasswd = False
ssh_pass = ""
root_pass = ""

# 2. Probe SSH Key Access First
print(f"\n[+] Probing SSH key access for {ssh_user}@{host_ip}:{ssh_port}...")
key_check = subprocess.run(
    [
        "ssh",
        "-p",
        ssh_port,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=3",
        f"{ssh_user}@{host_ip}",
        "echo auth_ok",
    ],
    capture_output=True,
    text=True,
)

if key_check.returncode == 0 and "auth_ok" in key_check.stdout:
    print("  [✓] SSH Key authentication successful.")
    use_ssh_keys = True

    # Check for passwordless sudo
    sudo_check = subprocess.run(
        [
            "ssh",
            "-p",
            ssh_port,
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            f"{ssh_user}@{host_ip}",
            "sudo -n true",
        ],
        capture_output=True,
        text=True,
    )

    if sudo_check.returncode == 0:
        print("  [✓] Passwordless sudo detected.")
        use_sudo_nopasswd = True
    else:
        print("  [!] Sudo requires elevation.")
        root_pass = getpass.getpass("Enter Root/Sudo Password: ")
else:
    print("  [!] SSH Key unavailable. Falling back to password auth.")

    if not shutil.which("sshpass"):
        print(
            "\n[X] Error: 'sshpass' is required when SSH key authentication is missing."
        )
        print("    Install via package manager (e.g., sudo apt install sshpass)")
        sys.exit(1)

    ssh_pass = getpass.getpass("Enter SSH Password: ")
    root_pass = getpass.getpass("Enter Root/Sudo Password: ")


def run_host_ssh(remote_cmd):
    """Executes host commands via SSH using the active authentication mode."""
    env = os.environ.copy()

    if use_ssh_keys:
        if use_sudo_nopasswd:
            cmd = [
                "ssh",
                "-p",
                ssh_port,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=5",
                f"{ssh_user}@{host_ip}",
                f"sudo {remote_cmd}",
            ]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15
            )
        else:
            cmd = [
                "ssh",
                "-p",
                ssh_port,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=5",
                f"{ssh_user}@{host_ip}",
                f"sudo -S -p '' {remote_cmd}",
            ]
            res = subprocess.run(
                cmd,
                input=f"{root_pass}\n",
                capture_output=True,
                text=True,
                timeout=15,
            )
    else:
        env["SSHPASS"] = ssh_pass
        cmd = [
            "sshpass",
            "-e",
            "ssh",
            "-p",
            ssh_port,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            f"{ssh_user}@{host_ip}",
            f"sudo -S -p '' {remote_cmd}",
        ]
        res = subprocess.run(
            cmd,
            input=f"{root_pass}\n",
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
        )

    return res.stdout.strip(), res.stderr.strip()


def discover_serverware_vps():
    """Discovers all active LXC containers and IP assignments on the host."""
    print(f"\n[+] Discovering VPS instances on {host_ip}...")
    stdout, stderr = run_host_ssh("lxc-ls -f")

    containers = []
    if stdout:
        for line in stdout.splitlines():
            if "RUNNING" in line:
                parts = line.split()
                vps_name = parts[0]
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                vps_ip = ip_match.group(0) if ip_match else "Unknown IP"
                containers.append((vps_name, vps_ip))
    elif stderr:
        print(f"[-] Error querying host: {stderr}")

    return containers


def check_nginx(vps):
    """Fetches Nginx version directly inside the guest LXC container."""
    vps_name, vps_ip = vps
    stdout, stderr = run_host_ssh(
        f"lxc-attach -n {vps_name} -- /opt/pbxware/sh/nginx -v"
    )

    output = stderr if stderr else stdout
    nginx_ver = "Unknown Error"

    match = re.search(r"nginx/([\d.]+)", output)
    if match:
        nginx_ver = match.group(1)
    elif "not found" in output.lower():
        nginx_ver = "Not Installed"
    else:
        nginx_ver = "Execution Failed"

    print(f" -> [{vps_name}] ({vps_ip}): Nginx {nginx_ver}")
    return [cluster_name, host_ip, vps_name, vps_ip, nginx_ver]


def main():
    vps_list = discover_serverware_vps()
    if not vps_list:
        print("[-] No running VPS instances found. Verification aborted.")
        return

    print(
        f"[+] Found {len(vps_list)} running instances. Scanning in parallel..."
    )

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        results = list(executor.map(check_nginx, vps_list))

    output_file = "nginx_cluster_audit.csv"
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["Cluster", "Host IP", "VPS Name", "VPS IP", "Nginx Version"]
        )
        writer.writerows(results)

    print(f"\n[+] Audit complete! Report generated at '{output_file}'.")


if __name__ == "__main__":
    main()

