#!/usr/bin/env python3
"""
Controller-Native SERVERware Fleet Nginx Audit Tool
Connects directly to Storage Hosts via root@<HOST_IP>:4400 using SSH key trust.
Formats output as: Host Name/Cluster | Host IP | VPS Name | VPS IP | Nginx Version
"""

import concurrent.futures
import csv
import re
import subprocess

OUTPUT_CSV = "nginx_fleet_audit.csv"
DB_NAME = "serverware"
HOST_SSH_PORT = "4400"
HOST_USER = "root"


def get_host_ip_column():
  """Inspects sw_hosts schema to find the active host IP column name."""
  cmd = ["mysql", DB_NAME, "-N", "-B", "-e", "DESCRIBE sw_hosts;"]
  try:
    res = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if res.returncode == 0:
      columns = [
          line.split("\t")[0].strip()
          for line in res.stdout.strip().split("\n")
          if line.strip()
      ]
      for candidate in [
          "ip_address",
          "ip",
          "mgmt_ip",
          "management_ip",
          "host_ip",
          "address",
      ]:
        if candidate in columns:
          return candidate
  except Exception:
    pass
  return "ip_address"


def get_vps_host_mappings():
  """Queries local MySQL database to map active VPS instances to Storage Hosts."""
  host_ip_col = get_host_ip_column()

  # Selects Host Name, Host IP, VPS Name, VPS IP
  query = f"""
    SELECT h.name, h.{host_ip_col}, v.name, i.address
    FROM sw_vpses v
    JOIN sw_vps_interfaces i ON v.id = i.vps_id
    JOIN sw_hosts h ON v.host_id = h.id
    WHERE v.state = 'RUNNING' 
      AND i.address IS NOT NULL 
      AND i.address != '';
    """
  cmd = ["mysql", DB_NAME, "-N", "-B", "-e", query]
  try:
    res = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if res.returncode != 0:
      print(f"[-] Database Error: {res.stderr.strip()}")
      return []

    vps_list = []
    for line in res.stdout.strip().split("\n"):
      if not line.strip():
        continue
      parts = line.split("\t")
      if len(parts) >= 4:
        host_name = parts[0].strip()
        host_ip = parts[1].strip()
        vps_name = parts[2].strip()
        vps_ip = parts[3].strip()

        host_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", host_ip)
        vps_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", vps_ip)

        if host_match and vps_match:
          vps_list.append(
              (host_name, host_match.group(0), vps_name, vps_match.group(0))
          )
    return vps_list
  except FileNotFoundError:
    print("[-] Error: 'mysql' command not found on Controller.")
    return []


def inspect_vps_via_host(vps_data):
  """SSHs into Storage Host on port 4400 as root and executes in-container fallback logic."""
  host_name, host_ip, vps_name, vps_ip = vps_data

  # In-container shell wrapper:
  # 1. Checks PBXware chroot binary first
  # 2. Checks PBXware wrapper script second
  # 3. Checks standard system Nginx binary for Ubuntu VPS instances
  in_container_shell = (
      "/bin/sh -c '"
      "if [ -f /opt/pbxware/pw/usr/sbin/nginx ]; then "
      "  chroot /opt/pbxware/pw /usr/sbin/nginx -v; "
      "elif [ -f /opt/pbxware/sh/nginx ]; then "
      "  /opt/pbxware/sh/nginx -v; "
      "elif command -v nginx >/dev/null 2>&1; then "
      "  nginx -v; "
      "elif [ -f /usr/sbin/nginx ]; then "
      "  /usr/sbin/nginx -v; "
      "else "
      '  echo "Nginx Not Found"; '
      "fi'"
  )

  ssh_cmd = [
      "ssh",
      "-p",
      HOST_SSH_PORT,
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "ConnectTimeout=5",
      f"{HOST_USER}@{host_ip}",
      f"lxc-attach -n {vps_name} -- {in_container_shell}",
  ]

  version = "Execution Failed"
  try:
    res = subprocess.run(
        ssh_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=8,
    )

    output = res.stderr if res.stderr else res.stdout
    match = re.search(r"nginx/([\d.]+)", output, re.IGNORECASE)

    if match:
      version = match.group(1)
    elif "Nginx Not Found" in output:
      version = "Not Installed"
  except Exception:
    pass

  # Output directly in requested format: Host Name/Cluster | Host IP | VPS Name | VPS IP | Nginx Version
  print(f" -> {host_name} | {host_ip} | {vps_name} | {vps_ip} | Nginx {version}")
  return [host_name, host_ip, vps_name, vps_ip, version]


def main():
  print("=== Controller Centralized Fleet Nginx Audit ===")
  vps_list = get_vps_host_mappings()
  if not vps_list:
    print("[-] No running VPS instances mapped to hosts.")
    return

  print(
      f"[+] Mapped {len(vps_list)} active VPS instances. Connecting via"
      f" {HOST_USER}@{HOST_SSH_PORT}...\n"
  )
  print("Host Name/Cluster | Host IP | VPS Name | VPS IP | Nginx Version")
  print("-" * 75)

  all_results = []
  with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
    futures = [
        executor.submit(inspect_vps_via_host, vps) for vps in vps_list
    ]
    for future in concurrent.futures.as_completed(futures):
      res = future.result()
      if res:
        all_results.append(res)

  with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(
        ["Host Name/Cluster", "Host IP", "VPS Name", "VPS IP", "Nginx Version"]
    )
    writer.writerows(all_results)

  print(f"\n[+] Audit complete! Report saved to '{OUTPUT_CSV}'.")


if __name__ == "__main__":
  main()
