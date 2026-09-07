#!/usr/bin/env python3
"""
Controller-Native SERVERware Fleet Nginx Audit Tool
Connects directly to Storage Hosts via root@<HOST_IP>:4400 using SSH key trust.
Uses 'lxc-attach' with an in-container shell fallback to inspect PBXware chroots
and standard Ubuntu VPS instances seamlessly without password prompts.
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
  """Queries local MySQL database to map active VPS instances to Storage Host IPs."""
  host_ip_col = get_host_ip_column()
  query = f"""
    SELECT v.name, i.address, h.{host_ip_col}
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
      if len(parts) >= 3:
        vps_name, vps_ip, host_ip = (
            parts[0].strip(),
            parts[1].strip(),
            parts[2].strip(),
        )
        vps_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", vps_ip)
        host_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", host_ip)
        if vps_match and host_match:
          vps_list.append((vps_name, vps_match.group(0), host_match.group(0)))
    return vps_list
  except FileNotFoundError:
    print("[-] Error: 'mysql' command not found on Controller.")
    return []


def inspect_vps_via_host(vps_data):
  """SSHs into Storage Host on port 4400 as root and executes in-container fallback logic."""
  vps_name, vps_ip, host_ip = vps_data

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
      print(f" -> [{vps_name}] ({vps_ip}) on Host [{host_ip}]: Nginx {version}")
      return [vps_name, vps_ip, host_ip, version, "Host LXC Attach"]
    elif "Nginx Not Found" in output:
      print(f" -> [{vps_name}] ({vps_ip}) on Host [{host_ip}]: Non-Nginx VPS")
      return [vps_name, vps_ip, host_ip, "Not Installed", "Host LXC Attach"]
  except Exception:
    pass

  print(
      f" -> [{vps_name}] ({vps_ip}) on Host [{host_ip}]: Connection or"
      " Execution Error"
  )
  return [vps_name, vps_ip, host_ip, "Execution Failed", "Failed"]


def main():
  print("=== Controller Centralized Fleet Nginx Audit ===")
  vps_list = get_vps_host_mappings()
  if not vps_list:
    print("[-] No running VPS instances mapped to hosts.")
    return

  print(
      f"[+] Mapped {len(vps_list)} active VPS instances. Connecting to Hosts"
      f" via {HOST_USER}@{HOST_SSH_PORT}..."
  )

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
        ["VPS Name", "VPS IP", "Host IP", "Nginx Version", "Detection Method"]
    )
    writer.writerows(all_results)

  print(f"\n[+] Audit complete! Report saved to '{OUTPUT_CSV}'.")


if __name__ == "__main__":
  main()
