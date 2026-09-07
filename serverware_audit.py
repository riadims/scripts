# scripts#!/usr/bin/env python3
import concurrent.futures
import csv
import getpass
import os
import re
import subprocess

print("=== Smart-Auth SERVERware Cluster Audit ===")

# 1. Collect Target Parameters
cluster_name = input("Enter Cluster Name: ").strip() or "Cluster1"
host_ip = (
   input("Enter SERVERware Host IP: ").strip() or ""
)
ssh_port = input("Enter SSH Port [Leave empty for 22]: ").strip() or "22"
ssh_user = input("Enter SSH User: ").strip() or ""

# Authentication States
use_ssh_keys = False
use_sudo_nopasswd = False
ssh_pass = ""
root_pass = ""

# 2. Test SSH Key Authentication
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
   print("  [] Passwordless sudo (NOPASSWD) detected. No passwords required!")
       use_sudo_nopasswd = True
   else:
       print("  [!] Sudo requires elevation. Prompting for root password only.")
       root_pass = getpass.getpass("Enter Root/Sudo Password: ")
else:
   print("  [!] SSH Key authentication unavailable. Falling back to password auth.")
   ssh_pass = getpass.getpass("Enter SSH Password: ")
   root_pass = getpass.getpass("Enter Root/Sudo Password: ")


def run_host_ssh(remote_cmd):
   """Executes commands using the best authentication path available."""
   env = os.environ.copy()

   if use_ssh_keys:
       if use_sudo_nopasswd:
           # Path A: Passwordless SSH + Passwordless Sudo
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
           # Path B: Passwordless SSH + Password Sudo
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
       # Path C: Password SSH + Password Sudo (sshpass)
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
   print(f"\n[+] Discovering VPS instances on {host_ip}...")
   stdout, _ = run_host_ssh("lxc-ls -f")

   containers = []
   if stdout:
       for line in stdout.splitlines():
           if "RUNNING" in line:
               parts = line.split()
               vps_name = parts[0]
               ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
               vps_ip = ip_match.group(0) if ip_match else "Unknown IP"
               containers.append((vps_name, vps_ip))

   return containers


def check_nginx(vps):
   vps_name, vps_ip = vps
   exec_cmd = f"lxc-attach -n {vps_name} -- /opt/pbxware/sh/nginx -v"
   stdout, stderr = run_host_ssh(exec_cmd)

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
       print("[-] No running VPS instances found.")
       return

   print(f"[+] Found {len(vps_list)} running instances. Scanning Nginx...")

   results = []
   with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
       results = list(executor.map(check_nginx, vps_list))

   output_file = "nginx_cluster_audit.csv"
   with open(output_file, "w", newline="") as f:
       writer = csv.writer(f)
       writer.writerow(
           ["Cluster", "Host IP", "VPS Name", "VPS IP", "Nginx Version"]
       )
       writer.writerows(results)

   print(f"\n[+] Audit complete! File saved to '{output_file}'.")


if __name__ == "__main__":
   main()