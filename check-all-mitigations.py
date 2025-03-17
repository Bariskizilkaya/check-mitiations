import os
import subprocess
from prettytable import PrettyTable

def check_aslr():
    try:
        with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
            value = f.read().strip()
            return "Enabled" if value != "0" else "Disabled"
    except FileNotFoundError:
        return "Unknown"

def check_nx():
    try:
        output = subprocess.check_output(['dmesg'], stderr=subprocess.DEVNULL).decode()
        return "Enabled" if "NX (Execute Disable) protection: active" in output else "Disabled"
    except subprocess.CalledProcessError:
        return "Unknown"

def check_smep():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return "Enabled" if "smep" in f.read() else "Disabled"
    except FileNotFoundError:
        return "Unknown"

def check_smap():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return "Enabled" if "smap" in f.read() else "Disabled"
    except FileNotFoundError:
        return "Unknown"

def check_kptr_restrict():
    try:
        with open('/proc/sys/kernel/kptr_restrict', 'r') as f:
            value = f.read().strip()
            return "Enabled" if value != "0" else "Disabled"
    except FileNotFoundError:
        return "Unknown"

def check_restrict_procfs():
    try:
        with open('/proc/sys/kernel/yama/ptrace_scope', 'r') as f:
            value = f.read().strip()
            return "Enabled" if value != "0" else "Disabled"
    except FileNotFoundError:
        return "Unknown"

def check_uao():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            return "Enabled" if "uao" in f.read() else "Disabled"
    except FileNotFoundError:
        return "Unknown"

def check_mitigations():
    try:
        output = subprocess.check_output(['cat', '/sys/devices/system/cpu/vulnerabilities/*'], stderr=subprocess.DEVNULL).decode()
        return output
    except subprocess.CalledProcessError:
        return "Unknown"

def main():
    table = PrettyTable()
    table.field_names = ["Mitigation", "Status"]
    
    table.add_row(["ASLR", check_aslr()])
    table.add_row(["NX (No Execute)", check_nx()])
    table.add_row(["SMEP (Supervisor Mode Execution Prevention)", check_smep()])
    table.add_row(["SMAP (Supervisor Mode Access Prevention)", check_smap()])
    table.add_row(["kptr_restrict", check_kptr_restrict()])
    table.add_row(["Restrict /proc", check_restrict_procfs()])
    table.add_row(["UAO (User Access Override)", check_uao()])
    
    print(table)
    
    print("\nCPU Vulnerabilities:")
    print(check_mitigations())

if __name__ == "__main__":
    main()
