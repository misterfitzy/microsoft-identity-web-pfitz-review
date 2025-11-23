# Run the following commands
#!/bin/bash

# Function to print section header
print_header() {
  echo -e "\n==============================================="
  echo -e "$1"
  echo -e "==============================================="
}

# Get basic system information
print_header "System Information"
echo "Hostname: $(hostname)"
echo "Operating System: $(uname -o)"
echo "Kernel Version: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Uptime: $(uptime -p)"
echo "Date: $(date)"
echo "Boot Time: $(who -b)"

# System Users
print_header "System Users"
echo "List of users:"
cat /etc/passwd | cut -d: -f1
echo
echo "List of users with UID 0 (root privileges):"
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Groups
print_header "Groups"
echo "List of groups:"
cat /etc/group | cut -d: -f1
echo
echo "Groups with members having UID 0:"
awk -F: '$3 == 0 {print $1}' /etc/group

# Running Processes
print_header "Running Processes"
echo "List of running processes:"
ps aux

# Open Ports and Services
print_header "Open Ports and Services"
echo "List of open ports (netstat):"
netstat -tuln
echo
echo "List of open ports (ss):"
ss -tuln

# Installed Packages
print_header "Installed Packages"
echo "List of installed packages (Debian-based systems):"
dpkg -l
echo
echo "List of installed packages (RedHat-based systems):"
rpm -qa

# Cron Jobs
print_header "Cron Jobs"
echo "Cron jobs for all users:"
cat /etc/crontab
echo "Cron jobs for specific users:"
ls /var/spool/cron/crontabs

# Sudo Users
print_header "Sudo Users"
echo "List of users with sudo privileges:"
grep 'sudo' /etc/group
echo "List of sudoers:"
cat /etc/sudoers
echo "Sudoers include files:"
cat /etc/sudoers.d/*

# SSH Configuration
print_header "SSH Configuration"
echo "SSH Configurations:"
cat /etc/ssh/sshd_config | grep -v '^#'

# Disk Information
print_header "Disk Information"
echo "Disk usage (df):"
df -h
echo
echo "Disk partitions (fdisk):"
fdisk -l
echo
echo "Disk usage by directories (du):"
du -sh /* 2>/dev/null

# Filesystem Mounts
print_header "Filesystem Mounts"
echo "List of mounted filesystems:"
mount

# Security Information
print_header "Security Information"
echo "List of installed security patches (Debian-based systems):"
apt list --installed | grep security
echo
echo "List of installed security patches (RedHat-based systems):"
yum list installed | grep security
echo
echo "Firewall status:"
ufw status
echo "AppArmor status:"
aa-status

# SUID/SGID Files
print_header "SUID/SGID Files"
echo "List of files with SUID/SGID permissions:"
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null

# World Writable Files
print_header "World Writable Files"
echo "List of world-writable files:"
find / -type f -perm -002 -exec ls -l {} \; 2>/dev/null

# Sudo History
print_header "Sudo History"
echo "Sudo history:"
cat /var/log/sudo.log 2>/dev/null

# Network Information
print_header "Network Information"
echo "IP addresses and routing:"
ip a
echo "Routing table:"
ip route
echo "DNS Configuration:"
cat /etc/resolv.conf

# System Logs
print_header "System Logs"
echo "Recent system logs (dmesg):"
dmesg | tail -n 20
echo
echo "Recent authentication logs (auth.log):"
tail -n 20 /var/log/auth.log
echo
echo "Recent syslog entries (syslog):"
tail -n 20 /var/log/syslog

echo -e "\nSystem enumeration completed."

