#!/bin/bash

### Hardening Script for Ubuntu Servers.
AUDITDIR="/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"

mkdir -p $AUDITDIR
echo "Disabling Legacy Filesystems"
cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squahfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

echo "Update Repository"
apt-get update -y

echo "Create kmsadmin"
adduser kmsadmin
usermod -G sudo kmsadmin

echo "Install NTP and Switch to KMS NTP server"
apt install ntp -y
cp /etc/ntp.conf $AUDITDIR/ntp_conf_$TIME.bak
sed -i 's/pool 0.ubuntu.pool.ntp.org iburst/#pool 0.ubuntu.pool.ntp.org iburst/g' /etc/ntp.conf
sed -i 's/pool 1.ubuntu.pool.ntp.org iburst/#pool 1.ubuntu.pool.ntp.org iburst/g' /etc/ntp.conf
sed -i 's/pool 2.ubuntu.pool.ntp.org iburst/#pool 2.ubuntu.pool.ntp.org iburst/g' /etc/ntp.conf
sed -i 's/pool 3.ubuntu.pool.ntp.org iburst/#pool 3.ubuntu.pool.ntp.org iburst/g' /etc/ntp.conf
sed -i 's/pool ntp.ubuntu.com/#pool ntp.ubuntu.com/g' /etc/ntp.conf
echo "server 192.168.150.19"  >> /etc/ntp.conf
echo "server 192.168.150.18"  >> /etc/ntp.conf
timedatectl set-timezone Asia/Saigon
systemctl restart ntp

echo "Join Domain"
apt -y install sssd sssd-tools libnss-sss libpam-sss adcli samba-common-bin realmd
realm discover -v kms.com.vn
echo "Input admin account for joining domain"
realm join -v kms.com.vn -U kms/tienmtran
adgpo=$(cat /etc/sssd/sssd.conf | grep ad_gpo_access_control)
if [ "$adgpo" != "ad_gpo_access_control" ]
then
        echo "Add ad gpo"
        echo "ad_gpo_access_control = permissive”" >> /etc/sssd/sssd.conf
else
         echo "already configured sssd"
fi 
systemctl restart sssd
pam-auth-update --enable mkhomedir

echo "Configuring sudoers log..."
sudolog_status=$(cat /etc/sudoers | grep /var/log/sudo.log)

if [ "$sudolog_status" != "/var/log/sudo.log" ]
then
        echo "Add sudolog"
        echo "Defaults  logfile = “/var/log/sudo.log”" >> /etc/sudoers
else
         echo "already configured"
fi 


echo "Removing GCC compiler..."
apt-get -y remove gcc*

echo "Removing legacy services..."
apt-get -y remove rsh-server rsh ypserv tftp tftp-server talk talk-server telnet-server xinetd >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling DNS..."
apt-get -y remove bind >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling FTP Server..."
apt-get -y remove vsftpd >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling Dovecot..."
apt-get -y remove dovecot >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling Samba..."
apt-get -y remove --purge samba smbclient libsmbclient >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling HTTP Proxy Server..."
apt -y remove squid >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling SNMP..."
apt -y remove net-snmp >> $AUDITDIR/service_remove_$TIME.log

echo "Setting Daemon umask..."
cp /etc/init.d/functions $AUDITDIR/functions_$TIME.bak
echo "umask 027" >> /etc/init.d/functions

echo "Disabling Unnecessary Services..."
servicelist=(dhcpd avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd)
for i in ${servicelist[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done

echo "Upgrading password hashing algorithm to SHA512..."
authconfig --passalgo=sha512 --update


echo "Setting core dump security limits..."
echo '* hard core 0' > /etc/security/limits.conf

echo "Generating additional logs..."
echo 'auth,user.* /var/log/user' >> /etc/rsyslog.conf
echo 'kern.* /var/log/kern.log' >> /etc/rsyslog.conf
echo 'daemon.* /var/log/daemon.log' >> /etc/rsyslog.conf
echo 'syslog.* /var/log/syslog' >> /etc/rsyslog.conf
echo 'lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log' >> /etc/rsyslog.conf
touch /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod og-rwx /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chown root:root /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

echo "Enabling auditd service..."
apt-get -y install auditd
systemctl enable auditd

echo "Configuring Audit Log Storage Size..."
cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed -i 's/^space_left_action.*$/space_left_action = SYSLOG/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = SYSLOG/' /etc/audit/auditd.conf

echo "Setting audit rules..."
cat > /etc/audit/audit.rules << "EOF"
-D
-b 320
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-e 2
EOF

echo "Configuring Cron and Anacron..."
apt -y install cronie-anacron >> $AUDITDIR/service_install_$TIME.log
systemctl enable crond
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
/bin/rm -f /etc/cron.deny

echo "Creating Banner..."
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
==================================================================
=        88      a8P     88b           d88     ad88888ba         =
=        88    ,88'      888b         d888    d8"     "8b        =
=        88  ,88"        88`8b       d8'88    Y8,                =
=        88,d88'         88 `8b     d8' 88    `Y8aaaaa,          =
=        8888"88,        88  `8b   d8'  88      `"""""8b,        =
=        88P   Y8b       88   `8b d8'   88            `8b        =
=        88     "88,     88    `888'    88    Y8a     a8P        =
=        88       Y8b    88     `8'     88     "Y88888P"         =
==================================================================
= IT IS AN OFFENSE TO CONTINUE WITHOUT PROPER AUTHORIZATION      =
= This system is restricted to authorized users. Individuals who =
= attempt unauthorized access may result in criminal penalties.  =
= If you are unauthorized, terminate access now. Click OK to     =
= indicate your acceptance of this information.                  =
= Your IP, Login Time, Username has been logged and alert to     =
= KMS System Administrator.                                      =
==================================================================
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
SYKES ASSISTANCE SERVICES AUTHORIZED USE ONLY
EOF

echo "Configuring SSH..."
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 900/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 3/g' /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr"  >> /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

systemctl restart sshd >> $AUDITDIR/service_restart_$TIME.log

echo "Setting default umask for users..."
line_num=$(grep -n "^[[:space:]]*umask" /etc/bashrc | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/bashrc
line_num=$(grep -n "^[[:space:]]*umask" /etc/profile | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/profile

echo "Locking inactive user accounts..."
useradd -D -f 30

echo "Verifying System File Permissions..."
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group
chown root:root /etc/passwd
chown root:root /etc/shadow
chown root:root /etc/gshadow
chown root:root /etc/group


echo "Reviewing User and Group Settings..."
echo "Reviewing User and Group Settings..." >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/passwd >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/shadow >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/group >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/reviewusrgrp_$TIME.log

echo "Checking root PATH integrity..."

if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)" >> $AUDITDIR/root_path_$TIME.log
fi

if [ "`echo $PATH | /bin/grep :$`"  != "" ]; then
    echo "Trailing : in PATH" >> $AUDITDIR/root_path_$TIME.log
fi

p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
        echo "PATH contains ." >> $AUDITDIR/root_path_$TIME.log
        shift
        continue
    fi
    if [ -d $1 ]; then
        dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
           if [ "$dirown" != "root" ] ; then
             echo "$1 is not owned by root" >> $AUDITDIR/root_path_$TIME.log
              fi
    else
            echo "$1 is not a directory" >> $AUDITDIR/root_path_$TIME.log
      fi
    shift
done

echo "Checking Permissions on User Home Directories..."

for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
            echo "Other Read permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log

        fi

        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
            echo "Other Execute permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
done

echo "Checking User Dot File Permissions..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do

        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`

            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
        fi

    done

done

echo "Checking Permissions on User .netrc Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
        fi
    done
done

echo "Checking for Presence of User .rhosts Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
        fi    done
done

echo "Checking Groups in /etc/passwd..."

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:x:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
  fi
done

echo "Checking That Users Are Assigned Home Directories..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist." >> $AUDITDIR/audit_$TIME.log
 fi
done

echo "Checking That Defined Home Directories Exist..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner." >> $AUDITDIR/audit_$TIME.log
 fi
 fi
done

echo "Checking for Duplicate User Names..."

cat /etc/passwd | cut -f1 -d":" | sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Duplicate Group Names..."

cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .netrc Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Checking for Presence of User .forward Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done

echo "Modifying Network Parameters..."
cp /etc/sysctl.conf $AUDITDIR/sysctl.conf_$TIME.bak

cat > /etc/sysctl.conf << 'EOF'
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.route.flush=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF

echo "Disabling IPv6..."
cp /etc/sysconfig/network $AUDITDIR/network_$TIME.bak
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/ipv6.conf

echo "Restricting Access to the su Command..."
cp /etc/pam.d/su $AUDITDIR/su_$TIME.bak
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth        required    pam_wheel.so use_uid" ${pam_su}

echo ""
echo "Successfully Completed"
echo "Please check $AUDITDIR"