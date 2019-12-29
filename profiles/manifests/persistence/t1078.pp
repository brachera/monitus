# A profile for controlling auditing around ATT&CK technique T1078
# URL: https://attack.mitre.org/techniques/T1078/
#
# This profile contains a large number of rules so if enabled could produce a large amount of logs/false positives,
#
# @param enabled - boolean
class profiles::persistence::t1078 (
    $enabled = lookup('profiles::persistence::t1078::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-w /etc/sudoers -p wa -k t1078_valid_accounts',
    '-w /usr/bin/passwd -p x -k t1078_valid_accounts',
    '-w /usr/sbin/groupadd -p x -k t1078_valid_accounts',
    '-w /usr/sbin/groupmod -p x -k t1078_valid_accounts',
    '-w /usr/sbin/addgroup -p x -k t1078_valid_accounts',
    '-w /usr/sbin/useradd -p x -k t1078_valid_accounts',
    '-w /usr/sbin/usermod -p x -k t1078_valid_accounts',
    '-w /usr/sbin/adduser -p x -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/bin/chgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/sbin/pwck -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/suexec -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/newusers -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/ccreds_validate -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/Xorg -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/rlogin -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/rsh -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/kgrantpty -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/rcp -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/newrole -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts',
    '-a always,exit -F path=/usr/bin/kpac_dhcp_helper -F perm=x -F auid>=500 -F auid!=4294967295 -k t1078_valid_accounts'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
