# A profile for controlling auditing around ATT&CK technique T1166
# URL: https://attack.mitre.org/techniques/T1166/
#
# @param enabled - boolean
class profiles::persistence::t1166 (
  $enabled = lookup('profiles::persistence::t1166::enabled', Boolean, 'first', false),
){
  $rules = [
    '-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -C auid!=uid -S execve -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -C auid!=uid -S execve -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S setuid -S setgid, -S setreuid -S setregid -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S setuid -S setgid, -S setreuid -S setregid -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b64 -S setuid -S setgid, -S setreuid -S setregid -F exit=EPERM -k t1166_setuid_and_setgid',
    '-a always,exit -F arch=b32 -S setuid -S setgid, -S setreuid -S setregid -F exit=EPERM -k t1166_setuid_and_setgid'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
