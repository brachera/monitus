# A profile for controlling auditing around ATT&CK technique T1055
# URL: https://attack.mitre.org/techniques/T1055/
#
# @param enabled - boolean
class profiles::privilege_escalation::t1055 (
    $enabled = lookup('profiles::privilege_escalation::t1055::enabled', Boolean, 'first', false),
) {
  $rules = [
    '-a always,exit -F arch=b32 -S ptrace -k t1055_process_injection',
    '-a always,exit -F arch=b64 -S ptrace -k t1055_process_injection',
    '-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k t1055_process_injection',
    '-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k t1055_process_injection',
    '-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k t1055_process_injection',
    '-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k t1055_process_injection',
    '-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k t1055_process_injection',
    '-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k t1055_process_injection',
    '-w /etc/ld.so.preload -k t1055_process_injection'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
