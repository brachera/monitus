# A profile for controlling auditing around ATT&CK technique T1215
# URL: https://attack.mitre.org/techniques/T1215/
#
# @param enabled - boolean
class profiles::persistence::t1215 (
  $enabled = lookup('profiles::persistence::t1215::enabled', Boolean, 'first', false),
){
  $rules = [
    '-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k t1215_kernel_modules_and_extensions',
    '-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k t1215_kernel_modules_and_extensions',
    '-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k t1215_kernel_modules_and_extensions',
    '-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k t1215_kernel_modules_and_extensions',
    '-a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k t1215_kernel_modules_and_extensions',
    '-w /etc/modprobe.conf -p wa -k t1215_kernel_modules_and_extensions'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
