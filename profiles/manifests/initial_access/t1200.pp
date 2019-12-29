# A profile for controlling auditing around ATT&CK technique T1200
# URL: https://attack.mitre.org/techniques/T1200/
#
# @param enabled - boolean
class profiles::initial_access::t1200 (
  $enabled = lookup('profiles::initial_access::t1200::enabled', Boolean, 'first', false),
){
  $rules = [
    '-a exit,always -F arch=b64 -S mount -F success=1 -F dir=/media -k t1200_hardware_additions',
    '-a exit,always -F arch=b32 -S umount -F success=1 -F dir=/media -k t1200_hardware_additions',
    '-a exit,always -F arch=b64 -S umount2 -F success=1 -F dir=/media -k t1200_hardware_additions'
  ]

  if $enabled {
    auditd::rule { $rules: }
  }
}
