# A profile for controlling auditing around ATT&CK technique T1064
# URL: https://attack.mitre.org/techniques/T1064/
#
# Uses custom python fact to iterate over installed python versions
#
# @param enabled - boolean
class profiles::execution::t1064 (
    $enabled = lookup('profiles::execution::t1064::enabled', Boolean, 'first', false),
) {
  if $enabled {
    $::py_vers.split('\n').each | String $py_ver | {
      auditd::rule { "-w /usr/bin/${py_ver} -p x -k t1064_scripting": }
    }
  }
}
