# A profile for controlling auditing around ATT&CK technique T1072
# URL: https://attack.mitre.org/techniques/T1072/
#
# @param enabled - boolean
class profiles::execution::t1072 (
    $enabled = lookup('profiles::execution::t1072::enabled', Boolean, 'first', false),
) {
  case $facts['os']['name'] {
    'Suse': {
      $rules = [
        '-w /sbin/yast -p x -k t1072_third_party_software',
        '-w /sbin/yast2 -p x -k t1072_third_party_software',
        '-w /bin/rpm -p x -k t1072_third_party_software',
        '-w /usr/bin/zypper -k t1072_third_party_software'
      ]
    }
    'RedHat', 'CentOS': {
      $rules = [
        '-w /usr/bin/rpm -p x -k t1072_third_party_software',
        '-w /usr/bin/yum -p x -k t1072_third_party_software'
      ]
    }
    /^(Debian|Ubuntu)$/: {
        $rules = [
          '-w /usr/bin/dpkg -p x -k t1072_third_party_software',
          '-w /usr/bin/apt-add-repository -p x -k t1072_third_party_software',
          '-w /usr/bin/apt-get -p x -k t1072_third_party_software',
          '-w /usr/bin/aptitude -p x -k t1072_third_party_software'
        ]
    }
    default: {
      $rules = [
        '-w /usr/bin/rpm -p x -k t1072_third_party_software',
        '-w /usr/bin/yum -p x -k t1072_third_party_software'
      ]
    }
  }

  if $enabled {
    auditd::rule { $rules: }
  }
}
