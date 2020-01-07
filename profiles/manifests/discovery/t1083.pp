class profiles::discovery::t1083(
    $enabled = lookup('profiles::discovery::t1083', Boolean, 'first', true),
) {
  $rules = ['-w /usr/bin/ls -p x -k t1083_file_and_directory_discovery',
            '-w /usr/bin/find -p x -k t1083_file_and_directory_discovery']

  if $enabled {
    auditd::rule { $rules: }
  }
}
