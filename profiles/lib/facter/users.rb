require 'etc'

    Facter::Util::Resolution.exec('cat /etc/passwd').each_line do |line|
        line.strip!
        user = line.split(':')

        users << user[0] unless user[2].to_i < 500
    end
    
    Facter.add('users') do
      setcode { users.sort.join(',') }
    end