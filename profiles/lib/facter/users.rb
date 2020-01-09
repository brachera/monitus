require 'etc'

Etc.passwd { |user|

   Facter.add("#{user.name}") do
      setcode do
         user.name
      end
   end

}