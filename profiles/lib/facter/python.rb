Facter.add(:py_vers) do
  setcode do
    Facter::Core::Execution.execute('ls /usr/bin | grep "python[2-3].[0-9]$"')
  end
end