Facter.add(:bash_histories) do
    setcode do
        Facter::Core::Execution.execute('find /home -name .bash_history')
    end
end