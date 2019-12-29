Facter.add(:mozilla_places_sqlites) do
    setcode do
        Facter::Core::Execution.execute('find /home /root -name places.sqlite')
    end
end