#!/usr/bin/env ruby

Vagrant.configure("2") do |config|
	config.vm.define "agent.csf.local" do |c|
    c.vm.box = "bento/centos-7"
    c.vm.hostname = "acute.csf.local"
    c.vm.network "private_network", ip: "192.168.56.40"

    # disable default synced folder.
    c.vm.synced_folder ".", "/vagrant", disabled: true

    c.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = "2"
    end
  end
end
