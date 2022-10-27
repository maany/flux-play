VAGRANT_EXPERIMENTAL="disks"

NUM_WORKER_NODES=2
NUM_STORAGE_NODES=1
IP_NW="172.16.16."
IP_START=10

Vagrant.configure("2") do |config|
  config.vm.provision "shell", env: {"IP_NW" => IP_NW, "IP_START" => IP_START}, inline: <<-SHELL
      apt-get update -y
      echo "$IP_NW$((IP_START)) master-node" >> /etc/hosts
      for i in $(seq 1 $NUM_WORKER_NODES); do
        echo "$IP_NW$((IP_START+i)) worker-node${i}" >> /etc/hosts
      done
      for i in $(seq 1 $NUM_STORAGE_NODES); do
        echo "$IP_NW$((IP_START+NUM_WORKER_NODES+i)) storage-node${i}" >> /etc/hosts
      done
  SHELL

  config.vm.box = "bento/ubuntu-22.04"
  config.vm.box_check_update = true

  config.vm.define "master" do |master|
    # master.vm.box = "bento/ubuntu-18.04"
    master.vm.hostname = "master-node"
    master.vm.network "private_network", ip: IP_NW + "#{IP_START}"
    master.vm.provider "virtualbox" do |vb|
        vb.memory = 4096
        vb.cpus = 2
    end
    master.vm.provision "shell", path: "scripts/common.sh"
    master.vm.provision "shell", path: "scripts/master.sh"
  end

  (1..NUM_WORKER_NODES).each do |i|

    config.vm.define "node#{i}" do |node|
      node.vm.hostname = "worker-node#{i}"
      node.vm.network "private_network", ip: IP_NW + "#{IP_START + i}"
      node.vm.provider "virtualbox" do |vb|
          vb.memory = 4096
          vb.cpus = 1
      end
      node.vm.provision "shell", path: "scripts/common.sh"
      node.vm.provision "shell", path: "scripts/node.sh"
    end
  end

  (1..NUM_STORAGE_NODES).each do |i|
    config.vm.define "storage#{i}" do |node|
      node.vm.hostname = "storage-node#{i}"
      node.vm.network "private_network", ip: IP_NW + "#{IP_START + NUM_WORKER_NODES + i}"
      node.vm.disk :disk, size: "5GB", primary: true, name: "storage#{i}"
      # node.vm.disksize.size = '5GB'
      node.vm.provider "virtualbox" do |vb|
        vb.memory = 1024
        vb.cpus = 1
      end
      node.vm.provision "shell", path: "scripts/common.sh"
      node.vm.provision "shell", path: "scripts/node.sh"
      node.vm.provision "shell", path: "scripts/storage-node.sh"
    end
  end
end 
