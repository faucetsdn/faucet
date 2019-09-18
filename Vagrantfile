# -*- mode: ruby -*-
# vi: set ft=ruby :

# Simulate ActiveModel::Type::Boolean.new.cast(value)
$FALSE_VALUES = [false, 0, "0", "f", "F", "false", "FALSE", "off", "OFF"]

# Should Vagrant will not modify your /etc/exports automatically ?
$env_nfs_export = ENV['VAGRANT_NFS_EXPORT']
if $env_nfs_export
    $nfs_export = $FALSE_VALUES.none? $env_nfs_export
else
    $nfs_export = true
end

prov_env = {
  "DEBIAN_FRONTEND" => "noninteractive",
}

$init = <<SCRIPT
  set -e
  apt -y update
  apt -y install \
    build-essential git tmux vim \
    autoconf automake libtool \
    libssl-dev net-tools
SCRIPT

$python = <<SCRIPT
  set -e
  apt -y install \
    python3-all python3-dev \
    python3-pip python3-venv
SCRIPT

$dockerce = <<SCRIPT
  apt -y install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg |
    apt-key add -
  add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) \
    stable"
  apt -y install \
    containerd.io \
    docker-ce \
    docker-ce-cli
SCRIPT

$mininet = <<SCRIPT
  set -e
  apt -y install \
    mininet \
    openvswitch-switch
SCRIPT

# WAND Open vSwitch
$wand_ovs = <<SCRIPT
  set -e
  apt install apt-transport-https
  echo "deb https://packages.wand.net.nz $(lsb_release -sc) main" >/etc/apt/sources.list.d/wand.list
  curl -s https://packages.wand.net.nz/keyring.gpg -o /etc/apt/trusted.gpg.d/wand.gpg
  apt -y update
  apt -y install openvswitch-switch
SCRIPT

$faucet_dev = <<SCRIPT
  set -e

  ln -sfT /vagrant ~/faucet

  python3 -m pip install --upgrade pip
  python3 -m pip install docker-compose

  python3 -m venv .venv
  . .venv/bin/activate
  python3 -m pip install --upgrade pip

  cd faucet
  python3 -m pip install -r requirements.txt
  python3 -m pip install -e .
SCRIPT

$cleanup = <<SCRIPT
  apt -y clean
  apt -y autoremove
  rm -rf /tmp/*
SCRIPT


Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2004"
  config.vm.box_check_update = false

  config.vm.provider :virtualbox do |v|
    v.cpus = 2
    v.memory = 4 * 1024
  end

  config.vm.provider :libvirt do |v|
    v.cpus = 2
    v.memory = 4 * 1024
    config.vm.synced_folder ".", "/vagrant",
                            type: "nfs", nfs_export: $nfs_export,
                            mount_options: ['local_lock=all']
  end

  ## Dev Machine
  config.vm.define :dev do |dev|
    dev.vm.hostname = "faucet-dev"

    ## Network access
    dev.vm.network :forwarded_port, guest:6653, host:6653 # Faucet OpenFlow
    dev.vm.network :forwarded_port, guest:6654, host:6654 # Gauge OpenFlow
    dev.vm.network :forwarded_port, guest:3000, host:3000 # Grafana Web
    dev.vm.network :forwarded_port, guest:9090, host:9090 # Prometheus Web

    dev.vm.provision :shell, :env => prov_env, :inline => $init
    dev.vm.provision :shell, :env => prov_env, :inline => $python
    dev.vm.provision :shell, :env => prov_env, :inline => $dockerce
    dev.vm.provision :shell, :env => prov_env, :inline => $mininet
    # dev.vm.provision :shell, :env => prov_env, :inline => $wand_ovs
    dev.vm.provision :shell, :env => prov_env, :inline => $cleanup
    dev.vm.provision :shell, :env => prov_env, :inline => $faucet_dev,
                     privileged: false
  end
end
