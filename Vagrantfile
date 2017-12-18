Vagrant.configure("2") do |config|
#  config.vm.box = "trusty64"
#  config.vm.box_url = "http://cloud-images.ubuntu.com/vagrant/trusty/current/trusty-server-cloudimg-amd64-vagrant-disk1.box"
  config.vm.box = "terrywang/archlinux"

  config.vm.provision :shell, :path => "Vagrantfile.sh", :privileged => false
  config.ssh.username = 'vagrant'
  config.ssh.forward_agent = true
  config.vm.network "forwarded_port", guest: 9999, host: 9999
  config.vm.network "forwarded_port", guest: 9090, host: 9090

#  config.vm.synced_folder "/mnt", "/"

  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--memory", "2048"]
  end
end
