Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.provision "shell",
    inline: <<-EOS
      curl https://sh.rustup.rs -sSf | sh -s -- -y
      fallocate -l 128M /tmp/test.img
      mv /tmp/test.img /vagrant/
EOS
end
