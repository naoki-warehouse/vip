sudo ip a add 192.168.10.1/24 dev vip-test
sudo ip link set up dev vip-test
ping 192.168.10.2
