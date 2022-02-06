sudo ip a add 192.168.10.1/24 dev vip-test
sudo ip link set up dev vip-test
sudo ping 192.168.10.2 -i 0.1
