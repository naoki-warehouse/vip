sudo ip a add 2001:db8::FFFF:0000/64 dev test_tap
sudo ip link set up dev test_tap
sudo liblevelip/level-ip ping 2001:db8::ffff:0000
