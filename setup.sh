#!/bin/sh

make clean
make
sudo install -d /lib/modules/$(uname -r)/extra
sudo make install
sudo depmod -a
sudo modprobe fuzzer
