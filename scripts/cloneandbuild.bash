#/bin/bash

mkdir build
cd build

git clone git://dpdk.org/dpdk
cd dpdk

#meson -Dexamples=ecdc,helloworld,l2fwd,l3fwd build
meson build
cd build
ninja
sudo ninja install
sudo ldconfig
