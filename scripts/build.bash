#/bin/bash

mkdir build
cd build

git clone git://dpdk.org/dpdk
cd dpdk

ln -s ../../src/ecdc examples/ecdc

meson -Dexamples=ecdc,helloworld,l2fwd,l3fwd build
cd build
ninja
