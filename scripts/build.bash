#/bin/bash

cd build

cd dpdk

cp -r ../../src/ecdc examples/ecdc

meson --reconfigure build
cd build
ninja
