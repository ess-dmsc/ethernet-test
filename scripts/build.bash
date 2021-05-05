#/bin/bash

#cd src/ecdc
#make clean
#make
#cd ..

cp -r src/ecdc-pmd build/dpdk/app
cp src/meson.build build/dpdk/app

cd build/dpdk
pwd
if [[ -d build ]]; then
  echo "reconfigure"
  meson --reconfigure build
else
  echo first build
  meson build
fi

cd build
ninja

