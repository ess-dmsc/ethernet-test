#!/bin/bash

function errexit() {
  echo "error: $1"
  exit
}

rm -fr dpdk/app/ecdc-pmd
cp -r app/ecdc-pmd dpdk/app
cp app/meson.build dpdk/app

cd dpdk || errexit "dpdk dir doesnt exist - make clone ?"

if [[ -d build ]]; then
  echo meson reconfigure
  meson --reconfigure build
else
  echo meson build
  meson build
fi

cd build
ninja
