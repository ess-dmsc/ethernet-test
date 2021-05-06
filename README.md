# ethernet-test
Experiments with DPDK as 100G Ethernet tester (Ubuntu 20.04)


## Prerequisites
Kernel config and mellanox driver installation needs only be done once

### Kernel config
Add the following to the kerne boot parameters: /etc/default/grub

    iommu=pt intel_iommu=on default_hugepagesz=1G hugepagesz=1G hugepages=4

then

    > sudo update-grub

### Mellanox drivers
The Mellanox poll mode driver requires libmlx5 to be built and installed before building dpdk

    > tar xvf mlnx-en-5.3-1.0.0.1-ubuntu20.04-x86_64.tar
    > cd mlnx-en-5.3-1.0.0.1-ubuntu20.04-x86_64/
    > sudo ./install --upstream-libs --dpdk

### DPDK build and install
    > make dpdkclone
    > make dpdkbuild

Not sure this is necessary, perhaps first try without?
    > make dpdkinstall

### Bind dpdk NICs
    > dpdk-devbind.py --status
    > dpdk-devbind.py --status-dev net
    > sudo dpdk-devbind --bind=vfio-pci eth

on mobunto:
    > sudo ../usertools/dpdk-devbind.py --bind=vfio-pci enp9s0



## Ethernet tester

### Build and run ethernet test app
You will be prompted for the sudo password

    > make pmd
    > make runpmd

