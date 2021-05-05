# ethernet-test
Experiments with DPDK as 100G Ethernet tester (Ubuntu 20.04)


## Build
### Clone and build dpdk 

    > make dpdkclone
    > make dpdkbuild
    > make dpdkinstall

### Build ethernet test app

    > make pmd

### Run test app
    > make runpmd 


## Kernel config

Add the following to the kerne boot parameters: /etc/default/grub

    iommu=pt intel_iommu=on default_hugepagesz=1G hugepagesz=1G hugepages=4

then

    sudo update-grub

### Bind dpdk NICs
    > dpdk-devbind.py --status
    > dpdk-devbind.py --status-dev net
    > sudo dpdk-devbind --bind=vfio-pci eth

on mobunto:
    > sudo ../usertools/dpdk-devbind.py --bind=vfio-pci enp9s0


