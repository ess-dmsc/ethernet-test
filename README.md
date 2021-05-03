# ethernet-test
Experiments with DPDK as 100G Ethernet tester (Linux only)


## Kernel config

Add the following to the kerne boot parameters: /etc/default/grub

    iommu=pt intel_iommu=on default_hugepagesz=1G hugepagesz=1G hugepages=4

then

    sudo update-grub

## Build
### Clone DPDK and build test application

    > ./scripts/build.bash


### Bind dpdk NICs
    > dpdk-devbind.py --status
    > dpdk-devbind.py --status-dev net
    > sudo dpdk-devbind --bind=vfio-pci eth

on mobunto:
    > sudo ../usertools/dpdk-devbind.py --bind=vfio-pci enp9s0


### Run application
    > sudo ./examples/dpdk-l2fwd --legacy-mem -c0xf -n4 -- -p0x1
