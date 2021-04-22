# ethernet-test
Experiments with DPDK as 100G Ethernet tester (Linux only)

## Build
### Clone DPDK and build test application

    > ./scripts/build.bash

### Setup hugepages
    > dpdk-hugepages.py --show
    > sudo dpdk-hugepages.py -p 1G --setup 2G

### Bind dpdk NICs
    > dpdk-devbind.py --status
    > dpdk-devbind.py --status-dev net
    > sudo dpdk-devbind --bind=vfio-pci eth
