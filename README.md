# ethernet-test
100G Ethernet tester (rx stats only) based on
[Data Plane Development Kit (DPDK)](https://www.dpdk.org/)
which is a frameworks for software and user space based packet processing.

The code was developed and tested on Ubuntu 20.04 but should work on other
distributions.

The application is a stripped-down version of the large and complex
[test-pmd application](https://doc.dpdk.org/guides/testpmd_app_ug/) provided
by the DPDK. Here the interactive shell has been removed alongside all other
forwarding engines than **rxonly**. The periodic printout has been tailored
to the specific application of printing receive stats from multiple queues
on multiple ports.

The original application with its many forwarding examples and command line
features was above 45000 lines of code making it a bit unwieldy for a DPDK
newcomer. This example is about 6000 lines and should be easier to navigate.


## Prerequisites
The prerequisites consists of enabling iommu, configuring hugepages and install
Mellanox/NVIDIA libraries and drivers. If you do not use Mellanox NICs you can
skip the last step.

The kernel configuration and driver installation needs only be done once.

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
Before running the application the relevant Ethernet devices (found using
the lspci command) must be unbound from the Linux kernel and bound to DPDK (vfio)

    > dpdk-devbind.py --status
    > dpdk-devbind.py --status-dev net
    > sudo dpdk-devbind --bind=vfio-pci eth

Example:
    > sudo ../usertools/dpdk-devbind.py --bind=vfio-pci enp9s0


## Ethernet tester

### Build and run ethernet test app
You will be prompted for the sudo password

    > make pmd
    > make runpmd

### Sending test data
You can use the **hping3** tool to flood the test port with either ping
(icmp echo) or udp data.

    > sudo hping3 --flood --udp -d 1400 --rand-source 10.1.1.2

The rand-source option is necessary of you want to test the NIC multi-queue
rx offload.
