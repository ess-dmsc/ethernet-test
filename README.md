# ethernet-test
100G Ethernet tester (rx stats only) based on
[Data Plane Development Kit (DPDK)](https://www.dpdk.org/)
which is a framework for software and user space based packet processing.

The code was developed and tested on Ubuntu 20.04 but should work on other
distributions.

The application is a stripped-down version of the large and complex
[test-pmd application](https://doc.dpdk.org/guides/testpmd_app_ug/) provided
by DPDK. The interactive shell has been removed alongside all other
forwarding engines but **rxonly**. The periodic printout has been tailored
to the specific application of printing receive stats from multiple queues
on multiple ports.

The original application with its many forwarding examples and command line
features exceeds 45000 lines of code making it a bit unwieldy for a DPDK
newcomer. This example is trimmed to about 6000 lines and should be
much easier to navigate.


## Prerequisites
The prerequisites consist of enabling **iommu**, configuring hugepages and install
Mellanox/NVIDIA libraries and drivers. If you do not use Mellanox NICs you can
skip that step. In addition some build tools are required.

The build tool installation, kernel configuration and driver installation needs only be done once.

### Build tools
DPDK builds require **meson**, **ninja** and **elftools**.

    > pip3 install meson
    > pip3 install pyelftools
    > sudo apt-get install ninja-build  # Ubuntu
    > sudo yum install ninja-build      # CentOS

### Kernel config
Add the following to the kernel boot parameters: /etc/default/grub

    iommu=pt intel_iommu=on default_hugepagesz=1G hugepagesz=1G hugepages=4

then

    > sudo update-grub  # Ubuntu
    > sudo grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg   # CentOS

### Mellanox drivers
The Mellanox poll mode driver requires libmlx5 to be built and installed before
building DPDK.

Figuring out which software to download can be a little tricky. But have a look
at the [Mellanox website](https://www.mellanox.com/products/ethernet-drivers/linux/mlnx_en).

There are further [installation instructions here](https://community.mellanox.com/s/article/howto-install-mlnx-ofed-driver)

Depending on the NIC the installation looks something like this

#### Ubuntu 20.04 - ConnectX-5
    > tar xvf mlnx-en-5.3-1.0.0.1-ubuntu20.04-x86_64.tar
    > cd mlnx-en-5.3-1.0.0.1-ubuntu20.04-x86_64/
    > sudo ./install --upstream-libs --dpdk

#### CentOS - ConnectX-4
    > tar xvf mlnx-en-5.3-1.0.0.1-rhel7.9-x86_64.tar
    > cd cd mlnx-en-5.3-1.0.0.1-rhel7.9-x86_64
    > sudo ./install --upstream-libs --dpdk

### DPDK clone, build and install
    > make dpdkclone
    > make dpdkbuild

Not sure this is necessary, perhaps first try without?

    > make dpdkinstall

### Load vfio kernel module
    > sudo modprobe vfio-pci

### Bind dpdk NICs
Before running the application the relevant Ethernet devices (found using
the lspci command) must be unbound from the Linux kernel and bound to DPDK (vfio)

    > dpdk-devbind.py --status
    > dpdk-devbind.py --status-dev net
    > sudo dpdk-devbind.py --bind=vfio-pci eth

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
