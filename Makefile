#

dpdkclone:
	git clone git://dpdk.org/dpdk


dpdkbuild:
	cd dpdk && meson build && cd build && ninja


dpdkinstall:
	cd dpdk/build && sudo ninja install
	sudo ldconfig

pmd:
	./scripts/build.bash

runpmd:
	sudo ./dpdk/build/app/dpdk-ecdcpmd -c 0x1f --legacy-mem -- --rxq 4 --txq 4 --nb-cores=4
