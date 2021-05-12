# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# override default name to drop the hyphen
name = 'ecdcpmd'
cflags += '-Wno-deprecated-declarations'
sources = files(
        'config.c',
        'parameters.c',
        'rxonly.c',
        'testpmd.c',
        'util.c',
        'ecdc.c',
)

deps += ['ethdev', 'gro', 'gso', 'cmdline', 'metrics', 'meter', 'bus_pci']
if dpdk_conf.has('RTE_LIB_PDUMP')
    deps += 'pdump'
endif
if dpdk_conf.has('RTE_CRYPTO_SCHEDULER')
    deps += 'crypto_scheduler'
endif
if dpdk_conf.has('RTE_NET_BOND')
    deps += 'net_bond'
endif
if dpdk_conf.has('RTE_NET_BNXT')
    deps += 'net_bnxt'
endif
if dpdk_conf.has('RTE_NET_I40E')
    deps += 'net_i40e'
endif
if dpdk_conf.has('RTE_NET_IXGBE')
    deps += 'net_ixgbe'
endif
if dpdk_conf.has('RTE_NET_DPAA')
    deps += ['bus_dpaa', 'mempool_dpaa', 'net_dpaa']
endif
