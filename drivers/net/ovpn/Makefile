# SPDX-License-Identifier: GPL-2.0
#
# ovpn -- OpenVPN data channel offload in kernel space
#
# Copyright (C) 2020-2025 OpenVPN, Inc.
#
# Author:	Antonio Quartulli <antonio@openvpn.net>

obj-$(CONFIG_OVPN) := ovpn.o
ovpn-y += bind.o
ovpn-y += crypto.o
ovpn-y += crypto_aead.o
ovpn-y += main.o
ovpn-y += io.o
ovpn-y += netlink.o
ovpn-y += netlink-gen.o
ovpn-y += peer.o
ovpn-y += pktid.o
ovpn-y += socket.o
ovpn-y += stats.o
ovpn-y += tcp.o
ovpn-y += udp.o
ovpn-$(CONFIG_X86_64) += gcm_lib.o gcm-vaes-avx512.o	# TEST
