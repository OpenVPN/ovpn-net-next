#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#  Author:	Antonio Quartulli <antonio@openvpn.net>

OVPN_ALG="aegis128x4"

# AEGIS-128X4 is only implemented on x86_64 with VAES and AVX512
modprobe -q crypto-aegis128x4 2>/dev/null
if ! grep -q '^name *: aegis128x4$' /proc/crypto; then
	echo "SKIP: aegis128x4 not available"
	exit 4
fi

source test.sh
