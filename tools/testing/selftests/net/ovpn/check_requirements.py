#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 OpenVPN, Inc.
#
#  Author:  Ralf Lici <ralf@mandelbit.com>

from importlib.metadata import version, PackageNotFoundError
from packaging.requirements import Requirement
from packaging.version import Version, InvalidVersion
from pathlib import Path
import sys

def check_requirements(requirements_path="requirements.txt"):
    issues = []
    with open(requirements_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                req = Requirement(line)
                try:
                    installed_version = Version(version(req.name))
                    if req.specifier and installed_version not in req.specifier:
                        issues.append(f"{req.name}=={installed_version} does not satisfy {req.specifier}")
                except PackageNotFoundError:
                    issues.append(f"{req.name} is not installed")
                except InvalidVersion:
                    issues.append(f"{req.name} has an invalid installed version")
            except Exception as e:
                issues.append(f"Could not parse requirement line: '{line}' ({e})")
    return issues

problems = check_requirements()
if problems:
    print("Dependency issues found:")
    for p in problems:
        print(" -", p)
    sys.exit(1)
else:
    sys.exit(0)
