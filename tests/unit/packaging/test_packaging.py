#!/usr/bin/env python3

"""Test FAUCET packaging"""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import unittest

from deb_pkg_tools.control import parse_control_fields
from deb_pkg_tools.deb822 import parse_deb822
from deb_pkg_tools.deps import VersionedRelationship
import requirements


class CheckDebianPackageTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test debian packaging."""

    def _parse_deb_control(self, control_file):
        with open(control_file, 'r', encoding='utf-8') as handle:
            control = handle.read()

        faucet_dpkg = str()
        for line in control.split("\n"):
            if line.startswith("Package: python3-faucet"):
                faucet_dpkg += line
            elif faucet_dpkg:
                if not line:
                    break
                faucet_dpkg += "\n{}".format(line)

        faucet_dpkg = parse_control_fields(parse_deb822(faucet_dpkg))
        self.faucet_dpkg_deps = {}
        for dep in faucet_dpkg['Depends']:
            if isinstance(dep, VersionedRelationship):
                if dep.name not in self.faucet_dpkg_deps:
                    self.faucet_dpkg_deps[dep.name] = []
                self.faucet_dpkg_deps[dep.name].append("{}{}".format(dep.operator, dep.version))

    def _parse_pip_requirements(self, requirements_file):
        self.faucet_pip_reqs = {}
        with open(requirements_file, 'r', encoding='utf-8') as handle:
            for pip_req in requirements.parse(handle):
                self.faucet_pip_reqs[pip_req.name] = pip_req.specs

    def _pip_req_to_dpkg_name(self, pip_req):
        if pip_req in self.dpkg_name:
            return self.dpkg_name[pip_req]
        return "python3-" + pip_req

    def setUp(self):
        src_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../')
        control_file = os.path.join(src_dir, 'debian/control')
        requirements_file = os.path.join(src_dir, 'requirements.txt')

        self.dpkg_name = {
            'pyyaml': 'python3-yaml',
            'prometheus_client': 'python3-prometheus-client'
        }

        self._parse_deb_control(control_file)
        self._parse_pip_requirements(requirements_file)

    def disabled_test_pip_reqs_in_deb_package(self):
        """Test pip requirements are listed as dependencies on debian package."""

        for pip_req in self.faucet_pip_reqs:
            dpkg_name = self._pip_req_to_dpkg_name(pip_req)
            self.assertIn(dpkg_name, self.faucet_dpkg_deps)

    def disabled_test_pip_reqs_versions_match_deb_package(self):
        """Test pip requirements versions match debian package dependencies."""

        for pip_req, pip_req_versions in self.faucet_pip_reqs.items():
            dpkg_name = self._pip_req_to_dpkg_name(pip_req)

            if pip_req_versions:
                debian_package_dependencies = [
                    dpkg_name + x for x in self.faucet_dpkg_deps[dpkg_name]
                ]
                for pip_req_specifier, pip_req_version in pip_req_versions:
                    if pip_req_specifier == '==':
                        # debian/control is annoying about how it handles exact
                        # versions, calculate the debian equivalent of the
                        # pip requirements match and compare that
                        lower_version = pip_req_version
                        lower_match = '>=' + lower_version

                        upper_version = pip_req_version.split('.')
                        upper_version[-1] = str(int(upper_version[-1]) + 1)
                        upper_version = '.'.join(upper_version)
                        upper_match = '<<' + upper_version

                        self.assertIn(dpkg_name + lower_match, debian_package_dependencies)
                        self.assertIn(dpkg_name + upper_match, debian_package_dependencies)
                    elif pip_req_specifier == '<':
                        # debian/control uses << instead of <
                        match = dpkg_name + '<<' + pip_req_version
                        self.assertIn(match, debian_package_dependencies)
                    elif pip_req_specifier == '>':
                        # debian/control uses >> instead of >
                        match = dpkg_name + '>>' + pip_req_version
                        self.assertIn(match, debian_package_dependencies)
                    else:
                        match = dpkg_name + pip_req_specifier + pip_req_version
                        self.assertIn(match, debian_package_dependencies)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
