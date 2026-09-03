#!/usr/bin/env python3

"""Guard that Faucet's runtime pulls in none of the packages os-ken brought."""

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
import subprocess
import sys
import unittest


class NoEventletTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Faucet's runtime import graph must stay free of os-ken's dependencies."""

    # Modules covering the full runtime surface: valve/valve_ryuapp (c65of),
    # faucet_bgp (beka), faucet_dot1x (chewie), faucet_event, prom_client,
    # gauge.
    RUNTIME_MODULES = ("faucet.faucet", "faucet.gauge")

    # os-ken required all of these; c65of requires none of them. netaddr is
    # not listed: faucet uses it directly, and now declares it, having relied
    # on os-ken to supply it.
    FORBIDDEN = ("eventlet", "oslo_config", "os_ken")

    def test_runtime_has_no_os_ken_dependencies(self):
        """Importing the runtime modules imports nothing os-ken needed."""
        probe = (
            "import sys;"
            "import %s;" % ", ".join(self.RUNTIME_MODULES)
            + "found = sorted(m for m in sys.modules "
            "if m.split('.')[0] in %r);" % (self.FORBIDDEN,) + "assert not found, found"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            env=dict(os.environ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            "an os-ken dependency leaked into the runtime:\n%s" % result.stderr,
        )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
