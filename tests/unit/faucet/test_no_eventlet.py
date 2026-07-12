#!/usr/bin/env python3

"""Guard that Faucet runs eventlet-free on os-ken's native hub."""

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
    """Faucet's runtime import graph must never pull in eventlet."""

    # Modules covering the full runtime surface: valve/valve_ryuapp (os-ken
    # hub), faucet_bgp (beka), faucet_dot1x (chewie), faucet_event,
    # prom_client, gauge.
    RUNTIME_MODULES = ("faucet.faucet", "faucet.gauge")

    def test_native_hub_no_eventlet(self):
        """Importing the runtime modules on the default hub imports no eventlet."""
        # Force os-ken's default hub selection; assert it is native and that
        # nothing in the import graph reached for eventlet.
        probe = (
            "import os, sys;"
            "os.environ.pop('OSKEN_HUB_TYPE', None);"
            "import %s;" % ", ".join(self.RUNTIME_MODULES)
            + "from os_ken.lib import hub;"
            "assert hub.HUB_TYPE == 'native', hub.HUB_TYPE;"
            "assert 'eventlet' not in sys.modules, "
            "sorted(m for m in sys.modules if m.split('.')[0] == 'eventlet')"
        )
        env = dict(os.environ)
        env.pop("OSKEN_HUB_TYPE", None)
        result = subprocess.run(
            [sys.executable, "-c", probe],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            "eventlet leaked into the runtime import graph:\n%s" % result.stderr,
        )


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
