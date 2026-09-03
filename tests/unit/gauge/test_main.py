#!/usr/bin/env python3

"""Test GAUGE main."""

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

import unittest

# pylint: disable=import-error
from faucet.__main__ import app_lists, channel_settings, parse_args


class MainTestCase(unittest.TestCase):  # pytype: disable=module-attr
    """Test __main__ methods."""

    def test_parse_args(self):
        """Sanity check argument parsing."""
        self.assertFalse(parse_args([]).verbose)
        self.assertTrue(parse_args(["--verbose"]).verbose)

    def test_app_lists(self):
        """The OpenFlow channel is loaded alongside the requested app."""
        # The listener is last: it must not accept a switch before the
        # application that handles it has read its configuration.
        self.assertEqual(
            app_lists(parse_args([]), "faucet"), ["faucet.faucet", "c65of.controller"]
        )
        self.assertEqual(
            app_lists(parse_args(["--gauge"]), "faucet"),
            ["faucet.gauge", "c65of.controller"],
        )
        self.assertEqual(
            app_lists(parse_args([]), "/usr/local/bin/gauge"),
            ["faucet.gauge", "c65of.controller"],
        )
        self.assertEqual(app_lists(parse_args([]), "faucet")[-1], "c65of.controller")
        self.assertIn(
            "extra.app",
            app_lists(parse_args(["--ryu-app-lists=extra.app"]), "faucet"),
        )
        self.assertEqual(
            app_lists(parse_args(["--ryu-app-lists=extra.app"]), "faucet")[-1],
            "c65of.controller",
        )

    def test_channel_settings_from_flags(self):
        """A command line flag configures the listener."""
        settings = channel_settings(
            parse_args(["--ryu-ofp-tcp-listen-port=6699", "--ryu-ofp-listen-host=::1"])
        )
        self.assertEqual(settings["tcp_port"], 6699)
        self.assertEqual(settings["listen_host"], "::1")

    def test_channel_settings_from_conf_file(self):
        """ryu.conf supplies defaults and the command line overrides them."""
        import tempfile  # pylint: disable=import-outside-toplevel

        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as conf:
            conf.write(
                "[DEFAULT]\n"
                "echo_request_interval=7\n"
                "maximum_unreplied_echo_requests=5\n"
                "socket_timeout=15\n"
                "ofp_tcp_listen_port=1234\n"
                "unrelated_key=ignored\n"
            )
            name = conf.name
        settings = channel_settings(parse_args(["--ryu-config-file=%s" % name]))
        self.assertEqual(settings["echo_request_interval"], 7)
        self.assertEqual(settings["max_unreplied_echo_requests"], 5)
        self.assertEqual(settings["socket_timeout"], 15)
        self.assertEqual(settings["tcp_port"], 1234)
        self.assertNotIn("unrelated_key", settings)

        overridden = channel_settings(
            parse_args(
                ["--ryu-config-file=%s" % name, "--ryu-ofp-tcp-listen-port=6653"]
            )
        )
        self.assertEqual(overridden["tcp_port"], 6653)

    def test_channel_settings_without_conf_file(self):
        """A missing config file leaves the listener on its defaults."""
        self.assertEqual(channel_settings(parse_args(["--ryu-config-file=/nope"])), {})

    def test_channel_settings_tls(self):
        """Certificate paths reach the listener."""
        settings = channel_settings(
            parse_args(
                [
                    "--ryu-ctl-cert=/c.pem",
                    "--ryu-ctl-privkey=/k.pem",
                    "--ryu-ca-certs=/ca.pem",
                ]
            )
        )
        self.assertEqual(settings["ctl_cert"], "/c.pem")
        self.assertEqual(settings["ctl_privkey"], "/k.pem")
        self.assertEqual(settings["ca_certs"], "/ca.pem")


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
