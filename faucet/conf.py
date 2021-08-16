"""Base configuration implementation."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

import difflib
import ipaddress
import json
from collections import OrderedDict


class InvalidConfigError(Exception):
    """This error is thrown when the config file is not valid."""


def test_config_condition(cond, msg):
    """
    Evaluate condition and raise InvalidConfigError if condition True.

    Args:
        cond (bool): Condition on which to raise an error if it is true
        msg (str): Message for the error if the condition is true
    """
    if cond:
        raise InvalidConfigError(msg)


class Conf:
    """Base class for FAUCET configuration."""

    mutable_attrs = frozenset()  # type: frozenset
    defaults = {}  # type: dict
    defaults_types = {}  # type: dict
    dyn_finalized = False
    dyn_hash = None

    def __init__(self, _id, dp_id, conf=None):
        self._id = _id
        self.dp_id = dp_id
        if conf is None:
            conf = {}
        if self.defaults is not None and self.defaults_types is not None:
            diff = set(self.defaults.keys()).symmetric_difference(set(self.defaults_types.keys()))
            assert not diff, diff
        if isinstance(conf, dict):
            self.update(conf)
            self.set_defaults()
        self.check_config()
        self.orig_conf = {k: self.__dict__[k] for k in self.defaults}
        for k, conf_v in self.orig_conf.items():
            if isinstance(conf_v, Conf):
                self.orig_conf[k] = conf_v.orig_conf

    def __setattr__(self, name, value):
        if not self.dyn_finalized or name.startswith('dyn') or name in self.mutable_attrs:
            super().__setattr__(name, value)
        else:
            raise ValueError('cannot update %s on finalized Conf object' % name)

    def _set_default(self, key, value, conf=None):
        if conf is None:
            conf = self.__dict__
        assert key in conf, key
        if conf[key] is None:
            conf[key] = value

    def _set_conf_defaults(self, defaults, conf):
        for key, value in defaults.items():
            self._set_default(key, value, conf=conf)

    def set_defaults(self):
        """Set default values and run any basic sanity checks."""
        self._set_conf_defaults(self.defaults, self.__dict__)

    def _check_unknown_conf(self, conf):
        """Check that supplied conf dict doesn't specify keys not defined."""
        sub_conf_names = set(conf.keys())
        unknown_conf_names = sub_conf_names - set(self.defaults.keys())
        test_config_condition(unknown_conf_names, '%s fields unknown in %s' % (
            unknown_conf_names, self._id))

    def _check_conf_types(self, conf, conf_types):
        """Check that conf value is of the correct type."""
        test_config_condition(not isinstance(conf, dict), (
            'Conf object %s contents %s must be type %s not %s' % (
                self._id, conf, dict, type(conf))))
        for conf_key, conf_value in conf.items():
            test_config_condition(
                conf_key not in conf_types, '%s field unknown in %s (known types %s)' % (
                    conf_key, self._id, conf_types))
            if conf_value is not None:
                conf_type = conf_types[conf_key]
                test_config_condition(
                    not isinstance(conf_value, conf_type), '%s value %s must be %s not %s' % (
                        conf_key, conf_value,
                        conf_type, type(conf_value)))  # pytype: disable=invalid-typevar

    @staticmethod
    def _set_unknown_conf(conf, conf_types):
        for conf_key, conf_type in conf_types.items():
            if conf_key not in conf:
                if conf_type == list:
                    conf[conf_key] = []
                else:
                    conf[conf_key] = None
        return conf

    def update(self, conf):
        """Parse supplied YAML config and sanity check."""
        self.__dict__.update(conf)
        self._check_unknown_conf(conf)
        self._check_conf_types(conf, self.defaults_types)

    @staticmethod
    def check_config():
        """Check config at instantiation time for errors, typically via assert."""
        return

    def _conf_keys(self, conf, subconf=True, ignore_keys=None):
        """Return a list of key/values of attributes with dyn/Conf attributes/filtered."""
        conf_keys = []
        for key, value in sorted(
                ((key, value) for key, value in conf.orig_conf.items()
                    if key in self.defaults)):
            if ignore_keys and key in ignore_keys:
                continue
            if not subconf and value:
                if isinstance(value, Conf):
                    continue
                if isinstance(value, (tuple, list, set)) and isinstance(value[0], Conf):
                    continue
            conf_keys.append((key, self._str_conf(value)))
        return conf_keys

    @staticmethod
    def _conf_dyn_keys(conf):
        return [(key, value) for key, value in conf.__dict__.items() if key.startswith('dyn')]

    def merge_dyn(self, other_conf):
        """Merge dynamic state from other conf object."""
        self.__dict__.update(self._conf_dyn_keys(other_conf))

    def _str_conf(self, conf_v):
        if isinstance(conf_v, (bool, str, int)):
            return conf_v
        if isinstance(conf_v, (
                ipaddress.IPv4Address, ipaddress.IPv4Interface, ipaddress.IPv4Network,
                ipaddress.IPv6Address, ipaddress.IPv6Interface, ipaddress.IPv6Network)):
            return str(conf_v)
        if isinstance(conf_v, (dict, OrderedDict)):
            return {str(i): self._str_conf(j) for i, j in conf_v.items() if j is not None}
        if isinstance(conf_v, (list, tuple, frozenset)):
            return tuple(self._str_conf(i) for i in conf_v if i is not None)
        if isinstance(conf_v, Conf):
            for i in ('name', '_id'):
                if hasattr(conf_v, i):
                    return getattr(conf_v, i)
        return None

    def to_conf(self):
        """Return configuration as a dict."""
        conf = {
            k: self.orig_conf[str(k)] for k in self.defaults if k != 'name'}
        return json.dumps(self._str_conf(conf), sort_keys=True, indent=4, separators=(',', ': '))

    def conf_diff(self, other):
        """Return text diff between two Confs."""
        differ = difflib.Differ()
        return '\n'.join(differ.compare(
            self.to_conf().splitlines(), other.to_conf().splitlines()))

    def conf_hash(self, subconf=True, ignore_keys=None):
        """Return hash of keys configurably filtering attributes."""
        return hash(frozenset(list(map(
            str, self._conf_keys(self, subconf=subconf, ignore_keys=ignore_keys)))))

    def __hash__(self):
        if self.dyn_hash is not None:
            return self.dyn_hash
        dyn_hash = self.conf_hash(subconf=True)
        if self.dyn_finalized:
            self.dyn_hash = dyn_hash
        return dyn_hash

    def _finalize_val(self, val):
        if isinstance(val, list):
            return tuple(
                self._finalize_val(v) for v in val)
        if isinstance(val, set):
            return frozenset(
                [self._finalize_val(v) for v in val])
        if isinstance(val, dict):
            return OrderedDict([
                (k, self._finalize_val(v)) for k, v in sorted(val.items(), key=str)])
        return val

    def finalize(self):
        """Configuration parsing marked complete."""
        self.__dict__.update(
            {k: self._finalize_val(v) for k, v in self.__dict__.items()
             if not k.startswith('dyn')})
        self.dyn_finalized = True

    def ignore_subconf(self, other, ignore_keys=None):
        """Return True if this config same as other, ignoring sub config."""
        return (self.conf_hash(
            subconf=False, ignore_keys=ignore_keys) == other.conf_hash(
                subconf=False, ignore_keys=ignore_keys))

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __ne__(self, other):
        return not self.__eq__(other)

    @staticmethod
    def _check_ip_str(ip_str, ip_method=ipaddress.ip_address):
        try:
            # bool type is deprecated by the library ipaddress
            if not isinstance(ip_str, bool):
                return ip_method(ip_str)
            raise InvalidConfigError('Invalid IP address %s: IP address of type bool' % (ip_str))
        except (ValueError, AttributeError, TypeError) as err:
            raise InvalidConfigError('Invalid IP address %s: %s' % (ip_str, err)) from err

    @staticmethod
    def _ipvs(ipas):
        return frozenset([ipa.version for ipa in ipas])

    @staticmethod
    def _by_ipv(ipas, ipv):
        return frozenset([ipa for ipa in ipas if ipa.version == ipv])
