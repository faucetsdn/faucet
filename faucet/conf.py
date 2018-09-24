"""Base configuration implementation."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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

from collections import OrderedDict


class InvalidConfigError(Exception):
    """This error is thrown when the config file is not valid."""
    pass


def test_config_condition(cond, msg):
    """Evaluate condition and raise InvalidConfigError if condition not True."""
    if cond:
        raise InvalidConfigError(msg)


class Conf:
    """Base class for FAUCET configuration."""

    mutable_attrs = frozenset() # type: frozenset
    defaults = None # type: dict
    defaults_types = None # type: dict
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
        # TODO: handle conf as a sequence. # pylint: disable=fixme
        if isinstance(conf, dict):
            self.update(conf)
            self.set_defaults()
        self.check_config()

    def __setattr__(self, name, value):
        if not self.dyn_finalized or name.startswith('dyn') or name in self.mutable_attrs:
            super(Conf, self).__setattr__(name, value)
        else:
            raise ValueError('cannot update %s on finalized Conf object' % name)

    def set_defaults(self):
        """Set default values and run any basic sanity checks."""
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)

    def _check_unknown_conf(self, conf):
        """Check that supplied conf dict doesn't specify keys not defined."""
        sub_conf_names = set(conf.keys())
        unknown_conf_names = sub_conf_names - set(self.defaults.keys())
        test_config_condition(unknown_conf_names, '%s fields unknown in %s' % (
            unknown_conf_names, self._id))

    def _check_conf_types(self, conf, conf_types):
        """Check that conf value is of the correct type."""
        for conf_key, conf_value in list(conf.items()):
            test_config_condition(
                conf_key not in conf_types, '%s field unknown in %s (known types %s)' % (
                    conf_key, self._id, conf_types))
            if conf_value is not None:
                conf_type = conf_types[conf_key]
                test_config_condition(
                    not isinstance(conf_value, conf_type), '%s value %s must be %s not %s' % (
                        conf_key, conf_value,
                        conf_type, type(conf_value))) # pytype: disable=invalid-typevar

    @staticmethod
    def _set_unknown_conf(conf, conf_types):
        for conf_key, conf_type in list(conf_types.items()):
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

    def check_config(self):
        """Check config at instantiation time for errors, typically via assert."""
        pass

    @staticmethod
    def _conf_keys(conf, dyn=False, subconf=True, ignore_keys=None):
        """Return a list of key/values of attributes with dyn/Conf attributes/filtered."""
        conf_keys = []
        for key, value in list(conf.__dict__.items()):
            if not dyn and key.startswith('dyn'):
                continue
            if not subconf and isinstance(value, Conf):
                continue
            if ignore_keys and key in ignore_keys:
                continue
            conf_keys.append((key, value))
        return conf_keys

    def merge_dyn(self, other_conf):
        """Merge dynamic state from other conf object."""
        self.__dict__.update(
            {k: v for k, v in self._conf_keys(other_conf, dyn=True)})

    def _set_default(self, key, value):
        assert key in self.__dict__, key
        if self.__dict__[key] is None:
            self.__dict__[key] = value

    def to_conf(self):
        """Return configuration as a dict."""
        return {
            k: self.__dict__[str(k)] for k in self.defaults.keys() if k != 'name'}

    def conf_hash(self, dyn=False, subconf=True, ignore_keys=None):
        """Return hash of keys configurably filtering attributes."""
        return hash(frozenset(list(map(
            str, self._conf_keys(self, dyn=dyn, subconf=subconf, ignore_keys=ignore_keys)))))

    def __hash__(self):
        if self.dyn_hash is not None:
            return self.dyn_hash
        dyn_hash = self.conf_hash(dyn=False, subconf=True)
        if self.dyn_finalized:
            self.dyn_hash = dyn_hash
        return dyn_hash

    def _finalize_val(self, val):
        if isinstance(val, list):
            return tuple(
                [self._finalize_val(v) for v in val])
        if isinstance(val, set):
            return frozenset(
                [self._finalize_val(v) for v in val])
        if isinstance(val, dict):
            return OrderedDict([
                (k, self._finalize_val(v)) for k, v in sorted(list(val.items()), key=str)])
        return val

    def finalize(self):
        """Configuration parsing marked complete."""
        self.__dict__.update(
            {k: self._finalize_val(v) for k, v in list(self.__dict__.items())
             if not k.startswith('dyn')})
        self.dyn_finalized = True

    def ignore_subconf(self, other, ignore_keys=None):
        """Return True if this config same as other, ignoring sub config."""
        return (self.conf_hash(dyn=False, subconf=False, ignore_keys=ignore_keys)
                == other.conf_hash(dyn=False, subconf=False, ignore_keys=ignore_keys))

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __ne__(self, other):
        return not self.__eq__(other)
