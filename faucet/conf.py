"""Base configuration implementation."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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


class Conf(object):
    """Base class for FAUCET configuration."""

    defaults = {}
    defaults_types = {}
    dyn_finalized = False
    dyn_hash = None

    def __init__(self, _id, conf=None):
        if conf is None:
            conf = {}
        self._id = _id
        # TODO: handle conf as a sequence.
        if isinstance(conf, dict):
            self.update(conf)
            self.set_defaults()

    def set_defaults(self):
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)

    def _check_unknown_conf(self, conf):
        """Check that supplied conf dict doesn't specify keys not defined."""
        sub_conf_names = set(conf.keys())
        unknown_conf_names = sub_conf_names - set(self.defaults.keys())
        assert not unknown_conf_names, 'unknown config items: %s' % unknown_conf_names

    def _check_defaults_types(self, conf):
        """Check that conf value is of the correct type."""
        #  assert set(list(self.defaults_types.keys())) == set(list(conf.keys()))
        for conf_key, conf_value in list(conf.items()):
            if conf_key in self.defaults_types and conf_value is not None:
                default_type = self.defaults_types[conf_key]
                assert isinstance(conf_value, default_type), '%s value %s must be %s not %s' % (
                    conf_key, conf_value, default_type, type(conf_value))

    def update(self, conf):
        """Parse supplied YAML config and sanity check."""
        self.__dict__.update(conf)
        self._check_unknown_conf(conf)
        self._check_defaults_types(conf)

    def _conf_keys(self, conf, dyn=False, subconf=True, ignore_keys=None):
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
        for key, value in self._conf_keys(other_conf, dyn=True):
            self.__dict__[key] = value

    def _set_default(self, key, value):
        if key not in self.__dict__ or self.__dict__[key] is None:
            self.__dict__[key] = value

    def to_conf(self):
        """Return configuration as a dict."""
        result = {}
        for key in self.defaults:
            if key != 'name':
                result[key] = self.__dict__[str(key)]
        return result

    def conf_hash(self, dyn=False, subconf=True, ignore_keys=None):
        return hash(frozenset(list(map(
            str, self._conf_keys(self, dyn=dyn, subconf=subconf, ignore_keys=ignore_keys)))))

    def __hash__(self):
        if self.dyn_hash is not None:
            return self.dyn_hash
        dyn_hash = self.conf_hash(dyn=False, subconf=True)
        if self.dyn_finalized:
            self.dyn_hash = dyn_hash
        return dyn_hash

    def finalize(self):
        """Configuration parsing marked complete."""
        self.dyn_finalized = True

    def ignore_subconf(self, other, ignore_keys=None):
        """Return True if this config same as other, ignoring sub config."""
        return (self.conf_hash(dyn=False, subconf=False, ignore_keys=ignore_keys) 
            == other.conf_hash(dyn=False, subconf=False, ignore_keys=ignore_keys))

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __ne__(self, other):
        return not self.__eq__(other)
