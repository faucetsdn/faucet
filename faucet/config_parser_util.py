"""Utility functions supporting FAUCET/Gauge config parsing."""

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

import hashlib
import logging
import os
# pytype: disable=pyi-error
import yaml
from yaml.constructor import ConstructorError

# handle libyaml-dev not installed
try:
    from yaml import CLoader as Loader  # type: ignore
except ImportError:
    from yaml import Loader

CONFIG_HASH_FUNC = 'sha256'


class UniqueKeyLoader(Loader):  # pylint: disable=too-many-ancestors
    """YAML loader that will reject duplicate/overwriting keys."""

    def construct_mapping(self, node, deep=False):
        """Check for duplicate YAML keys."""
        try:
            key_value_pairs = [
                (self.construct_object(key_node, deep=deep),
                 self.construct_object(value_node, deep=deep))
                for key_node, value_node in node.value]
        except TypeError as err:
            raise ConstructorError('invalid key type: %s' % err) from err
        mapping = {}
        for key, value in key_value_pairs:
            try:
                if key in mapping:
                    raise ConstructorError('duplicate key: %s' % key)
            except TypeError as type_error:
                raise ConstructorError('unhashable key: %s' % key) from type_error
            mapping[key] = value
        return mapping


yaml.SafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    UniqueKeyLoader.construct_mapping)


def get_logger(logname):
    """Return logger instance for config parsing."""
    return logging.getLogger(logname + '.config')


def read_config(config_file, logname):
    """Return a parsed YAML config file or None."""
    logger = get_logger(logname)
    conf_txt = None
    conf = None

    try:
        with open(config_file, 'r', encoding='utf-8') as stream:
            conf_txt = stream.read()
        conf = yaml.safe_load(conf_txt)
    except (yaml.YAMLError, UnicodeDecodeError,
            PermissionError, ValueError) as err:  # pytype: disable=name-error
        logger.error('Error in file %s (%s)', config_file, str(err))
    except FileNotFoundError as err:  # pytype: disable=name-error
        logger.error('Could not find requested file: %s (%s)', config_file, str(err))
    return conf, conf_txt


def config_hash_content(content):
    """Return hash of config file content."""
    config_hash = getattr(hashlib, CONFIG_HASH_FUNC)
    return config_hash(content.encode('utf-8')).hexdigest()


def config_file_hash(config_file_name):
    """Return hash of YAML config file contents."""
    with open(config_file_name, encoding='utf-8') as config_file:
        return config_hash_content(config_file.read())


def dp_config_path(config_file, parent_file=None):
    """Return full path to config file."""
    if parent_file and not os.path.isabs(config_file):
        return os.path.realpath(os.path.join(os.path.dirname(parent_file), config_file))
    return os.path.realpath(config_file)


def dp_include(config_hashes, config_contents, config_file, logname,  # pylint: disable=too-many-locals
               top_confs):
    """Handles including additional config files"""
    logger = get_logger(logname)
    if not os.path.isfile(config_file):
        logger.warning('not a regular file or does not exist: %s', config_file)
        return False
    conf, config_content = read_config(config_file, logname)
    if not conf:
        logger.warning('error loading config from file: %s', config_file)
        return False

    valid_conf_keys = set(top_confs.keys()).union({'include', 'include-optional', 'version'})
    unknown_top_confs = set(conf.keys()) - valid_conf_keys
    if unknown_top_confs:
        logger.error('unknown top level config items: %s', unknown_top_confs)
        return False

    # Add the SHA256 hash for this configuration file, so FAUCET can determine
    # whether or not this configuration file should be reloaded upon receiving
    # a HUP signal.
    new_config_hashes = config_hashes.copy()
    new_config_hashes[config_file] = config_hash_content(config_content)
    new_config_contents = config_contents.copy()
    new_config_contents[config_file] = config_content

    # Save the updated configuration state in separate dicts,
    # so if an error is found, the changes can simply be thrown away.
    new_top_confs = {}
    for conf_name, curr_conf in top_confs.items():
        new_top_confs[conf_name] = curr_conf.copy()
        try:
            new_top_confs[conf_name].update(conf.pop(conf_name, {}))
        except (TypeError, ValueError):
            logger.error('Invalid config for "%s"', conf_name)
            return False

    for include_directive, file_required in (
            ('include', True),
            ('include-optional', False)):
        include_values = conf.pop(include_directive, [])
        if not isinstance(include_values, list):
            logger.error('Include directive is not in a valid format')
            return False
        for include_file in include_values:
            if not isinstance(include_file, str):
                include_file = str(include_file)

            include_path = dp_config_path(include_file, parent_file=config_file)
            logger.info('including file: %s', include_path)
            if include_path in config_hashes:
                logger.error(
                    'include file %s already loaded, include loop found in file: %s',
                    include_path, config_file,)
                return False
            if not dp_include(
                    new_config_hashes, config_contents, include_path, logname, new_top_confs):
                if file_required:
                    logger.error('unable to load required include file: %s', include_path)
                    return False
                new_config_hashes[include_path] = None
                logger.warning('skipping optional include file: %s', include_path)

    # Actually update the configuration data structures,
    # now that this file has been successfully loaded.
    config_hashes.update(new_config_hashes)
    config_contents.update(new_config_contents)
    for conf_name, new_conf in new_top_confs.items():
        top_confs[conf_name].update(new_conf)
    return True


def config_changed(top_config_file, new_top_config_file, config_hashes):
    """Return True if configuration has changed.

    Args:
        top_config_file (str): name of FAUCET config file
        new_top_config_file (str): name, possibly new, of FAUCET config file.
        config_hashes (dict): map of config file/includes and hashes of contents.
    Returns:
        bool: True if the file, or any file it includes, has changed.
    """
    if new_top_config_file != top_config_file:
        return True
    if config_hashes is None or new_top_config_file is None:
        return False
    for config_file, config_hash in config_hashes.items():
        config_file_exists = os.path.isfile(config_file)
        # Config file not loaded but exists = reload.
        if config_hash is None and config_file_exists:
            return True
        # Config file loaded but no longer exists = reload.
        if config_hash and not config_file_exists:
            return True
        # Config file hash has changed = reload.
        if config_file_exists:
            new_config_hash = config_file_hash(config_file)
            if new_config_hash != config_hash:
                return True
    return False
