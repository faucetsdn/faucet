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

import hashlib
import logging
import os
import yaml


def get_logger(logname):
    return logging.getLogger(logname + '.config')


def read_config(config_file, logname):
    logger = get_logger(logname)
    try:
        with open(config_file, 'r') as stream:
            conf = yaml.safe_load(stream)
    except yaml.YAMLError as ex:
        logger.error('Error in file %s (%s)', config_file, str(ex))
        return None
    return conf


def config_file_hash(config_file_name):
    with open(config_file_name) as config_file:
        return hashlib.sha256(config_file.read().encode('utf-8')).hexdigest()


def dp_config_path(config_file, parent_file=None):
    if parent_file and not os.path.isabs(config_file):
        return os.path.realpath(os.path.join(os.path.dirname(parent_file), config_file))
    else:
        return os.path.realpath(config_file)


def dp_include(config_hashes, config_file, logname, top_confs):
    logger = get_logger(logname)
    if not os.path.isfile(config_file):
        logger.warning('not a regular file or does not exist: %s', config_file)
        return False
    conf = read_config(config_file, logname)
    if not conf:
        logger.warning('error loading config from file: %s', config_file)
        return False

    unknown_top_confs = (
        set(conf.keys()) -
        set(list(top_confs.keys()) +
            ['include', 'include-optional', 'version']))
    if unknown_top_confs:
        logger.error('unknown top level config items: %s', unknown_top_confs)
        return False

    # Add the SHA256 hash for this configuration file, so FAUCET can determine
    # whether or not this configuration file should be reloaded upon receiving
    # a HUP signal.
    new_config_hashes = config_hashes.copy()
    new_config_hashes[config_file] = config_file_hash(config_file)

    # Save the updated configuration state in separate dicts,
    # so if an error is found, the changes can simply be thrown away.
    new_top_confs = {}
    for conf_name, curr_conf in list(top_confs.items()):
        new_top_confs[conf_name] = curr_conf.copy()
        new_top_confs[conf_name].update(conf.pop(conf_name, {}))

    for include_directive, file_required in (
            ('include', True),
            ('include-optional', False)):
        for include_file in conf.pop(include_directive, []):
            include_path = dp_config_path(include_file, parent_file=config_file)
            if include_path in config_hashes:
                logger.error(
                    'include file %s already loaded, include loop found in file: %s',
                    include_path, config_file,)
                return False
            if not dp_include(
                    new_config_hashes, include_path, logname, new_top_confs):
                if file_required:
                    logger.error('unable to load required include file: %s', include_path)
                    return False
                else:
                    new_config_hashes[include_path] = None
                    logger.warning('skipping optional include file: %s', include_path)

    # Actually update the configuration data structures,
    # now that this file has been successfully loaded.
    config_hashes.update(new_config_hashes)
    for conf_name, new_conf in list(new_top_confs.items()):
        top_confs[conf_name].update(new_conf)
    return True


def config_changed(config_file, new_config_file, config_hashes):
    """Return True if configuration has changed.

    Args:
        config_file (str): name of FAUCET config file
        new_config_file (str): name, possibly new, of FAUCET config file.
        config_hashes (dict): map of config file/includes and hashes of contents.
    Returns:
        bool: True if the file, or any file it includes, has changed.
    """
    if new_config_file != config_file:
        return True
    for config_file, config_hash in list(config_hashes.items()):
        config_file_exists = os.path.isfile(config_file)
        # Config file not loaded but exists = reload.
        if config_hash is None and config_file_exists:
            return True
        # Config file loaded but no longer exists = reload.
        if config_hash and not config_file_exists:
            return True
        # Config file hash has changed = reload.
        new_config_hash = config_file_hash(config_file)
        if new_config_hash != config_hash:
            return True
    return False
