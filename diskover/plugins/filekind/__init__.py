#!/usr/bin/env python3
"""
diskover
https://diskoverdata.com

Copyright 2017-2023 Diskover Data, Inc.
"Community" portion of Diskover made available under the Apache 2.0 License found here:
https://www.diskoverdata.com/apache-license/
 
All other content is subject to the Diskover Data, Inc. end user license agreement found at:
https://www.diskoverdata.com/eula-subscriptions/
  
Diskover Data products and features for all versions found here:
https://www.diskoverdata.com/solutions/


=== Plugin Name ===
diskover file kind plugin

=== Plugin Description ===
diskover file kind plugin - This is an example plugin
for diskover. It adds extra meta data (file kind for each file) to diskover index during indexing.
A new field is added "filekind" with a keyword of the file kind.

=== Plugin Requirements ===
none

=== Diskover Indexing Plugins Requirements ===
all indexing plugins require six functions:
- add_mappings
- add_meta
- add_tags
- for_type
- init
- close

"""

import sys
import os
import confuse
import logging
import warnings
from pathlib import Path


version = '0.0.1'
__version__ = version
__name__ = 'filekind_plugin'


"""Load yaml config file.
Checks for env var DISKOVER_FILEKIND_PLUGIN as alternate config file.
"""
config = confuse.Configuration('diskover_filekind_plugin', __name__)
config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
if not os.path.exists(config_filename):
    print('Config file {0} not found! Copy from default config.'.format(config_filename))
    sys.exit(1)

# load creationtime plugin default config file
config_defaults = confuse.Configuration('diskover_filekind_plugin', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
# get parent path two levels up
scriptpath_parent = Path(scriptpath).parents[1]
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_filekind_plugin/config.yaml')
config_defaults.set_file(default_config_filename)

def config_warn(e):
    warnings.warn('Config setting {}. Using default.'.format(e))

# laod config values
try:
    filekinds = config['filekinds'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    filekinds = config_defaults['filekinds'].get()
    

def add_mappings(mappings):
    """Returns a dict with additional es mappings."""
    mappings['mappings']['properties'].update({
        'filekind': {
            'type': 'keyword'
        }
    })
    return mappings


def add_meta(path, osstat):
    """Returns a dict with additional file meta data.
    For any warnings or errors, raise RuntimeWarning or RuntimeError.
    RuntimeWarning and RuntimeError requires two args, error message string and dict or None."""
    filename = os.path.basename(path)
    extension = os.path.splitext(filename)[1][1:].lower()
    if extension == '':
        return {'filekind': 'Other'}
    for filekindlabel, filekindext in filekinds.items():
        if extension in filekindext:
            return {'filekind': filekindlabel}
    return {'filekind': 'Other'}


def add_tags(metadict):
    """Returns a dict with additional tag data or return None to not alter tags."""
    # check if permissions are fully open and add extra tags
    return None


def for_type(doc_type):
    """Determine if this plugin should run for file and/or directory."""
    if doc_type in ('file'):
        return True
    return False


def init(diskover_globals):
    """Init the plugin.
    Called by diskover when the plugin is first loaded.
    """
    global logger
    global logger_warn
    global logtofile
    
    # Setup logging
    logger = logging.getLogger(__name__)
    logger_warn = logging.getLogger(__name__ + '_warn')
    logtofile = False
    if diskover_globals['logtofile']:
        logtofile = True
        logger.setLevel(diskover_globals['loglevel'])
        logger.addHandler(diskover_globals['handler_file'])
        # console logging
        logger.addHandler(diskover_globals['handler_con'])
        # warnings log
        logger_warn.setLevel(logging.WARN)
        logger_warn.addHandler(diskover_globals['handler_warnfile'])
    return


def close(diskover_globals):
    """Close the plugin.
    Called by diskover at end of crawl.
    """
    return