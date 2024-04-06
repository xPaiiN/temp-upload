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
diskover file first index time plugin

=== Plugin Description ===
diskover file first index time plugin - This is an example plugin
for diskover. It adds first index time (firstindextime field) meta data to diskover index
during indexing.

File info is cached in sqlite3 db using diskover cache module.

=== Plugin Requirements ===
- xxhhash python module when using xxhash

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
import hashlib
import warnings
import re
from pathlib import Path
from datetime import datetime

import diskover_cache as d_cache
import diskover_lic


version = '0.0.1'
__version__ = version
__name__ = 'firstindextime_plugin'


"""Load yaml config file.
Checks for env var DISKOVER_FIRSTINDEXTIME_PLUGIN as alternate config file.
"""
config = confuse.Configuration('diskover_firstindextime_plugin', __name__)
config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
if not os.path.exists(config_filename):
    print('Config file {0} not found! Copy from default config.'.format(config_filename))
    sys.exit(1)

# load creationtime plugin default config file
config_defaults = confuse.Configuration('diskover_firstindextime_plugin', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
# get parent path two levels up
scriptpath_parent = Path(scriptpath).parents[1]
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_firstindextime_plugin/config.yaml')
config_defaults.set_file(default_config_filename)

def config_warn(e):
    warnings.warn('Config setting {}. Using default.'.format(e))

# laod config values
try:
    verbose = config['verbose'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    verbose = config_defaults['verbose'].get()
try:
    cachedir = config['cachedir'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    cachedir = config_defaults['cachedir'].get()
try:
    cache_expiretime = config['cacheexpiretime'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    cache_expiretime = config_defaults['cacheexpiretime'].get()
finally:
    if cache_expiretime == 0: cache_expiretime = None
try:
    include_dirs = config['includedirs'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    include_dirs = config_defaults['includedirs'].get()
try:
    exclude_dirs = config['excludedirs'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    exclude_dirs = config_defaults['excludedirs'].get()


def get_firstindextime(file, ino):
    """Get first index time of file."""
    
    # check if file path in cache
    # md5 hash file path
    pathhash = hashlib.md5(file.encode('utf-8')).hexdigest()
    # Get file hash from cache
    cache_res = cache.get_value(pathhash)
    if cache_res and cache_res['ino'] == ino:
        logger.debug('CACHE HIT {0}'.format(file))
        return cache_res['firstindextime']
    logger.debug('CACHE MISS {0}'.format(file))
    
    # cache firstindextime
    firstindextime = datetime.utcnow().replace(microsecond=0).isoformat()
    cache_data = {
        'firstindextime': firstindextime,
        'ino': ino
    }
    cache.set_value(pathhash, cache_data, expire_seconds=cache_expiretime)
    
    return firstindextime


def dir_excluded(path):
    """Return True if path in exclude_dirs, False if not in the list."""
    # return False if dir exclude list is empty
    if not exclude_dirs:
        return False
    name = os.path.basename(path)
    pp = os.path.dirname(path)
    # skip any dirs in excludedirs
    if name in exclude_dirs or pp in exclude_dirs:
        return True
    # skip any dirs that are found in reg exp checks including wildcard searches
    for d in exclude_dirs:        
        if d.startswith('*'):
            d = d.lstrip('*')
            
        if d.endswith('/'):
            d = d.rstrip('/')
        
        try:
            res = re.search(d, name)
        except re.error as e:
            raise Exception(e)
        else:
            if res:
                return True
            
        try:
            res = re.search(d, pp)
        except re.error as e:
            raise Exception(e)
        else:
            if res:
                return True
    return False


def dir_included(path):
    """Return True if path in include_dirs, False if not in the list."""
    # return True if dir include list is empty
    if not include_dirs:
        return True
    name = os.path.basename(path)
    pp = os.path.dirname(path)
    # return True if any dirs in include_dirs
    if name in include_dirs or pp in include_dirs:
        return True
    # retun True if any dirs that are found in reg exp checks including wildcard searches
    for d in include_dirs:        
        if d.startswith('*'):
            d = d.lstrip('*')
            
        if d.endswith('/'):
            d = d.rstrip('/')
        
        try:
            res = re.search(d, name)
        except re.error as e:
            raise Exception(e)
        else:
            if res:
                return True
            
        try:
            res = re.search(d, pp)
        except re.error as e:
            raise Exception(e)
        else:
            if res:
                return True
    return False


def add_mappings(mappings):
    """Returns a dict with additional es mappings."""
    mappings['mappings']['properties'].update({
        'firstindextime': {
            'type': 'date'
        }
    })
    return mappings


def add_meta(path, osstat):
    """Returns a dict with additional file meta data.
    For any warnings or errors, raise RuntimeWarning or RuntimeError.
    RuntimeWarning and RuntimeError requires two args, error message string and dict or None."""
    
    # skip excluded dirs
    if dir_excluded(path):
        if verbose:
            logger.info('Skipping excluded directory {0}'.format(path))
        return None
    
    # check if dir is included
    if not dir_included(path):
        if verbose:
            logger.info('Skipping directory {0} since it is not in included dirs'.format(path))
        return None
    
    if verbose:
        logger.info('Getting file creation time for {0}...'.format(path))
    ino = osstat.st_ino  # file inode
    firstindextime = get_firstindextime(path, ino)
    if firstindextime is not None:
        return { 'firstindextime': firstindextime }
    return None


def add_tags(metadict):
    """Returns a dict with additional tag data or return None to not alter tags."""
    return None


def for_type(doc_type):
    """Determine if this plugin should run for file and/or directory."""
    if doc_type in ('file'):
        return True
    return False


def init(diskover_globals):
    """Initialize the plugin.
    Called by diskover when the plugin is first loaded.
    """
    global cache
    global logger
    global logger_warn
    global logtofile
    
    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = diskover_lic.License()
    lic.check_license()
    diskover_lic.licfc(lic, 'PRO', __name__)
    
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
    
    # Setup checksum hash cache db
    try:
        toppaths = diskover_globals['tree_dirs']
        toppaths_hash = hashlib.md5(" ".join(toppaths).encode('utf-8')).hexdigest()
        cachedir_abspath = os.path.abspath(os.path.join(cachedir, toppaths_hash))
        cache = d_cache.cache(cachedir_abspath)
    except FileExistsError:
        pass
    except OSError as e:
        logger.error('Error creating cache directory {0}'.format(e))
        sys.exit(1)
    logger.info('Using/ caching file info in {0}'.format(cachedir_abspath))
    return


def close(diskover_globals):
    """Close the plugin.
    Called by diskover at end of crawl.
    """
    cache.close_db()
    return