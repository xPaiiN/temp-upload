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
diskover file checksum/hash plugin

=== Plugin Description ===
diskover file checksum/hash plugin - This is an example plugin
for diskover. It adds file checksum (md5, sha1, sha256, xxhash) hash meta data to diskover index
during indexing.

Checksum type can be md5, sha1, sha256, xxhash depending on what is set in config.

Hashes are cached in sqlite3 db using diskover cache module.

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
import time
import re
from datetime import timedelta
from timeit import default_timer as timer
from pathlib import Path
from threading import Lock

import diskover_cache as d_cache
import diskover_lic
from diskover_helpers import set_times, convert_size, speed, get_time


version = '0.0.2'
__version__ = version
__name__ = 'checksum_plugin'


"""Load yaml config file.
Checks for env var DISKOVER_CHECKSUM_PLUGIN as alternate config file.
"""
config = confuse.Configuration('diskover_checksum_plugin', __name__)
config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
if not os.path.exists(config_filename):
    print('Config file {0} not found! Copy from default config.'.format(config_filename))
    sys.exit(1)

# load checksum plugin default config file
config_defaults = confuse.Configuration('diskover_checksum_plugin', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
# get parent path two levels up
scriptpath_parent = Path(scriptpath).parents[1]
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_checksum_plugin/config.yaml')
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
    hash_mode = config['mode'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_mode = config_defaults['mode'].get()
finally:
     # check if xxhash installed
    if hash_mode == 'xxhash':
        try:
            import xxhash
        except ModuleNotFoundError:
            print('Missing xxhash Python module')
            sys.exit(1)
try:
    hash_blocksize = config['blocksize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_blocksize = config_defaults['blocksize'].get()
try:
    hash_cachedir = config['cachedir'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_cachedir = config_defaults['cachedir'].get()
try:
    hash_cache_expiretime = config['cacheexpiretime'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_cache_expiretime = config_defaults['cacheexpiretime'].get()
finally:
    if hash_cache_expiretime == 0: hash_cache_expiretime = None
try:
    hash_minsize = config['minsize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_minsize = config_defaults['minsize'].get()
finally:
    # check if minsize is 0 and set to 1
    if hash_minsize == 0: hash_minsize = 1
try:
    hash_maxsize = config['maxsize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_maxsize = config_defaults['maxsize'].get()
try:
    hash_extensions = config['extensions'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_extensions = config_defaults['extensions'].get()
try:
    exclude_extensions = config['excludeextensions'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    exclude_extensions = config_defaults['excludeextensions'].get()
try:
    exclude_dirs = config['excludedirs'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    exclude_dirs = config_defaults['excludedirs'].get()
try:
    hash_restore_times = config['restoretimes'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_restore_times = config_defaults['restoretimes'].get()


lock = Lock()
totalhashtime = 0


def get_hash(file, size, mtime):
    """Use xxhash or md5, etc to get the hexadecimal digest of the file hash.
    Returns hash"""
    # return if size is 0
    if size == 0:
        return None
    
    # check if hash in cache
    # md5 hash file path
    pathhash = hashlib.md5(file.encode('utf-8')).hexdigest()
    # Get file hash from cache
    cache_res = hashcache.get_value(pathhash)
    if cache_res:
        if hash_mode in cache_res and mtime == cache_res['mtime']:
            checksumpluglogger.debug('CACHE HIT {0}'.format(file))
            return cache_res[hash_mode]
    checksumpluglogger.debug('CACHE MISS {0}'.format(file))
    
    if hash_mode == 'xxhash':
        x = xxhash.xxh64()
    elif hash_mode == 'md5':
        x = hashlib.md5()
    elif hash_mode == 'sha1':
        x = hashlib.sha1()
    elif hash_mode == 'sha256':
        x = hashlib.sha256()
    
    # get current atime/mtime before opening file to get hash
    if hash_restore_times:
        try:
            st = os.stat(file)
        except OSError as e:
            if verbose:
                checksumpluglogger.warning('Error stat file: {0} ({1})'.format(file, e))
                if logtofile:
                    checksumpluglogger_warn.warning('Error stat file: {0} ({1})'.format(file, e))
            return None
    try:
        with open(file, 'rb') as f:
            fb = f.read(hash_blocksize)
            while len(fb) > 0:
                x.update(fb)
                fb = f.read(hash_blocksize)
    except OSError as e:
        if verbose:
            checksumpluglogger.warning('Error open file: {0} ({1})'.format(file, e))
            if logtofile:
                checksumpluglogger_warn.warning('Error open file: {0} ({1})'.format(file, e))
        return None
    
    xhex = x.hexdigest()
    
    # restore times (atime/mtime)
    if hash_restore_times:
        res, err = set_times(file, st.st_atime, st.st_mtime)
        if not res and verbose:
            checksumpluglogger.warning('Error set times file: {0} ({1})'.format(file, err))
            if logtofile:
                checksumpluglogger_warn.warning('Error set times file: {0} ({1})'.format(file, err))
    
    # cache file hash
    if cache_res:
        cache_data = cache_res.copy()
    else:
        cache_data = dict()
    cache_data['mtime'] = mtime
    cache_data[hash_mode] = xhex
    hashcache.set_value(pathhash, cache_data, expire_seconds=hash_cache_expiretime)
    
    return xhex


def dir_excluded(path):
    """Return True if path in exclude_dirs, False if not in the list."""
    # return False if dir exclude list is empty
    if not exclude_dirs:
        return False
    name = os.path.basename(path)
    # skip any dirs in exclude_dirs
    if name in exclude_dirs or path in exclude_dirs:
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
            res = re.search(d, path)
        except re.error as e:
            raise Exception(e)
        else:
            if res:
                return True
    return False


def add_mappings(mappings):
    """Returns a dict with additional es mappings."""
    mappings['mappings']['properties'].update({
        'hash': {
            'type': 'object',
            'properties': {
                'xxhash': {
                    'type': 'keyword'
                },
                'md5': {
                    'type': 'keyword'
                },
                'sha1': {
                    'type': 'keyword'
                },
                'sha256': {
                    'type': 'keyword'
                }
            }
        }
    })
    return mappings


def add_meta(path, osstat):
    """Returns a dict with additional file meta data.
    For any warnings or errors, raise RuntimeWarning or RuntimeError.
    RuntimeWarning and RuntimeError requires two args, error message string and dict or None."""
    global totalhashtime
    
    # skip excluded dirs
    if dir_excluded(path):
        if verbose:
            checksumpluglogger.info('Skipping excluded directory {0}'.format(path))
        return None
    
    # skip excluded file extensions
    extension = os.path.splitext(os.path.basename(path))[1][1:].lower()
    if (hash_extensions and extension not in hash_extensions) or (extension in exclude_extensions):
        if verbose:
            checksumpluglogger.info('Skipping excluded file extension {0}'.format(path))
        return None
    
    if verbose:
        checksumpluglogger.info('Getting checksum hash for {0}...'.format(path))
    size = osstat.st_size  # size in bytes
    mtime = osstat.st_mtime  # unix epoch modified time
    start = timer()
    start_time_epoch = time.time()
    filehash = get_hash(path, size, mtime)
    end = timer()
    seconds = end - start
    with lock:
        totalhashtime += seconds
    if filehash is not None:
        if verbose:
            hashtime = timedelta(seconds = seconds)
            checksumpluglogger.info('Finished getting checksum hash for {0} in {1}s (size {2}, speed {3}, hash {4})'.format(
                    path, hashtime, convert_size(size), speed(start_time_epoch, size), filehash))
        return { 'hash': { hash_mode: filehash } }
    else:
        if verbose:
            checksumpluglogger.warning('Checksum hash returned None for {0}'.format(path))
            if logtofile:
                checksumpluglogger_warn.warning('Checksum hash returned None for {0}'.format(path))
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
    global hashcache
    global checksumpluglogger
    global checksumpluglogger_warn
    global logtofile
    
    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = diskover_lic.License()
    lic.check_license()
    diskover_lic.licfc(lic, 'ESS', __name__)
    
    # Setup logging
    checksumpluglogger = logging.getLogger(__name__)
    checksumpluglogger_warn = logging.getLogger(__name__ + '_warn')
    logtofile = False
    if diskover_globals['logtofile']:
        logtofile = True
        checksumpluglogger.setLevel(diskover_globals['loglevel'])
        checksumpluglogger.addHandler(diskover_globals['handler_file'])
        # console logging
        checksumpluglogger.addHandler(diskover_globals['handler_con'])
        # warnings log
        checksumpluglogger_warn.setLevel(logging.WARN)
        checksumpluglogger_warn.addHandler(diskover_globals['handler_warnfile'])
    
    # Check for valid checksum hash type
    if hash_mode not in ('xxhash', 'md5', 'sha1', 'sha256'):
        checksumpluglogger.error('Unsupported hash mode {0}, supported types are xxhash, md5, sha1, sha256'.format(hash_mode))
        sys.exit(1)
    
    checksumpluglogger.info('Using hash mode {0}'.format(hash_mode))
    
    # Setup checksum hash cache db
    try:
        toppaths = diskover_globals['tree_dirs']
        toppaths_hash = hashlib.md5(" ".join(toppaths).encode('utf-8')).hexdigest()
        cachedir_abspath = os.path.abspath(os.path.join(hash_cachedir, toppaths_hash))
        hashcache = d_cache.cache(cachedir_abspath)
    except FileExistsError:
        pass
    except OSError as e:
        checksumpluglogger.error('Error creating hash cache directory {0}'.format(e))
        sys.exit(1)
    checksumpluglogger.info('Using/ caching file hashes in {0}'.format(cachedir_abspath))
    return


def close(diskover_globals):
    """Close the plugin.
    Called by diskover at end of crawl.
    """
    checksumpluglogger.info('*** Total time to get checksums: {0} ***'.format(get_time(totalhashtime)))
    hashcache.close_db()
    return
