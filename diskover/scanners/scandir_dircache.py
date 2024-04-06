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


=== Crawler Description ===

scandir_dircache, a dir cache directory iterator equivalent of os.scandir()

scandir_dircache() is a generator that returns an iterator over files in a directory, 
and also caches directory mtime, file list and stat info while iterating files in a directory
(such as type and stat information).

This module also includes walk_dircache() an equivalent of os.walk() that uses scandir_dircache().


=== Crawler Requirements ===

crawlers require these function names:
- log_setup
- check_dirpath
- scandir
- stat
- get_storage_size
- abspath
- add_mappings
- add_meta
- add_tags

crawlers optional function names:
- log_setup
- init
- close


=== diskover Usage ===

python3 diskover.py --altscanner scandir_dircache /toppath

"""

import os
import sys
import logging
import hashlib
import confuse
import warnings
import re
import diskover_cache as dir_cache
from os.path import join
from os import scandir as os_scandir
from diskover import blocksize
from diskover_lic import License, licfc

__version__ = '0.0.10'
__all__ = ['scandir_dircache', 'walk_dircache']

# Windows check
if os.name == 'nt':
    IS_WIN = True
else:
    IS_WIN = False


def init(diskover_globals):
    global dircache
    global verbose
    global dirlist_expire
    global load_db_mem
    
    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'PRO', __name__)
    # end license check
    
    # Load yaml config file
    config = confuse.Configuration('diskover_scandir_dircache', __name__)
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    if not os.path.exists(config_filename):
        print('Config file {0} not found! Copy from default config.'.format(config_filename))
        raise SystemExit(1)

    # load default config file
    config_defaults = confuse.Configuration('diskover_scandir_dircache', __name__)
    scriptpath = os.path.dirname(os.path.realpath(__file__))
    scriptparentpath = os.path.dirname(scriptpath)
    defaultconfig_filename = os.path.join(scriptparentpath, 'configs_sample/diskover_scandir_dircache/config.yaml')
    config_defaults.set_file(defaultconfig_filename)

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
        dirlist_expire = config['dirlist_expire'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        dirlist_expire = config_defaults['dirlist_expire'].get()
    finally:
        if dirlist_expire == 0:
            dirlist_expire = None
    try:
        load_db_mem = config['load_db_mem'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        load_db_mem = config_defaults['load_db_mem'].get()
    finally:
        if load_db_mem:
            warnings.warn('Setting load_db_mem in config to True can cause sqlite db corruption if scan crashes. \
                          It is recommended to set this to False.')
    
    # print config being used
    dircachelogger.info('Config file: {0}'.format(config_filename))
    dircachelogger.info('Config env var DISKOVER_SCANDIR_DIRCACHEDIR: {0}'.format(os.getenv('DISKOVER_SCANDIR_DIRCACHEDIR')))
    
    tree_dirs = []
    dirs = diskover_globals['args'][0:]
    for d in dirs:
        tree_dirs.append(abspath(d))
        
    toppaths = tree_dirs
    toppaths_hash = hashlib.md5(" ".join(toppaths).encode('utf-8')).hexdigest()
    
    # setup dir list cache db
    try:
        cachedir_abspath = os.path.abspath(os.path.join(cachedir, toppaths_hash))
        dircache = dir_cache.cache(cachedir_abspath, load_into_mem=load_db_mem)
    except FileExistsError:
        pass
    except OSError as e:
        dircachelogger.error('Error creating dir cache directory {0}'.format(e))
        sys.exit(1)


def log_setup(loglevel, logformat, filelogging, handler_file, handler_warnfile, handler_con):
    """Logging set up."""
    global dircachelogger
    global dircachelogger_warn
    global logtofile
    if filelogging:
        logtofile = True
    else:
        logtofile = False
    dircachelogger = logging.getLogger('scandir_dircache')
    dircachelogger_warn = logging.getLogger('scandir_dircache_warn')
    dircachelogger.setLevel(loglevel)
    if logtofile:
        dircachelogger.addHandler(handler_file)
        dircachelogger.addHandler(handler_con)
        dircachelogger_warn.addHandler(handler_warnfile)
        dircachelogger.setLevel(loglevel)
        dircachelogger_warn.setLevel(logging.WARN)
    else:
        logging.basicConfig(format=logformat, level=loglevel)
        

def check_dirpath(path):
    """Check toppath arg is valid."""
     # check path exists
    if not os.path.exists(path):
        return (False, '{0} no such directory!'.format(path))
    else:
        return (True, None)


class DirCacheDirEntry(object):
    __slots__ = ('name', '_d_type', '_inode', '_stat', '_lstat', '_scandir_path', '_path')

    def __init__(self, scandir_path, name, d_type, inode, stat):
        self._scandir_path = scandir_path
        self.name = name
        self._d_type = d_type
        self._inode = inode
        self._stat = stat
        self._lstat = None
        self._path = None

    @property
    def path(self):
        if self._path is None:
            self._path = join(self._scandir_path, self.name)
        return self._path

    def stat(self, follow_symlinks=False):
        if self._lstat is None:
            self._lstat = stat(self.path, self._stat)
        return self._lstat

    def is_dir(self, follow_symlinks=False):
        return self._d_type == 'DIR'

    def is_file(self, follow_symlinks=False):
        return self._d_type == 'REG'

    def is_symlink(self):
        return self._d_type == 'LNK'

    def inode(self):
        return self._inode

    def __str__(self):
        return '<{0}: {1!r}>'.format(self.__class__.__name__, self.name)

    __repr__ = __str__


class stat_result(object):
    __slots__ = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                 'st_atime', 'st_mtime', 'st_ctime', 'st_sizedu')
    
    def __init__(self, stat_tup):
        st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_atime, st_mtime, \
            st_ctime, st_sizedu = stat_tup
        # standard stat params
        self.st_mode = st_mode
        self.st_ino = st_ino
        self.st_dev = st_dev
        self.st_nlink = st_nlink
        self.st_uid = st_uid
        self.st_gid = st_gid
        self.st_size = st_size
        self.st_atime = st_atime
        self.st_mtime = st_mtime
        self.st_ctime = st_ctime
        # size used (allocated) param
        self.st_sizedu = st_sizedu


def stat(path, st=None):
    if st is None:
        try:
            st = os.lstat(path)
        except OSError as e:
            raise RuntimeError(e)
        st_list = list(st)
        if not IS_WIN:
            st_list.append(st.st_blocks)
        st = st_list
    st_mode = st[0]
    st_ino = st[1]
    st_dev = st[2]
    st_nlink = st[3]
    st_uid = st[4]
    st_gid = st[5]
    st_size = st[6]
    st_atime = st[7]
    st_mtime = st[8]
    st_ctime = st[9]
    if IS_WIN:
        st_sizedu = st_size
    else:
        st_sizedu = st[10] * blocksize
    return stat_result((st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_atime, 
                        st_mtime, st_ctime, st_sizedu))


def get_cached_dirlist(path):
    """Gets cached directory list for path."""
    # hash path and see if it's stored in cache
    global dircache
    pathhash = hashlib.md5(path.encode('utf-8', errors='ignore')).hexdigest()
    res = dircache.get_value(pathhash)
    mtime = os.path.getmtime(path)
    if res:
        # check if modified times are same
        if mtime == res['mtime']:
            if verbose:
                dircachelogger.info('DIR LIST CACHE HIT {0}'.format(path))
            return res['dirlist']
    # not in cache or mtime not same
    if verbose:
        dircachelogger.info('DIR LIST CACHE MISS {0}'.format(path))
    dirlist = []
    for entry in os_scandir(path):
        if entry.is_symlink():
            d_type = 'LNK'
        elif entry.is_dir():
            d_type = 'DIR'
        else:
            d_type = 'REG'
        st = entry.stat(follow_symlinks=False)
        st_list = list(st)
        if not IS_WIN:
            st_list.append(st.st_blocks)
        dirlist.append((entry.name, entry.inode(), d_type, st_list))
    # cache directory list
    dircache.set_value(pathhash, {'mtime': mtime, 'dirlist': dirlist}, expire_seconds=dirlist_expire, force_update=True)
    return dirlist


def scandir_dircache(top):
    """Paginates over directory listing, tries to get file type from cache, 
    and yields DirEntry objects.
    """
    if not top:
        raise ValueError('No top path param')

    try:
        for item in get_cached_dirlist(top):
            name, inode, d_type, stat = item
            yield DirCacheDirEntry(top, name, d_type, inode, stat)
    except Exception:
        raise


def walk_dircache(top):
    """Like Python 3.5's implementation of os.walk().
    """
    if not top:
        raise ValueError('No top path param')
    
    dirs = []
    nondirs = []
    
    try:
        scandir_dircache_it = scandir_dircache(top)
    except Exception:
        return

    while True:
        try:
            try:
                entry = next(scandir_dircache_it)
            except StopIteration:
                break
        except Exception:
            return

        try:
            is_dir = entry.is_dir()
        except Exception:
            is_dir = False

        if is_dir:
            dirs.append(entry.name)
        else:
            nondirs.append(entry.name)
            
    yield top, dirs, nondirs

    # Recurse into sub-directories
    for name in dirs:
        new_path = join(top, name)
        for entry in walk_dircache(new_path):
            yield entry


def abspath(path):
    """Converts path to an absolute Posix path."""
    if IS_WIN:
        # check if only drive letter (C:) was used with no trailing slash
        if path.endswith(':'):
            path = os.path.join(path, '\\\\')
        elif re.search('^\\\\', path) is not None:
            # remove any trailing \ slash from UNC path
            path = path.rstrip('\\')
        path = os.path.realpath(path)
    else:
        # remove any trialing slash if not root /
        if path != '/':
            path = path.rstrip('/')
    return os.path.abspath(path)


def get_storage_size(path):
    """Gets the total, free, and available space of the storage path.
    """
    if not IS_WIN:
        statvfs = os.statvfs(path)
        # Size of filesystem in bytes
        storage_size = statvfs.f_frsize * statvfs.f_blocks
        # Actual number of free bytes
        free_space = statvfs.f_frsize * statvfs.f_bfree
        # Number of free bytes that ordinary users are allowed
        # to use (excl. reserved space)
        available_space = statvfs.f_frsize * statvfs.f_bavail
    else:
        import ctypes
        total_bytes = ctypes.c_ulonglong(0)
        free_bytes = ctypes.c_ulonglong(0)
        available_bytes = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(path),
            ctypes.pointer(available_bytes),
            ctypes.pointer(total_bytes),
            ctypes.pointer(free_bytes))
        storage_size = total_bytes.value
        free_space = free_bytes.value
        available_space = available_bytes.value
    return storage_size, free_space, available_space


def add_mappings(mappings):
    """Returns a dict with additional es mappings."""
    return mappings


def add_meta(path, osstat):
    """Returns a dict with additional file meta data."""
    return None


def add_tags(metadict):
    """Returns a dict with additional tag data or return None to not alter tags."""
    return None


def close(diskover_globals):
    """Close the alt scanner.
    Called by diskover at end of crawl.
    """
    # Close database
    dircache.close_db()


walk = walk_dircache
scandir = scandir_dircache