#!/usr/bin/env python3
"""
diskover
https://diskoverdata.com

Copyright 2017-2022 Diskover Data, Inc.
"Community" portion of Diskover made available under the Apache 2.0 License found here:
https://www.diskoverdata.com/apache-license/

All other content is subject to the Diskover Data, Inc. end user license agreement found at:
https://www.diskoverdata.com/eula-subscriptions/

Diskover Data products and features for all versions found here:
https://www.diskoverdata.com/solutions/


=== Crawler Description ===

Creates a user defined top level root directory (ROOT_PATH), with data scanned from a specified directory
and placed into another defined directory (MEDIA_LABEL) beneath.

The first time it is run it creates the ROOT_PATH top level dir while scanning.  On the next scan,
you should call it with the '-a' flag while changing the MEDIA_LABEL env var to a different value.

You will end up with a bunch of directories under the root, each named by MEDIA_LABEL, with the contents of each scan

FIRST RUN EXAMPLE:

    export MEDIA_LABEL=12345

    python3 diskover.py -i diskover-offline-media --altscanner scandir_offline_media /mnt/tape

SUBSEQUENT RUNS:

    export MEDIA_LABEL=23456

    python3 diskover.py -i diskover-offline-media -a --altscanner scandir_offline_media /mnt/another_tape

"""

import os
import sys
import uuid
import logging
import hashlib
import confuse
import warnings
import re
from datetime import datetime
import diskover_cache as dir_cache
from os.path import join
from os import scandir as os_scandir
from diskover import blocksize, version
from diskover_lic import License, licfc

from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload

__version__ = '0.0.1'
__all__ = ['scandir_dircache', 'walk_dircache']

# Windows check
if os.name == 'nt':
    IS_WIN = True
else:
    IS_WIN = False


class ConfigurationError(Exception): pass


def init(diskover_globals):
    global dircache
    global verbose
    global dirlist_expire
    global load_db_mem
    global es
    global index

    global MEDIA_LABEL
    global TOPDIR
    global ADD_TO_INDEX
    global ROOT_PATH

    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'PRO', __name__)
    # end license check

    es = elasticsearch_connection()

    index = diskover_globals['options'].index
    # Load yaml config file
    config = confuse.Configuration('diskover_offline_media', __name__)
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    if not os.path.exists(config_filename):
        print('Config file {0} not found! Copy from default config.'.format(config_filename))
        raise SystemExit(1)

    # load default config file
    config_defaults = confuse.Configuration('diskover_offline_media', __name__)
    scriptpath = os.path.dirname(os.path.realpath(__file__))
    scriptparentpath = os.path.dirname(scriptpath)
    defaultconfig_filename = os.path.join(scriptparentpath, 'configs_sample/diskover_offline_media/config.yaml')
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

    ROOT_PATH = os.environ.get('ROOT_PATH')
    if ROOT_PATH is None:
        try:
            ROOT_PATH = config['root_path'].get()
        except confuse.NotFoundError as e:
            config_warn(e)
            ROOT_PATH = config_defaults['root_path'].get()

    # print config being used
    dircachelogger.info('Config file: {0}'.format(config_filename))

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

    MEDIA_LABEL = os.environ.get('MEDIA_LABEL')
    if MEDIA_LABEL is None:
        raise ConfigurationError('The "MEDIA_LABEL" environment variable is not set!')

    TOPDIR = diskover_globals['args'][0]
    if TOPDIR != '/':
        TOPDIR = TOPDIR.rstrip('/')
    ADD_TO_INDEX = diskover_globals['options'].addtoindex


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
    __slots__ = ('name', '_d_type', '_inode', '_stat', '_lstat', '_scandir_path', '_path', '_fake_path')

    def __init__(self, scandir_path, fake_path, name, d_type, inode, stat):
        self._scandir_path = scandir_path
        self._fake_path = fake_path
        self.name = name
        self._d_type = d_type
        self._inode = inode
        self._stat = stat
        self._lstat = None
        self._path = None

    @property
    def path(self):
        if self._path is None:
            self._path = join(self._fake_path, self.name)
        return self._path

    def stat(self, follow_symlinks=False):
        if self._lstat is None:
            self._lstat = stat(join(self._scandir_path, self.name), self._stat)
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
    path = path.replace(os.path.join(ROOT_PATH, MEDIA_LABEL), TOPDIR, 1)
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
    top = top.replace(os.path.join(ROOT_PATH, MEDIA_LABEL), TOPDIR, 1)
    try:
        for item in get_cached_dirlist(top):
            name, inode, d_type, stat = item
            yield DirCacheDirEntry(top, top.replace(TOPDIR, os.path.join(ROOT_PATH, MEDIA_LABEL)), name, d_type, inode, stat)
    except Exception:
        raise


def walk_dircache(top):
    """Like Python 3.5's implementation of os.walk().
    """
    # walk the real directory, but return the paths with replaced paths
    if not top:
        raise ValueError('No top path param')
    dirs = []
    nondirs = []
    for entry in scandir_dircache(top):
        if entry.is_dir() is True:
            dirs.append(entry.name)
        else:
            nondirs.append(entry.name)
    yield top, dirs, nondirs

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

    # TODO If the indexing fails, we don't know here
    # we might error trying to find and update the index info

    # Close database
    dircache.close_db()

    #
    # Do all the shenanigans to fix up the index and add the top level root and media label, etc
    #

    es.indices.refresh(index=index)
    if ADD_TO_INDEX is True:
        update_index_info()
    else:
        update_index_path()
    update_top_dirs()


def update_index_info():
    # we are appending to the existing index!

    # get the spaceinfo and indexinfo docs
    # and update the source['path'] to /OFFLINE_MEDIA
    data = {
        "query": {
            "match": {
                "type": "indexinfo"
            }
        }

    }
    res = es.search(index=index, body=data)
    root = None
    new = None
    for res in res['hits']['hits']:
        if res['_source'].get('file_size') is None:
            # There are two indexinfo entries
            # one for the start and one for the end
            # we need to update the end one, delete the other
            if res['_source']['path'] == TOPDIR:
                es.delete(index=index, id=res['_id'], refresh=True)
            continue

        if res['_source']['path'] == TOPDIR:
            new = res
        elif res['_source']['path'] == ROOT_PATH:
            root = res

    doc = {
        "doc": {
            'file_size': root['_source']['file_size'] + new['_source']['file_size'],
            'file_size_du': root['_source']['file_size_du'] + new['_source']['file_size_du'],
            'file_count': root['_source']['file_count'] + new['_source']['file_count'],
            'dir_count': root['_source']['dir_count'] + new['_source']['dir_count'],
            'crawl_time': root['_source']['crawl_time'] + new['_source']['crawl_time']
        }
    }
    es.update(index=index, id=root['_id'], body=doc, refresh=True)
    es.delete(index=index, id=new['_id'], refresh=True)

    data = {
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "type": 'spaceinfo'
                        }
                    },
                    {
                        "match": {
                            "path": TOPDIR
                        }
                    }
                ]
            }
        }
    }
    res = es.search(index=index, body=data)
    for hit in res['hits']['hits']:
        es.delete(index=index, id=hit['_id'], refresh=True)


def update_index_path():
    # we are creating the index for the first time!

    data = {
        "query": {
            "bool": {
                "should": [
                    {
                        "match": {
                            "type": "spaceinfo"
                        }
                    },
                    {
                        "match": {
                            "type": "indexinfo"
                        }
                    }
                ],
            }
        }
    }
    res = es.search(index=index, body=data)

    for hit in res['hits']['hits']:
        id = hit['_id']
        es.update(index=index, id=id, body={"doc": {"path": ROOT_PATH}}, refresh=True)


def update_top_dirs():
    now = datetime.now()
    # Move the root path to the media label under /OFFLINE_MEDIA
    parent_path, name = os.path.split(TOPDIR)
    data = {
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "parent_path": parent_path
                        }
                    },
                    {
                        "match": {
                            "name": name
                        }
                    },
                    {
                        "match": {
                            "type": "directory"
                        }
                    }
                ]
            }
        }
    }
    res = es.search(index=index, body=data)
    for hit in res['hits']['hits']:
        id = hit['_id']
        es.update(index=index, id=id, body={"doc": {"parent_path": ROOT_PATH, 'name': MEDIA_LABEL}}, refresh=True)

        #there should really only be one hit

        if not ADD_TO_INDEX:
            # when we are scanning the index for the first time, we need to create a root directory node
            # with sizes from the root we replaced /OFFLINE_MEDIA/M12345
            doc = {
                "name": ROOT_PATH.lstrip('/'),
                "parent_path": "/",
                "size": hit['_source']['size'],
                "size_norecurs": hit['_source']['size_norecurs'],
                "size_du": hit['_source']['size_du'],
                "size_du_norecurs": hit['_source']['size_du_norecurs'],
                "file_count": hit['_source']['file_count'],
                "file_count_norecurs": hit['_source']['file_count_norecurs'],
                "dir_count": hit['_source']['dir_count'],
                "dir_count_norecurs": hit['_source']['dir_count_norecurs'],
                "dir_depth": 0,
                "mtime": now,
                "atime": now,
                "ctime": now,
                "nlink": 0,
                "ino": "16933009",
                "owner": "root",
                "group": "root",
                "costpergb": 0,
                "type": "directory"
            }
            es.index(index=index, body=doc)
        else:
            # When we are appending to the index, we need to add the sizes to the toplevel dir
            data = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "parent_path": '/'
                                }
                            },
                            {
                                "match": {
                                    "name": ROOT_PATH.lstrip('/')
                                }
                            },
                            {
                                "match": {
                                    "type": "directory"
                                }
                            }
                        ]
                    }
                }
            }
            update_res = es.search(index=index, body=data)

            for update_hit in update_res['hits']['hits']:
                update_doc = {
                    "doc":
                        {
                            "size": update_hit['_source']['size'] + hit['_source']['size'],
                            "size_norecurs": update_hit['_source']['size_norecurs'] + hit['_source']['size_norecurs'],
                            "size_du": update_hit['_source']['size_du'] + hit['_source']['size_du'],
                            "size_du_norecurs": update_hit['_source']['size_norecurs'] + hit['_source']['size_du_norecurs'],
                            "dir_count": update_hit['_source']['dir_count'] + hit['_source']['dir_count'],
                            "dir_count_norecurs": update_hit['_source']['dir_count_norecurs'] + hit['_source']['dir_count_norecurs'],
                            "file_count": update_hit['_source']['file_count'] + hit['_source']['file_count'],
                            "file_count_norecurs": update_hit['_source']['file_count_norecurs'] + hit['_source']['file_count_norecurs'],
                            "mtime": now,
                        }
                }
                es.update(index=index, id=update_hit['_id'], body=update_doc, refresh=True)


walk = walk_dircache
scandir = scandir_dircache
