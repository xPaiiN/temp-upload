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

scandir_s3, a s3 directory iterator equivalent of os.scandir()

scandir_s3() is a generator that returns an iterator over files in a directory, 
and also exposes the extra information s3 provides while iterating files in a directory
(such as type and stat information).

This module also includes walk_s3() an equivalent of os.walk() that uses scandir_s3().


=== Crawler Requirements ===

s3 crawler requirements:
- boto3 python module

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

python3 diskover.py --altscanner scandir_s3 s3://<bucket>

<bucket> is optional, using s3:// will scan all buckets as separate top paths

Environment variables for scandir_s3:

S3_ENDPOINT_URL -- (string) - The complete URL to use for the constructed client. Normally, botocore will automatically 
construct the appropriate URL to use when communicating with a service. 
You can specify a complete URL (including the "http/https" scheme) to override this behavior. 
If this value is provided, then use_ssl is ignored.

S3_VERIFY -- (boolean/string) - Whether or not to verify SSL certificates. By default SSL certificates are verified. 
You can provide the following values:

False - do not validate SSL certificates. SSL will still be used (unless use_ssl is False), but SSL certificates 
will not be verified.
path/to/cert/bundle.pem - A filename of the CA cert bundle to uses. You can specify this argument if you want to use a 
different CA cert bundle than the one used by botocore.

S3_USE_SSL -- (boolean) - Whether or not to use SSL. By default, SSL is used. Note that not all services support non-ssl connections.

"""

import os
try:
    import boto3
    import botocore
except ImportError:
    raise ImportError("Error importing boto3 python modules")
import logging
from datetime import datetime, timezone
from posixpath import join
from botocore.exceptions import ClientError
from diskover_lic import License, licfc

__version__ = '0.0.14'
__all__ = ['scandir_s3', 'walk_s3']


def init(diskover_globals):
    """Init alt scanner."""
    global s3
    
    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'PRO', __name__)
    # end license check
    
    # boto client set up
    client_config = botocore.config.Config(
        max_pool_connections=25,
    )
    client_endpointurl = os.getenv('S3_ENDPOINT_URL')
    s3logger.info('S3_ENDPOINT_URL env var: {0}'.format(client_endpointurl))
    client_usessl = os.getenv('S3_USE_SSL')
    if client_usessl is not None:
        if client_usessl.lower() == 'true':
            client_usessl = True
        elif client_usessl.lower() == 'false':
            client_usessl = False
    s3logger.info('S3_USE_SSL env var: {0}'.format(client_usessl))
    if client_usessl is None:
        client_usessl = True
    client_verify = os.getenv('S3_VERIFY')
    if client_verify is not None:
        if client_verify.lower() == 'true':
            client_verify = True
        elif client_verify.lower() == 'false':
            client_verify = False
    s3logger.info('S3_VERIFY env var: {0}'.format(client_verify))
    s3logger.info('Creating service client to s3...')
    s3 = boto3.client('s3', 
                      use_ssl=client_usessl,
                      verify=client_verify,
                      endpoint_url=client_endpointurl,
                      config=client_config)
    s3logger.info('Done.')

    scan_all_buckets(diskover_globals)   
    if not diskover_globals['args']:
        exit(1)
    get_owner(diskover_globals)
    


def scan_all_buckets(diskover_globals):
    """Find all s3 buckets if top path set to s3:// and add each bucket as top path for 
    diskover to scan."""
    if diskover_globals['args'][0] != 's3://':
        check_buckets_exist(diskover_globals)
        return
    
    buckets = []
    list_buckets_res = s3.list_buckets()
    for bucket in list_buckets_res['Buckets']:
        buckets.append('s3://' + bucket['Name'])
    s3logger.info('No bucket specified (s3://), will scan all buckets {}'.format(buckets))
    diskover_globals['args'] = buckets


def check_buckets_exist(diskover_globals):
    """Check s3 buckets exist."""
    buckets = diskover_globals['args']
    
    list_buckets_res = s3.list_buckets()
    for bucket in buckets:
        # remove s3:// and any path components after bucket name
        bucket_name = bucket.split('/')[2]
        if bucket_name not in [b['Name'] for b in list_buckets_res['Buckets']]:
            logmsg = '{} bucket does not exist, skipping scan'.format(bucket_name)
            s3logger.warning(logmsg)
            if logtofile: s3logger_warn.warning(logmsg)
            diskover_globals['args'].remove(bucket)

def get_owner(diskover_globals):
    """Tries to get s3 owner and set globals for uids_owners and gids_groups dicts in 
    diskover_helpers module."""
    s3logger.info('Getting owner...')

    list_buckets_res = s3.list_buckets()
    try:
        owner = list_buckets_res['Owner']['DisplayName']
        s3logger.info('Found owner {}'.format(owner))
    except KeyError:
        logmsg = 'Can\'t find owner!'
        s3logger.warning(logmsg)
        if logtofile: s3logger_warn.warning(logmsg)
        pass
    else:
        diskover_globals['diskover_helpers'].uids_owners = {0: owner}
        diskover_globals['diskover_helpers'].gids_groups = {0: owner}


def log_setup(loglevel, logformat, filelogging, handler_file, handler_warnfile, handler_con):
    """Logging set up."""
    global s3logger
    global s3logger_warn
    global botologger
    global logtofile
    if filelogging:
        logtofile = True
    else:
        logtofile = False
    s3logger = logging.getLogger('scandir_s3')
    s3logger_warn = logging.getLogger('scandir_s3_warn')
    botologger = logging.getLogger('boto3')
    botocorelogger = logging.getLogger('botocore')
    s3logger.setLevel(loglevel)
    botologger.setLevel(loglevel)
    if logtofile:
        s3logger.addHandler(handler_file)
        s3logger.addHandler(handler_con)
        s3logger_warn.addHandler(handler_warnfile)
        botologger.addHandler(handler_file)
        botologger.addHandler(handler_con)
        botocorelogger.addHandler(handler_file)
        botocorelogger.addHandler(handler_con)
        s3logger.setLevel(loglevel)
        botologger.setLevel(loglevel)
        botocorelogger.setLevel(loglevel)
    else:
        logging.basicConfig(format=logformat, level=loglevel)


def check_dirpath(path):
    """Check bucket arg is valid."""
    if 's3://' in path:
        return (True, None)
    else:
        return (False, 'Invalid tree_dir arg for s3 scanner, use s3://<bucketname>')


class S3DirEntry(object):
    __slots__ = ('name', '_d_type', '_inode', '_lstat', '_scandir_s3_path', '_path', '_obj', '_bucket', '_key')

    def __init__(self, scandir_s3_path, name, d_type, obj, bucket, key):
        self._scandir_s3_path = scandir_s3_path
        self.name = name
        self._d_type = d_type
        self._inode = 0
        if d_type == 'S3_REG':
            self._lstat = fstat(obj, bucket, key)
        else:
            self._lstat = None
        self._path = None
        self._obj = obj
        self._bucket = bucket
        self._key = key

    @property
    def path(self):
        if self._path is None:
            self._path = join(self._scandir_s3_path, self.name)
        return self._path

    def stat(self, follow_symlinks=False):
        if self._lstat is None:
            self._lstat = stat(self.path)
        return self._lstat

    def is_dir(self, follow_symlinks=False):
        return self._d_type == 'S3_DIR'

    def is_file(self, follow_symlinks=False):
        return self._d_type == 'S3_REG'

    def is_symlink(self):
        return False

    def inode(self):
        return self._inode

    def __str__(self):
        return '<{0}: {1!r}>'.format(self.__class__.__name__, self.name)

    __repr__ = __str__


class stat_result(object):
    __slots__ = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                 'st_mtime', 'st_atime', 'st_ctime', 'st_sizedu', 'st_s3etag', 'st_s3storageclass')
    
    def __init__(self, stat_tup):
        st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, \
            st_mtime, st_atime, st_ctime, st_sizedu, st_s3etag, st_s3storageclass = stat_tup
        # standard stat params
        self.st_mode = st_mode
        self.st_ino = st_ino
        self.st_dev = st_dev
        self.st_nlink = st_nlink
        self.st_uid = st_uid
        self.st_gid = st_gid
        self.st_size = st_size
        self.st_mtime = st_mtime
        self.st_atime = st_atime
        self.st_ctime = st_ctime
        # size used (allocated) param
        self.st_sizedu = st_sizedu
        # aditional s3 params
        self.st_s3etag = st_s3etag
        self.st_s3storageclass = st_s3storageclass


def fstat(obj, bucket, key):
    """Like os.stat() but for s3 "files".
    """
    st_mode = 0o644
    st_ino = 0
    st_dev = 0
    st_nlink = 1
    st_uid = 0
    st_gid = 0
    st_size = obj['Size']
    st_mtime = int(obj['LastModified'].timestamp())
    st_atime = st_mtime
    st_ctime = st_mtime
    st_sizedu = obj['Size']
    st_s3etag = obj['ETag'].strip('"')
    st_s3storageclass = obj['StorageClass']
    return stat_result((st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_mtime, 
                        st_atime, st_ctime, st_sizedu, st_s3etag, st_s3storageclass))


def stat(path):
    """Like os.stat() but for s3 "directories".
    """
    bucket, key = get_bucket_key(path)
    if key:
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                s3logger.debug('no such key {0} in bucket {1}'.format(key, bucket))
            elif e.response['Error']['Code'] == 'InvalidObjectState':
                s3logger.debug('boto s3 client invalid object state error: {0} (on Glacier?) (bucket: {1} key: {2})'.format(e, bucket, key))
            else:
                logmsg = 'unhandled boto s3 client error: {0} (bucket: {1} key: {2})'.format(e, bucket, key)
                s3logger.error(logmsg, exc_info=0)
                if logtofile: s3logger_warn.error(logmsg, exc_info=0)
            # "directory" prefix
            key = '/'
            obj = {'ContentLength': 0, 'LastModified': datetime.now(timezone.utc), 'ETag': '""'}
    else:
        # bucket
        key = '/'
        obj = {'ContentLength': 0, 'LastModified': datetime.now(timezone.utc), 'ETag': '""'}

    st_mode = 0o755 if key[-1] == '/' else 0o644
    st_ino = 0
    st_dev = 0
    st_nlink = 1
    st_uid = 0
    st_gid = 0
    st_size = obj['ContentLength']
    st_mtime = int(obj['LastModified'].timestamp())
    st_atime = st_mtime
    st_ctime = st_mtime
    st_sizedu = obj['ContentLength']
    st_s3etag = obj['ETag'].strip('"')
    obj_storage_class = 'STANDARD' if 'StorageClass' not in obj else obj['StorageClass']
    st_s3storageclass = obj_storage_class
    return stat_result((st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_mtime, 
                        st_atime, st_ctime, st_sizedu, st_s3etag, st_s3storageclass))


def scandir_s3(bucket=os.getenv('S3_BUCKET')):
    """Paginates over s3 bucket and yields DirEntry objects.
    """
    if not bucket:
        raise ValueError('No bucket param or S3_BUCKET env var')
    
    bucket, key = get_bucket_key(bucket)

    try:
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket, Prefix=key, Delimiter='/'):
            # directory
            if 'CommonPrefixes' in page:
                for obj in page['CommonPrefixes']:
                    key = obj['Prefix'].rstrip('/')
                    d_type = 'S3_DIR'
                    _obj = None
                    top = join('/' + bucket, os.path.dirname(key)).rstrip('/')
                    name = os.path.basename(key)
                    if name:
                        yield S3DirEntry(top, name, d_type, _obj, bucket, key)
            # file
            if 'Contents' in page:
                for obj in page['Contents']:
                    key = obj['Key']
                    d_type = 'S3_REG'
                    _obj = obj
                    top = join('/' + bucket, os.path.dirname(key)).rstrip('/')
                    name = os.path.basename(key)
                    if name:
                        yield S3DirEntry(top, name, d_type, _obj, bucket, key)
    except ClientError as e:
        logmsg = 'boto s3 client error: {0} (bucket: {1} prefix: {2})'.format(e, bucket, key)
        s3logger.error(logmsg, exc_info=0)
        if logtofile: s3logger_warn.error(logmsg, exc_info=0)
        raise RuntimeError(logmsg)


def walk_s3(bucket=os.getenv('S3_BUCKET')):
    """Like Python 3.5's implementation of os.walk() but for s3.
    """
    if not bucket:
        raise ValueError('No bucket param or S3_BUCKET env var')

    top = abspath(bucket)
    
    dirs = []
    nondirs = []
    
    try:
        scandir_s3_it = scandir_s3(bucket)
    except Exception:
        return

    while True:
        try:
            try:
                entry = next(scandir_s3_it)
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
        for entry in walk_s3(new_path):
            yield entry


def get_bucket_key(path):
    """From the path, return the bucket name and prefix key.
    """
    # remove any trailing slash
    path = path.rstrip('/')
    # remove s3:// uri
    bucket = path.replace('s3://', '')
    if bucket[0] == '/':
        bucket = bucket[1:]
    bucket_list = bucket.split('/')
    if len(bucket_list) == 1:
        key = ''
    else:
        key = '/'.join(bucket_list[1:]) + '/'
    bucket = bucket_list[0]
    return bucket, key


def abspath(path):
    """Converts the s3 bucket path to an absolute Posix path.
    """
    # remove s3:// uri
    if path == 's3://':
        return path
    path = path.replace('s3://', '')
    if path[0] != '/':
        path = '/' + path
    # remove any trailing /
    path = path.rstrip('/')
    return path


def get_storage_size(path):
    """Gets the total, free, and available space of the storage path.
    """
    storage_size = 9007199254740992  # 8 PB
    total_size = 0
    # using this method below is really slow when many obj in bucket
    #s3_resource = boto3.resource('s3')
    #bucket = s3_resource.Bucket(bucket)
    #for obj in bucket.objects.all():
    #    total_size += obj.size
    free_space = storage_size - total_size
    available_space = free_space
    return storage_size, free_space, available_space


def add_mappings(mappings):
    """Returns a dict with additional es mappings."""
    mappings['mappings']['properties'].update({
        's3_etag': {
            'type': 'keyword'
        },
        's3_storageclass': {
            'type': 'keyword'
        }
    })
    return mappings


def add_meta(path, osstat):
    """Returns a dict with additional file meta data."""
    return {'s3_etag': osstat.st_s3etag, 's3_storageclass': osstat.st_s3storageclass}


def add_tags(metadict):
    """Returns a dict with additional tag data or return None to not alter tags."""
    return None


def close(diskover_globals):
    """Close the alt scanner.
    Called by diskover at end of crawl.
    """
    return


walk = walk_s3
scandir = scandir_s3

