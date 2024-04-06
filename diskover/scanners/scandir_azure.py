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

scandir_azure, an Azure Storage Blob directory iterator equivalent of os.scandir()

scandir_azure() is a generator that returns an iterator over files in a directory, 
and also exposes the extra information Azure provides while iterating files in a directory
(such as type and stat information).

This module also includes walk_azure() an equivalent of os.walk() that uses scandir_azure().


=== Crawler Requirements ===

Azure Storage Blob crawler requirements:
- azure-storage-blob python client library
- azure-identity python client library

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

python3 diskover.py --altscanner scandir_azure az://<container>

<container> is optional, using az:// will scan all containers as separate top paths

Environment variables required for scandir_azure:

For using Azure connection string:

AZURE_STORAGE_CONNECTION_STRING

For using Azure AD app subscription IAM credentials:

AZURE_STORAGE_BLOB_URL
AZURE_TENANT_ID
AZURE_CLIENT_ID
AZURE_CLIENT_SECRET 

"""

import os
try:
    from azure.identity import ClientSecretCredential
    from azure.storage.blob import BlobServiceClient
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    raise ImportError("Error importing azure python modules")
import logging
import confuse
import warnings
from datetime import datetime, timezone
from posixpath import join
from diskover_lic import License, licfc

__version__ = '0.0.4'
__all__ = ['scandir_azure', 'walk_azure']
    

def init(diskover_globals):
    """Init alt scanner."""
    global service_client
    global connection_string
    global account_url
    
    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'PRO', __name__)
    # end license check
    
    # Load yaml config file
    config = confuse.Configuration('diskover_scandir_azure', __name__)
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    if not os.path.exists(config_filename):
        print('Config file {0} not found! Copy from default config.'.format(config_filename))
        raise SystemExit(1)

    # load default config file
    config_defaults = confuse.Configuration('diskover_scandir_azure', __name__)
    scriptpath = os.path.dirname(os.path.realpath(__file__))
    scriptparentpath = os.path.dirname(scriptpath)
    defaultconfig_filename = os.path.join(scriptparentpath, 'configs_sample/diskover_scandir_azure/config.yaml')
    config_defaults.set_file(defaultconfig_filename)

    def config_warn(e):
        warnings.warn('Config setting {}. Using default.'.format(e))

    # laod config values
    try:
        auth_method = config['authmethod'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        auth_method = config_defaults['authmethod'].get()
    try:
        connection_string = config['connectionstring'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        connection_string = config_defaults['connectionstring'].get()
    finally:
        if os.getenv('AZURE_STORAGE_CONNECTION_STRING') is not None:
            connection_string = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
            azurelogger.info('Using AZURE_STORAGE_CONNECTION_STRING env var')
    try:
        account_url = config['storagebloburl'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        account_url = config_defaults['storagebloburl'].get()
    try:
        tenant_id = config['tenantid'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        tenant_id = config_defaults['tenantid'].get()
    try:
        client_id = config['clientid'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        client_id = config_defaults['clientid'].get()
    try:
        client_secret = config['clientsecret'].get()
    except confuse.NotFoundError as e:
        config_warn(e)
        client_secret = config_defaults['clientsecret'].get()
    
    # azure storage blob client set up
    if account_url is None and connection_string is None:
        raise ValueError('connectionstring or storagebloburl not set in config')
    # use connection string to connect
    if auth_method == 'connectionstring':
        azurelogger.info('Creating blob service client to Azure Storage using connection string...')
        service_client = BlobServiceClient.from_connection_string(connection_string)
    # use credentials to connect
    elif auth_method == 'credentials':
        if tenant_id is None:
            raise ValueError('tenantid not set in config')
        if client_id is None:
            raise ValueError('clientid not set in config')
        if client_secret is None:
            raise ValueError('clientsecret not set in config')
        azurelogger.info('Creating blob service client to Azure Storage using Azure credentials...')
        credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        service_client = BlobServiceClient(account_url, credential=credential)
    else:
        raise ValueError('invalid authmethod set in config, use connectionstring or credentials')
    
    azurelogger.info('Done.')
    
    scan_all_containers(diskover_globals)


def scan_all_containers(diskover_globals):
    """Find all Azure Storage containers if top path set to az:// and add each bucket as top path for 
    diskover to scan."""    
    if diskover_globals['args'][0] != 'az://':
        return
    
    containers = []
    containers_list = service_client.list_containers()
    for container in containers_list:
        containers.append('az://' + container.name)
    azurelogger.info('No container specified (az://), will scan all containers {}'.format(containers))
    diskover_globals['args'] = containers


def log_setup(loglevel, logformat, filelogging, handler_file, handler_warnfile, handler_con):
    """Logging set up."""
    global azurelogger
    global azurelogger_warn
    global botologger
    global logtofile
    if filelogging:
        logtofile = True
    else:
        logtofile = False
    azurelogger = logging.getLogger('scandir_azure')
    azurelogger_warn = logging.getLogger('scandir_azure_warn')
    azurelogger.setLevel(loglevel)
    # Set the logging level for all azure-* libraries
    azurestorlogger = logging.getLogger('azure')
    azurestorlogger.setLevel(logging.WARN)
    if logtofile:
        azurelogger.addHandler(handler_file)
        azurelogger.addHandler(handler_con)
        azurelogger_warn.addHandler(handler_warnfile)
        azurestorlogger.addHandler(handler_file)
        azurestorlogger.addHandler(handler_con)
        azurelogger.setLevel(loglevel)
        azurestorlogger.setLevel(loglevel)
    else:
        logging.basicConfig(format=logformat, level=loglevel)


def check_dirpath(path):
    """Check bucket arg is valid."""
    if 'az://' in path:
        return (True, None)
    else:
        return (False, 'Invalid tree_dir arg for Azure Storage Blob scanner, use az://<container>')


class AzureBlobDirEntry(object):
    __slots__ = ('name', '_d_type', '_inode', '_lstat', '_scandir_azblob_path', '_path', '_obj', '_container', '_key')

    def __init__(self, scandir_azblob_path, name, d_type, obj, container, key):
        self._scandir_azblob_path = scandir_azblob_path
        self.name = name
        self._d_type = d_type
        self._inode = 0
        if d_type == 'AZBLOB_REG':
            self._lstat = fstat(obj, container, key)
        else:
            self._lstat = None
        self._path = None
        self._obj = obj
        self._container = container
        self._key = key

    @property
    def path(self):
        if self._path is None:
            self._path = join(self._scandir_azblob_path, self.name)
        return self._path

    def stat(self, follow_symlinks=False):
        if self._lstat is None:
            self._lstat = stat(self.path)
        return self._lstat

    def is_dir(self, follow_symlinks=False):
        return self._d_type == 'AZBLOB_DIR'

    def is_file(self, follow_symlinks=False):
        return self._d_type == 'AZBLOB_REG'

    def is_symlink(self):
        return False

    def inode(self):
        return self._inode

    def __str__(self):
        return '<{0}: {1!r}>'.format(self.__class__.__name__, self.name)

    __repr__ = __str__


class stat_result(object):
    __slots__ = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                 'st_mtime', 'st_atime', 'st_ctime', 'st_sizedu', 'st_azblobetag', 'st_azblobtier', 
                 'st_azblobtags', 'st_azblobmetadata')
    
    def __init__(self, stat_tup):
        st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, \
            st_mtime, st_atime, st_ctime, st_sizedu, st_azblobetag, st_azblobtier = stat_tup
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
        # aditional Azure Storage Blob params
        self.st_azblobetag = st_azblobetag
        self.st_azblobtier = st_azblobtier


def fstat(obj, container, key):
    """Like os.stat() but for Azure Storage Blob "files".
    """
    st_mode = 0o644
    st_ino = 0
    st_dev = 0
    st_nlink = 1
    st_uid = 0
    st_gid = 0
    st_size = obj.size
    st_mtime = int(obj.last_modified.timestamp())
    if obj.last_accessed_on is None:
        st_atime = st_mtime
    else:
        st_atime = int(obj.last_accessed_on.timestamp())
    st_ctime = int(obj.creation_time.timestamp())
    st_sizedu = obj.size
    st_azblobetag = obj.etag
    st_azblobtier = obj.blob_tier
    return stat_result((st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_mtime, 
                        st_atime, st_ctime, st_sizedu, st_azblobetag, st_azblobtier))


def stat(path):
    """Like os.stat() but for Azure Storage Blob "directories".
    """
    class Directory:
        path = '/'
        size = 0
        time = datetime.now(timezone.utc)
        last_modified = time
        last_accessed_on = None
        creation_time = time
        etag = ''
        tier = ''
    
    container, blobpath = get_container_blobpath(path)
    
    if blobpath:
        try:
            blob_client = service_client.get_blob_client(container, blobpath)
            obj = blob_client.get_blob_properties()
            
        except ResourceNotFoundError as e:
            azurelogger.debug('no such blob {0} in container {1} (Directory ?)'.format(blobpath, container))
            # "directory" prefix
            obj = Directory()
            blobpath = obj.path
            
        except Exception as e:
            logmsg = 'Azure Storage Blob client error: {0} (container: {1} blob: {2})'.format(e, container, blobpath)
            azurelogger.error(logmsg, exc_info=0)
            if logtofile: azurelogger_warn.error(logmsg, exc_info=0)
    else:
        # container
        obj = Directory()
        blobpath = obj.path

    st_mode = 0o755 if blobpath[-1] == '/' else 0o644
    st_ino = 0
    st_dev = 0
    st_nlink = 1
    st_uid = 0
    st_gid = 0
    st_size = obj.size
    st_mtime = int(obj.last_modified.timestamp())
    if obj.last_accessed_on is None:
        st_atime = st_mtime
    else:
        st_atime = int(obj.last_accessed_on.timestamp())
    st_ctime = int(obj.creation_time.timestamp())
    st_sizedu = obj.size
    st_azblobetag = obj.etag
    st_azblobtier = obj.tier
    return stat_result((st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_mtime, 
                        st_atime, st_ctime, st_sizedu, st_azblobetag, st_azblobtier))


def scandir_azure(container=os.getenv('AZURE_STORAGE_CONTAINER')):
    """Paginates over Azure Storage Container blobs and yields DirEntry objects.
    """
    if not container:
        raise ValueError('No container param or AZURE_STORAGE_CONTAINER env var')
    
    container, blobpath = get_container_blobpath(container)
    
    try:
        container_client = service_client.get_container_client(container)
        for blob in container_client.walk_blobs(name_starts_with=blobpath):
            # directory
            if hasattr(blob, 'prefix'):
                key = blob.prefix.rstrip('/')
                d_type = 'AZBLOB_DIR'
                _obj = None
                top = join('/' + container, os.path.dirname(key)).rstrip('/')
                name = os.path.basename(key)
                if name:
                    yield AzureBlobDirEntry(top, name, d_type, _obj, container, key)
            # file
            else:
                key = blob.name
                d_type = 'AZBLOB_REG'
                _obj = blob
                top = join('/' + container, os.path.dirname(key)).rstrip('/')
                name = os.path.basename(key)
                if name:
                    yield AzureBlobDirEntry(top, name, d_type, _obj, container, key)               
    
    except Exception as e:
        logmsg = 'Azure service client error: {0} (container: {1} blob: {2})'.format(e, container, blobpath)
        azurelogger.error(logmsg, exc_info=0)
        if logtofile: azurelogger_warn.error(logmsg, exc_info=0)
        raise RuntimeError(logmsg)


def walk_azure(container=os.getenv('AZURE_STORAGE_CONTAINER')):
    """Like Python 3.5's implementation of os.walk() but for Azure Storage Containers.
    """
    if not container:
        raise ValueError('No container param or AZURE_STORAGE_CONTAINER env var')

    top = abspath(container)
    
    dirs = []
    nondirs = []
    
    try:
        scandir_azure_it = scandir_azure(container)
    except Exception:
        return

    while True:
        try:
            try:
                entry = next(scandir_azure_it)
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
        for entry in walk_azure(new_path):
            yield entry


def get_container_blobpath(path):
    """From the path, return the container name and blob path.
    """
    # remove any trailing slash
    path = path.rstrip('/')
    # remove az:// uri
    container = path.replace('az://', '')
    if container[0] == '/':
        container = container[1:]
    container_list = container.split('/')
    if len(container_list) == 1:
        blobpath = ''
    else:
        blobpath = '/'.join(container_list[1:]) + '/'
    container = container_list[0]
    return container, blobpath


def abspath(path):
    """Converts the Azure Storage container path to an absolute Posix path.
    """
    # remove az:// uri
    if path == 'az://':
        return path
    path = path.replace('az://', '')
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
    free_space = storage_size - total_size
    available_space = free_space
    return storage_size, free_space, available_space


def add_mappings(mappings):
    """Returns a dict with additional es mappings."""
    mappings['mappings']['properties'].update({
        'azure_etag': {
            'type': 'keyword'
        },
        'azure_tier': {
            'type': 'keyword'
        }
    })
    return mappings


def add_meta(path, osstat):
    """Returns a dict with additional file meta data."""
    return {'azure_etag': osstat.st_azblobetag, 'azure_tier': osstat.st_azblobtier}


def add_tags(metadict):
    """Returns a dict with additional tag data or return None to not alter tags."""
    return None


def close(diskover_globals):
    """Close the alt scanner.
    Called by diskover at end of crawl.
    """
    return


walk = walk_azure
scandir = scandir_azure