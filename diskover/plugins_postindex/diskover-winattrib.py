#!/usr/bin/env python3
'''
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
diskover Windows attributes post-index plugin

=== Plugin Description ===
diskover Windows attributes (owner/group and acls) plugin - This is an example post-index plugin
for diskover. It updates owner, group and windacls fields meta data of 
each file or directory to diskover index after indexing with
the Windows owner, primary group and acl info using pywin32.

=== Plugin Requirements ===
- pywin32 python module
- enable long path support in Windows if long paths being scanned
https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=cmd

'''

import sys
import os
import optparse
import confuse
import logging
import win32security
import pywintypes
import hashlib
import warnings
import time
import signal
from threading import Thread, Lock
from queue import Queue
from datetime import datetime, timedelta
from timeit import default_timer as timer
from elasticsearch.exceptions import RequestError
from sqlite3.dbapi2 import OperationalError

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload
from diskover_helpers import find_latest_index, get_mem_usage, get_win_path
from diskover_lic import License, licfc


plugin_name = 'winattrib'
version = '0.0.4'
__version__ = version

# Windows check
if os.name == 'nt':
    IS_WIN = True
    # Handle keyboard interupt for Windows
    def handler(a,b=None):
        logger.info('Received keyboard interrupt')
        close_app()
        sys.exit(1)
    def install_win_sig_handler():
        try:
            import win32api
        except ModuleNotFoundError:
            print('Windows requires pywin32 Python module')
            sys.exit(1)
        win32api.SetConsoleCtrlHandler(handler, True)
else:
    IS_WIN = False

# Python 3 check
IS_PY3 = sys.version_info >= (3, 5)
if not IS_PY3:
    print('Python 3.5 or higher required.')
    sys.exit(1)

"""Load yaml config file."""
diskover_config = confuse.Configuration('diskover', __name__)
config = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
if not os.path.exists(config_filename):
    print('Config file {0} not found! Copy from default config.'.format(config_filename))
    sys.exit(1)

# load diskover default config file
diskover_config_defaults = confuse.Configuration('diskover', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
scriptpath_parent = os.path.abspath(os.path.join(scriptpath, os.pardir))
default_diskover_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover/config.yaml')
diskover_config_defaults.set_file(default_diskover_config_filename)
# load windows acls plugin default config file
config_defaults = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_winattrib/config.yaml')
config_defaults.set_file(default_config_filename)

def config_warn(e):
    warnings.warn('Config setting {}. Using default.'.format(e))
    
try:
    es_scrollsize = diskover_config['databases']['elasticsearch']['scrollsize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_scrollsize = diskover_config_defaults['databases']['elasticsearch']['scrollsize'].get()
try:
    es_timeout = diskover_config['databases']['elasticsearch']['timeout'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_timeout = diskover_config_defaults['databases']['elasticsearch']['timeout'].get()
try:
    logtofile = config['logToFile'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    logtofile = config_defaults['logToFile'].get()
try:
    logdir = config['logDirectory'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    logdir = config_defaults['logDirectory'].get()
try:
    maxthreads = config['maxthreads'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    maxthreads = config_defaults['maxthreads'].get()
finally:
    if maxthreads is None:
        maxthreads = int(os.cpu_count())
try:
    incdomain = config['incdomain'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    incdomain = config_defaults['incdomain'].get()
try:
    getgroup = config['getgroup'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    getgroup = config_defaults['getgroup'].get()
try:
    usesid = config['usesid'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    usesid = config_defaults['usesid'].get()
try:
    getdacls = config['getdacls'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    getdacls = config_defaults['getdacls'].get()
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
    searchfiles = config['file'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    searchfiles = config_defaults['file'].get()
try:
    searchdirs = config['directory'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    searchdirs = config_defaults['directory'].get()
try:
    otherquery = config['otherquery'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    otherquery = config_defaults['otherquery'].get()
try:
    replacepaths_from = config['replacepaths']['from'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    replacepaths_from = config_defaults['replacepaths']['from'].get()
try:
    replacepaths_to = config['replacepaths']['to'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    replacepaths_to = config_defaults['replacepaths']['to'].get()
    

doccount = 0
processedcount = 0
processedfailcount = 0
queue = Queue()
lock = Lock()
sid_name_cache = dict()


OBJECT_INHERIT_ACE         = 0x01
CONTAINER_INHERIT_ACE      = 0x02
NO_PROPAGATE_INHERIT_ACE   = 0x04
INHERIT_ONLY_ACE           = 0x08
INHERITED_ACE              = 0x10
SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
FAILED_ACCESS_ACE_FLAG     = 0x80

ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE  = 1
SYSTEM_AUDIT_ACE_TYPE   = 2

DELETE                 = 0x00010000 # DE
READ_CONTROL           = 0x00020000 # RC
WRITE_DAC              = 0x00040000 # WDAC
WRITE_OWNER            = 0x00080000 # WO
SYNCHRONIZE            = 0x00100000 # S
ACCESS_SYSTEM_SECURITY = 0x01000000 # AS
GENERIC_READ           = 0x80000000 # GR
GENERIC_WRITE          = 0x40000000 # GW
GENERIC_EXECUTE        = 0x20000000 # GE
GENERIC_ALL            = 0x10000000 # GA

FILE_READ_DATA         = 0x00000001 # RD
FILE_LIST_DIRECTORY    = 0x00000001
FILE_WRITE_DATA        = 0x00000002 # WD
FILE_ADD_FILE          = 0x00000002
FILE_APPEND_DATA       = 0x00000004 # AD
FILE_ADD_SUBDIRECTORY  = 0x00000004
FILE_READ_EA           = 0x00000008 # REA
FILE_WRITE_EA          = 0x00000010 # WEA
FILE_EXECUTE           = 0x00000020 # X
FILE_TRAVERSE          = 0x00000020
FILE_DELETE_CHILD      = 0x00000040 # DC
FILE_READ_ATTRIBUTES   = 0x00000080 # RA
FILE_WRITE_ATTRIBUTES  = 0x00000100 # WA

FILE_GENERIC_READ      = (FILE_READ_DATA        |
                          FILE_READ_EA          |
                          FILE_READ_ATTRIBUTES  |
                          READ_CONTROL          |
                          SYNCHRONIZE)

FILE_GENERIC_WRITE     = (FILE_WRITE_DATA       |
                          FILE_APPEND_DATA      |
                          FILE_WRITE_EA         |
                          FILE_WRITE_ATTRIBUTES |
                          READ_CONTROL          |
                          SYNCHRONIZE)

FILE_GENERIC_EXECUTE    = (FILE_EXECUTE         |
                           FILE_READ_ATTRIBUTES |
                           READ_CONTROL         |
                           SYNCHRONIZE)

FILE_ALL_ACCESS         = 0x001F01FF

FILE_MODIIFY_ACCESS     = FILE_ALL_ACCESS & ~(FILE_DELETE_CHILD |
                                              WRITE_DAC         |
                                              WRITE_OWNER)

FILE_READ_EXEC_ACCESS   = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE

FILE_DELETE_ACCESS      = DELETE | SYNCHRONIZE


class Ace():
    def __init__(self, ace_type, flags, mask, sid, trustee):
        self.ace_type = ace_type
        self.flags = flags
        self.mask = mask
        self.sid = sid
        self.trustee = trustee
        self.mapped_mask = self._map_generic(mask)

    @staticmethod
    def _map_generic(mask):
        if mask & GENERIC_READ:
            mask = (mask & ~GENERIC_READ) | FILE_GENERIC_READ
        if mask & GENERIC_WRITE:
            mask = (mask & ~GENERIC_WRITE) | FILE_GENERIC_WRITE
        if mask & GENERIC_EXECUTE:
            mask = (mask & ~GENERIC_EXECUTE) | FILE_GENERIC_EXECUTE
        if mask & GENERIC_ALL:
            mask = (mask & ~GENERIC_ALL) | FILE_ALL_ACCESS
        return mask

    def inherited(self):         # I
        return bool(self.flags & INHERITED_ACE)
    def object_inherit(self):    # OI
        return bool(self.flags & OBJECT_INHERIT_ACE)
    def container_inherit(self): # CI
        return bool(self.flags & CONTAINER_INHERIT_ACE)
    def inherit_only(self):      # IO
        return bool(self.flags & INHERIT_ONLY_ACE)
    def no_propagate(self):      # NP
        return bool(self.flags & NO_PROPAGATE_INHERIT_ACE)

    def no_access(self):         # N
        return self.mapped_mask == 0
    def full_access(self):       # F
        return self.mapped_mask == FILE_ALL_ACCESS
    def modify_access(self):     # M
        return self.mapped_mask == FILE_MODIIFY_ACCESS
    def read_exec_access(self):  # RX
        return self.mapped_mask == FILE_READ_EXEC_ACCESS
    def read_only_access(self):  # R
        return self.mapped_mask == FILE_GENERIC_READ
    def write_only_access(self): # W
        return self.mapped_mask == FILE_GENERIC_WRITE
    def delete_access(self):     # D
        return self.mapped_mask == FILE_DELETE_ACCESS

    def get_file_rights(self):
        if self.no_access(): return ['N']
        if self.full_access(): return ['F']
        if self.modify_access(): return ['M']
        if self.read_exec_access(): return ['RX']
        if self.read_only_access(): return ['R']
        if self.write_only_access(): return ['W']
        if self.delete_access(): return ['D']
        rights = []
        for right, name in ((DELETE, 'DE'), (READ_CONTROL, 'RC'),
                            (WRITE_DAC, 'WDAC'), (WRITE_OWNER, 'WO'),
                            (SYNCHRONIZE, 'S'),
                            (ACCESS_SYSTEM_SECURITY, 'AS'),
                            (GENERIC_READ, 'GR'), (GENERIC_WRITE, 'GW'),
                            (GENERIC_EXECUTE, 'GE'), (GENERIC_ALL, 'GA'),
                            (FILE_READ_DATA, 'RD'), (FILE_WRITE_DATA, 'WD'),
                            (FILE_APPEND_DATA, 'AD'), (FILE_READ_EA, 'REA'),
                            (FILE_WRITE_EA, 'WEA'), (FILE_EXECUTE, 'X'),
                            (FILE_DELETE_CHILD, 'DC'),
                            (FILE_READ_ATTRIBUTES, 'RA'),
                            (FILE_WRITE_ATTRIBUTES, 'WA')):
            if self.mask & right:
                rights.append(name)
        return rights

    def granted_access(self, mask):
        return bool(self.mapped_mask & self._map_generic(mask))

    def get_aces(self):
        trustee = self.trustee if self.trustee else self.sid
        access = []
        if self.ace_type == ACCESS_DENIED_ACE_TYPE:
            access.append('(DENY)')
        elif self.ace_type == SYSTEM_AUDIT_ACE_TYPE:
            access.append('(AUDIT)')
        if self.inherited(): access.append('(I)')
        if self.object_inherit(): access.append('(OI)')
        if self.container_inherit(): access.append('(CI)')
        if self.inherit_only(): access.append('(IO)')
        if self.no_propagate(): access.append('(NP)')
        access.append('(%s)' % ','.join(self.get_file_rights()))
        return '%s:%s' % (trustee, ''.join(access))


def log_setup():
    """Setup logging for plugin."""
    logger = logging.getLogger('diskover-{0}'.format(plugin_name))
    eslogger = logging.getLogger('elasticsearch')
    loglevel = config['logLevel'].get()
    if loglevel == 'DEBUG':
        loglevel = logging.DEBUG
    elif loglevel == 'INFO':
        loglevel = logging.INFO
    else:
        loglevel = logging.WARN
    logformat = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if logtofile:
        logfiletime = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
        logname = 'diskover-{0}_{1}.log'.format(plugin_name, logfiletime)
        logfile = os.path.join(logdir, logname)
        logging.basicConfig(format=logformat, level=loglevel, 
            handlers=[logging.FileHandler(logfile, encoding='utf-8'), logging.StreamHandler()])
    else:
        logging.basicConfig(format=logformat, level=loglevel)
    eslogger.setLevel(level=logging.WARN)
    return logger


def index_get_docs(indexname):
    """Generator to scroll over files/directories in index and yield doc info."""
    global doccount
    
    if not searchfiles and searchdirs:
        doctype = 'directory'
    elif searchfiles and not searchdirs:
        doctype = 'file'
    else:
        doctype = '(file OR directory)'
        
    query = 'type:' + doctype
        
    if otherquery is not None:
        query += ' AND (' + otherquery + ')'

    data = {
        'size': 0,
        '_source': ['name', 'parent_path', 'atime'],
        'query': {
            'query_string': {
                'query': query
            }
        }
    }
    
    if options.verbose:
        logger.info('ES search query: {}'.format(data['query']['query_string']['query']))

    es.indices.refresh(index=indexname)

    res = es.search(index=indexname, scroll='1m', size=es_scrollsize,
                    body=data, request_timeout=es_timeout)

    with lock:
        doccount = res['hits']['total']['value']

    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            fullpath = hit['_source']['parent_path'] + '/' + hit['_source']['name']
            atime = hit['_source']['atime']
            docid = hit['_id']
            yield (fullpath, atime, docid)

        res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                        request_timeout=es_timeout)
        

def log_stats_thread():
    """Shows plugin stats."""
    global plugin_done
    start = time.time()
    percentdone = 0.0

    while True:
        time.sleep(3)
        if plugin_done:
            break
        timenow = time.time()
        elapsed = str(timedelta(seconds = timenow - start))
        docsps = processedcount / (timenow - start)
        try:
            percentdone = processedcount/doccount*100
        except ZeroDivisionError:
            pass
        logger.info('STATS (docs processed {0} ({1:.1f}%), docs in queue {2}, elapsed {3}, perf {4:.3f} docs/s, memory usage {5})'.format(
            processedcount, percentdone, queue.qsize(), elapsed, docsps, get_mem_usage()))


def get_attrib_thread(i):
    global queue
    global lock

    while True:
        try:
            index, results = queue.get()
            docs = []
            for res in results:
                fullpath, atime, docid = res

                if options.verbose:
                    logger.info('thread {0} starting processing {1}'.format(i, fullpath))

                start = timer()
                
                wininfo = get_wininfo(fullpath, atime)
                
                end = timer()
                processtime = timedelta(seconds = end - start)
                
                if options.verbose:
                    logger.info('thread {0} finished processing {1} in {2}s)'.format(i, fullpath, processtime))

                if wininfo is not None:
                    d = {
                        '_op_type': 'update',
                        '_index': index,
                        '_id': docid,
                        'doc': {
                            'owner': wininfo['owner'],
                            'group': wininfo['group'],
                            'windacls': wininfo['windacls']
                        }
                    }
                    docs.append(d)
                        
            bulk_upload(es, index, docs)
            del docs[:]
    
        except (KeyboardInterrupt, SystemExit):
            raise
        queue.task_done()


def enqueue_docs(index):
    # Get all docs from diskover index and enqueue to hash queue
    try:
        results = []
        logger.info('Queuing docs from index {0}...'.format(index))
        for res in index_get_docs(index):
            results.append(res)
            if len(results) > 100:
                queue.put((index, results[:]))
                del results[:]
        queue.put((index, results))

        logger.info('Done queuing {0} docs in index {1}. Waiting for threads to finish...'.format(doccount, index))
        # Wait for threads to finish
        queue.join()
    except (KeyboardInterrupt, SystemExit):
        raise


def get_wininfo(path, atime):
    """Gets Windows attributes of file/folder."""
    global processedcount, processedfailcount
    
    # replace path
    path = path.replace(replacepaths_from, replacepaths_to, 1)
    # Windows path seperator translation
    path = path.replace('/', '\\')
    path = get_win_path(path)
    
    # check file/folder still exists
    if not os.path.exists(path):
        logger.warning('No such file or directory: {0}'.format(path))
        with lock:
            processedfailcount += 1
        return None
    
    # check if hash in cache
    if options.usecache:
        # md5 hash path
        pathhash = hashlib.md5(path.encode('utf-8')).hexdigest()
        # Get windows attributes from cache
        cache_res = cache.get_value(pathhash)
        if cache_res:
            if atime == cache_res['atime']:
                logger.debug('CACHE HIT {0}'.format(path))
                with lock:
                    processedcount += 1
                return cache_res
        logger.debug('CACHE MISS {0}'.format(path)) 
    
    wininfo = {
        'owner': get_owner(path),
        'group': get_group(path),
        'windacls': get_dacls(path)
    }
    
    # cache windows attributes
    if options.usecache:
        if cache_res:
            cache_data = cache_res.copy()
        else:
            cache_data = dict()
        cache_data = {
            'atime': atime,
            'owner': wininfo['owner'],
            'group': wininfo['group'],
            'windacls': wininfo['windacls']
        }
        cache.set_value(pathhash, cache_data, expire_seconds=cache_expiretime)
    
    with lock:
        processedcount += 1
    
    return wininfo


def get_owner(path):
    """This uses the Windows security API
    Get the file's security descriptor, pull out of that the field which refers to the owner and 
    then translate that from the SID to a user name.""" 
    global sid_name_cache, processedfailcount
      
    try:
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
    except pywintypes.error as e:
        logger.warning('Error getting owner security info: {0} ({1})'.format(path, e))
        with lock:
            processedfailcount += 1
        return 0
    
    owner_sid = sd.GetSecurityDescriptorOwner()
    owner_sid_str = win32security.ConvertSidToStringSid(owner_sid)
    # check sid cache for owner sid
    if owner_sid_str in sid_name_cache:
        name, domain, type = sid_name_cache[owner_sid_str]
    else:
        try:
            # lookup sid and cache values
            name, domain, type = win32security.LookupAccountSid(None, owner_sid)
        except pywintypes.error:
            if usesid:
                return owner_sid_str
            else:
                return 0
        else:
            with lock:
                sid_name_cache[owner_sid_str] = (name, domain, type)
    if incdomain and domain != '':
        return domain + '\\' + name
    else:
        return name


def get_group(path):
    """Get Windows primary group."""
    global sid_name_cache, processedfailcount
    
    if not getgroup:
        return 0
          
    try:
        sd = win32security.GetNamedSecurityInfo(path, win32security.SE_FILE_OBJECT, 
            win32security.GROUP_SECURITY_INFORMATION)
    except pywintypes.error as e:
        logger.warning('Error getting group security info: {0} ({1})'.format(path, e))
        with lock:
            processedfailcount += 1
        return 0
        
    primary_group_sid = sd.GetSecurityDescriptorGroup()
    group_sid_str = win32security.ConvertSidToStringSid(primary_group_sid)
    # check sid cache for group sid
    if group_sid_str in sid_name_cache:
        name, domain, type = sid_name_cache[group_sid_str]
    else:
        try:
            # lookup sid and cache values
            name, domain, type = win32security.LookupAccountSid(None, primary_group_sid)
        except pywintypes.error:
            if usesid:
                return group_sid_str
            else:
                return 0
        else:
            with lock:
                sid_name_cache[group_sid_str] = (name, domain, type)
    if incdomain and domain != '':
        return domain + '\\' + name
    else:
        return name
    

def get_dacls(path):
    """Get Windows Dacl's for file path."""
    global sid_name_cache, processedfailcount
    
    if not getdacls:
        return None
    
    if options.verbose:
        logger.info('Getting Dacl\'s: {}'.format(path))
          
    try:
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    except pywintypes.error as e:
        logger.warning('Error getting dacl security info: {0} ({1})'.format(path, e))
        with lock:
            processedfailcount += 1
        return None
        
    dacl = sd.GetSecurityDescriptorDacl()
    
    dacls = []
    
    ace_count = dacl.GetAceCount()
    
    if options.verbose:
        logger.info('{0} has {1} ACEs'.format(path, ace_count))
    
    for ace_no in range(0, ace_count):
        ace = dacl.GetAce(ace_no)
        (ace_type, ace_flags) = ace[0]
        if len(ace) == 3:  # Conventional ACE's
            mask, sid = ace[1:]
        else:  # Object ACE's
            mask, object_type, inherited_object_type, sid = ace[1:]
        sid_str = win32security.ConvertSidToStringSid(sid)
        # check sid cache for owner sid
        if sid_str in sid_name_cache:
            name, domain, type = sid_name_cache[sid_str]
            if domain != '':
                trustee = domain + "\\" + name
            else:
                trustee = name
        else:
            try:
                # lookup sid
                name, domain, type = win32security.LookupAccountSid(None, sid)
            except pywintypes.error as e:
                if usesid:
                    trustee = sid_str
                else:
                    if options.verbose:
                        logger.warning('Error looking up account sid "{0}": {1} ({2})'.format(sid_str, path, e))
                        with lock:
                            processedfailcount += 1
                    continue
            else:
                with lock:
                    sid_name_cache[sid_str] = (name, domain, type)
                if domain != '':
                    trustee = domain + "\\" + name
                else:
                    trustee = name
        
        ace = Ace(ace_type, ace_flags, mask,
                        sid_str, trustee)
        ace_data = ace.get_aces()
        dacls.append(ace_data)
    
    if options.verbose:
        logger.info('Finished getting Dacl\'s: {}'.format(path))
    
    return dacls

        
def close_app():
    # close cache db
    if options.usecache is not None:
        cache.update_db(force=True)
        cache.close_db() 


def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    close_app() 
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-windowsattrib.py [-h] [index]

diskover windows attributes v{0}
Gets Windows owner/group and acls attributes for files/directories in a diskover Elasticsearch index.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-u', '--usecache', action='store_true', 
                        help='store and use cache db')                 
    parser.add_option('-f', '--flushcache', action='store_true', 
                        help='flush hash cache db (when usecache enabled)')
    parser.add_option('-l', '--latestindex', metavar='TOPPATH',
                        help='auto-finds most recent index based on top path')
    parser.add_option('-v', '--verbose', action='store_true', 
                        help='verbose logging')
    parser.add_option('--version', action='store_true',
                        help='print diskover-winattrib version number and exit')
    options, args = parser.parse_args()

    if options.version:
        print('diskover-winattrib v{}'.format(version))
        sys.exit(0)

    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'PRO')

    logger = log_setup()

    if IS_WIN is True:
        install_win_sig_handler()
    
    # catch SIGTERM sent by kill command 
    signal.signal(signal.SIGTERM, receive_signal)

    es = elasticsearch_connection()
    
    logger.info('Starting diskover windows attributes ...')

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_WINATTRIBDIR: {0}'.format(os.getenv('DISKOVER_WINATTRIBDIR')))

    try:
        if options.latestindex is not None:
            toppath = options.latestindex
            if toppath != '/':
                toppath = toppath.rstrip('/')
            logger.info('Finding latest index name for {} ...'.format(toppath))
            latest_index = find_latest_index(es, toppath)
            if latest_index is None:
                logger.error('No latest index found!')
                sys.exit(1)
            logger.info('Found latest index {0}'.format(latest_index))
            index = latest_index
        else:
            if not args:
                logger.error('no index in args!')
                sys.exit(1)
            index = args[0]
            if not check_index_exists(index, es):
                logger.error('{0} no such index!'.format(index))
                sys.exit(1)
                
        logger.info('Updating index mappings for windacls field in {0}...'.format(index))
        # update index mappings to be dual field keyword and text
        try:
            index_mappings = {'properties': {
                'windacls': {
                    'type': 'keyword',
                    'fields': {
                        'text': {
                            'type': 'text'
                        }
                    }
                }
            }}
            es.indices.put_mapping(index=index, body=index_mappings)
        except RequestError as e:
            logger.error("Error updating index mappings {0}".format(e))
            sys.exit(1)
        logger.info('Done.')
        
        if options.usecache:
            import diskover_cache as d_cache
            try:
                cache = d_cache.cache(cachedir)
            except FileExistsError:
                pass
            except OSError as e:
                logger.error('Error creating directory {0}'.format(e))
                sys.exit(1)
            logger.info('Using cache db in {0}'.format(cachedir))
            if options.flushcache:
                logger.info('Flushing cache db in {0}...'.format(cachedir))
                try:
                    cache.flush()
                except OperationalError as e:
                    logger.error('Error flushing cache db {0}'.format(e))
                    sys.exit(1)
                    
        for i in range(maxthreads):
            t = Thread(daemon=True, target=get_attrib_thread, args=(i,))
            t.start()
        logger.info('Started {0} windows attrib processing threads'.format(maxthreads))
        
        plugin_done = False
        
        t = Thread(daemon=True, target=log_stats_thread)
        t.start()

        start_time = timer()
        
        logger.info('Starting get windows attributes for index {0}...'.format(index))
        enqueue_docs(index)
        logger.info('Done.')

        plugin_done = True

        end_time = timer()
        elapsed = timedelta(seconds = end_time - start_time)
        if processedcount > 0:
            processedokcount = processedcount - processedfailcount
        else:
            processedokcount = 0
        logger.info('*** Elapsed time {0} ***'.format(elapsed))
        logger.info('*** Total files/folders (ES docs): {0} ***'.format(doccount))
        logger.info('*** Files/folders processed Win attrib OK: {0} ***'.format(processedokcount))
        logger.info('*** Files/folders processed Win attrib ERROR: {0} ***'.format(processedfailcount))
    except KeyboardInterrupt:
        logger.info('Received keyboard interrupt')
        close_app()
