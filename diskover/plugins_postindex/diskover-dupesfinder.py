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


diskover dupes finder plugin

'''

from sqlite3.dbapi2 import OperationalError
import sys
import os
import optparse
import confuse
import logging
import hashlib
import csv
import warnings
import time
import signal
from threading import Thread, Lock
from queue import Queue
from datetime import datetime, timedelta
from timeit import default_timer as timer
from collections import defaultdict
from elasticsearch.exceptions import RequestError
from elasticsearch.helpers.errors import BulkIndexError
from elasticsearch.exceptions import TransportError

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload
from diskover_helpers import set_times, find_prev_index, find_latest_index, get_mem_usage, convert_size, speed, escape_chars, timestamp_to_isoutc
from diskover_lic import License, licfc


plugin_name = 'dupesfinder'
version = '2.0.11'
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
# load dupes finder plugin default config file
config_defaults = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_dupesfinder/config.yaml')
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
    hash_mode = config['mode'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_mode = config_defaults['mode'].get()
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
    exclude_files = config['excludefiles'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    exclude_files = config_defaults['excludefiles'].get()
try:
    exclude_dirs = config['excludedirs'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    exclude_dirs = config_defaults['excludedirs'].get()
try:
    hash_hardlinks = config['hardlinks'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_hardlinks = config_defaults['hardlinks'].get()
try:
    hash_other_query = config['otherquery'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_other_query = config_defaults['otherquery'].get()
try:
    hash_restore_times = config['restoretimes'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_restore_times = config_defaults['restoretimes'].get()
try:
    hash_replacepaths = config['replacepaths']['replace'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_replacepaths = config_defaults['replacepaths']['replace'].get()
try:
    hash_replacepaths_from = config['replacepaths']['from'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_replacepaths_from = config_defaults['replacepaths']['from'].get()
try:
    hash_replacepaths_to = config['replacepaths']['to'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hash_replacepaths_to = config_defaults['replacepaths']['to'].get()
try:
    usediskmtime = config['usediskmtime'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    usediskmtime = config_defaults['usediskmtime'].get()
try:
    csvdir = config['csvdir'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    csvdir = config_defaults['csvdir'].get()


dups = defaultdict(list)
files_by_small_hash = defaultdict(list)
filecount = 0
filehashcount = 0
filecount_similar_size = 0
filecount_similar_firstchunk = 0
hash_queue = Queue()
hash_thread_lock = Lock()


def log_setup():
    """Setup logging for diskover dupes finder."""
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


def close_app_critical_error():
    """Handle exiting when a critical error exception occurs."""
    logger.critical('CRITICAL ERROR EXITING')
    try:
        sys.exit(1)
    except SystemExit:
        os._exit(1)
        

def index_get_files(indexname):
    """Generator to scroll over files in index and yield inodes and doc id."""
    global filecount

    n = len(hash_extensions)
    if n > 0:
        extension = ''
        i = 0
        while i < n:
            extension += hash_extensions[i]
            if i < n-1:
                extension += ' OR '
            i += 1
        query = 'type:file AND size:>={0} AND size:<={1} AND extension:({2})'.format(hash_minsize, hash_maxsize, extension)
    else:
        query = 'type:file AND size:>={0} AND size:<={1}'.format(hash_minsize, hash_maxsize)
    
    if not hash_hardlinks:
        query = query + ' AND nlink:1'
        
    if exclude_extensions:
        n = len(exclude_extensions)
        extension = ''
        i = 0
        while i < n:
            extension += exclude_extensions[i]
            if i < n-1:
                extension += ' OR '
            i += 1
        query = query + ' AND NOT extension:({0})'.format(extension)
        
    if exclude_files:
        n = len(exclude_files)
        filename = ''
        i = 0
        while i < n:
            filename += '"' + exclude_files[i] + '"'
            if i < n-1:
                filename += ' OR '
            i += 1
        query = query + ' AND NOT name:({0})'.format(filename)
        
    if exclude_dirs:
        n = len(exclude_dirs)
        dirpath = ''
        i = 0
        while i < n:
            if exclude_dirs[i].endswith('*'):
                exclude_dirs[i] = exclude_dirs[i].rstrip('*')
                dirpath += escape_chars(exclude_dirs[i]) + '*'
            else:
                dirpath += escape_chars(exclude_dirs[i])
            if i < n-1:
                dirpath += ' OR '
            i += 1
        query = query + ' AND NOT parent_path:({0})'.format(dirpath)
        
    if options.excludehashes:
        query = query + ' AND NOT hash:*'

    if hash_other_query:
        query = query + ' AND (' + hash_other_query + ')'

    if options.verbose or options.vverbose:
        logger.info('ES query: {0}'.format(query))

    data = {
        'size': 0,
        '_source': ['name', 'parent_path', 'size', 'mtime', 'ino'],
        'query': {
            'query_string': {
                'query': query
            }
        }
    }

    es.indices.refresh(index=indexname)

    res = es.search(index=indexname, scroll='1m', size=es_scrollsize,
                    body=data, request_timeout=es_timeout)

    with hash_thread_lock:
        filecount += res['hits']['total']['value']

    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            filepath = os.path.join(hit['_source']['parent_path'], hit['_source']['name'])
            ino = hit['_source']['ino']
            size = hit['_source']['size']
            mtime = hit['_source']['mtime']
            doc_id = hit['_id']
            yield (filepath, ino, size, mtime, doc_id)

        res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                        request_timeout=es_timeout)


def remove_hashes(indexname):
    """Unsets all file hash fields and removes is_dupe fields in index."""
    docs = []
    data = {
        'size': 0,
        '_source': [],
        'query': {
            'query_string': {
                'query': 'type:file AND (is_dupe:* OR hash:*)'
            }
        }
    }

    es.indices.refresh(index=indexname)

    res = es.search(index=indexname, scroll='1m', size=es_scrollsize,
                    body=data, request_timeout=es_timeout)

    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            d = {
                    '_op_type': 'update',
                    '_index': indexname,
                    '_id': hit['_id'],
                    'doc': {
                        'hash': None,
                        'is_dupe': None
                    }
                }
            docs.append(d)

        res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                        request_timeout=es_timeout)

    doccount = res['hits']['total']['value']
    
    if len(docs) > 0:
        logger.info('Updating {0} docs in {1}...'.format(doccount, indexname))
        try:
            bulk_upload(es, index, docs)
        except (BulkIndexError, TransportError) as e:
            logger.critical('thread {0} FATAL ERROR: Elasticsearch bulk index/transport error! ({1})'.format(i, e), exc_info=1)
            close_app_critical_error()
    else:
        logger.info('No docs found in {0}'.format(indexname))


def get_hash_index(ino, mtime):
    """Gets a file hash from an index using inode search."""
    data = {
        'size': 1,
        '_source': ['hash', 'mtime'],
        'query': {
            'match': {
                'ino': ino
            }
        }
    }

    res = es.search(index=hash_index, body=data, request_timeout=es_timeout)

    f_hash = None
    f_mtime = None
    if (res['hits']['hits']):
        try:
            f_hash = res['hits']['hits'][0]['_source']['hash'][hash_mode]
            f_mtime = res['hits']['hits'][0]['_source']['mtime']
        except KeyError:
            pass
    if f_hash is not None and mtime == f_mtime:
        return f_hash
    return None


def log_stats_thread():
    """Shows dupes finder stats."""
    global hashing_done
    start = time.time()
    hashedpercent = 0.0

    while True:
        time.sleep(3)
        if hashing_done:
            break
        timenow = time.time()
        elapsed = str(timedelta(seconds = timenow - start))
        filesps = filehashcount / (timenow - start)
        try:
            hashedpercent = filehashcount/filecount_similar_firstchunk*100
        except ZeroDivisionError:
            pass
        logger.info('STATS (files hashed {0}/{1} ({2:.1f}%), files in queue {3}, elapsed {4}, perf {5:.3f} files/s, memory usage {6})'.format(
            filehashcount, filecount_similar_firstchunk, hashedpercent, hash_queue.qsize(), elapsed, filesps, get_mem_usage()))


def hash_thread(i):
    global dups
    global hash_queue
    global hash_thread_lock
    global filehashcount
    global files_by_small_hash

    while True:
        try:
            index, res, first_chunk_only = hash_queue.get()
            filepath, ino, size, mtime, doc_id = res
            filehash = None

            if options.verbose or options.vverbose:
                logger.info('thread {0} starting hashing {1} (size {2}, first chunk only {3})'.format(
                    i, filepath, convert_size(size), first_chunk_only))

            start = timer()
            start_time_epoch = time.time()

            if options.useindex:
                filehash = get_hash_index(ino, mtime)
                if options.vverbose:
                    if filehash is not None:
                        logger.info('thread {0} found {1} hash for {2} in index'.format(i, hash_mode, filepath))
                    else:
                        logger.info('thread {0} no {1} hash for {2} found in index'.format(i, hash_mode, filepath))
            
            if filehash is None:
                filehash = get_hash(filepath, size, mtime, first_chunk_only)
            
                if filehash is not None and first_chunk_only:
                    with hash_thread_lock:
                        files_by_small_hash[(size, filehash)].append((filepath, ino, size, mtime, doc_id))
            
            end = timer()
            hashtime = timedelta(seconds = end - start)
            
            if options.verbose or options.vverbose:
                logger.info('thread {0} finished hashing {1} in {2}s (size {3}, speed {4}, hash {5}, first chunk only {6})'.format(
                    i, filepath, hashtime, convert_size(size), speed(start_time_epoch, size), filehash, first_chunk_only))

            if filehash is not None and not first_chunk_only:
                with hash_thread_lock:
                    dups[filehash].append((filepath, doc_id, index, size, mtime))
                    filehashcount += 1
    
        except (KeyboardInterrupt, SystemExit):
            raise
        hash_queue.task_done()


def find_dups(indexname):
    # Get all files from diskover index and enqueue to hash queue
    global filecount_similar_size
    global filecount_similar_firstchunk
    global files_by_small_hash
    files_by_size = defaultdict(list)
    
    try:
        logger.info('Queuing files from index {0}...'.format(indexname))
        for res in index_get_files(indexname):
            if len(indices) > 1 or options.alldocs:
                # Get all file hashes
                hash_queue.put((index, res, False))
                filecount_similar_firstchunk += 1
            else:
                filepath, ino, size, mtime, doc_id = res
                files_by_size[size].append((filepath, ino, size, mtime, doc_id))
        
                # For all files with the same file size, get their hash 
                for size, files in files_by_size.items():
                    if len(files) < 2:
                        continue  # this file size is unique, no need to spend cpu cycles on it

                    for file in files:
                        if options.useindex or options.usecache:
                            hash_queue.put((index, file, False))
                            filecount_similar_size += 1
                            filecount_similar_firstchunk += 1
                        else:
                            hash_queue.put((index, file, True))
                            filecount_similar_size += 1
                        
                while hash_queue.qsize() > 0:
                    time.sleep(1)
                
                # For all files with the hash on the first blocksize bytes, get their hash on the full
                # file - collisions will be duplicates
                for files in files_by_small_hash.values():
                    if len(files) < 2:
                        # the hash of the first blocksize bytes is unique -> skip this file
                        continue

                    for file in files:
                        hash_queue.put((index, file, False))
                        filecount_similar_firstchunk += 1

        logger.info('Done queuing files in index {0}. Waiting for hash threads to finish...'.format(indexname))
        # Wait for hash threads to finish
        hash_queue.join()
    except (KeyboardInterrupt, SystemExit):
        raise


def update_dupes(all_dups):
    dupes = 0
    docstoupdate = 0
    all_docs = defaultdict(list)
    if options.csv:
        row_list = [['File', 'Hash('+hash_mode+')', 'Size(bytes)', 'Mtime(utc)', 'Index', 'Docid']]
    
    logger.info('*** Total files: {0} ***'.format(filecount))
    logger.info('*** Files hashed: {0} ({1:.1f}% reduction of total files) ***'.format(filehashcount, (filecount-filehashcount)/filecount*100))
    if not options.alldocs and len(indices) == 1:
        logger.info('*** Files with similar sizes: {0} ({1:.1f}% reduction of total files) ***'.format(filecount_similar_size, (filecount-filecount_similar_size)/filecount*100))
        logger.info('*** Files with similar first chunk size: {0} ({1:.1f}% reduction of total files) ***'.format(filecount_similar_firstchunk, (filecount-filecount_similar_firstchunk)/filecount*100))
            
    results = dict(filter(lambda x: len(x[1]) > 1, all_dups.items()))
    if len(results) > 0:
        if options.vverbose:
            logger.info('Duplicates Found:')
            logger.info('The following files are identical. The name could differ, but the content is identical')
            print('___________________')
        for filehash, files in results.items():
            for file in files:
                path = file[0]
                if options.vverbose:
                    print('\t\t{0}'.format(path))
                docid = file[1]
                index = file[2]
                size = file[3]
                mtime = file[4]
                if options.csv:
                    row_list.append([path, filehash, size, mtime, index, docid])
                d = {
                    '_op_type': 'update',
                    '_index': index,
                    '_id': docid,
                    'doc': {'hash': { hash_mode: filehash }, 'is_dupe': True}
                }
                all_docs[index].append(d)
                dupes += 1
                docstoupdate += 1
            if options.vverbose:
                print('___________________')
        sys.stdout.flush()
        logger.info('*** Dupes found: {0} ({1:.1f}% of total files) ***'.format(dupes, dupes/filecount*100))
    else:
        logger.info('*** No duplicate files found. ***')
        
    if options.alldocs:
        results = dict(filter(lambda x: len(x[1]) == 1, all_dups.items()))
        if len(results) > 0:
            for filehash, files in results.items():
                for file in files:
                    docid = file[1]
                    index = file[2]
                    d = {
                        '_op_type': 'update',
                        '_index': index,
                        '_id': docid,
                        'doc': {'hash': { hash_mode: filehash }}
                    }
                    all_docs[index].append(d)
                    docstoupdate += 1
                    
    logger.info('Updating {0} ES docs...'.format(docstoupdate))
    for index, docs in all_docs.items():
        try:
            bulk_upload(es, index, docs)
        except (BulkIndexError, TransportError) as e:
            logger.critical('thread {0} FATAL ERROR: Elasticsearch bulk index/transport error! ({1})'.format(i, e), exc_info=1)
            close_app_critical_error()
    logger.info('Done.')
    
    if options.csv and dupes > 0:
        csvfiletime = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
        csvfile = 'diskover-dupesfinder_{0}_{1}_{2}.csv'.format('_'.join(indices), hash_mode, csvfiletime)
        csvpath = os.path.join(csvdir, csvfile)
        logger.info('Saving results to {0}'.format(csvpath))
        try:
            with open(csvpath, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerows(row_list)
            logger.info('Done.')
        except OSError as e:
            logger.error('Error saving file: {0}'.format(e))


def get_hash(file, size, mtime, first_chunk_only):
    """Use xxhash or md5, etc to get the hexadecimal digest of the file hash.
    Returns hash"""
    # return if size is 0
    if size == 0:
        return None
    # replace path
    if hash_replacepaths:
        file = file.replace(hash_replacepaths_from, hash_replacepaths_to, 1)
    # Windows path translations
    if IS_WIN:
        file = file.replace('/', '\\')
    
    # check if hash in cache
    if options.usecache:
        # use mtime on disk instead of in index to compare to cached mtime
        if usediskmtime:
            try:
                mtime_unix = os.path.getmtime(file)
                mtime = timestamp_to_isoutc(mtime_unix)
            except OSError as e:
                if options.verbose or options.vverbose:
                    logger.warning('Error getting file mtime {0} ({1})'.format(file, e))
                pass
        # md5 hash file path
        pathhash = hashlib.md5(file.encode('utf-8')).hexdigest()
        # Get file hash from cache
        cache_res = cache.get_value(pathhash)
        if cache_res:
            if hash_mode in cache_res and mtime == cache_res['mtime']:
                logger.debug('CACHE HIT {0}'.format(file))
                return cache_res[hash_mode]
        logger.debug('CACHE MISS {0}'.format(file))
    
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
            if options.verbose or options.vverbose:
                logger.warning('Error stat file: {0} ({1})'.format(file, e))
            return None
    try:
        with open(file, 'rb') as f:
            if first_chunk_only:
                x.update(f.read(hash_blocksize))
            else:
                fb = f.read(hash_blocksize)
                while len(fb) > 0:
                    x.update(fb)
                    fb = f.read(hash_blocksize)
    except OSError as e:
        if options.verbose or options.vverbose:
            logger.warning('Error open file: {0} ({1})'.format(file, e))
        return None
    
    xhex = x.hexdigest()
    
    # restore times (atime/mtime)
    if hash_restore_times:
        res, err = set_times(file, st.st_atime, st.st_mtime)
        if not res:
            if options.verbose or options.vverbose:
                logger.warning('Error set times file: {0} ({1})'.format(file, err))
    
    # cache file hash
    if options.usecache and not first_chunk_only:
        if cache_res:
            cache_data = cache_res.copy()
        else:
            cache_data = dict()
        cache_data['mtime'] = mtime
        cache_data[hash_mode] = xhex
        cache.set_value(pathhash, cache_data, expire_seconds=hash_cache_expiretime)
    
    return xhex


def join_dicts(dict1, dict2):
    for key in dict2.keys():
        if key in dict1:
            dict1[key] = dict1[key] + dict2[key]
        else:
            dict1[key] = dict2[key]


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
    usage = """Usage: diskover-dupesfinder.py [-h] [index] [index]...

diskover dupes finder v{0}
Finds duplicate files in a diskover Elasticsearch index.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-a', '--alldocs', action='store_true', 
                        help='update all file docs hash field in index, not just found dupes')
    parser.add_option('-c', '--csv', action='store_true', 
                        help='save any dupe files to csv file')
    parser.add_option('-u', '--usecache', action='store_true', 
                        help='store and use hash cache db')                 
    parser.add_option('-f', '--flushcache', action='store_true', 
                        help='flush hash cache db (when usecache enabled)')
    parser.add_option('-U', '--useindex', metavar='INDEX',
                        help='use an existing index to try to get file hash, if no hash found or mtime diff, hash file again or use hash cache db')
    parser.add_option('--useindexauto', action='store_true', 
                        help='same as useindex but auto-finds previous index based on index arg\'s top paths')
    parser.add_option('-r', '--removehashes', action='store_true', 
                        help='unset all file hash and is_dupe fields from existing index')
    parser.add_option('-l', '--latestindex', action='append', metavar='TOPPATH',
                        help='auto-finds most recent index based on top path, multiple -l can be used for addtional top paths')
    parser.add_option('-e', '--excludehashes', action='store_true', 
                        help='exclude any files when searching that already have hash in index doc')
    parser.add_option('-m', '--hashmode', metavar='HASHMODE', 
                        help='which hash/checksum type to use, can be xxhash, md5, sha1, sha256, overrides mode config setting')
    parser.add_option('-v', '--verbose', action='store_true', 
                        help='verbose logging')
    parser.add_option('-V', '--vverbose', action='store_true', 
                        help='more verbose logging')
    parser.add_option('--version', action='store_true',
                        help='print diskover-dupesfinder version number and exit')
    options, args = parser.parse_args()

    if options.version:
        print('diskover-dupesfinder v{}'.format(version))
        sys.exit(0)

    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'ESS')
    
    # check if hashmode cli option is set
    if options.hashmode is not None:
        hash_mode = options.hashmode
    # check hash mode is supported
    if hash_mode not in ('xxhash', 'md5', 'sha1', 'sha256'):
        print('Unsupported hash mode {}, supported types are xxhash, md5, sha1, sha256'.format(hash_mode))
        sys.exit(1)
        
    # check if xxhash installed
    if hash_mode == 'xxhash':
        try:
            import xxhash
        except ModuleNotFoundError:
            print('Missing xxhash Python module')
            sys.exit(1)

    logger = log_setup()

    if IS_WIN is True:
        install_win_sig_handler()

    # catch SIGTERM sent by kill command 
    signal.signal(signal.SIGTERM, receive_signal)

    es = elasticsearch_connection()
    
    logger.info('Starting diskover dupes finder ...')

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_DUPESFINDERDIR: {0}'.format(os.getenv('DISKOVER_DUPESFINDERDIR')))

    if len(args) > 0 or options.latestindex is not None:
        if not options.removehashes:
            all_dups = dict()
            if options.usecache:
                import diskover_cache as d_cache
                try:
                    cache = d_cache.cache(hash_cachedir)
                except FileExistsError:
                    pass
                except OSError as e:
                    logger.error('Error creating directory {0}'.format(e))
                    sys.exit(1)
                logger.info('Using/ caching file hashes in {0}'.format(hash_cachedir))
                if options.flushcache:
                    logger.info('Flushing hash cache db in {0}...'.format(hash_cachedir))
                    try:
                        cache.flush()
                    except OperationalError as e:
                        logger.error('Error flushing hash cache db {0}'.format(e))
                        sys.exit(1)
                        
            for i in range(maxthreads):
                t = Thread(daemon=True, target=hash_thread, args=(i,))
                t.start()
            logger.info('Started {0} file hash threads'.format(maxthreads))
            
            hashing_done = False
            
            t = Thread(daemon=True, target=log_stats_thread)
            t.start()
            
            logger.info('Using hash mode {}'.format(hash_mode))

        start_time = timer()

        try:
            if options.latestindex is not None:
                indices = []
                for toppath in options.latestindex:
                    if toppath != '/':
                        toppath = toppath.rstrip('/')
                    logger.info('Finding latest index name for {} ...'.format(toppath))
                    latest_index = find_latest_index(es, toppath)
                    if latest_index is None:
                        logger.error('No latest index found!')
                        sys.exit(1)
                    logger.info('Found latest index {0}'.format(latest_index))
                    indices.append(latest_index)
            else:
                indices = args[0:]
            for index in indices:
                if check_index_exists(index, es):
                    if options.useindex:
                        hash_index = options.useindex
                        logger.info('Using index {0} for cache'.format(hash_index))
                        if not check_index_exists(hash_index, es):
                            logger.error('{0} no such index!'.format(hash_index))
                            sys.exit(1)
                    elif options.useindexauto:
                        logger.info('Finding previous index name...')
                        prev_index = find_prev_index(es, index)
                        if prev_index is None:
                            logger.error('No previous index found!')
                            sys.exit(1)
                        else:
                            hash_index = prev_index
                            logger.info('Found previous index {0}, using for cache'.format(prev_index))
                            
                    if options.removehashes:
                        logger.info('Unsetting existing file hash and is_dupe fields in {0}...'.format(index))
                        remove_hashes(index)
                        logger.info('Done.')
                    else:
                        logger.info('Updating index mappings for hash and is_dupe fields in {0}...'.format(index))
                        # update index mappings
                        try:
                            index_mappings = {'properties': {
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
                                },
                                'is_dupe': {
                                    'type': 'boolean'
                                }
                            }}
                            es.indices.put_mapping(index=index, body=index_mappings)
                        except RequestError as e:
                            logger.error("Error updating index mappings {0}".format(e))
                            sys.exit(1)
                        logger.info('Done.')
                        logger.info('Starting dupes finding for index {0}...'.format(index))
                        # Find the duplicated files and append them to the dups
                        find_dups(index)
                        join_dicts(all_dups, dups)
                        dups.clear()
                        logger.info('Done.')
                else:
                    logger.error('{0} no such index!'.format(index))
                    sys.exit(1)

            if not options.removehashes:
                logger.info('Finding and updating any duplicate files...')
                hashing_done = True
                update_dupes(all_dups)

            end_time = timer()
            elapsed = timedelta(seconds = end_time - start_time)
            logger.info('Elapsed time {0}'.format(elapsed))        
        except KeyboardInterrupt:
            logger.info('Received keyboard interrupt')
            close_app()  
    else:
        logger.error('no index in args!')
        sys.exit(1)
