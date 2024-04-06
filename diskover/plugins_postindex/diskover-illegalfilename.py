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

diskover illegal file name plugin

'''

import sys
import os
import time
import signal
import optparse
import confuse
import logging
import warnings
import string
import unicodedata
import re
from threading import Thread, Lock
from queue import Queue
from datetime import datetime

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload
from diskover_helpers import get_time, escape_chars, find_latest_index
from diskover_lic import License, licfc

plugin_name = 'illegalfilename'
version = '0.1.6'
__version__ = version

# Python 3 check
IS_PY3 = sys.version_info >= (3, 5)
if not IS_PY3:
    print('Python 3.5 or higher required.')
    sys.exit(1)

# Windows check
if os.name == 'nt':
    IS_WIN = True
    # Handle keyboard interupt for Windows
    def handler(a, b=None):
        logger.info('Received keyboard interrupt')
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
# load illegalfilename default config file
config_defaults = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_illegalfilename/config.yaml')
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
    es_chunksize = diskover_config['databases']['elasticsearch']['chunksize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_chunksize = diskover_config_defaults['databases']['elasticsearch']['chunksize'].get()
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
try:
    validchars = config['validchars'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    validchars = config_defaults['validchars'].get()
# add all ascii letters and numbers to validchars
for char in string.ascii_letters:
    validchars.append(char)
for char in string.digits:
    validchars.append(char)
re_validchars = "".join(validchars)
fixname_whitelist = "".join(c.lstrip('\\') for c in validchars)
try:
    checkfile = config['checkfile'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    checkfile = config_defaults['checkfile'].get()
try:
    checkdirectory = config['checkdirectory'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    checkdirectory = config_defaults['checkdirectory'].get()
try:
    checklongnames = config['checklongnames'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    checklongnames = config_defaults['checklongnames'].get()
try:
    longnameminchars = config['longnameminchars'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    longnameminchars = config_defaults['longnameminchars'].get()
try:
    extensions = config['extensions'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    extensions = config_defaults['extensions'].get()
try:
    excludedirs = config['excludedirs'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    excludedirs = config_defaults['excludedirs'].get()
try:
    illegaltag = config['illegaltag'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    illegaltag = config_defaults['illegaltag'].get()
try:
    longtag = config['longtag'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    longtag = config_defaults['longtag'].get()
try:
    normalizeunicode = config['normalizeunicode'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    normalizeunicode = config_defaults['normalizeunicode'].get()
try:
    encodeascii = config['encodeascii'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    encodeascii = config_defaults['encodeascii'].get()
try:
    filenamecharlimit = config['filenamecharlimit'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    filenamecharlimit = config_defaults['filenamecharlimit'].get()
try:
    replacespaces = config['replacespaces'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    replacespaces = config_defaults['replacespaces'].get()


file_queue = Queue()
file_queue_lock = Lock()
totaldocstagged = 0
illegalfilenames = 0
longfilenames = 0
filenamesfixed = 0
filenamesfixed_errors = 0
filenamesfixed_skipped = 0


def log_setup():
    """Setup logging for diskover tagcopier.
    """
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


def check_valid_filename(filename):
    """Checks if a file name contains only valid characters.
    """
    res = re.search(r'[^' + re_validchars + ']+', filename)
    if res is None or res.end() == res.endpos:   
        return True
    else:
        return False
    

def index_get_illegal_filenames(es, index):
    """Generator to scroll over files and directories in index and files with illegal filenames.
    """
    global illegalfilenames
    global longfilenames

    if checkfile and checkdirectory:
        doctype = 'type:(file OR directory)'
    elif checkfile and not checkdirectory:
        doctype = 'type:file'
    elif not checkfile and checkdirectory:
        doctype = 'type:directory'

    extensions_len = len(extensions)
    extensions_str = ""
    n = 0
    for ext in extensions:
        extensions_str += ext
        if n < extensions_len - 1:
            extensions_str += ' OR '
        n += 1
        
    if extensions_str == "":
        query = '{0}'.format(doctype)
    elif checkfile and not checkdirectory:
        query = 'extension:({0}) AND type:file'.format(extensions_str)
    elif checkfile and checkdirectory:
        query = '(extension:({0}) AND type:file) OR (type:directory)'.format(extensions_str)
    elif not checkfile and checkdirectory:
        query = 'type:directory'
    
    if len(excludedirs) > 0:
        for dirpath in excludedirs:
            query += ' AND NOT parent_path:{0}*'.format(escape_chars(dirpath))

    data = {
        'size': 0,
        '_source': ['tags', 'name', 'parent_path', 'type'],
        'query': {
            'query_string': {
                'query': query
            }
        }
    }
    
    logger.info('Finding any illegal file names in index {0}...'.format(index))
    
    if options.verbose:
        logger.info('searching for {0} in index...'.format(query))

    es.indices.refresh(index=index)
    
    res = es.search(index=index, scroll='1m', size=es_scrollsize,
                    body=data, request_timeout=es_timeout)

    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            name = hit['_source']['name']
            if not check_valid_filename(name):
                docid = hit['_id']
                try:
                    tags = hit['_source']['tags']
                except KeyError:
                    tags = None
                parent_path = hit['_source']['parent_path']
                source_type = hit['_source']['type']
                fullpath = os.path.join(parent_path, name)
                if options.verbose:
                    if source_type == 'file':
                        logger.info('illegal file found: {0}'.format(fullpath))
                    else:
                        logger.info('illegal directory found: {0}'.format(fullpath))
                illegalfilenames += 1
                yield (fullpath, docid, tags, illegaltag)

        res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                        request_timeout=es_timeout)
        
    # check for long file names
    if checklongnames:
        if extensions_str == "":
            query = 'name:/.{' + str(longnameminchars) + ',}/ AND ' + doctype
        elif checkfile and not checkdirectory:
            query = 'name:/.{' + str(longnameminchars) + ',}/ AND extension:(' + extensions_str + ') AND type:file'
        elif checkfile and checkdirectory:
            query = '(name:/.{' + str(longnameminchars) + ',}/ AND extension:(' + extensions_str + ') AND type:file) OR (name:/.{' + str(longnameminchars) + ',}/ AND type:directory)'
        elif not checkfile and checkdirectory:
            query = 'name:/.{' + str(longnameminchars) + ',}/ AND type:directory'
        
        if len(excludedirs) > 0:
            for dirpath in excludedirs:
                query += ' AND NOT parent_path:{0}*'.format(escape_chars(dirpath))
        
        data = {
            'size': 0,
            '_source': ['tags', 'name', 'parent_path', 'type'],
            'query': {
                'query_string': {
                    'query': query
                }
            }
        }
        
        logger.info('Finding any long file names in index {0}...'.format(index))
    
        if options.verbose:
            logger.info('searching for {0} in index...'.format(query))
            
        es.indices.refresh(index=index)
        
        res = es.search(index=index, scroll='1m', size=es_scrollsize,
                        body=data, request_timeout=es_timeout)

        while res['hits']['hits'] and len(res['hits']['hits']) > 0:
            for hit in res['hits']['hits']:
                docid = hit['_id']
                try:
                    tags = hit['_source']['tags']
                except KeyError:
                    tags = None
                name = hit['_source']['name']
                parent_path = hit['_source']['parent_path']
                doctype = hit['_source']['type']
                fullpath = os.path.join(parent_path, name)
                if options.verbose:
                    if doctype == 'file':
                        logger.info('long file name found: {0}'.format(fullpath))
                    else:
                        logger.info('long directory name found: {0}'.format(fullpath))
                longfilenames += 1
                yield (fullpath, docid, tags, longtag)

            res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                            request_timeout=es_timeout)


def filetag_thread(i):
    global file_queue
    global totaldocstagged

    while True:
        results = file_queue.get()
        doccount = 0
        docs = []
        
        start = time.time()
        
        if options.verbose:
            logger.info('thread {0} Started searching for {1} docs in index...'.format(i, len(results)))
        
        for res in results:
            fullpath, docid, tags, newtag = res
            
            newtags = []
            
            # combine any existings tags in index with illegal tag
            if tags is None:
                newtags.append(newtag)
            # check we aren't duplicating illegal tag already in index doc
            elif newtag == illegaltag and illegaltag in tags:
                newtags = tags
            # check we aren't duplicating long tag already in index doc
            elif newtag == longtag and longtag in tags:
                newtags = tags
            else:
                newtags = tags
                newtags.append(newtag)

            d = {
                '_op_type': 'update',
                '_index': index,
                '_id': docid,
                'doc': {'tags': newtags}
            }
            docs.append(d)
            doccount += 1
                
        searchtime = get_time(time.time() - start)

        if options.verbose:
            logger.info('thread {0} Finished searching index in {1}'.format(i, searchtime))

        start = time.time()

        bulk_upload(es, index, docs)

        tagtime = get_time(time.time() - start)
            
        if options.verbose:
            logger.info('thread {0} Finished updating tags for {1} docs in {2}'.format(i, doccount, tagtime))
        
        with file_queue_lock:
            totaldocstagged += doccount
        
        # fix file names
        if options.fixnames:
            fixcount = 0
            start = time.time()
        
            if options.verbose:
                logger.info('thread {0} Started fixing file names for {1} files/directories...'.format(i, len(results)))
            
            for res in results:
                fullpath, docid, tags, newtag = res
                res = rename_file(i, fullpath)
                if res:
                    fixcount += 1
                    
            fixtime = get_time(time.time() - start)

            if options.verbose:
                logger.info('thread {0} Finished fixing {1} file names in {2}'.format(i, fixcount, fixtime))           

        del docs[:]
        file_queue.task_done()


def index_find_illegal(es, index):
    """Get all files and directories with any illegal file names from diskover index and enqueue.
    """
    results = []
    start = time.time()
    docs = 0
    for res in index_get_illegal_filenames(es, index):
        results.append(res)
        docs += 1
        if len(results) >= 500:
            file_queue.put(results[:])
            del results[:]
    file_queue.put(results)
    
    queuetime = get_time(time.time() - start)
    
    if options.verbose:
        logger.info('Finished searching index and enqueueing {0} docs in {1}'.format(docs, queuetime))
        logger.info('Waiting for tagging threads to finish...')
        
    # Wait for threads to finish
    file_queue.join()
    

def sanitize_filename(thread, filename):
    """Sanitizes a filename and returns a sanitized file name.
    """
    cleaned_filename = filename
    
    # replace spaces
    if replacespaces:
        cleaned_filename = cleaned_filename.replace(' ', '_')
    
    # normalize unicode and keep only valid ascii chars
    if normalizeunicode:
        cleaned_filename = unicodedata.normalize('NFKD', cleaned_filename)
        if encodeascii:
            cleaned_filename = cleaned_filename.encode('ASCII', 'ignore').decode()
    
    # keep only whitelisted valid chars
    cleaned_filename = ''.join(c for c in cleaned_filename if c in fixname_whitelist)
    
    # check file name length
    if len(cleaned_filename) > filenamecharlimit:
        logger.warning("thread {0} Renaming {1} => {2} will be truncated because it is over {3}".format(thread, filename, cleaned_filename, filenamecharlimit))
    return cleaned_filename[:filenamecharlimit]


def rename_file(thread, filepath):
    """Renames a file to a sanitized name.
    """
    global filenamesfixed
    global filenamefixed_errors
    global filenamesfixed_skipped
    
    filename = os.path.basename(filepath)
    parent_path = os.path.abspath(os.path.join(filepath, os.pardir))
    
    sanitized_filename = sanitize_filename(thread, filename)
    
    sanitized_filepath = os.path.join(parent_path, sanitized_filename)
    
    # check if file name hasn't changed
    if filename == sanitized_filename:
        logger.info('thread {0} Skipping renaming {1} => {2} file name unchanged'.format(thread, filepath, sanitized_filepath))
        with file_queue_lock:
            filenamesfixed_skipped += 1
        return False
    
    if options.fixnamesdryrun:
        logger.info('thread {0} Renaming {1} => {2} (DRY-RUN)'.format(thread, filepath, sanitized_filepath))
        return True
    
    if not os.path.exists(filepath):
        logger.error('thread {0} Error renaming {1} => {2} path does not exist'.format(thread, filepath, sanitized_filepath))
        with file_queue_lock:
            filenamefixed_errors += 1
        return False
    
    try:
        os.rename(filepath, sanitized_filepath)
    except FileExistsError as e:
        logger.error('thread {0} Error renaming {1} => {2} already exists ({3})'.format(thread, filepath, sanitized_filepath, e))
        with file_queue_lock:
            filenamefixed_errors += 1
        return False
    except OSError as e:
        logger.error('thread {0} Error renaming {1} => {2} ({3})'.format(thread, filepath, sanitized_filepath, e))
        with file_queue_lock:
            filenamefixed_errors += 1
        return False
    else:
        filenames_fixed += 1
        return True
    

def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-illegalfilename.py [-h] [index]

diskover illegal file name finder v{0}
Checks for illegal file names in a diskover Elasticsearch index.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-l', '--latestindex', metavar='TOPPATH',
                        help='auto-finds most recent index based on top path')
    parser.add_option('-f', '--fixnames', action='store_true', 
                        help='fix file/directory names')
    parser.add_option('--fixnamesdryrun', action='store_true', 
                        help='fix file/directory names and log fixes but do not actually rename the files (DRY-RUN)')
    parser.add_option('-v', '--verbose', action='store_true', 
                        help='verbose logging')
    parser.add_option('--version', action='store_true',
                        help='print diskover-illegalfilename version number and exit')
    options, args = parser.parse_args()

    if options.version:
        print('diskover-illegalfilename v{}'.format(version))
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
    
    logger.info('Starting diskover illegal file name finder ...')

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_ILLEGALFILENAMEDIR: {0}'.format(os.getenv('DISKOVER_ILLEGALFILENAMEDIR')))
    
    if options.latestindex:
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
        if len(args) < 1:
            logger.error('no index in args!')
            sys.exit(1)
        else:
            index = args[0]
            if not check_index_exists(index, es):
                logger.error('{0} no such index!'.format(index))
                sys.exit(1)

    for i in range(maxthreads):
        t = Thread(daemon=True, target=filetag_thread, args=(i,))
        t.start()

    start = time.time()
    index_find_illegal(es, index)
    elapsed = get_time(time.time() - start)
    logger.info('Finished tagging {0} docs in {1}'.format(totaldocstagged, elapsed))
    logger.info('Illegal file names found: {0}'.format(illegalfilenames))
    if longfilenames:
        logger.info('Long file names found: {0}'.format(longfilenames))
    if options.fixnames:
        logger.info('File names fixed: {0}'.format(filenamesfixed))
        logger.info('File names fixed (errors): {0}'.format(filenamesfixed_errors))
        logger.info('File names fixed (skipped): {0}'.format(filenamesfixed_skipped))