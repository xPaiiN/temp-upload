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

diskover tag copier plugin

'''

import sys
import os
import time
import signal
import optparse
import confuse
import logging
import warnings
from threading import Thread, Lock
from queue import Queue
from datetime import datetime
from elasticsearch.helpers.errors import BulkIndexError
from elasticsearch.exceptions import TransportError

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload
from diskover_helpers import find_prev_index, get_time
from diskover_lic import License, licfc

plugin_name = 'tagcopier'
version = '2.0.4'
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
# load autoclean default config file
config_defaults = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_tagcopier/config.yaml')
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
    copyfiletags = config['filetags'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    copyfiletags = config_defaults['filetags'].get()
try:
    copydirectorytags = config['directorytags'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    copydirectorytags = config_defaults['directorytags'].get()
try:
    exclude_tags = config['excludetags'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    exclude_tags = config_defaults['excludetags'].get()
try:
    exclude_auto_tags = config['excludeautotags'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    exclude_auto_tags = config_defaults['excludeautotags'].get()


tagcopy_queue = Queue()
tagcopy_lock = Lock()
totaldocstagged = 0


def log_setup():
    """Setup logging for diskover tagcopier."""
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
    

def index_get_tags(es, index_from, index_to):
    """Generator to scroll over files and directories in index and get inode and tags."""

    es.indices.refresh(index=index_from)
    es.indices.refresh(index=index_to)

    if copyfiletags and copydirectorytags:
        doctype = 'type:(file OR directory)'
    elif copyfiletags and not copydirectorytags:
        doctype = 'type:file'
    elif not copyfiletags and copydirectorytags:
        doctype = 'type:directory'

    exclude = ''
    exclude_tags_len = len(exclude_auto_tags)
    n = 0
    for tag in exclude_auto_tags:
        exclude += tag
        if n < exclude_tags_len - 1:
            exclude += ' OR '
        n += 1
        
    query = 'tags:* AND NOT tags:({0}) AND {1}'.format(exclude, doctype)

    data = {
        'size': 0,
        '_source': ['ino', 'tags'],
        'query': {
            'query_string': {
                'query': query,
                'analyze_wildcard': 'true'
            }
        }
    }
    
    if options.verbose:
        logger.info('searching for {0} in source index...'.format(query))
        
    try:
        res = es.search(index=index_from, scroll='1m', size=es_scrollsize,
                        body=data, request_timeout=es_timeout)

        while res['hits']['hits'] and len(res['hits']['hits']) > 0:
            for hit in res['hits']['hits']:
                ino = hit['_source']['ino']
                tags = hit['_source']['tags']
                yield (ino, tags)

            res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                            request_timeout=es_timeout)
    except TransportError as e:
        logger.critical('FATAL ERROR: Elasticsearch transport error! ({0})'.format(e), exc_info=1)
        close_app_critical_error()


def tagcopy_thread(i):
    global tagcopy_queue
    global totaldocstagged

    while True:
        try:
            results = tagcopy_queue.get()
            doccount = 0
            docs = []
            
            start = time.time()
            
            if options.verbose:
                logger.info('thread {0} started searching for {1} docs in destination index...'.format(i, len(results)))
            
            for res in results:
                ino, tags = res

                # get doc id and tags from inode in target index
                data = {
                    'size': 1,
                    '_source': ['tags'],
                    'query': {
                        'match': {
                            'ino': ino
                        }
                    }
                }

                try:
                    res = es.search(index=index_to, body=data, request_timeout=es_timeout)
                except TransportError as e:
                    logger.critical('thread {0} FATAL ERROR: Elasticsearch transport error! ({1})'.format(i, e), exc_info=1)
                    close_app_critical_error()
                
                # continue if there is no matching inode in target index
                if not res['hits']['hits']:
                    continue
                
                docid = res['hits']['hits'][0]['_id']
                try:
                    existing_tags = res['hits']['hits'][0]['_source']['tags']
                except KeyError:
                    existing_tags = None
                    pass
                
                # combine any existings tags in target index with tags from source index
                if existing_tags is None:
                    newtags = tags
                else:
                    # remove any excluded tags
                    if exclude_tags:
                        for tag in exclude_tags:
                            if tag in existing_tags:
                                existing_tags.remove(tag)
                    # check we aren't duplicating tags already in target index
                    for tag in existing_tags:
                        if tag in tags:
                            tags.remove(tag)
                    newtags = existing_tags + tags

                d = {
                    '_op_type': 'update',
                    '_index': index_to,
                    '_id': docid,
                    'doc': {'tags': newtags}
                }
                docs.append(d)
                doccount += 1
                    
            searchtime = get_time(time.time() - start)

            if options.verbose:
                logger.info('thread {0} finished searching destination index in {1}'.format(i, searchtime))

            start = time.time()

            try:
                bulk_upload(es, index_to, docs)
            except (BulkIndexError, TransportError) as e:
                logger.critical('thread {0} FATAL ERROR: Elasticsearch bulk index/transport error! ({1})'.format(i, e), exc_info=1)
                close_app_critical_error()

            tagtime = get_time(time.time() - start)
                
            if options.verbose:
                logger.info('thread {0} finished updating tags for {1} docs in {2}'.format(i, doccount, tagtime))
            
            with tagcopy_lock:
                totaldocstagged += doccount

            del docs[:]

        except (KeyboardInterrupt, SystemExit):
            raise
        tagcopy_queue.task_done()


def index_copy_tags(es, index_from, index_to):
    # Get all files and directories with any tags from diskover index and enqueue to tagcopy queue
    results = []
    start = time.time()
    docs = 0
    
    try:
        for res in index_get_tags(es, index_from, index_to):
            results.append(res)
            docs += 1
            if len(results) >= 500:
                tagcopy_queue.put(results[:])
                del results[:]
        tagcopy_queue.put(results)
        
        queuetime = get_time(time.time() - start)
        
        if options.verbose:
            logger.info('Finished searching source index and enqueueing {0} docs in {1}'.format(docs, queuetime))
            logger.info('Waiting for tag copy threads to finish...')
            
        # Wait for hash threads to finish
        tagcopy_queue.join()
    except (KeyboardInterrupt, SystemExit):
        raise


def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-tagcopier.py [-h] [index_from] [index_to]

diskover tag copier v{0}
Copies tags from a diskover Elasticsearch index to another.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-a', '--autoindexfrom', action='store_true', 
                        help='find index_from (previous index) based on index_to\'s top paths')
    parser.add_option('-v', '--verbose', action='store_true', 
                        help='verbose logging')
    parser.add_option('--version', action='store_true',
                        help='print diskover-tagcopier version number and exit')
    options, args = parser.parse_args()

    if options.version:
        print('diskover-tagcopier v{}'.format(version))
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
    
    logger.info('Starting diskover tag copier ...')

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_TAGCOPIERDIR: {0}'.format(os.getenv('DISKOVER_TAGCOPIERDIR')))

    if options.autoindexfrom:
        if len(args) < 1:
            logger.error('no index_to in args!')
            sys.exit(1)
        else:
            index_to = args[0]
        logger.info('Finding previous index name...')
        prev_index = find_prev_index(es, index_to)
        if prev_index is None:
            logger.error('No previous index found!')
            sys.exit(1)
        else:
            logger.info('Found previous index {0}'.format(prev_index))
            args[0] = prev_index
        args.append(index_to)
    
    if len(args) < 2:
        logger.error('no index_from or index_to in args!')
        sys.exit(1)
    else:
        index_from = args[0]
        index_to = args[1]
        if not check_index_exists(index_from, es):
            logger.error('{0} no such index!'.format(index_from))
            sys.exit(1)
        if not check_index_exists(index_to, es):
            logger.error('{0} no such index!'.format(index_to))
            sys.exit(1)

    for i in range(maxthreads):
        t = Thread(daemon=True, target=tagcopy_thread, args=(i,))
        t.start()

    logger.info('Finding and copying any tags in index {0} to index {1}...'.format(index_from, index_to))
    start = time.time()
    index_copy_tags(es, index_from, index_to)
    elapsed = get_time(time.time() - start)
    logger.info('Finished tagging {0} docs in {1}'.format(totaldocstagged, elapsed))