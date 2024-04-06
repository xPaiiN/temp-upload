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


diskover autotag plugin

'''

import sys
import os
import time
import signal
import optparse
import confuse
import logging
import warnings
from threading import Thread
from queue import Queue
from datetime import datetime

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload
from diskover_lic import License, licfc

plugin_name = 'autotag'
version = '2.0.3'
__version__ = version

# Python 3 check
IS_PY3 = sys.version_info >= (3, 5)
if not IS_PY3:
    print('Python 3.5 or higher required.')
    sys.exit(1)

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
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_autotag/config.yaml')
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
    autotag_dirs = config['dirs'].get()
except confuse.NotFoundError as e:
    config_warn(e)  
    autotag_dirs = config_defaults['dirs'].get()
try:
    autotag_files = config['files'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    autotag_files = config_defaults['files'].get()


autotag_queue = Queue()


def log_setup():
    """Setup logging for diskover autotag."""
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


def index_get_files(es, indexname):
    """Generator to scroll over files in index and get doc id."""

    #es.indices.refresh(index=indexname)

    for doc_type in ('directory', 'file'):
        if doc_type == 'directory':
            autotag_list = autotag_dirs
        else:
            autotag_list = autotag_files
        for t in autotag_list:
            query = '{0} AND type:{1}'.format(t['query'], doc_type)
            
            if options.vverbose:
                logger.info('es query: {0}'.format(query))

            data = {
                'size': 0,
                '_source': ['tags'],
                'query': {
                    'query_string': {
                        'query': query,
                        'analyze_wildcard': 'true'
                    }
                }
            }
            
            es.indices.refresh(index=indexname)

            res = es.search(index=indexname, scroll='1m', size=es_scrollsize,
                            body=data, request_timeout=es_timeout)
            
            totaldocs = res['hits']['total']['value']
            
            if options.vverbose:
                logger.info('found {0} matching docs'.format(totaldocs))

            while res['hits']['hits'] and len(res['hits']['hits']) > 0:
                for hit in res['hits']['hits']:
                    docid = hit['_id']
                    # add on any new tags to existing tags, skipping tags with same name
                    if options.addtags:
                        tags = hit['_source']['tags']
                        if tags is None:
                            tags = t['tags']
                        else:
                            for tag in t['tags']:
                                if tag not in tags:
                                    tags.append(tag)
                    # replace any existing tags with new tags
                    else:
                        tags = t['tags']
                    yield (docid, tags)

                res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                                request_timeout=es_timeout)


def autotag_thread(i):
    global autotag_queue

    while True:
        results = autotag_queue.get()
        doccount = 0
        docs = []
        docids = {}
        for res in results:
            docid, tags = res
            if docid in docids:
                for tag in tags:
                    if tag not in docs[docids[docid]]['doc']['tags']:
                        docs[docids[docid]]['doc']['tags'].append(tag)
            else:
                docids[docid] = doccount
            d = {
                '_op_type': 'update',
                '_index': index,
                '_id': docid,
                'doc': {'tags': tags}
            }
            docs.append(d.copy())
            doccount += 1

        if options.verbose or options.vverbose:
            logger.info('thread {0} started tagging {1} docs'.format(i, doccount))

        start = time.time()
            
        bulk_upload(es, index, docs)

        end = time.time()
        tagtime = round(end - start, 6)
            
        if options.verbose or options.vverbose:
            logger.info('thread {0} finished tagging {1} docs in {2}s'.format(i, doccount, tagtime))

        del docs[:]
        docids.clear()
        autotag_queue.task_done()


def index_update_tags(es, indexname):
    # Get all files from diskover index and enqueue to autotag queue
    results = []
    for res in index_get_files(es, indexname):
        results.append(res)
        if len(results) >= es_chunksize:
            autotag_queue.put(results[:])
            del results[:]
    autotag_queue.put(results)

    # Wait for hash threads to finish
    autotag_queue.join()


def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-autotag.py [-h] [index]

diskover autotag v{0}
Autotags docs in a diskover Elasticsearch index.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-a', '--addtags', action='store_true', 
                        help='add new tags to any existing tags, default is to replace')
    parser.add_option('-v', '--verbose', action='store_true', 
                        help='verbose logging')
    parser.add_option('-V', '--vverbose', action='store_true', 
                        help='more verbose logging')
    parser.add_option('--version', action='store_true',
                        help='print diskover-autotag version number and exit')
    options, args = parser.parse_args()
    
    if options.version:
        print('diskover-autotag v{}'.format(version))
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
    
    logger.info('Starting diskover auto-tag ...')

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_AUTOTAGDIR: {0}'.format(os.getenv('DISKOVER_AUTOTAGDIR')))

    if not args:
        logger.error('no index in args!')
        sys.exit(1)
    else:
        index = args[0]
        if not check_index_exists(index, es):
            logger.error('{0} no such index!'.format(index))
            sys.exit(1)

    for i in range(maxthreads):
        t = Thread(daemon=True, target=autotag_thread, args=(i,))
        t.start()

    logger.info('Finding and updating tags in index {0}...'.format(index))
    index_update_tags(es, index)