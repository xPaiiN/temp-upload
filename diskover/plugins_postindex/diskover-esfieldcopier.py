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

diskover es field copier plugin

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

plugin_name = 'esfieldcopier'
version = '0.1.4'
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
# load es field copier default config file
config_defaults = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_esfieldcopier/config.yaml')
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
    copyfilefields = config['filefields'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    copyfilefields = config_defaults['filefields'].get()
try:
    copydirectoryfields = config['directoryfields'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    copydirectoryfields = config_defaults['directoryfields'].get()
try:
    fieldstocopy = config['fieldstocopy'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    fieldstocopy = config_defaults['fieldstocopy'].get()
try:
    overwriteexisting = config['overwriteexisting'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    overwriteexisting = config_defaults['overwriteexisting'].get()
    

fieldcopy_queue = Queue()
fieldcopy_lock = Lock()
totaldocsupdated = 0


def log_setup():
    """Setup logging for diskover es field copier."""
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
        

def index_get_fields(es, index_from, index_to):
    """Generator to scroll over files and directories in index and get inode and field values 
    of any docs that have field values to copy."""

    es.indices.refresh(index=index_from)
    es.indices.refresh(index=index_to)
    
    # copy index mappings
    # get mappings from source index and check if any are missing from target index and add them if any missing
    index_src_mappings = es.indices.get_mapping(index=index_from)
    index_dst_mappings = es.indices.get_mapping(index=index_to)
    index_dst_mappings_new = {"properties": {}}
    for key, value in index_src_mappings[index_from]["mappings"]["properties"].items():
        if not key in index_dst_mappings[index_to]["mappings"]["properties"]:
            index_dst_mappings_new["properties"][key] = value
    if index_dst_mappings_new["properties"]:
        es.indices.put_mapping(index=index_to, body=index_dst_mappings_new)

    # create search query
    if copyfilefields and copydirectoryfields:
        doctype = 'type:(file OR directory)'
    elif copyfilefields and not copydirectoryfields:
        doctype = 'type:file'
    elif not copyfilefields and copydirectoryfields:
        doctype = 'type:directory'

    queryfields = ''
    queryfields_len = len(fieldstocopy)
    n = 0
    for field in fieldstocopy:
        queryfields += field + ":*"
        if n < queryfields_len - 1:
            queryfields += ' OR '
        n += 1
        
    query = '({0}) AND {1}'.format(queryfields, doctype)

    source = ['ino']
    for field in fieldstocopy:
        source.append(field)

    data = {
        'size': 0,
        '_source': source,
        'query': {
            'query_string': {
                'query': query,
                'analyze_wildcard': 'true'
            }
        }
    }
    
    if options.verbose:
        logger.info('searching for {0} in source index...'.format(query))
        
    res = es.search(index=index_from, scroll='1m', size=es_scrollsize,
                    body=data, request_timeout=es_timeout)

    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            fields = {'ino': hit['_source']['ino']}
            for field in fieldstocopy:
                try:
                    fields[field] = hit['_source'][field]
                except KeyError:
                    pass
            yield fields

        res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                        request_timeout=es_timeout)


def fieldcopy_thread(i):
    global fieldcopy_queue
    global totaldocsupdated

    while True:
        results = fieldcopy_queue.get()
        doccount = 0
        docs = []
        
        start = time.time()
        
        if options.verbose:
            logger.info('thread {0} started searching for {1} docs in destination index...'.format(i, len(results)))
        
        for source_field_values in results:
            ino = source_field_values['ino']
            del source_field_values['ino']

            # get doc id from inode in target index
            source = ['ino']
            for field in fieldstocopy:
                source.append(field)
    
            data = {
                'size': 1,
                '_source': source,
                'query': {
                    'match': {
                        'ino': ino
                    }
                }
            }

            res = es.search(index=index_to, body=data, request_timeout=es_timeout)
            
            # continue if there is no matching inode in target index
            if not res['hits']['hits']:
                continue
            
            docid = res['hits']['hits'][0]['_id']
            
            # copy fields values from source doc into destination doc
            docfields = {}
            
            for key, value in source_field_values.items():
                try:
                    dest_field_value = res['hits']['hits'][0]['_source'][key]
                    if overwriteexisting:
                        docfields[key] = value
                    elif not overwriteexisting and not dest_field_value:
                        docfields[key] = value
                except KeyError:
                    docfields[key] = value
                    pass

            d = {
                '_op_type': 'update',
                '_index': index_to,
                '_id': docid,
                'doc': docfields
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

        copyfieldtime = get_time(time.time() - start)
            
        if options.verbose:
            logger.info('thread {0} finished copying fields for {1} docs in {2}'.format(i, doccount, copyfieldtime))
        
        with fieldcopy_lock:
            totaldocsupdated += doccount

        del docs[:]
        fieldcopy_queue.task_done()


def index_copy_fields(es, index_from, index_to):
    # Get all files and directories with es fields from diskover index and enqueue to fieldcopy queue
    results = []
    start = time.time()
    docs = 0
    for res in index_get_fields(es, index_from, index_to):
        results.append(res)
        docs += 1
        if len(results) >= 500:
            fieldcopy_queue.put(results[:])
            del results[:]
    fieldcopy_queue.put(results)
    
    queuetime = get_time(time.time() - start)
    
    if options.verbose:
        logger.info('Finished searching source index and enqueueing {0} docs in {1}'.format(docs, queuetime))
        logger.info('Waiting for field copy threads to finish...')
        
    # Wait for threads to finish
    fieldcopy_queue.join()


def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-esfieldcopier.py [-h] [index_from] [index_to]

diskover es field copier v{0}
Copies ES index doc fields from a diskover Elasticsearch index to another.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-a', '--autoindexfrom', action='store_true', 
                        help='find index_from (previous index) based on index_to\'s top paths')
    parser.add_option('-f', '--field', action="append", dest="fields", metavar="FIELDNAME", 
                        help='index doc field to copy, can use multiple --field, overrides config')
    parser.add_option('-v', '--verbose', action='store_true', 
                        help='verbose logging')
    parser.add_option('--version', action='store_true',
                        help='print diskover-esfieldcopier version number and exit')
    options, args = parser.parse_args()

    if options.version:
        print('diskover-esfieldcopier v{}'.format(version))
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
    
    logger.info('Starting diskover es field copier ...')

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_ESFIELDCOPIERDIR: {0}'.format(os.getenv('DISKOVER_ESFIELDCOPIERDIR')))

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

    if options.fields is not None:
        fieldstocopy = options.fields

    for i in range(maxthreads):
        t = Thread(daemon=True, target=fieldcopy_thread, args=(i,))
        t.start()

    logger.info('Finding and copying es fields {0} in index {1} to index {2}...'.format(fieldstocopy, index_from, index_to))
    start = time.time()
    index_copy_fields(es, index_from, index_to)
    elapsed = get_time(time.time() - start)
    logger.info('Finished updating {0} docs in {1}'.format(totaldocsupdated, elapsed))