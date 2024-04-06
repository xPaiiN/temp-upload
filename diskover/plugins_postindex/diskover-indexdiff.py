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


diskover indexdiff plugin

Compare (diff) two indexes for different files and create a csv
with the different files and their pathhash, size, mtime, ctime, atime, and hash.
Supports indices in different Elasticsearch hosts.

'''

import sys
import os
import time
import signal
import logging
import optparse
import confuse
import csv
import hashlib
import warnings
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait

sys.path.insert(1, os.path.join(sys.path[0], '..'))
import diskover_elasticsearch
from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload
from diskover_helpers import escape_chars, get_time
from diskover_lic import License, licfc

plugin_name = 'indexdiff'
version = '2.0.7'
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
    print('Config file {0} not found! Copy from default config.'.format(
        config_filename))
    sys.exit(1)
    
# load diskover default config file
diskover_config_defaults = confuse.Configuration('diskover', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
scriptpath_parent = os.path.abspath(os.path.join(scriptpath, os.pardir))
default_diskover_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover/config.yaml')
diskover_config_defaults.set_file(default_diskover_config_filename)
# load autoclean default config file
config_defaults = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_indexdiff/config.yaml')
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
    es2host = config['es2host'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es2host = config_defaults['es2host'].get()
try:
    es2port = config['es2port'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es2port = config_defaults['es2port'].get()
try:
    es2user = config['es2user'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es2user = config_defaults['es2user'].get()
finally:
    if not es2user: es2user = ""
try:
    es2password = config['es2password'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es2password = config_defaults['es2password'].get()
finally:
    if not es2password: es2password = ""
try:
    es2https = config['es2https'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es2https = config_defaults['es2https'].get()
try:
    hashskipempty = config['hashskipempty'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hashskipempty = config_defaults['hashskipempty'].get()
try:
    hashskipmissing = config['hashskipmissing'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    hashskipmissing = config_defaults['hashskipmissing'].get()
try:
    csvdir = config['csvdir'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    csvdir = config_defaults['csvdir'].get()
    

def log_setup():
    """Setup logging for diskover index diff."""
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


def replace_path(path, frompath, topath):
    return path.replace(frompath, topath)


def get_files_gen(eshost, index, path):
    newpath = escape_chars(path)
    if newpath == '\/':
        newpathwildcard = '\/*'
    else:
        newpathwildcard = newpath + '\/*'
    logger.info('Searching for all file docs in %s for path %s...', index, path)
    eshost.indices.refresh(index)
    if IS_WIN:
        parentpath = os.path.join(path, os.pardir)
    else:
        parentpath = os.path.abspath(os.path.join(path, os.pardir))
    data = {
        '_source': ['parent_path', 'name', 'size', 'mtime', 'atime', 'ctime', 'hash', 'nlink'],
        'query': {
            'query_string': {
                'query': '((parent_path: ' + newpath + ') OR '
                '(parent_path: ' + newpathwildcard + ') OR (name: "'
                + os.path.basename(path) + '" AND parent_path: "'
                + parentpath + '")) AND type:file',
            }
        }
    }
    if options.esquery:
        data['query']['query_string']['query'] += ' AND ' + options.esquery
    res = eshost.search(index=index, scroll='1m', size=es_scrollsize,
                        body=data, request_timeout=es_timeout)

    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            if IS_WIN:
                fullpath = os.path.join(hit['_source']['parent_path'], hit['_source']['name'])
            else:
                fullpath = os.path.abspath(os.path.join(
                    hit['_source']['parent_path'], hit['_source']['name']))
            size = hit['_source']['size']
            nlink = hit['_source']['nlink']
            if options.rootdir2 != options.rootdir:
                fullpath = replace_path(fullpath, options.rootdir2, options.rootdir)
            file_hashed = hashlib.md5(fullpath.encode('utf-8')).hexdigest()
            mtime = time.mktime(datetime.strptime(
                hit['_source']['mtime'], '%Y-%m-%dT%H:%M:%S').timetuple())
            ctime = time.mktime(datetime.strptime(
                hit['_source']['ctime'], '%Y-%m-%dT%H:%M:%S').timetuple())
            atime = time.mktime(datetime.strptime(
                hit['_source']['atime'], '%Y-%m-%dT%H:%M:%S').timetuple())
            try:
                hash = hit['_source']['hash'][hash_mode]
            except KeyError:
                hash = None
            yield fullpath, file_hashed, size, mtime, ctime, atime, hash, nlink

        # use es scroll api
        res = eshost.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                            request_timeout=es_timeout)


def get_files(eshost, index, path):
    newpath = escape_chars(path)
    if newpath == '\/':
        newpathwildcard = '\/*'
    else:
        newpathwildcard = newpath + '\/*'
    logger.info('Searching for all file docs in %s for path %s...', index, path)
    eshost.indices.refresh(index)
    if IS_WIN:
        parentpath = os.path.join(path, os.pardir)
    else:
        parentpath = os.path.abspath(os.path.join(path, os.pardir))
    data = {
        '_source': ['parent_path', 'name', 'size', 'mtime', 'atime', 'ctime', 'hash', 'nlink'],
        'query': {
            'query_string': {
                'query': '((parent_path: ' + newpath + ') OR '
                '(parent_path: ' + newpathwildcard + ') OR (name: "'
                + os.path.basename(path) + '" AND parent_path: "'
                + parentpath + '")) AND type:file',
            }
        }
    }
    if options.esquery:
        data['query']['query_string']['query'] += ' AND ' + options.esquery
    res = eshost.search(index=index, scroll='1m', size=es_scrollsize,
                        body=data, request_timeout=es_timeout)

    filedict = {}
    doccount = 0
    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            if IS_WIN:
                fullpath = os.path.join(hit['_source']['parent_path'], hit['_source']['name'])
            else:
                fullpath = os.path.abspath(os.path.join(
                    hit['_source']['parent_path'], hit['_source']['name']))
            size = hit['_source']['size']
            mtime = time.mktime(datetime.strptime(
                hit['_source']['mtime'], '%Y-%m-%dT%H:%M:%S').timetuple())
            ctime = time.mktime(datetime.strptime(
                hit['_source']['ctime'], '%Y-%m-%dT%H:%M:%S').timetuple())
            atime = time.mktime(datetime.strptime(
                hit['_source']['atime'], '%Y-%m-%dT%H:%M:%S').timetuple())
            nlink = hit['_source']['nlink']
            if options.rootdir2 != options.rootdir:
                fullpath = replace_path(fullpath, options.rootdir2, options.rootdir)
            try:
                hash = hit['_source']['hash'][hash_mode]
            except KeyError:
                hash = None
            filehash = hashlib.md5(fullpath.encode('utf-8')).hexdigest()
            filedict[filehash] = (fullpath, size, mtime, ctime, atime, hash, nlink)
            doccount += 1
        # use es scroll api
        res = eshost.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                            request_timeout=es_timeout)
    logger.info('Found %s file docs in %s' % (str(doccount), index))
    return filedict


def read_csv(csvfile):
    filedict = {}
    logger.info('Reading csv file %s...', csvfile)
    with open(csvfile, mode='r', encoding='utf-8', newline='') as fh:
        fr = csv.reader(fh, delimiter=',', quotechar='"',
                        quoting=csv.QUOTE_MINIMAL)
        n = 1
        for row in fr:
            # skip column title header row
            if n == 1: continue
            filehash = hashlib.md5(row[1].encode('utf-8')).hexdigest()
            filedict[filehash] = (row[1], row[2], row[3], row[4], row[5], row[6], row[7])
            n += 1
    logger.info('Found %s files in csv file %s' % (str(n-1), csvfile))
    return filedict


def write_csv(diff1, diff2):
    # write diffs to csv file
    csvfiletime = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
    csvfile = 'diskover_filediffs_%s_%s_%s.csv' % (options.index, options.index2, csvfiletime)
    csvpath = os.path.join(csvdir, csvfile)
    logger.info('creating csv %s...' % csvpath)
    with open(csvpath, mode='w', encoding='utf-8', newline='') as fh:
        fw = csv.writer(fh, delimiter=',', quotechar='"',
                        quoting=csv.QUOTE_MINIMAL)
        # write headers
        fw.writerow(['diff', 'path', 'size', 'mtime', 'ctime', 'atime', f'hash({hash_mode})', 'nlink'])
        for item in diff1:
            fw.writerow([item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7]])
        for item in diff2:
            fw.writerow([item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7]])
    logger.info('done')


def add_tags(diffs, filedict2):
    # add tags to index
    if not diffs:
        logger.info('no diffs to tag')
        return
    logger.info('addings tags to index %s...' % options.index)
    
    docs = []
    doccount = 0
    
    start = time.time()
    
    logger.info('started searching for %s docs in index...' % len(diffs))
    
    # refresh index
    es.indices.refresh(options.index)
    
    for item in diffs:
        path = item[1]
        filehash = hashlib.md5(path.encode('utf-8')).hexdigest()
        hash2 = filedict2[filehash][5]
        if hash2 is None:
            hash2 = 'null'
        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        
        # get doc id and tags from parent_path in target index
        data = {
            'size': 1,
            '_source': ['tags'],
            "query": {
                "bool": {
                    "must": [
                        { "match": { "parent_path": parent_path } },
                        { "match": { "name": filename } },
                        { "match": { "type": "file" } }
                        ]
                }
            }
        }

        # search index and get results
        res = es.search(index=options.index, body=data, request_timeout=es_timeout)
        
        # continue if there is no matching file in target index
        if not res['hits']['hits']:
            continue
        
        docid = res['hits']['hits'][0]['_id']
        try:
            existing_tags = res['hits']['hits'][0]['_source']['tags']
        except KeyError:
            existing_tags = None
            pass
        
        # set diff tag
        difftag = item[0]
        if difftag == '<':
            difftag = "diff_newfile"
        elif difftag == '<!=hash':
            difftag = "diff_hash_" + hash_mode
        elif difftag == '<!=size':
            difftag = "diff_size"
        elif difftag == '<!=mtime':
            difftag = "diff_mtime"
        elif difftag == '<!=nlink':
            difftag = "diff_nlink"
        difftag += "_" + options.index2 + "_" + hash2
        tags = [difftag]
        
        # combine any existings tags in target index with tags from source index
        if existing_tags is None:
            newtags = tags
        else:
            # check we aren't duplicating tags already in target index
            for tag in existing_tags:
                if tag in tags:
                    tags.remove(tag)
            newtags = existing_tags + tags

        d = {
            '_op_type': 'update',
            '_index': options.index,
            '_id': docid,
            'doc': {'tags': newtags}
        }
        docs.append(d)
        doccount += 1

    searchtime = get_time(time.time() - start)

    logger.info('finished searching index in %s' % searchtime)
            
    start = time.time()
    
    bulk_upload(es, options.index, docs)
    
    tagtime = get_time(time.time() - start)

    logger.info('finished updating tags for %s docs in %s' % (doccount, tagtime))
    logger.info('done')


def diff(filedict1, filedict2):
    # compare and print diffs
    diff1 = []
    for filehash, fileinfo in filedict1.items():
        size = fileinfo[1]
        mtime = datetime.utcfromtimestamp(fileinfo[2]).isoformat()
        ctime = datetime.utcfromtimestamp(fileinfo[3]).isoformat()
        atime = datetime.utcfromtimestamp(fileinfo[4]).isoformat()
        hash = fileinfo[5]
        nlink = fileinfo[6]
        file = fileinfo[0]
        if filehash not in filedict2:
            if not hashskipmissing:
                diff1.append(('<', file, size, mtime, ctime, atime, hash, nlink))
                print("<  %s,%s,%s,%s,%s,%s,%s" % (file, size, mtime, ctime, atime, hash, nlink))
        # compare size or mtime or hash
        elif options.sizediff or options.mtimediff or options.hashdiff or options.linkdiff:
            size2 = filedict2[filehash][1]
            mtime2 = filedict2[filehash][2]
            hash2 = filedict2[filehash][5]
            nlink2 = filedict2[filehash][6]
            if options.sizediff and size != size2:
                diff1.append(('<!=size', file, size, mtime, ctime, atime, hash, nlink))
                print("<!=size  %s,%s,%s,%s,%s,%s,%s" %
                      (file, size, mtime, ctime, atime, hash, nlink))
            if options.mtimediff and fileinfo[2] != mtime2:
                diff1.append(('<!=mtime', file, size, mtime, ctime, atime, hash, nlink))
                print("<!=mtime  %s,%s,%s,%s,%s,%s,%s" %
                      (file, size, mtime, ctime, atime, hash, nlink))
            if options.hashdiff and hash != hash2:
                if hashskipempty and (hash is None or hash2 is None):
                    pass
                else:
                    diff1.append(('<!=hash', file, size, mtime, ctime, atime, hash, nlink))
                    print("<!=hash  %s,%s,%s,%s,%s,%s,%s" %
                        (file, size, mtime, ctime, atime, hash, nlink))
            if options.linkdiff and nlink != nlink2:
                diff1.append(('<!=nlink', file, size, mtime, ctime, atime, hash, nlink))
                print("<!=nlink  %s,%s,%s,%s,%s,%s,%s" %
                      (file, size, mtime, ctime, atime, hash, nlink))
    diff2 = []
    for filehash, fileinfo in filedict2.items():
        size = fileinfo[1]
        mtime = datetime.utcfromtimestamp(fileinfo[2]).isoformat()
        ctime = datetime.utcfromtimestamp(fileinfo[3]).isoformat()
        atime = datetime.utcfromtimestamp(fileinfo[4]).isoformat()
        hash = fileinfo[5]
        nlink = fileinfo[6]
        file = fileinfo[0]
        if filehash not in filedict1:
            if not hashskipmissing:
                diff2.append(('>', file, size, mtime, ctime, atime, hash, nlink))
                print(">  %s,%s,%s,%s,%s,%s,%s" % (file, size, mtime, ctime, atime, hash, nlink))
        # compare size or mtime or hash
        elif options.sizediff or options.mtimediff or options.hashdiff or options.linkdiff:
            size2 = filedict1[filehash][1]
            mtime2 = filedict1[filehash][2]
            hash2 = filedict1[filehash][5]
            nlink2 = filedict1[filehash][6]
            if options.sizediff and size != size2:
                diff2.append(('>!=size', file, size, mtime, ctime, atime, hash, nlink))
                print(">!=size  %s,%s,%s,%s,%s,%s,%s" %
                      (file, size2, mtime, ctime, atime, hash, nlink))
            if options.mtimediff and fileinfo[2] != mtime2:
                diff2.append(('>!=mtime', file, size, mtime, ctime, atime, hash, nlink))
                print(">!=mtime  %s,%s,%s,%s,%s,%s,%s" %
                      (file, size2, mtime, ctime, atime, hash, nlink))
            if options.hashdiff and hash != hash2:
                if hashskipempty and (hash is None or hash2 is None):
                    pass
                else:
                    diff2.append(('>!=hash', file, size, mtime, ctime, atime, hash, nlink))
                    print(">!=hash  %s,%s,%s,%s,%s,%s,%s" %
                        (file, size2, mtime, ctime, atime, hash, nlink))
            if options.linkdiff and nlink != nlink2:
                diff2.append(('>!=nlink', file, size, mtime, ctime, atime, hash, nlink))
                print(">!=nlink  %s,%s,%s,%s,%s,%s,%s" %
                      (file, size2, mtime, ctime, atime, hash, nlink))
    logger.info('done')
    return diff1, diff2


def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-indexdiff.py [-h]

diskover indexdiff v{0}
Find file diffs between two diskover indices.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-d", "--rootdir",
                      help="Directory to start searching from in index")
    parser.add_option("-D", "--rootdir2",
                      help="Set if comparing file lists with different top index paths, example /mnt/stor1 and /mnt/stor2 \
or when using --index2 and it is on different es host, will replace --rootdir2 path with --rootdir path")
    parser.add_option("-i", "--index",
                      help="1st diskover ES index name, don\'t set when using --comparecsvs")
    parser.add_option("-I", "--index2",
                      help="2nd diskover ES index name (for comparison with --index), don\'t set when using \
--filelistonly or --comparecsvs")
    parser.add_option("-s", "--sizediff", action="store_true",
                      help="compare size of files when doing diff as well as file names, default does not compare size")
    parser.add_option("-m", "--mtimediff", action="store_true",
                      help="compare modified time (mtime) of files when doing diff as well as file names, default does not compare mtime")
    parser.add_option("-c", "--hashdiff", metavar="HASHMODE",
                      help="compare checksum/hash of files when doing diff as well as file names, hash modes are xxhash, md5, sha1, sha256, default does not compare hash")
    parser.add_option("-l", "--linkdiff", action="store_true",
                      help="compare number of hardlinks when doing diff as well as file names, default does not compare hardlinks")
    parser.add_option("-q", "--esquery", metavar='ESQUERYSTRING',
                      help="add ES query string to file search")
    parser.add_option("--filelistonly", action="store_true",
                      help="only output file list from --index and don't do comparison (no --index2 required)")
    parser.add_option("--comparecsvs", metavar='FILE', nargs=2,
                      help="compare two csv diff files exported from this script")
    parser.add_option("--tagindex", action="store_true",
                      help="add diff tag to index for any file diffs (index set with --index)")
    parser.add_option("--nocsv", action="store_true",
                      help="do not save csv file of diffs, useful when using --tagindex")
    parser.add_option("--es2", action="store_true",
                      help="use different es host in config (es2host) for index2")
    parser.add_option('--version', action='store_true',
                      help='print diskover-indexdiff version number and exit')
    options, args = parser.parse_args()

    if options.version:
        print('diskover-indexdiff v{}'.format(version))
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
    
    logger.info('Starting diskover indexdiff ...')

    # print config being used
    config_filename = os.path.join(
        config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info(
        'Config env var DISKOVER_INDEXDIFFDIR: {0}'.format(os.getenv('DISKOVER_INDEXDIFFDIR')))

    # check indices exist
    if options.index and not check_index_exists(options.index, es):
        logger.error('{0} no such index!'.format(options.index))
        sys.exit(1)
    if options.index2 and not check_index_exists(options.index2, es):
        logger.error('{0} no such index!'.format(options.index2))
        sys.exit(1)
        
    # check if hashdiff cli option is set
    hash_mode = None
    if options.hashdiff is not None:
        hash_mode = options.hashdiff
        # check hash mode is supported
        if hash_mode not in ('xxhash', 'md5', 'sha1', 'sha256'):
            print('Unsupported hash mode {}, supported types are xxhash, md5, sha1, sha256'.format(hash_mode))
            sys.exit(1)

    # compare csv files
    if options.comparecsvs:
        csvfile1 = options.comparecsvs[0]
        csvfile2 = options.comparecsvs[1]
        logger.info('comparing csv %s with %s...' % (csvfile1, csvfile2))

        # set up threads for reading csv files
        futures = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            future = executor.submit(read_csv, csvfile1)
            futures.append(future)
            future2 = executor.submit(read_csv, csvfile2)
            futures.append(future2)

        # get results from threads
        wait(futures)
        filedict1 = futures[0].result()
        filedict2 = futures[1].result()

        diff1, diff2 = diff(filedict1, filedict2)

        if not options.nocsv:
            write_csv(diff1, diff2)
        if options.tagindex:
            add_tags(diff1, filedict2)
        logger.info('all done')
        sys.exit(0)

    if not options.index or not options.rootdir:
        print('--index and --rootdir cli args required (unless using --comparecsvs), use -h for help')
        sys.exit(1)

    if not options.rootdir2:
        options.rootdir2 = options.rootdir

    # create csv file from files in index
    if options.filelistonly:
        csvfiletime = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
        csvfile = 'diskover_filelist_%s_%s.csv' % (options.index, csvfiletime)
        logger.info('creating csv %s...' % csvfile)
        with open(csvfile, mode='w', encoding='utf-8', newline='') as fh:
            fw = csv.writer(fh, delimiter=',', quotechar='"',
                            quoting=csv.QUOTE_MINIMAL)
            # write headers
            fw.writerow(['path', 'pathhash', 'size', 'mtime', 'ctime', 'atime', 'hash', 'nlink'])
            for file, file_hashed, size, mtime, ctime, atime, hash, nlink in get_files_gen(es, options.index, options.rootdir):
                mtime = datetime.utcfromtimestamp(mtime).isoformat()
                ctime = datetime.utcfromtimestamp(ctime).isoformat()
                atime = datetime.utcfromtimestamp(atime).isoformat()
                fw.writerow([file, file_hashed, size, mtime, ctime, atime, hash, nlink])
        logger.info('done')
        sys.exit(0)

    # compare two indices, print diffs and create csv file
    logger.info('getting files from es...')
    
    # if using es2, set up new connection to es host
    if options.es2:
        logger.info('connecting to es2 host %s:%s...' % (es2host, es2port))
        diskover_elasticsearch.es_https = es2https
        diskover_elasticsearch.es_host = es2host
        diskover_elasticsearch.es_port = es2port
        diskover_elasticsearch.es_user = es2user
        diskover_elasticsearch.es_password = es2password
        es2 = elasticsearch_connection()
    else:
        es2 = es
        
    # set up threads for getting files
    futures = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        future = executor.submit(
            get_files, es, options.index, options.rootdir)
        futures.append(future)
        future2 = executor.submit(
            get_files, es2, options.index2, options.rootdir2)
        futures.append(future2)

    # get results from threads
    wait(futures)
    filedict1 = futures[0].result()
    filedict2 = futures[1].result()

    diff1, diff2 = diff(filedict1, filedict2)

    if not options.nocsv:
        write_csv(diff1, diff2)
    if options.tagindex:
        add_tags(diff1, filedict2)
    logger.info('all done')
    sys.exit(0)