#!/usr/bin/env python
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


diskover s3 checksums post index plugin

'''

import sys
import os
import time
import json
import random
import optparse
import logging
import asyncio
import hashlib
from signal import *
from timeit import default_timer as timer
from datetime import datetime, timedelta
from functools import partial
import concurrent.futures

import boto3
import botocore
import requests
from requests_auth_aws_sigv4 import AWSSigV4
import elasticsearch

from config import Config
from cache import Cache


sys.path.insert(1, os.path.join(sys.path[0], '../..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists, bulk_upload
from diskover_helpers import get_mem_usage, convert_size, speed
from diskover_lic import License, licfc


plugin_name = 's3_checksums'
version = '0.0.4'
__version__ = version


DISKOVER_INSTALL_DIR = '/opt/diskover'
FILECOUNT = 0
FILEHASHCOUNT = 0


class NoMoreItems(Exception): pass
class ConfigError(Exception): pass


class DiskoverConfig(Config):
    def __init__(self, install_path):
        self.field_map = {
            None: ['logToFile', 'logDirectory'],
            'databases': {
                'elasticsearch': ['scrollsize', 'timeout']
            }
        }
        Config.__init__(self, 'diskover', install_path)


class ChecksumsConfig(Config):
    def __init__(self, name, install_path, hash_mode=None):
        self.field_map = {
            None: [
                'workers',
                'fixity_api_endpoint',
                'check_interval',
                'hash_mode',
                'cache_dir',
                'logLevel',
                'logToFile',
                'logDirectory',
                'cache_expiretime'

            ]
        }
        Config.__init__(self, name, install_path)
        if hash_mode is not None:
            self.hash_mode = hash_mode
        self._verify_fields()

    def _verify_fields(self):
        valid_hash_modes = ('md5', 'sha1')
        if self.hash_mode not in valid_hash_modes:
            raise ConfigError(f"Invalid config value for hash_mode: {repr(self.hash_mode)}. "
                              f"Expecting one of {valid_hash_modes}")
        try:
            self.check_interval = int(self.check_interval)
            if self.check_interval < 1:
                raise ValueError()
        except ValueError:
            raise ConfigError(f'Invalid config value for check_interval {repr(self.check_interval)}'
                              f'It should be a positive integer')

        try:
            self.workers = int(self.workers)
            if self.workers < 1:
                raise ValueError()
        except ValueError:
            raise ConfigError(f"Invalid config value for workers: {repr(self.workers)} not valid. "
                              f"It should be a positive integer")

        if self.fixity_api_endpoint is None:
            raise ConfigError("Missing config value for fixity_api_endpoint.")

def log_setup(config, options):
    logger = logging.getLogger('diskover-{0}'.format(plugin_name))
    eslogger = logging.getLogger('elasticsearch')
    loglevel = config.logLevel
    if loglevel == 'DEBUG' or options.verbose is True:
        loglevel = logging.DEBUG
    elif loglevel == 'INFO':
        loglevel = logging.INFO
    else:
        loglevel = logging.WARN
    logformat = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if config.logToFile:
        logfiletime = datetime.now().strftime('%Y_%m_%d_%H_%M_%S')
        logname = 'diskover-{0}_{1}.log'.format(plugin_name, logfiletime)
        logfile = os.path.join(config.logDirectory, logname)
        logging.basicConfig(format=logformat, level=loglevel,
                            handlers=[logging.FileHandler(logfile, encoding='utf-8'), logging.StreamHandler()])
    else:
        logging.basicConfig(format=logformat, level=loglevel)
    eslogger.setLevel(level=logging.WARN)
    return logger


def update_mappings(es, index):
    try:
        index_mappings = {'properties': {
            'hash': {
                'type': 'object',
                'properties': {
                    'md5': {
                        'type': 'keyword'
                    },
                    'sha1': {
                        'type': 'keyword'
                    }
                }
            }
        }}
        es.indices.put_mapping(index=index, body=index_mappings)
    except Exception as e:
        logger.error("Error updating index mappings {0}".format(e))
        sys.exit(1)


def index_get_files(es, indexname, diskover_config):
    """Generator to scroll over files in index and yield inodes and doc id."""
    data = {
        'size': 0,
        '_source': ['name', 'parent_path', 'size', 'mtime', 'ino'],
        'query': {
            'query_string': {
                'query': 'type:file AND size:>=0'
            }
        }
    }
    es.indices.refresh(index=indexname)

    res = es.search(index=indexname, scroll='10m', size=diskover_config.scrollsize,
                    body=data, request_timeout=diskover_config.timeout)
    count = 0
    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            filepath = os.path.join(hit['_source']['parent_path'], hit['_source']['name'])
            ino = hit['_source']['ino']
            size = hit['_source']['size']
            mtime = hit['_source']['mtime']
            doc_id = hit['_id']
            count += 1
            yield (filepath, ino, size, mtime, doc_id)

        try:
            res = es.scroll(scroll_id=res['_scroll_id'], scroll='10m', request_timeout=diskover_config.timeout)
        except elasticsearch.exceptions.NotFoundError:
            logger.warning(f'Could not check for new docs since initial start.  Scroll timeout exceeded: 10m')
    raise NoMoreItems()

async def log_stats_thread(work_queue):
    global FILEHASHCOUNT
    start = time.time()
    hashedpercent = 0.0
    while True:
        try:
            await asyncio.sleep(3)
            timenow = time.time()
            elapsed = str(timedelta(seconds=timenow - start))
            filesps = FILEHASHCOUNT / (timenow - start)
            try:
                hashedpercent = FILEHASHCOUNT / FILECOUNT * 100
            except ZeroDivisionError:
                pass
            logger.info(
                'STATS (files hashed {0} ({1:.1f}%), files in queue {2}, elapsed {3}, perf {4:.3f} files/s, memory usage {5})'.format(
                    FILEHASHCOUNT, hashedpercent, work_queue.qsize(), elapsed, filesps, get_mem_usage()))
        except asyncio.exceptions.CancelledError:
            break
        except Exception as e:
            logger.exception(e)
            await shutdown(asyncio.get_event_loop())


class HashTask:
    def __init__(self, index, path, inode, size, mtime, docid, plugin_config, cache, aws_auth, session):
        self.index = index
        self.path = path
        self.inode = inode
        self.size = size
        self.mtime = mtime
        self.docid = docid
        self.cache = cache
        self.aws_auth = aws_auth
        self.session = session

        self.config = plugin_config
        self.hash_mode = plugin_config.hash_mode
        self.fixity_api_endpoint = plugin_config.fixity_api_endpoint

        path_parts = path.split(os.sep)[1:]
        self.bucket = path_parts[0]
        self.key = os.sep.join(path_parts[1:])

        self.execution_arn = None
        self.hash = None

    def start(self):
        r = self.session.post(self.fixity_api_endpoint,
                              json={'Bucket': self.bucket, 'Key': self.key, "Algorithm": self.hash_mode},
                              auth=self.aws_auth)

        self.execution_arn = r.json().get('executionArn')
        if self.execution_arn is None:
            raise RuntimeError(f'Error starting hash task: {r.json()}')
        return self.execution_arn

    def get_update_doc(self):
        if self.hash is None:
            raise AttributeError('"hash" attribute is not set')
        return {
            '_op_type': 'update',
            '_index': self.index,
            '_id': self.docid,
            'doc': {'hash': {self.hash_mode: self.hash}}
        }


async def upload_to_es(es, index, upload_queue, config):
    loop = asyncio.get_running_loop()

    tasks = list()
    while True:
        try:
            task = await upload_queue.get()
            if task is None:
                break
            tasks.append(task)
            if len(tasks) >= int(config.workers):
                logger.debug(f'Uploading {len(tasks)} docs to elasticsearch')
                await loop.run_in_executor(None, bulk_upload, es, index, [t.get_update_doc() for t in tasks])
                tasks = list()
        except asyncio.exceptions.CancelledError:
            break
        except Exception as e:
            logger.exception(e)
            await shutdown(asyncio.get_event_loop())
        finally:
            upload_queue.task_done()

    if len(tasks):
        logger.debug(f'uploading {len(tasks)} docs to elasticsearch')
        bulk_upload(es, index, [t.get_update_doc() for t in tasks])


async def process_task(client, task, upload_queue, options, config):
    global FILEHASHCOUNT
    
    # first check if its cached and just return that value if it is
    if options.usecache:
        pathhash = hashlib.md5(task.path.encode('utf-8')).hexdigest()
        cache_res = task.cache.get(pathhash)
        if cache_res:
            if task.hash_mode in cache_res and task.mtime == cache_res['mtime']:
                logger.debug('CACHE HIT {0}'.format(task.path))
                task.hash = cache_res[task.hash_mode]
                return task

    loop = asyncio.get_running_loop()
    execution_arn = await loop.run_in_executor(None, task.start)

    while True:
        response = await loop.run_in_executor(None, partial(client.describe_execution, executionArn=execution_arn))

        if response['status'] == 'RUNNING':
            await asyncio.sleep(config.check_interval)
            continue
        elif response['status'] == 'SUCCEEDED':
            hash = json.loads(response['output'])['Computed']
            task.hash = hash
            asyncio.create_task(upload_queue.put(task))
        else:
            logger.exception(json.dumps(response, indent=2, default=str))
            raise OSError('Execution failed')
        break

    #update the cache with the hash value we got
    if options.usecache:
        if cache_res:
            cache_data = cache_res.copy()
        else:
            cache_data = dict()
        cache_data['mtime'] = task.mtime
        cache_data[task.hash_mode] = hash
        task.cache.set(pathhash, cache_data)

    FILEHASHCOUNT += 1
    return task


async def produce(work_queue, es, index, diskover_config, plugin_config, cache, options, client, aws_auth, session):
    global FILECOUNT
    loop = asyncio.get_running_loop()
    gen = index_get_files(es, index, diskover_config)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)
    while 1:
        try:
            res = await loop.run_in_executor(executor, next, gen)
            FILECOUNT += 1
            filepath, ino, size, mtime, docid = res
            task = HashTask(index, filepath, ino, size, mtime, docid, plugin_config, cache, aws_auth, session)
            asyncio.create_task(work_queue.put((client, task, options, plugin_config)))
        except NoMoreItems:
            break
        except asyncio.exceptions.CancelledError:
            break
        except Exception as e:
            logger.exception(e)
            await shutdown(loop)

    logger.info(f'Found {FILECOUNT} total files to index')


async def worker(worker_id, work_queue, upload_queue):
    while True:
        try:
            client, task, options, config = await work_queue.get()
            await asyncio.sleep(random.randrange(0, 10)*.1)
            logger.debug(f'Worker {worker_id}: Processing {task.path}')
            await process_task(client, task, upload_queue, options, config)
            logger.debug(f'Worker {worker_id}: Completed {task.path}')
        except asyncio.exceptions.CancelledError:
            break
        except Exception as e:
            logger.exception(e)
            await shutdown(asyncio.get_event_loop())
        finally:
            work_queue.task_done()


async def shutdown(sig):
    logger.warning(f'Received signal {sig}. Shutting down.')
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    [task.cancel() for task in tasks]
    logger.warning(f"Cancelling {len(tasks)} outstanding tasks")
    await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.get_running_loop().stop()


def add_signal_handlers():
    loop = asyncio.get_event_loop()
    for sig in [SIGINT, SIGTERM]:
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(sig)))


async def main(options, args, diskover_config, plugin_config):
    #loop = asyncio.get_running_loop()
    #loop.set_debug(enabled=True)

    add_signal_handlers()

    es = elasticsearch_connection()

    client_config = botocore.config.Config(
            max_pool_connections=1000,
            retries={
                'max_attempts': 20,
                'mode': 'standard'
            }
    )
    client = boto3.client('stepfunctions', config=client_config)
    aws_auth = AWSSigV4('execute-api')
    session = requests.session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=1000)
    session.mount('https://', adapter)

    index = args[0]

    cache = None
    if options.usecache:
        cache = Cache(plugin_config.cache_dir, plugin_config.cache_expiretime)

    if check_index_exists(index, es) is False:
        logger.error(f'{repr(index)} no such index!')
        sys.exit(1)

    update_mappings(es, index)

    work_queue = asyncio.Queue()
    upload_queue = asyncio.Queue()

    workers = []
    for i in range(int(plugin_config.workers)):
        aworker = asyncio.create_task(worker(i, work_queue, upload_queue))
        workers.append(aworker)

    stats_thread = asyncio.create_task(log_stats_thread(work_queue))

    uploader = asyncio.create_task(upload_to_es(es, index, upload_queue, plugin_config))
    producer = produce(work_queue, es, index, diskover_config, plugin_config, cache, options, client, aws_auth, session)

    await asyncio.gather(producer)

    await work_queue.join()

    # sentinel to stop consuming from upload queue
    asyncio.create_task(upload_queue.put(None))

    await upload_queue.join()

    for aworker in workers:
        aworker.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    uploader.cancel()
    await uploader

    stats_thread.cancel()
    await stats_thread


if __name__ == "__main__":
    usage = """Usage: diskover-s3-checksums.py [-h] [index] [index]...

    diskover s3 checksums v{0}
    Checksum files in a diskover Elasticsearch index.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-u', '--usecache', action='store_true',
                      help='store and use hash cache db')
    parser.add_option('-m', '--hashmode', metavar='HASHMODE',
                      help='which hash/checksum type to use, can be md5 or sha1, overrides mode config setting')
    parser.add_option('-v', '--verbose', action='store_true',
                      help='verbose logging')
    parser.add_option('--version', action='store_true',
                      help='print diskover-checksums version number and exit')
    options, args = parser.parse_args()

    if len(args) == 0:
        print('ERROR: You must provide an index as the final argument. Exiting')
        sys.exit(1)
    elif len(args) > 1:
        print(f'ERROR: Extra arguments {args[1:]}. This plugin is only configured to handle one index at a time')
        sys.exit()

    if options.version:
        print('diskover-s3-checksums v{}'.format(version))
        sys.exit(0)

    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'PRO', __name__)

    diskover_config = DiskoverConfig(DISKOVER_INSTALL_DIR)
    plugin_config = ChecksumsConfig(f'diskover_{plugin_name}', DISKOVER_INSTALL_DIR, hash_mode=options.hashmode)

    logger = log_setup(plugin_config, options)

    logger.info('Starting diskover s3 checksums ...')
    logger.info(f'Config file: {plugin_config.filename}')
    logger.info(f'Hashing S3 bucket with {plugin_config.workers} workers')

    start_time = timer()

    try:
        asyncio.run(main(options, args, diskover_config, plugin_config))
    except asyncio.exceptions.CancelledError:
        logger.warning('exiting with error')
        exit(1)

    end_time = timer()
    elapsed = timedelta(seconds=end_time - start_time)
    logger.info('*** Elapsed time {0} ***'.format(elapsed))
    logger.info('*** Total files: {0} ***'.format(FILECOUNT))
    logger.info('*** Files hashed: {0} ({1:.1f}% reduction of total files) ***'.format(FILEHASHCOUNT, (
            FILECOUNT - FILEHASHCOUNT) / FILECOUNT * 100))
