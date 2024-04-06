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

"""

import os
import sys
import confuse
import requests
import logging
import elasticsearch
import warnings
from elasticsearch import helpers


from diskover_helpers import load_plugins


logger = logging.getLogger(__name__)

"""Load yaml config file."""
config = confuse.Configuration('diskover', __name__)
config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
if not os.path.exists(config_filename):
    print('Config file {0} not found! Copy from default config.'.format(config_filename))
    sys.exit(1)

# load default config file
config_defaults = confuse.Configuration('diskover', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
defaultconfig_filename = os.path.join(scriptpath, 'configs_sample/diskover/config.yaml')
config_defaults.set_file(defaultconfig_filename)

def config_warn(e):
    warnings.warn('Config setting {}. Using default.'.format(e))

# laod config values
try:
    # check for any env vars to override config
    es_host = os.getenv('ES_HOST', config['databases']['elasticsearch']['host'].get())
except confuse.NotFoundError as e:
    config_warn(e)
    es_host = config_defaults['databases']['elasticsearch']['host'].get()
try:
    es_port = os.getenv('ES_PORT', config['databases']['elasticsearch']['port'].get())
except confuse.NotFoundError as e:
    config_warn(e)
    es_port = config_defaults['databases']['elasticsearch']['port'].get()
try:
    es_user = os.getenv('ES_USER', config['databases']['elasticsearch']['user'].get())
except confuse.NotFoundError as e:
    config_warn(e)
    es_user = config_defaults['databases']['elasticsearch']['user'].get()
finally:
    if not es_user:
        es_user = ""
try:
    es_password = os.getenv('ES_PASS', config['databases']['elasticsearch']['password'].get())
except confuse.NotFoundError as e:
    config_warn(e)
    es_password = config_defaults['databases']['elasticsearch']['password'].get()
finally:
    if not es_password:
        es_password = ""
try:
    es_https_env = os.getenv('ES_HTTPS')
    if es_https_env is not None:
        if es_https_env.lower() == "true":
            es_https = True
        elif es_https_env.lower() == "false":
            es_https = False
    else:
        es_https = config['databases']['elasticsearch']['https'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_https = config_defaults['databases']['elasticsearch']['https'].get()
try:
    es_sslverify_env = os.getenv('ES_SSLVERIFICATION')
    if es_sslverify_env is not None:
        if es_sslverify_env.lower() == "true":
            es_sslverify = True
        elif es_sslverify_env.lower() == "false":
            es_sslverify = False
    else:
        es_sslverify = config['databases']['elasticsearch']['sslverification'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_sslverify = config_defaults['databases']['elasticsearch']['sslverification'].get()
try:
    es_httpcompress = config['databases']['elasticsearch']['httpcompress'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_httpcompress = config_defaults['databases']['elasticsearch']['httpcompress'].get()
try:
    es_timeout = config['databases']['elasticsearch']['timeout'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_timeout = config_defaults['databases']['elasticsearch']['timeout'].get()
try:
    es_maxsize = config['databases']['elasticsearch']['maxsize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_maxsize = config_defaults['databases']['elasticsearch']['maxsize'].get()
try:
    es_max_retries = config['databases']['elasticsearch']['maxretries'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_max_retries = config_defaults['databases']['elasticsearch']['maxretries'].get()
try:
    es_scrollsize = config['databases']['elasticsearch']['scrollsize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_scrollsize = config_defaults['databases']['elasticsearch']['scrollsize'].get()
try:
    es_wait_status_yellow = config['databases']['elasticsearch']['wait'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_wait_status_yellow = config_defaults['databases']['elasticsearch']['wait'].get()
try:
    es_chunksize = config['databases']['elasticsearch']['chunksize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_chunksize = config_defaults['databases']['elasticsearch']['chunksize'].get()
try:
    es_disablereplicas = config['databases']['elasticsearch']['disablereplicas'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_disablereplicas = config_defaults['databases']['elasticsearch']['disablereplicas'].get()
try:
    es_translogsize = config['databases']['elasticsearch']['translogsize'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_translogsize = config_defaults['databases']['elasticsearch']['translogsize'].get()
try:
    es_translogsyncint = config['databases']['elasticsearch']['translogsyncint'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_translogsyncint = config_defaults['databases']['elasticsearch']['translogsyncint'].get()
try:
    es_indexrefresh = config['databases']['elasticsearch']['indexrefresh'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_indexrefresh = config_defaults['databases']['elasticsearch']['indexrefresh'].get()
try:
    es_shards = config['databases']['elasticsearch']['shards'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_shards = config_defaults['databases']['elasticsearch']['shards'].get()
try:
    es_replicas = config['databases']['elasticsearch']['replicas'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_replicas = config_defaults['databases']['elasticsearch']['replicas'].get()
try:
    es_compression = config['databases']['elasticsearch']['compression'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    es_compression = config_defaults['databases']['elasticsearch']['compression'].get()


# load any available plugins
plugins = load_plugins()


def user_prompt(question):
    """Prompt the yes/no-*question* to the user."""
    from distutils.util import strtobool

    while True:
        try:
            user_input = input(question + " [y/n]: ").lower()
            result = strtobool(user_input)
            return result
        except ValueError:
            print("Please use y/n or yes/no.\n")
        except KeyboardInterrupt:
            print("Ctrl-c keyboard interrupt, exiting...")
            sys.exit(0)


def elasticsearch_connection():
    """Connect to Elasticsearch."""
    # Check if Elasticsearch is alive
    if isinstance(es_host, list):
        host = es_host[0]
    else:
        host = es_host
    if es_https:
        scheme = 'https'
    # Local connection to es
    else:
        scheme = 'http'
    url = scheme + '://' + host + ':' + str(es_port)
    try:
        if (es_sslverify):
            r = requests.get(url, auth=(es_user, es_password))
        else:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = requests.get(url, auth=(es_user, es_password), verify=False)
    except Exception as e:
        print('Error connecting to Elasticsearch node {0}, check config and Elasticsearch is running.\n\nError: {1}'.format(host, e))
        sys.exit(1)

    # Check if we are using HTTP TLS/SSL
    if es_https:
        if (es_sslverify):
            verifycerts = True
        else:
            verifycerts = False
        es = elasticsearch.Elasticsearch(
            hosts=es_host,
            port=es_port,
            http_auth=(es_user, es_password),
            scheme="https", use_ssl=True, verify_certs=verifycerts,
            connection_class=elasticsearch.RequestsHttpConnection,
            timeout=es_timeout, maxsize=es_maxsize,
            max_retries=es_max_retries, retry_on_timeout=True, http_compress=es_httpcompress)
    # Local connection to es
    else:
        es = elasticsearch.Elasticsearch(
            hosts=es_host,
            port=es_port,
            http_auth=(es_user, es_password),
            connection_class=elasticsearch.Urllib3HttpConnection,
            timeout=es_timeout, maxsize=es_maxsize,
            max_retries=es_max_retries, retry_on_timeout=True, http_compress=es_httpcompress)

    return es


def get_es_cluster_health(es):
    """Get ES cluster health info."""
    return es.cluster.health()


def get_es_cluster_stats(es):
    """Get ES cluster stats info."""
    return es.cluster.stats()


def check_index_exists(indexname, es):
    """Check if index in Elasticsearch."""
    if es.indices.exists(index=indexname):
        return True
    return False


def create_index(indexname, es):
    """Create index in Elasticsearch."""

    # check for existing es index
    indexexists = check_index_exists(indexname, es)
    if indexexists:
        # delete existing index
        logger.info('ES index {0} already exists, deleting'.format(indexname))
        es.indices.delete(index=indexname, ignore=[400, 404])

    mappings = {
        'settings': {
            'index': {
                'number_of_shards': es_shards,
                'number_of_replicas': es_replicas,
                'codec': es_compression
            },
            'analysis': {
                'tokenizer': {
                    'filename_tokenizer': {
                        'type': 'char_group',
                        'tokenize_on_chars': [
                            'whitespace',
                            'punctuation',
                            '-',
                            '_'
                        ]
                    },
                    'path_tokenizer': {
                        'type': 'char_group',
                        'tokenize_on_chars': [
                            'whitespace',
                            'punctuation',
                            '/',
                            '-',
                            '_'
                        ]
                    }
                },
                'analyzer': {
                    'filename_analyzer': {
                        'tokenizer': 'filename_tokenizer',
                        'filter': [
                            'word_filter',
                            'lowercase'
                        ]
                    },
                    'path_analyzer': {
                        'tokenizer': 'path_tokenizer',
                        'filter': [
                            'word_filter',
                            'lowercase'
                        ]
                    }
                },
                'filter': {
                    'word_filter': {
                        'type': 'word_delimiter_graph',
                        'generate_number_parts': 'false',
                        'stem_english_possessive': 'false',
                        'split_on_numerics': 'false',
                        'catenate_all': 'true',
                        'preserve_original': 'true'
                    }
                }
            }
        },
        'mappings': {
            'properties': {
                'name': {
                    'type': 'keyword',
                            'fields': {
                                'text': {
                                    'type': 'text',
                                    'analyzer': 'filename_analyzer'
                                }
                            }
                },
                'parent_path': {
                    'type': 'keyword',
                            'fields': {
                                'text': {
                                    'type': 'text',
                                    'analyzer': 'path_analyzer'
                                }
                            }
                },
                'size': {
                    'type': 'long'
                },
                'size_norecurs': {
                    'type': 'long'
                },
                'size_du': {
                    'type': 'long'
                },
                'size_du_norecurs': {
                    'type': 'long'
                },
                'file_count': {
                    'type': 'long'
                },
                'file_count_norecurs': {
                    'type': 'long'
                },
                'dir_count': {
                    'type': 'long'
                },
                'dir_count_norecurs': {
                    'type': 'long'
                },
                'dir_depth': {
                    'type': 'integer'
                },
                'owner': {
                    'type': 'keyword'
                },
                'group': {
                    'type': 'keyword'
                },
                'mtime': {
                    'type': 'date'
                },
                'atime': {
                    'type': 'date'
                },
                'ctime': {
                    'type': 'date'
                },
                'nlink': {
                    'type': 'integer'
                },
                'ino': {
                    'type': 'keyword'
                },
                'tags': {
                    'type': 'keyword'
                },
                'costpergb': {
                    'type': 'scaled_float',
                            'scaling_factor': 100
                },
                'extension': {
                    'type': 'keyword'
                },
                'path': {
                    'type': 'keyword'
                },
                'total': {
                    'type': 'long'
                },
                'used': {
                    'type': 'long'
                },
                'free': {
                    'type': 'long'
                },
                'free_percent': {
                    'type': 'float'
                },
                'available': {
                    'type': 'long'
                },
                'available_percent': {
                    'type': 'float'
                },
                'file_size': {
                    'type': 'long'
                },
                'file_size_du': {
                    'type': 'long'
                },
                'file_count': {
                    'type': 'long'
                },
                'dir_count': {
                    'type': 'long'
                },
                'start_at': {
                    'type': 'date'
                },
                'end_at': {
                    'type': 'date'
                },
                'crawl_time': {
                    'type': 'float'
                },
                'diskover_ver': {
                    'type': 'keyword'
                },
                'hostname': {
                    'type': 'keyword'
                },
                'fileages': {
                    'type': 'object'
                },
                'timerollup': {
                    'type': 'object'
                },
                'type': {
                    'type': 'keyword'
                }
            }
        }
    }

    # check plugins for additional mappings
    for plugin in plugins:
        mappings = (plugin.add_mappings(mappings))

    try:
        es.indices.create(index=indexname, body=mappings)
    except elasticsearch.ConnectionError as e:
        print('ERROR: unable to connect to Elasticsearch! ({})'.format(e))
        sys.exit(1)
    return True


def bulk_upload(es, indexname, docs):
    """Elasticsearch Bulk uploader."""
    if es_wait_status_yellow:
        # wait for es health to be at least yellow
        es.cluster.health(wait_for_status='yellow', request_timeout=es_timeout)
    
    # bulk load data to Elasticsearch index
    helpers.bulk(es, docs, index=indexname,
                    chunk_size=es_chunksize, request_timeout=es_timeout)


def tune_index(es, indexname, defaults=False):
    """Tune ES index for faster indexing performance."""
    if es_disablereplicas:
        replicas = 0
    else:
        replicas = es_replicas
    default_settings = {
        "index": {
            "refresh_interval": "1s",
            "number_of_replicas": es_replicas,
            "translog.flush_threshold_size": "512mb",
            "translog.durability": "request",
            "translog.sync_interval": "5s"
        }
    }
    tuned_settings = {
        "index": {
            "refresh_interval": es_indexrefresh,
            "number_of_replicas": replicas,
            "translog.flush_threshold_size": es_translogsize,
            "translog.durability": "async",
            "translog.sync_interval": es_translogsyncint
        }
    }
    if not defaults:
        logger.info("Tuning index settings for crawl")
        es.indices.put_settings(index=indexname, body=tuned_settings,
                                request_timeout=es_timeout)
    else:
        logger.info("Setting index settings back to defaults")
        es.indices.put_settings(index=indexname, body=default_settings,
                                request_timeout=es_timeout)
