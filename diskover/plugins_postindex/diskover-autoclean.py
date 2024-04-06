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


diskover autoclean plugin

'''

import sys
import os
import shutil
import optparse
import confuse
import logging
import subprocess
import concurrent.futures
import time
import shlex
import stat
import signal
from threading import Lock, current_thread
from queue import Queue
from datetime import datetime
from elasticsearch import ElasticsearchException

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists
from diskover_helpers import isoutc_to_timestamp, find_latest_index, convert_size, speed, get_win_path, rem_win_path
from diskover_lic import License, licfc


plugin_name = 'autoclean'
version = '0.0.10'
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
            logger.error('Windows requires pywin32 Python module')
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
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_autoclean/config.yaml')
config_defaults.set_file(default_config_filename)

def config_warn(e):
    warnings.warn('Config setting {}. Using default.'.format(e))

# laod config values
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
try:
    autoclean_dirs = config['dirs'].get()
except confuse.NotFoundError as e:
    config_warn(e)  
    autoclean_dirs = config_defaults['dirs'].get()
try:
    autoclean_files = config['files'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    autoclean_files = config_defaults['files'].get()
try:
    delete_dirs_recursive = config['deleteDirsRecursive'].get()
except confuse.NotFoundError as e:
    config_warn(e) 
    delete_dirs_recursive = config_defaults['deleteDirsRecursive'].get()
try:
    replacepaths = config['replacepaths']['replace'].get()
except confuse.NotFoundError as e:
    config_warn(e) 
    replacepaths = config_defaults['replacepaths']['replace'].get()
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
try:
    move_preserve_path = config['movePreservePath'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    move_preserve_path = config_defaults['movePreservePath'].get()
try:
    copy_preserve_path = config['copyPreservePath'].get()
except confuse.NotFoundError as e:
    config_warn(e) 
    copy_preserve_path = config_defaults['copyPreservePath'].get()


autoclean_queue = Queue()
autoclean_thread_lock = Lock()

deleted_size = 0
deleted_size_du = 0
copied_size = 0
copied_size_du = 0
moved_size = 0
moved_size_du = 0
processed_files = 0
processed_dirs = 0
warnings = 0
errors = 0


def log_setup():
    """Setup logging for diskover autoclean."""
    logger = logging.getLogger('diskover-{0}'.format(plugin_name))
    logger_warn = logging.getLogger('diskover-{0}_warn'.format(plugin_name))
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
        handler_file = logging.FileHandler(logfile, encoding='utf-8')
        handler_file.setFormatter(logging.Formatter(logformat))
        logger.setLevel(loglevel)
        logger.addHandler(handler_file)
        # console logging
        handler_con = logging.StreamHandler()
        handler_con.setFormatter(logging.Formatter(logformat))
        logger.addHandler(handler_con)
        logger.info('Logging output to {}'.format(logfile))
        # warnings log
        logname_warn = 'diskover-{0}_{1}_warnings.log'.format(plugin_name, logfiletime)
        logfile_warn = os.path.join(logdir, logname_warn)
        handler_warnfile = logging.FileHandler(logfile_warn, encoding='utf-8')
        handler_warnfile.setFormatter(logging.Formatter(logformat))
        logger_warn.setLevel(logging.WARN)
        logger_warn.addHandler(handler_warnfile)
        logger.info('Logging warnings to {}'.format(logfile_warn))
    else:
        logging.basicConfig(format=logformat, level=loglevel)
    eslogger.setLevel(level=logging.WARN)
    return logger, logger_warn


def index_get_cleanup_docs(es, indexname):
    """Get all files and directories in index matching autoclean list and return them in a list."""
    docstoclean = []
    
    # refresh index
    es.indices.refresh(index=indexname)

    for doc_type in ('directory', 'file'):
        if doc_type == 'directory':
            autoclean_list = autoclean_dirs
        else:
            autoclean_list = autoclean_files
        if autoclean_list is None:
            continue
        for t in autoclean_list:
            query = '{0} AND type:{1}'.format(t['query'], doc_type)
            
            if options.vverbose:
                logger.info('es query: {0}'.format(query))

            data = {
                'size': 0,
                '_source': ['tags', 'parent_path', 'name', 'mtime', 'ctime', 'size', 'size_du'],
                'query': {
                    'query_string': {
                        'query': query,
                        'analyze_wildcard': 'true'
                    }
                }
            }

            res = es.search(index=indexname, scroll='1m', size=es_scrollsize,
                            body=data, request_timeout=es_timeout)
            
            totaldocs = res['hits']['total']['value']
            
            if options.vverbose:
                logger.info('found {0} matching docs for type {1}'.format(totaldocs, doc_type))

            while res['hits']['hits'] and len(res['hits']['hits']) > 0:
                for hit in res['hits']['hits']:
                    docid = hit['_id']
                    # add on any new tags to existing tags, skipping tags with same name
                    tags = hit['_source'].get('tags')
                    if tags is None:
                        tags = t['tags']
                    else:
                        for tag in t['tags']:
                            if tag not in tags:
                                tags.append(tag)
                    fullpath = os.path.join(hit['_source']['parent_path'], hit['_source']['name'])
                    ctime = hit['_source']['ctime']
                    mtime = hit['_source']['mtime']
                    size = hit['_source']['size']
                    size_du = hit['_source']['size_du']
                    docstoclean.append((docid, tags, fullpath, ctime, mtime, t, size, size_du))

                res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                                request_timeout=es_timeout)
    return docstoclean

def better_split(value):
    '''
        Handles quotes in paths
    '''
    lex = shlex.shlex(value)
    lex.quotes = '"'
    lex.whitespace_split = True
    lex.commenters = ''
    return list(lex)


def dst_path(src, dstdir, preserve_path):
    """Makes destination path from source path."""
    if IS_WIN:
        src = rem_win_path(src)
        # remove drive letter or unc server/share from src path
        drive, tail = os.path.splitdrive(src)
        src = tail
        dst_basename = os.path.basename(src)
        dst_parentdir = os.path.dirname(src)
        if ('.\\' in dstdir):
            dst_dir = dst_parentdir + os.path.sep + dstdir.replace('.\\', '')
        else:
            if preserve_path:
                dst_dir = dstdir + dst_parentdir
            else:
                dst_dir = dstdir
    else:
        dst_basename = os.path.basename(src)
        dst_parentdir = os.path.abspath(os.path.join(src, os.pardir))
        dstdir = dstdir.rstrip('/')
        if ('./' in dstdir):
            dst_dir = dst_parentdir + os.path.sep + dstdir.replace('./', '')
        else:
            if preserve_path:
                dst_dir = dstdir + dst_parentdir
            else:
                dst_dir = dstdir
    dst = os.path.join(dst_dir, dst_basename)
    return dst, dst_dir


def autoclean_thread(item):
    global deleted_size
    global deleted_size_du
    global copied_size
    global copied_size_du
    global moved_size
    global moved_size_du
    global processed_files
    global processed_dirs
    global warnings
    global errors
    thread = current_thread().name

    docid, tags, filepath, ctime, mtime, ac_rule, size, size_du = item
    fileaction = ac_rule['action']
    # check file action
    if fileaction not in ('rename', 'delete', 'move', 'copy', 'custom'):
        raise ValueError('Error unknown action {0} in config!'.format(fileaction))
    customcmd = ac_rule['customcmd']
    renametext = ac_rule['renametext']
    movedir = ac_rule['movedir']
    copydir = ac_rule['copydir']
    checktimes = ac_rule['checktimes']
    
    # do file action
    success = False
    
    # do any path translations
    if replacepaths:
        src = filepath.replace(replacepaths_from, replacepaths_to, 1)
    else:
        src = filepath
    # Windows path translations
    if IS_WIN:
        src = src.replace('/', '\\')
        src = get_win_path(src)
    
    # check if file/directory still exists
    if not os.path.exists(src):
        logmsg = '[{0}] {1} not found!'.format(thread, src)
        logger.warning(logmsg)
        if logtofile: logger_warn.warning(logmsg)
        with autoclean_thread_lock:
            warnings += 1
        return              
    
    # get current stat info
    try:
        osstat = os.stat(src)
    except OSError as e:
        logmsg = '[{0}] Error checking file {1} ({2})'.format(thread, src, e)
        logger.error(logmsg)
        if logtofile: logger_warn.error(logmsg)
        with autoclean_thread_lock:
            errors += 1
        return
    else:
        if os.path.isfile(src):
            with autoclean_thread_lock:
                processed_files += 1
        elif os.path.isdir(src):
            with autoclean_thread_lock:
                processed_dirs += 1
    
    # file time check
    if checktimes:
        if 'ctime' in checktimes and isoutc_to_timestamp(ctime) == int(osstat.st_ctime):
            timepass = True
        else:
            timepass = False
        if 'mtime' in checktimes and isoutc_to_timestamp(mtime) == int(osstat.st_mtime):
            timepass = True
        else:
            timepass = False
        if not timepass:
            logmsg = '[{0}] File times are different than indexed doc {1}, skipping'.format(thread, src)
            logger.warning(logmsg)
            if logtofile: logger_warn.error(logmsg)
            with autoclean_thread_lock:
                warnings += 1
            return
    
    # do action
    start_time = datetime.now()
    start_time_epoch = time.time()
    if fileaction == 'rename':
        dst = src + renametext
        if options.verbose or options.vverbose:
            logger.info('[{0}] Renaming {1} to {2} ...'.format(thread, src, dst))
        try:
            if not options.dryrun:
                os.rename(src, dst)
        except OSError as e:
            logmsg = '[{0}] Error renaming {1} ({2})'.format(thread, src, e)
            logger.error(logmsg)
            if logtofile: logger_warn.error(logmsg)
            with autoclean_thread_lock:
                errors += 1
            pass
        else:
            success = True
            logger.info('[{0}] Finished renaming {1} to {2} (Duration: {3})'.format(
                thread, src, dst, datetime.now() - start_time))
        
    elif fileaction == 'delete':
        if options.verbose or options.vverbose:
            logger.info('[{0}] Deleting {1} ({2}) ...'.format(thread, src, convert_size(size)))
        try:
            if os.path.isfile(src):
                if not options.dryrun:
                    try:
                        os.remove(src)
                    except OSError:
                        if IS_WIN:
                            # workaround for some files getting permission denied errors on Windows when deleting
                            try:
                                if options.vverbose:
                                    logger.info('[{0}] Changing owner file permissions for {1}'.format(thread, src))
                                os.chmod(src, stat.S_IWUSR|stat.S_IRUSR)
                            except Exception as e:
                                if options.vverbose:
                                    logger.info('[{0}] Error changing owner file permissions for {1} ({2})'.format(thread, src, e))
                                pass
                            finally:
                                os.remove(src)
                        else:
                            raise
                    with autoclean_thread_lock:
                        deleted_size += size
                        deleted_size_du += size_du
            elif os.path.isdir(src):
                if not options.dryrun:
                    if delete_dirs_recursive:
                        if options.verbose or options.vverbose:
                            logger.info('[{0}] Deleting directory tree (recursive) {1} ...'.format(thread, src))
                        shutil.rmtree(src)
                        with autoclean_thread_lock:
                            deleted_size += size
                            deleted_size_du += size_du
                    else:
                        if options.verbose or options.vverbose:
                            logger.info('[{0}] Deleting files in directory (non-recursive) {1} ...'.format(thread, src))
                        for entry in os.scandir(src):
                            if entry.is_file():
                                try:
                                    try:
                                        os.remove(entry.path)
                                    except OSError:
                                        if IS_WIN:
                                            # workaround for some files getting permission denied errors on Windows when deleting
                                            try:
                                                if options.vverbose:
                                                    logger.info('[{0}] Changing owner file permissions for {1}'.format(thread, entry.path))
                                                os.chmod(entry.path, stat.S_IWUSR|stat.S_IRUSR)
                                            except Exception as e:
                                                if options.vverbose:
                                                    logger.info('[{0}] Error changing owner file permissions for {1} ({2})'.format(thread, entry.path, e))
                                                pass
                                            finally:
                                                os.remove(entry.path)
                                        else:
                                            raise
                                    with autoclean_thread_lock:
                                        deleted_size += size
                                        deleted_size_du += size_du
                                except OSError as e:
                                    logmsg = '[{0}] Error deleting {1} ({2})'.format(thread, entry.path, e)
                                    logger.error(logmsg)
                                    if logtofile: logger_warn.error(logmsg)
                                    with autoclean_thread_lock:
                                        errors += 1
                                    pass
            else:
                logmsg = '[{0}] Error deleting {1}: No such file or directory'.format(thread, src)
                logger.warning(logmsg)
                if logtofile: logger_warn.warning(logmsg)
                with autoclean_thread_lock:
                    warnings += 1
                pass
        except OSError as e:
            logmsg = '[{0}] Error deleting {1} ({2})'.format(thread, src, e)
            logger.error(logmsg)
            if logtofile: logger_warn.error(logmsg)
            with autoclean_thread_lock:
                errors += 1
            pass
        else:
            success = True
            logger.info('[{0}] Finished deleting {1} (Size: {2}, Duration: {3}, Speed: {4})'.format(
                thread, src, convert_size(size), datetime.now() - start_time, speed(start_time_epoch, size)))
        
    elif fileaction == 'move':
        dst, dst_movedir = dst_path(src, movedir, move_preserve_path)
        if IS_WIN:
            dst = get_win_path(dst)
        if options.verbose or options.vverbose:
            logger.info('[{0}] Moving {1} to {2} ({3}) ...'.format(thread, src, dst, convert_size(size)))
        try:
            # check directories exists and if not make them
            if not options.dryrun:
                if not os.path.isdir(dst_movedir):
                    try:
                        os.makedirs(dst_movedir)
                    except OSError as e:
                        logmsg = '[{0}] Error making directory {1} ({2})'.format(thread, dst_movedir, e)
                        logger.error(logmsg)
                        if logtofile: logger_warn.error(logmsg)
                        with autoclean_thread_lock:
                            errors += 1
                        raise
            if os.path.exists(src):
                if not options.dryrun:
                    shutil.move(src, dst)
                    with autoclean_thread_lock:
                        moved_size += size
                        moved_size_du += size_du
            else:
                logmsg = '[{0}] Error moving {1}: No such file or directory'.format(thread, src)
                logger.warning(logmsg)
                if logtofile: logger_warn.warning(logmsg)
                with autoclean_thread_lock:
                    warnings += 1
                pass
        except OSError as e:
            logmsg = '[{0}] Error moving {1} ({2})'.format(thread, src, e)
            logger.error(logmsg)
            if logtofile: logger_warn.error(logmsg)
            with autoclean_thread_lock:
                errors += 1
            pass
        else:
            success = True
            logger.info('[{0}] Finished moving {1} to {2} (Size: {3}, Duration: {4}, Speed: {5})'.format(
                thread, src, dst, convert_size(size), datetime.now() - start_time, speed(start_time_epoch, size)))
        
    elif fileaction == 'copy':
        dst, dst_copydir = dst_path(src, copydir, copy_preserve_path)
        if IS_WIN:
            dst = get_win_path(dst)
        if options.verbose or options.vverbose:
            logger.info('[{0}] Copying {1} to {2} ({3}) ...'.format(thread, src, dst, convert_size(size)))
        try:
            # check directories exists and if not make them
            if not options.dryrun:
                if not os.path.isdir(dst_copydir):
                    try:
                        os.makedirs(dst_copydir)
                    except OSError as e:
                        logmsg = '[{0}] Error making directory {1} ({2})'.format(thread, dst_copydir, e)
                        logger.error(logmsg)
                        if logtofile: logger_warn.error(logmsg)
                        with autoclean_thread_lock:
                            errors += 1
                        raise
            if os.path.isfile(src):
                if not options.dryrun:
                    shutil.copy2(src, dst)
                    with autoclean_thread_lock:
                        copied_size += size
                        copied_size_du += size_du
            elif os.path.isdir(src):
                if not options.dryrun:
                    shutil.copytree(src, dst)
                    with autoclean_thread_lock:
                        copied_size += size
                        copied_size_du += size_du
            else:
                logmsg = '[{0}] Error copying {1}: No such file or directory'.format(thread, src)
                logger.warning(logmsg)
                if logtofile: logger_warn.warning(logmsg)
                with autoclean_thread_lock:
                    warnings += 1
                pass
        except OSError as e:
            logmsg = '[{0}] Error copying {1} ({2})'.format(thread, src, e)
            logger.error(logmsg)
            if logtofile: logger_warn.error(logmsg)
            with autoclean_thread_lock:
                errors += 1
            pass
        else:
            success = True
            logger.info('[{0}] Finished copying {1} to {2} (Size: {3}, Duration: {4}, Speed: {5})'.format(
                thread, src, dst, convert_size(size), datetime.now() - start_time, speed(start_time_epoch, size)))
        
    elif fileaction == 'custom':
        if not customcmd:
            raise ValueError('Error no customcmd in config!')
        cmd = customcmd + " " + src
        if options.verbose or options.vverbose:
            logger.info('[{0}] Running custom action cmd: {1} ({2}) ...'.format(thread, cmd, convert_size(size)))

        process = None
        try:
            if not options.dryrun:
                process = subprocess.Popen(better_split(cmd), stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, universal_newlines=True)
                if options.verbose or options.vverbose:
                    logger.info('[{0}] Custom action output: '.format(thread))
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            logger.info('[{0}] {1}'.format(thread, output.strip()))               
                    out, err = process.communicate()
                    if err != "":
                        logmsg = '[{0}] Custom action error: {1}'.format(thread, err.strip())
                        logger.error(logmsg)
                        if logtofile: logger_warn.error(logmsg)
                        with autoclean_thread_lock:
                            errors += 1
        except OSError as e:
            logmsg = '[{0}] Custom action cmd: {1} error: {2}'.format(thread, cmd, e)
            logger.error(logmsg)
            if logtofile: logger_warn.error(logmsg)
            with autoclean_thread_lock:
                errors += 1
        except:
            logmsg = '[{0}] Custom action cmd: {1} error: {2}'.format(thread, cmd, sys.exc_info()[0])
            logger.error(logmsg)
            if logtofile: logger_warn.error(logmsg)
            with autoclean_thread_lock:
                errors += 1
        else:
            # With dry-run 'process' will never have been initialized!!  So no returncode to print
            if process is not None:
                logger.info('[{0}] Finished running custom action cmd: {1} (Return code: {2}) (Size: {3}, Duration: {4}, Speed: {5})'.format(
                            thread, cmd, process.returncode, convert_size(size), datetime.now() - start_time, speed(start_time_epoch, size)))
                # handle non-zero exit code
                # only success if return code is 0
                if process.returncode == 0:
                    success = True
                else:
                    with autoclean_thread_lock:
                        errors += 1
            else:
                logger.info('[{0}] Finished dry-run custom action cmd: {1} (Size: {3}, Duration: {4}, Speed: {5})'.format(
                            thread, cmd, convert_size(size), datetime.now() - start_time, speed(start_time_epoch, size)))



    # update doc tags
    if success:
        if options.vverbose:
            logger.info('[{0}] updating doc tags for {1}'.format(thread, src))
        if not options.dryrun:
            # update doc tags
            try:
                es.update(index=index, id=docid, body={'doc': {'tags': tags}})
            except ElasticsearchException as e:
                logmsg = '[{0}] Error updating doc tags for {1} error: {2}'.format(thread, src, e)
                logger.error(logmsg)
                if logtofile: logger_warn.error(logmsg)
                pass


def banner():
    print("""\u001b[32;1m
                                                  |
   _____     _           _____ _                  |
  |  _  |_ _| |_ ___ ___|     | |___ ___ ___      |
  |     | | |  _| . |___|   --| | -_| .'|   |     |
  |__|__|___|_| |___|   |_____|_|___|__,|_|_|     |
    diskover auto-clean v{0}                   /X\\
                                                //X\\\\
                                               0 1 1 0 
    \u001b[0m\n""".format(version))
    sys.stdout.flush()


def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-autoclean.py [-h] [index]

diskover autoclean v{0}
Auto-cleans files and directories using docs in a diskover Elasticsearch index.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-n', '--dryrun', action='store_true', 
                        help='just output what would happen without doing any actual file actions (DRY-RUN)')
    parser.add_option('-l', '--latestindex', metavar='TOPPATH',
                        help='auto-finds most recent index based on top path')
    parser.add_option('-v', '--verbose', action='store_true', 
                        help='verbose logging')
    parser.add_option('-V', '--vverbose', action='store_true', 
                        help='more verbose logging')
    parser.add_option('--version', action='store_true',
                        help='print diskover-autoclean version number and exit')
    options, args = parser.parse_args()
    
    if options.version:
        print('diskover-autoclean v{}'.format(version))
        sys.exit(0)

    # license check
    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'PRO')
    
    logger, logger_warn = log_setup()

    if IS_WIN is True:
        install_win_sig_handler()

    # catch SIGTERM sent by kill command
    signal.signal(signal.SIGTERM, receive_signal)

    es = elasticsearch_connection()
    
    banner()
    
    logger.info('Starting diskover auto-clean ...')
    start_time = datetime.now()
    
    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_AUTOCLEANDIR: {0}'.format(os.getenv('DISKOVER_AUTOCLEANDIR')))

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

    if options.dryrun:
        dryrun = '(DRY-RUN)'
    else:
        dryrun = ''
    logger.info('Finding files and directories to cleanup in index {0} ... {1}'.format(index, dryrun))
    docstoclean = index_get_cleanup_docs(es, index)
    if len(docstoclean) == 0:
        logger.info('No docs found that need cleaning')
        sys.exit(0)
    
    logger.info('Starting {0} cleaning threads ...'.format(maxthreads))
    # Set up thread for autocleaning
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxthreads) as executor:
        futures = []
        for item in docstoclean:
            futures.append(executor.submit(autoclean_thread, item))
        for future in concurrent.futures.as_completed(futures):
            if future.exception() is not None:
                raise future.exception()
            #else:
            #    logger.info(future.result())
    
    logger.info('Finished cleaning')
    logger.info('*** Duration: {0} ***'.format(datetime.now() - start_time))
    logger.info('*** Processed {0} files, {1} dirs ***'.format(processed_files, processed_dirs))
    logger.info('*** Removed {0}, allocated size {1} ***'.format(convert_size(deleted_size), convert_size(deleted_size_du)))
    logger.info('*** Moved {0}, allocated size {1} ***'.format(convert_size(moved_size), convert_size(moved_size_du)))
    logger.info('*** Copied {0}, allocated size {1} ***'.format(convert_size(copied_size), convert_size(copied_size_du)))
    logger.info('*** Warnings {0}, Errors {1} ***'.format(warnings, errors))
    logger.info('Good bye!')