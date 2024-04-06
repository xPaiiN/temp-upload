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


diskover cache db

'''

import os
import sys
import sqlite3
import json
import logging
import time
from threading import Lock
from diskover_helpers import convert_size

version = '0.0.9'
__version__ = version

IS_PY37 = sys.version_info >= (3, 7)

"""Setup logging for diskover_cache."""
cachelogger = logging.getLogger(__name__)

class Cache:
    def __init__(self, path, load_into_mem=False):
        self.cachelock = Lock()
        self.commit_time = time.time()
        self.hitratio_time = time.time()
        # cache dir
        self.path = path
        # cache db file
        self.db_file = os.path.join(self.path, "cache_database.db")
        # load db into memory
        self.load_into_mem = load_into_mem
        self.loaded_into_mem = False
        self.cache_misses = 0
        self.cache_hits = 0
        self.cache_hit_ratio = 0
        
        # make sure path exists
        os.makedirs(path, exist_ok=True)

        # if cache_database exists, open the db
        if os.path.isfile(self.db_file):
            self.db = self.open_db()
            db_size = convert_size(os.path.getsize(self.db_file))
            cachelogger.info('Using cache DB {0} ({1})'.format(self.db_file, db_size))
            
            # load db into memory
            if self.load_into_mem:
                cachelogger.info('Loading cache DB {} into memory...'.format(self.db_file))
                self.db_mem = self.open_db_mem()
                # check if python 3.7 for built in backup
                if IS_PY37:
                    self.db.backup(self.db_mem)
                else:
                    query = "".join(line for line in self.db.iterdump())
                    self.db_mem.executescript(query)
                self.db.close()
                cachelogger.info('Done!')
                self.loaded_into_mem = True
                self.db = self.db_mem
            
        # if not, create a mew db
        else:
            cachelogger.info('Creating cache DB {0}'.format(self.db_file))
            self.db = self.create_db()
    
    def open_db_mem(self):
        return sqlite3.connect(':memory:', check_same_thread=False)
    
    def write_db_mem_disk(self):
        if not self.loaded_into_mem:
            return
        cachelogger.info('Saving in-memory cache DB {} to disk...'.format(self.db_file))
        self.update_db(force=True)
        # check if python 3.7 for built in backup
        if IS_PY37:
            db_disk = self.open_db()     
            self.db.backup(db_disk)
            db_disk.close()
        else:
            with open(self.db_file, 'w') as f:
                for line in self.db.iterdump():
                    f.write('%s\n' % line)
        cachelogger.info('Done!')
        self.db.close()
    
    def open_db(self):
        return sqlite3.connect(self.db_file, isolation_level="DEFERRED", 
                               check_same_thread=False, timeout=10)
    
    def create_db(self):
        cache_db = self.open_db()
        self.db = cache_db
        c = cache_db.cursor()

        c.execute("""
CREATE TABLE IF NOT EXISTS pathhashes (
id integer PRIMARY KEY,
pathhash text UNIQUE,
data json NOT NULL,
expire_seconds integer,
expire_at integer
)
"""
                )

        c.execute("PRAGMA synchronous=OFF")
        c.execute("PRAGMA journal_mode=OFF")
        
        # create index
        c.execute("CREATE INDEX index_pathhashes ON pathhashes (pathhash)")
        
        self.update_db(force=True)
        
        c.close()

        return cache_db

    def set_value(self, key, data, expire_seconds=60*60, force_update=False):
        # add record into the database
        expire_at = None if expire_seconds is None else time.time() + expire_seconds
        data_json = json.dumps(data)
        with self.cachelock:
            try:
                c = self.db.cursor()
                c.execute('INSERT OR REPLACE INTO pathhashes (pathhash, data, expire_seconds, expire_at) values (?,?,?,?)', (key, data_json, expire_seconds, expire_at,))   
                self.update_db(force_update)
                c.close()
            except sqlite3.InterfaceError as e:
                cachelogger.debug('sqlite3 db execute error {0}'.format(e))
                pass

    def get_value(self, key):
        c = self.db.cursor()
        c.execute('SELECT data, expire_seconds, expire_at FROM pathhashes WHERE pathhash = ?', (key,))
        record = c.fetchone()
        if record is None:
            self.cache_misses += 1
            return False
        data = record[0]
        expire_seconds = record[1]
        expire_at = record[2]

        # if expired, remove database record
        if expire_at is not None and time.time() > expire_at:
            with self.cachelock:
                c.execute('DELETE FROM pathhashes WHERE pathhash = ?', (key,))
                self.update_db()
            self.cache_misses += 1
            return False

        # renew cache expiration time
        if expire_at is not None:
            expire_at = time.time() + expire_seconds
            with self.cachelock:
                c.execute('UPDATE pathhashes SET expire_seconds = ?, expire_at = ? WHERE pathhash = ?', (expire_seconds, expire_at, key,))
                self.update_db()

        c.close()
        self.cache_hits += 1
        self.log_cache_hits()

        return json.loads(data)
    
    def get_all_values(self):
        results = {}
        c = self.db.cursor()
        c.execute('SELECT pathhash, data, expire_seconds, expire_at FROM pathhashes')
        records = c.fetchall()
        if records is None:
            c.close()
            self.cache_misses += 1
            return False
        
        for record in records:
            pathhash = record[0]
            data = record[1]
            expire_seconds = record[2]
            expire_at = record[3]

            # if expired, remove database record and continue
            if expire_at is not None and time.time() > expire_at:
                with self.cachelock:
                    c.execute('DELETE FROM pathhashes WHERE pathhash = ?', (pathhash,))
                    self.update_db()
                self.cache_misses += 1
                continue
            
            # renew cache expiration time
            if expire_at is not None:
                expire_at = time.time() + expire_seconds
                with self.cachelock:
                    c.execute('UPDATE pathhashes SET expire_seconds = ?, expire_at = ? WHERE pathhash = ?', (expire_seconds, expire_at, pathhash,))
                    self.update_db()
            
            c.close()
            
            self.cache_hits += 1
            
            results[pathhash] = json.loads(data)

        return results
    
    def update_db(self, force=False):
        if force or time.time() - self.commit_time > 5:
            if force:
                cachelogger.debug('Writing changes to cache DB (force commit)')
            else:
                cachelogger.debug('Writing changes to cache DB, next commit in 5 sec')
            commited = False
            while not commited:
                try:
                    self.db.commit()
                    commited = True
                except sqlite3.OperationalError as e:
                    cachelogger.debug('sqlite3 db commit error {0}, trying again...'.format(e))
                    time.sleep(1)
            self.commit_time = time.time()
        self.log_cache_hits()
            
    def log_cache_hits(self, forcelog=False):
        if time.time() - self.hitratio_time > 10 or forcelog:
            try:
                self.cache_hit_ratio = round(self.cache_hits/(self.cache_hits+self.cache_misses)*100, 1)
            except ZeroDivisionError:
                pass
            cachelogger.info('CACHE HITS: {0}, MISSES: {1}, HIT RATIO: {2}% ({3})'.format(
                self.cache_hits, self.cache_misses, self.cache_hit_ratio, self.path))
            self.hitratio_time = time.time()
        
    def close_db(self):
        self.log_cache_hits(forcelog=True)
        cachelogger.info('Closing cache DB {}...'.format(self.db_file))
        if self.loaded_into_mem:
            self.write_db_mem_disk()
        else:
            self.update_db(force=True) 
            self.db.close()
        cachelogger.info('Cache DB {} closed'.format(self.db_file))

    def flush(self):
        cachelogger.info('Flushing cache DB {}...'.format(self.db_file))
        c = self.db.cursor()
        c.execute('DELETE FROM pathhashes')
        self.update_db(force=True)
        c.close()
        cachelogger.info('Cache DB {} flushed'.format(self.db_file))


def cache(cachedir="storage/temp/", load_into_mem=False):
    return Cache(cachedir, load_into_mem)