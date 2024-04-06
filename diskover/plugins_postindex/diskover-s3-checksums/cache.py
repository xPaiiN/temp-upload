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
'''

import sys
import os
from logging import getLogger

sys.path.insert(1, os.path.join(sys.path[0], '../..'))
import diskover_cache as d_cache


logger = getLogger(__name__)


class Cache:
    def __init__(self, cache_dir, expire_time):
        self.cache_dir = cache_dir
        self.expire_time = expire_time
        self._cache = self._make_cache_dir(cache_dir)

    def _make_cache_dir(self, cache_dir):
        try:
            cache = d_cache.cache(cache_dir)
        except FileExistsError:
            pass
        except OSError as e:
            logger.error('Error creating directory {0}'.format(e))
            sys.exit(1)
        logger.info('Using/caching file hashes in {0}'.format(cache_dir))
        return cache

    def get(self, key):
        return self._cache.get_value(key)

    def set(self, key, value):
        self._cache.set_value(key, value, expire_seconds=self.expire_time)