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
'''

import sys
import os
import warnings
from logging import getLogger

import confuse


logger = getLogger(__name__)


class Config:
    def __init__(self, name, diskover_dir):
        self.name = name
        self.diskover_dir = diskover_dir
        self._config = confuse.Configuration(name, __name__)
        self.filename = os.path.join(self._config.config_dir(), confuse.CONFIG_FILENAME)

        self._config_defaults = confuse.Configuration(name, __name__)
        self._config_defaults.set_file(self.default_config)

        # define in subclass
        #self.field_map = dict()

        if not os.path.exists(self.filename):
            print(f'Config file {self.filename} not found! Copy from default config: {self.default_config}')
            sys.exit(1)

        # Should be recursive
        for top, fields in self.field_map.items():
            lookup = self._config
            default_lookup = self._config_defaults
            if top is None:
                pass
            elif isinstance(fields, (tuple, list)):
                lookup = lookup[top]
                default_lookup = default_lookup[top]
            elif isinstance(fields, dict):
                lookup = lookup[top]
                default_lookup = default_lookup[top]
                for next, fields in fields.items():
                    lookup = lookup[next]
                    default_lookup[next]
            self._set_fields(lookup, default_lookup, fields)


    def _set_fields(self, lookup, default_lookup, fields):
        for field in fields:
            #check for an env var first and use that if its set
            if os.environ.get(field.upper()) is not None:
                value = os.environ.get(field.upper())
                #cant use logger yet because its not set up yet!
                print(f'  Using config variable from env var {repr(field.upper())} value: {value}')
                setattr(self, field, value)
            else:
                try:
                    setattr(self, field, lookup[field].get())
                except confuse.NotFoundError as e:
                    self.config_warn(e)
                    setattr(self, field, default_lookup[field].get())

    def config_warn(self, e):
        warnings.warn(f'Config setting {e}. Using default.')

    @property
    def default_config(self):
        return os.path.join(self.diskover_dir, 'configs_sample', self.name, 'config.yaml')

    def __repr__(self):
        return f'Config(filename={self.filename}, default_config={self.default_config})'
