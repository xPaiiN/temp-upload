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


=== Plugin Name ===
diskover unix permissions plugin

=== Plugin Description ===
diskover unix permissions plugin - This is an example plugin
for diskover. It adds extra meta data (unix permissions of 
each file or directory) to diskover index during indexing.
Tags are added "mediainfo-plugin" and "ugo+rwx" if a file or directory
is found with fully open permissions.

=== Plugin Requirements ===
none

=== Diskover Indexing Plugins Requirements ===
all indexing plugins require six functions:
- add_mappings
- add_meta
- add_tags
- for_type
- init
- close

"""

version = '0.0.2'
__version__ = version


def add_mappings(mappings):
    """Returns a dict with additional es mappings."""
    mappings['mappings']['properties'].update({
        'unix_perms': {
            'type': 'keyword'
        }
    })
    return mappings


def add_meta(path, osstat):
    """Returns a dict with additional file meta data.
    For any warnings or errors, raise RuntimeWarning or RuntimeError.
    RuntimeWarning and RuntimeError requires two args, error message string and dict or None."""
    return {'unix_perms': oct(osstat.st_mode & 0o777)[-3:]}


def add_tags(metadict):
    """Returns a dict with additional tag data or return None to not alter tags."""
    # check if permissions are fully open and add extra tags
    if metadict['unix_perms'] in ('777', '666'):
        newtags = ['unixperms-plugin', 'ugo+rwx']
        if 'tags' in metadict:
            return {'tags': metadict['tags'] + newtags}
        else:
            return {'tags': newtags}
    return None


def for_type(doc_type):
    """Determine if this plugin should run for file and/or directory."""
    if doc_type in ('file', 'directory'):
        return True
    return False


def init(diskover_globals):
    """Init the plugin.
    Called by diskover when the plugin is first loaded.
    """
    return


def close(diskover_globals):
    """Close the plugin.
    Called by diskover at end of crawl.
    """
    return