# Diskover v2 Change Log

# [2.2.2] - 2023-11-03
### added
- file kind crawl plugin v0.0.1
- costs post-index plugin v0.0.1
### changed
- updated diskoverd to v2.1.10
    - fixes for multiple workers picking up same task
    - run now fixes
- updated s3 alt scanner to v0.0.14
    - fix for bucket does not exist when using s3://bucket/folder for scan path
- update index-diff plugin to v2.0.7
    - can now find differences in the number of hard links of files between indexes


# [2.2.1] - 2023-10-18
### changed
- version change only


# [2.2.0] - 2023-10-07
### fixed
- ctrl-c interupt handling log error in Windows
- Fix for filesystems that don't show a size
### added
- first index time crawl plugin v0.0.1
- more detailed logging for directory/file exclusions
- checkfiletimes to default/sample diskover config file excludes section
- added hostname to crawlend indexinfo
- --nofiles cli option to not index file docs
- fileagegroups config setting to diskover default/sample config
    - add file age range groups into directory docs fileages field
- rolluptimes to diskover default/sample config
    - roll up sub-directory times (atime, mtime, ctime) into directory docs timerollup field
### changed
- updated diskoverd to v2.1.9
    - fixed issue where starting multiple workers at same time could cause same task to be ran by different workers
    - changed task queue size to be same as worker threads (workthreads config setting), previously was infinite queue size. This way tasks will not get queued by the task worker if the task queue is full
	- allows better task sharing/load balancing for multiple workers since an individual worker will not queue up (and run) all tasks scheduled at same time
    - changed frequency to look for new tasks to 10-15 sec
    - fixed issue with tasks retrying when worker shutting down
    - fixed issue where tasks could be missed if scheduled to run every minute
    - fixed issue with not exiting if api returns no tasks data
- updated diskover cache (diskover_cache.py) to v0.0.9
    - fixed issue sqlite3.OperationalError: database is locked sleep error
    - minor improvements
- updated autoclean plugin to v0.0.10
    - fixed issue with files not deleting due to permission error on Windows
    - added ctrl-c handling
    - fixes for custom action commands
- updated mediainfo plugin to v0.0.20
    - fixed issue with directory excludes
- updated checksums plugin to v0.0.3
    - fixed issue with directory excludes
- updated requests version in pip requirements txt files
    - security update
- updated autotag plugin to v2.0.3
    - added ctrl-c handling
- updated autotag checksums to v0.0.4
    - added windows ctrl-c handling
- updated dupesfinder plugin to v2.0.11
    - added windows ctrl-c handling
- updated esfieldcopier plugin to v0.1.4
    - added ctrl-c handling
- updated esqueryreport plugin to v0.1.6
    - added ctrl-c handling
    - added check for es query
- updated illegalfilename plugin to v0.1.6
    - added ctrl-c handling
- updated indexdiff plugin to v2.0.6
    - added ctrl-c handling
- updated tagcopier plugin to v2.0.4
    - added ctrl-c handling
- updated winattrib plugin to v0.0.4
    - added ctrl-c handling
- updated checksums plugin to v0.0.5
    - fixed issue with stats log output ValueError
- updated s3 alt scanner to v0.0.13
    - added check to see if bucket exists


# [2.1.1] - 2023-04-18
### fixed
- diskover.py SIGTERM handling
- diskover.py bad file/directory timestamp handling
### added
- Elasticsearch 8.x support
- checksums crawl plugin v0.0.2
- checksums post index plugin v0.0.3
- checksums s3 post index plugin v0.0.4
- offline media scanner v0.0.1
- Windows attributes post index plugin v0.0.3 (Pro +)
    - gets and indexes Windows owner, group, dacl
### changed
- updated diskoverd to v2.1.1
    - bug fixes
- updated dupes finder plugin to v2.0.10
    - SIGTERM handling
    - added csvdir config setting to default/sample config
    - added handling of ES BulkIndexError/TransportError Exception to exit
- updated indexdiff plugin to v1.0.5
    - added csvdir config setting to default/sample config
- updated es query report plugin to v0.1.4
    - bug fixes
- updated tag copier to v2.0.3
    - added handling of ES BulkIndexError/TransportError Exception to exit
    - minor improvements
- updated es field copier to v0.1.3
    - added handling of ES BulkIndexError/TransportError Exception to exit
    - minor improvements
- updated illegal file name plugin to v0.1.5
    - minor improvements
- updated autoclean plugin to v0.0.7
    - added Windows long path support


# [2.1.0] - 2023-02-06
### fixed
- python error when indexing spaceinfo doc and disk space > max size for ES long field mapping (s3fs mount)
- diskover_cache not getting logged to file
- trailing slashes not geting removed from paths in Windows
- catching AttributeError exceptions in alt scanner log_setup, init, close functions
- python error finding threaddirdepth for directory tree with only 1 subfolder
- python error when scanning s3fs fuse mount and directory modified time (mtime) timestamp invalid
- bugs using alt scanners in Windows
### added
- free_percent and available_percent to spaceinfo doc and to es index mappings
- Windows path examples for log directory, etc. to all default/sample config files
- Azure Storage Blob alt scanner v0.0.4 (scandir_azure.py) in scanners directory and default/sample config in configs_sample/diskover_scandir_azure/ (Pro +)
- Windows pre and post diskover-web task panel script examples in scripts directory
### changed
- when not specifiying index name with -i cli option and using alt scanner, index name now contains alt scanner name in the index name, example diskover-s3_bucketname-datetime
- updated es field copier post-index plugin to v0.1.2
    - added copying field mappings from source to dst index if any missing
- updated media info plugin to v0.0.19
    - changed resolution, codec, codeclong, pixfmt, duration, bitrate field mappings to multi-field (keyword and text)
    - added codec_tag_string (FourCC codes) from ffprobe output as new es index field named codectag (keyword/text field)
    - fixed ffprobe errors getting cached in media info sqlite db
    - added "excludedirs" config setting (excluded directories) to default/sample config, copy to your config
    - fixed logs not getting output to file when logging to file enabled in diskover config
- updated illegal file name post-index plugin to v0.1.4
    - added -f --fixnames cli option to fix file names
    - added --fixnamesdryrun cli option to fix file names dry-run
    - added new config settings to default/sample config: normalizeunicode, encodeascii, filenamecharlimit, replacespaces
- updated dupes finder post-index plugin to v2.0.8
    - fixed issue with using -a, --alldocs cli option and not all files hashes getting indexed
    - fixed issue with using -c, --csv cli option and if no dupes found csv file still gets created
    - added -m --hashmode to cli options to set hash mode (overrides mode config setting)
    - changed hash index field from keyword to object and added hash.xxhash, hash.md5, hash.sha1, or hash.sha256, hash gets stored in one of these sub-fields of hash field depending on what mode is used
    - hash cache sqlite db now gets/sets separate hash keys (xxhash, md5, etc) for each hash type when retrieving/storing hashes instead of just single hash key
    - added hash mode to Hash column title and filename when saving csv
    - added datetime to filename when saving csv
    - set encoding to utf-8 when saving csv file
    - added file Size, Mtime columns when saving csv file
    - added usediskmtime to default/sample config file
- updated index diff post-index plugin to v2.0.4
    - added -c --hashdiff to cli options to compare checksum/hash of files when doing diff as well as file names
    - added --addtags to cli options to add diff tags to index for any file diffs
    - added datetime to filename when saving csv using filelistonly cli option
    - added hash column when saving csv using filelistonly cli option
    - fixed issues when using comparecsvs cli option
    - added "hashskipempty" and "hashskipmissing" settings to default/sample config, copy to your config
- updated dircache alt scanner to v0.0.10
    - fixed Windows path issues
- updated diskoverd to v2.1.0
    - added new config setting "sendemaillongruntask" to default/sample config for sending email when task taking more than n minutes to run, copy to your config
    - fixed exception handling issue running subprocess
    - fixed issue with task finishing but not getting removed from current tasks
    - fixed issue with shutting down diskoverd service in Windows did not send shutdown to diskover-web api
    - fixed issue with stopping diskoverd with kill command or ctrl+c and not stopping all running tasks causing diskoverd to not exit until subprocess tasks finish
    - removed support for Task Panel File Action tasks
    - added log warning if email config settings not set and task has email address set, causing python smtp email exception run connect() first and diskoverd not sending worker update to api
- updated s3 alt scanner to v0.0.12
    - added env vars S3_USE_SSL, and S3_VERIFY to set boto3 client use_ssl and verify params
    - fixed botocore not logging to screen when logging to file enabled
- slow directory scan warning time in diskover default/sample config to 10 minutes


# [2.0.7] - 2022-12-04
### fixed
- exception handling for Elasticsearch exception TransportError during bulk uploads
- fixed occasional directory scanning hanging at start of scan when searching for subdirs to start threads for calculating thread directory depth
- exception handling for close function call for plugins and alt scanners
### added
- es field copier post-index plugin v0.1
- log directry paths at start of scan when searching for subdirs to start threads for calculating thread directory depth when using -V or debug logging
- utf-8 encoding to all logging file handlers for diskover.py, diskoverd, and all post-index plugins
### changed
- reduced time to search for sub dirs at start of scan when calculating thread directory depth
- updated dircache alt scanner to v0.0.9
    - improved handling of errors for directory stat FileNotFoundError no such file or directory
- updated dupes finder plugin to v2.0.6
    - added index mappings for hash (keyword) and is_dupe (boolean) fields to index, allows for sorting by hash in diskover-web, Kibana, etc.
    - stopped logging stats when hashing complete
- updated diskoverd task worker daemon to v2.0.5
    - added check for additional cli options/tags for index tasks


# [2.0.6] - 2022-11-06
### changed
- better handling of errors when importing alternate scanner modules


# [2.0.5] - 2022-10-21
### fixed
- log file names using 12H timestamp instead of 24H
### added
- Elasticsearch SSL verification setting (sslverification) to default/sample diskover config, copy to your config and set for your env
    - ssl and certificate verification when connecting to ES
### changed
- updates dupes finder post index plugin to v2.0.4
    - log file name now uses 24H timestamp
- updates auto clean post index plugin to v0.0.5
    - log file name now uses 24H timestamp
- updated auto tag post index plugin to v2.0.1
    - log file name now uses 24H timestamp
- updated es query report post index plugin to v0.1.2
    - log file name now uses 24H timestamp
- updated illegal file name post index plugin to v0.1.2
    - log file name now uses 24H timestamp
- updated index diff post index plugin to v2.0.2
    - log file name now uses 24H timestamp
- updated tag copier post index plugin to v2.0.1
    - log file name now uses 24H timestamp


# [2.0.4-1] - 2022-10-11
### UPDATE 1
### changed
- updated media info plugin to v0.0.15
    - fixed UnboundLocalError: local variable 'cachedir' referenced before assignment causing scan to crash
    - log absolute path for cache directory
- updated scandir dircache alt scanner to v0.0.8
    - log absolute path for cache directory


# [2.0.4] - 2022-10-05
### fixed
- removed any colon from diskover linux log file names when log to file is enabled in config
### changed
- updated diskoverd to v2.0.3
    - fixed issue with post task exiting with status exit code > 0 and task not finishing
    - fixed issue with task retries set to 1 and task not retrying
    - fixed issue with sending stop command and command continues to retry if retries set to > 0
    - fixed UnboundLocalError: local variable 'indx' referenced before assignment when running custom task and contains post command args
- updated s3 alt scanner to v0.0.9
    - can now scan all buckets using s3:// as top path arg for diskover.py
    - owner is looked up in s3 instead of only using root (uid 0) and set for file and directory docs
    - added boto s3 client InvalidObjectState error exception handling if an object is on Glacier and only logs if debug logging set
- updated media info plugin to v0.0.14
    - added cachedir and cacheexpiretime to default/sample mediainfo plugin config, copy to your mediainfo plugin config
- updated scandir dircache alt scanner to v0.0.7
    - add cachedir setting to default/sample config file, copy to your config file
- updated illegal file name post index plugin to v0.1.1
    - fixed issue with docs not getting tagged with both illegal and long tags
- updated es query report post index plugin to v0.1.1
    - bug fixes
    - changed any index field that is an array (example tags) each item in array to be separated with semicolon in csv
    

# [2.0.3-1] - 2022-09-26
### UPDATE 1
### changed
- updated scandir dircache alt scanner to v0.0.6
    - fixed config read error exception when loading default config file


# [2.0.3] - 2022-09-19
### BREAKING CHANGES
- licensing changes
    - contact Diskover Data support@diskoverdata.com to get new license key file as existing diskover.lic file will no longer work
    - you will need to generate a new hardware id after updating before requesting new license keys https://docs.diskoverdata.com/diskover_installation_guide/#generating-a-hardware-id
- dir cache alt scanner critical bug fix (see changed below)
### fixed
- issue with replace paths config setting and using / as from path
- issue with dircache alt scanner scan would crash if sqlite error occured when adding data to db
- issue with dircache alt scanner scan indexing incorrect atime and mtime (see below changed)
- issue with ES bulk indexing and unicode encode error caused scan to crash
### changed
- changed license hardware id generation
- all log locations in default/sample config files to /var/log/diskover/ directory, this directory must exist first before using and have read/write permissions for the user
- updated autoclean to v0.0.4
    - bug fixes
    - added file size to log output
    - removed extra duration log output lines
    - added separate warnings/errors log file
    - removed extra error log line when warning printed for file not found
- updated media info plugin to v0.0.13
    - changed default framerate decimal points to 2 (rounded float)
    - added framerateDecimals to default/sample mediainfo plugin config, copy to your mediainfo plugin config
- updated diskoverd to v2.0.2
    - fixed issue when running multiple diskoverd on different hosts and task workers starting same task if assigned to any worker and diskoverd started at same time
    - added default config fallback values if any settings from config are missing
    - added support for task timeout
- updated diskover cache module to v0.0.7
    - added sqlite error exception handling to not cause fatal crash when errors occur adding data to db
- updated scandir dircache alt scanner to v0.0.5
    - fixed issue with stat atime (access time) and mtime (modified time) being indexed incorrectly
        - remove existing dir cache alt scanner cache directory /opt/diskover/__dircache__ when no scans running that use it
    - fixed issue with directory containing symlink that wasn't found would cause whole parent path directory to be skipped
    - added default config fallback values if any settings from config are missing
    - added warning if load_db_mem set to True in config
- updates dupes finder post index plugin to v2.0.3
    - improved dupes finding algorithm by skipping any files that have unique size and skipping any files with unique first chunksize bytes before doing full content hash (for single index arg only)
    - added stats and performance log ouput
    - added better stat info at end
    - added -e --excludehashes cli option to exclude searching for any files that already have hash in index doc
    - added excludeextensions, excludefiles, excludedirs to default/sample config file, copy to your config file
    - changed minsize setting in default/sample config to 1024 bytes, previously was 1 bytes


# [2.0.2] - 2022-07-20
### fixed
- Windows scanning issue causing directories not to be found (long path fix)
- python zero division error at end of crawl stats if crawl finished in 0 sec or 0 docs indexed
- when scanning multiple top paths, crawl stats for the top path still printing out after crawl finishes
### added
- Illegal file name post index plugin v0.1 (PRO +)
    - plugins_postindex/diskover-illegalfilename.py
    - configs_sample/diskover_illegalfilename/config.yaml
- ES query csv/email report post index plugin v0.1 (PRO +)
    - plugins_postindex/diskover-esqueryreport.py
    - configs_sample/diskover_esqueryreport/config.yaml
### changed
- updated dupes finder post index plugin to v2.0.2
    - added -l, --latestindex cli arg
- moved dircache alt scanner default/sample config directory to configs_sample directory and renamed to diskover_scandir_dircache


# [2.0.1] - 2022-05-31
### fixed
- generating hardware id with multiple ES nodes in diskover config
- life science edition (LSE) license not working
- logging issues in Windows
- scanning issues in Windows
- issue with restore times
### added
### changed
- improved crawl performance
- improved log naming
- updated diskover-dupesfinder to v2.0.1
    - fixed issue with setting restoretimes config setting to True and traceback error if times can not be set
- updated diskover-indexdiff to v2.0.1
    - bug fixes
    - fixed Windows issues
    - added headers to csv
    - added -q, --esquery add ES query string cli option
    - reduced memory usage
- default/sample diskover config autotag set to disabled


# [2.0] - 2022-04-04
### fixed
- issue with diskoverd where if task was disabled, task could not be sent stop from task panel
- issue with Windows scanning and long paths or paths with trailing space
- issue with Windows scanning and using unc path as top path with a trailing slash
### added
- option to set diskoverd worker name with env var DISKOVERD_WORKERNAME
### changed
- improved index analyzer word filter
- updated diskoverd to v2.0
- updated diskover-autotag to v2.0
- updated diskover-dupesfinder to v2.0
    - added sha1 and sha256 hash modes options in config
    - fixed issue with using replace path
    - fixed issue with restore times
    - fixed Windows bugs
- updated diskover-indexdiff to v2.0
- updated diskover-tagcopier to v2.0
- updated diskover autoclean to v0.0.3
    - fixed Windows bugs
    - other minor bug fixes and improvements
- updated windows-owner plugin to v0.0.5
	- added GET_GROUP, USE_SID settings at top of script
- update dircache alt scanner to v0.0.4
    - fixed os stat blocks error running in Windows


# [2.0-rc.5-2] - 2022-03-20
### fixed
- Windows scanning issue
### changed
- updated windows-owner plugin to v0.0.4
	- set INC_DOMAIN to False as default


# [2.0-rc.5-1] - 2022-03-18
### fixed
- license issues causing "this feature is unlicensed" with using valid license key
### changed
- updated diskoverd to v2.0-rc.5
    - fixed issue with diskoverd import module error


# [2.0-rc.5] - 2022-03-16
### BREAKING CHANGES
- new licensing
    - contact Diskover Data support@diskoverdata.com to get new license key file as existing diskover.lic file will no longer work
    - you will need to generate a hardware id before requesting new license keys https://docs.diskoverdata.com/diskover_installation_guide/#generating-a-hardware-id
    - features which were previously unlocked, will now require a valid edition license (Essential, Pro, etc)
- media info plugin now uses and requires config file, see changed
### fixed
- issue with enabling diskover logging in Windows causes exception
- issue when scanning using just drive letter in Windows (example C:), would scan current directory
- issue with default/sample autoclean config causing ConfigReadError exception
### added
- new licensing
- diskover_lic.py license helper module, use -h cli option for help
- defaults for configs
### changed
- if any missing config items are not in config files, a default config value gets set and a warning message gets printed
- updated dupesfinder post index plugin to v2.0-rc.1
- updated tagcopier post index plugin to v2.0-rc.1
- updated autoclean post index plugin to v0.0.2
    - Windows support
- updated autotag post index plugin to v2.0-rc.1
- updated indexdiff post index plugin to v2.0-rc.1
- updated diskoverd to v2.0-rc.4
    - added checks for Python command and diskover directory config settings
    - fixed issue with setting alternate config directory not getting used if use default config is checked in index task
    - fixed issue with task starting when already running and hasn't finished
    - fixed thread lock issues
- updated s3 alt scanner to v0.0.7
- updated media info plugin to v0.0.11
    - added config.yaml file to configs_sample/diskover_mediainfo_plugin/ directory, see top of file where to copy
    - options in config for "human friendly" formating for bitrate and duration
- updated dir cache alt scanner to v0.0.3
- log file names
- updated Windows file owner plugin to v0.0.3
    - added sid cache to improve performance
    - primary group is also now indexed
    - INC_DOMAIN variable at top of script to control if domain name is included in owner/group name


# [2.0-rc.4-1] - 2022-02-28
### fixed
- issue with slow indexing from hardlink checking, updated diskover.py to v2.0-rc.4-5
- issue with tag copier post-index plugin, updated diskover_helpers.py
### added
### changed


# [2.0-rc.4] - 2022-02-18
### BREAKING CHANGES
- autoclean config new settings movePreservePath, copyPreservePath, see default/sample config and copy to your config
- if using diskoverd api auth, auth will fail until api password changed on diskover-web settings page after logging in as admin, password now required to be hashed and stored in sqlite db
### fixed
- issue with scanning multiple top paths and multiple top directory docs getting indexed for each toppath
- issue with scanning multiple top paths and log output showing incorrect paths still being scanned for each top path
- issue where at the start of scanning, if one of the subdir threads started has permission denied, would cause the scan to fail
- issue with setting domain to True in ownersgroups section in diskover config would case the scan to fail
- UnicodeEncodeError exception when logging Unicode utf-8 file path warnings
- issue when using cache db and diskover crashes from an unhandled Exception causing a corrupt sqlite cache db file
- issue with finding latest index from toppath and indices with multiple top paths
- issue where scanning a toppath with only few files and no subdirs hangs at start of scan when threaddirdepth set to empty/blank
- optimized thread dir depth to not include any empty directories when threaddirdepth set to empty/blank and determining thread depth
### added
- dir_depth, size_norecurs, size_du_norecurs, file_count_norecurs, dir_count_norecurs to ES index field mappings
    - additional fields added to directory docs
### changed
- hardlink files size_du (allocated size) set to 0 when same inode already in scan
- indexing unrecognized Unicode utf-8 characters in file name or parent path, the characters are replaced with a ? character and file gets indexed with a warning log message
    - previously the file/directory was not indexed and just skipped with a warning message
- updated diskoverd to v2.0-rc.3-2
    - fixed issue with stop task could cause diskoverd to stop working on new tasks
    - fixed issue if diskoverd crashes, task list doesn't get set to empty list when diskoverd starts up next
    - fixed issue when network connection timeout would cause diskoverd to stop working
- updated diskover_cache to v0.0.6
    - fixed issue causing fatal error when config set to load db cache into memory when running on python 3.6
    - fixed issue with cache hit ratio not always logging
- updated scandir_dircache alt scanner to v0.0.2
    - bug fix causing scan to fail with UnicodeEncodeError
- updated autoclean to v0.0.1-b.14
    - added copy action, see default/sample config
    - added movePreservePath and copyPreservePath settings to default/sample autoclean config - preserve source's full path when moving or copying a directory or file when using move or copy action, copy from sample config to your config file
    - improved custom action to display realtime output of command in log
    - added more logging info including delete/copy/move speed when running in verbose


# [2.0-rc.3-5] - 2022-01-13
### fixed
- issue when using replace paths in diskover config would cause scanning to fail
- issues with threaddirdepth
### added
### changed
- maxthreads config setting when left empty/blank, now sets to cpu cores, previously was cpu cores x 2
- threaddirdepth config setting max limit is now 3, previously was unlimited
- threaddirdepth config setting when left empty/blank, now sets to a max limit of 3 directory depth, previously was unlimited


# [2.0-rc.3] - 2021-12-27
### fixed
- issue with using a list of ES nodes (cluster) for Elasticsearch host setting in config file
- issue with auto tags not applying to any new fields added with alt scanners or by plugins
- issue with auto tags not tagging docs that match tag patterns
- if an unhandled error occurred, diskover would not exit without keyboard interupt
### added
- Elasticsearch compression setting in default/sample diskover config, see default/sample config and copy to your diskover config file
- indices now tokenize camel case in file names and paths
- Windows file owner indexing plugin
- optional function name "init" used by alt scanners to set up connections to api, get env vars, etc.
- optional function name "close" used by alt scanners to close dbs, etc.
- scanndir_dircache alt scanner v0.0.1
- --threads and --walkthreads cli options, overrides maxthreads and maxwalkthreads config settings
- --threaddepth cli option, overrides threaddirdepth config setting
- slowdirtime and slowdirtimestopscan to default/sample diskover config, copy to your config
    - directories that are taking more than slowtime to scan you can set to stop scanning
- threaddirdepth to default/sample diskover config, copy to your config
    - set depth level for threads to be started for each subdir at depth level N from top path
### changed
- default/sample diskover config autotag pattern rules
    - autotag rules for cleanlist now match diskover-web dashboard "Files on Clealist"
- default/sample diskover config directory excludes
- maxwalkthreads and maxthreads diskover config settings now default to auto set based on number of cpus when leaving config settings blank, see default/sample config file
- updated scandir_s3 alt scanner to v0.0.6
    - added init and close functions
    - minor performance improvements
- updated diskoverd to v2.0-rc.2
    - added username/password auth to work with diskover-web REST API auth
    - added apiuser, apipass to config, see default/sample diskoverd config file and copy to your config
    - bug fixes
- updated Docker files to use linuxserver.io diskover docker container as base
- updated media info plugin to v0.0.10
    - changed index field mappings for better searchability
    - minor updates and improvements
- updated diskover_cache module to v0.0.5
    - added cache hits, misses, hit ratio to log output
    - minor updates and improvements
- removed merge top paths post indexing plugin: plugins_postindex/diskover-mergepaths.py
- improved crawl performance
    - improved directory scanning threading
    - a thread is started for each subdir at directory depth level N using new config setting threaddirdepth, previously was only level 1 subdirs (up to maxthreads)
    - other optimizations


# [2.0-rc.2] - 2021-10-19
### fixed
- issues with diskoverd (see changed)
### added
- cli option -r --removefromindex to remove top path(s) from an index
### changed
- set specific versions of python pip modules in requirements txt files
- added boto3 python pip module to requirements-aws.txt
- updated diskoverd to v2.0-rc.1
    - added system load average to stats output and api call
    - added workerpools config option to default/sample config, copy to your diskoverd config file
        - setting for worker pools
    - added ability for diskoverd to be able to stop tasks
    - fixed issues running in Windows
    - other minor bug fixes and improvements


# [2.0-rc.1] - 2021-10-10
### note
- if upgrading from version older than v2.0-b.11, please see v2.0-b.11 changelog
### fixed
- issue where stats output for dir count would decrease if excluded empty dirs was set to True and empty dir was found
- issue with directory docs directory count when using directory excludes
### added
### changed
- updated autoclean plugin to v0.0.1-b.10
    - bug fixes and improvements


# [2.0-b.11] - 2021-09-30
### fixed
- memory leak/ high memory usage
- occasional issue with diskover.py exiting before all es bulk uploads completed
- issue with using alt config for plugins and setting env var with - (hyphen) in name
- issue with directory docs and incorrect number in dir_count field
### added
- improved crawl performance
- new directory plugins_postindex/
- rawstrings to autotag and storagecost sections in diskover default/sample config, copy to your config
- https and httpcompress settings to elasticsearch section in diskover default/sample config, copy to your config
    - for AWS ES you will want to set these both to True, previous aws setting has been removed
- merge top paths post indexing plugin diskover-mergepaths v0.0.1
    - plugins_postindex/diskover-mergepaths.py
    - merges multiple top paths in an index into a single unified path
### changed
- moved all post indexing plugins into plugins_postindex/ directory
- renamed configs/ directory to configs_sample/
    - contains default/sample config files
- updated all post indexing plugins to use _ (underscore) instead of - (hyphen)
    - this will affect all plugins config directories, you will need to rename your config directories to use _ instead of - and change the appName setting at top of configs to use _ instead of - (see configs_sample/ directory for sample/default configs)
- updated diskoverd to v2.0-b.11
    - improved task status update emails
    - minor updates and improvements
- minor updates to docker files
- updated diskover-autoclean plugin to v0.0.1-b.9
    - changed move functionality to support absolute paths as well as relative, see sample config in configs_sample/diskover_autoclean/config.yaml
- updated media info plugin to v0.0.9
    - added explicit es index mappings to allow for improved search
- set diskover default/sample config bulksize setting to 1000, previously was 5000
- set diskover default/sample config maxthreads setting to 20, previously was 40
- set diskover-dupesfinder default/sample config maxthreads setting to 20, previously was 40
- removed hash es index field mapping
- removed separate threads used for es bulk uploading, crawl threads now do the bulk uploads to es
- updated auto tagging and storage costs
    - see default/sample diskover config and update your config
    - uses python re.search (regex)
    - when using wildcard * at start and end of string, only the * at start of string is now removed (* at start of string causes python re.search exception)
    - when using wilcard * at start or end of string, ^ and $ are no longer used to replace *
- removed aws setting from diskover default/sample config, remove from your config


# [2.0-b.10] - 2021-08-26
### fixed
- number of dirs count for top directory's finishing crawling log output
- ES bulk index error would cause diskover to print Exception but continue to run and consume memory, now any bulk index error will log the error and exit
- occasionnaly ino (inode) field in ES doc would be scientific notation number for large inode numbers, set ino to be string type in python before indexing doc
### added
- diskover-autoclean plugin
### changed
- updated diskover-dupes-finder plugin to v2.0-b.10
    - fixed issue with path translations when using translate paths in config
- updated diskoverd to v2.0-b.8
    - fixed issue with service not starting on boot when running on same host as diskover-web (nginx) and Elasticsearch and those services starting after diskoverd service
    - fixed issue with not retrying from no valid repsonse from api due to internet/dns issue causing diskoverd to stop working correctly
    - fixed issue with task that retries and completes successfully is marked as failed
    - fixed occasional issue when tasks scheduled at same time and not setting env vars or custom index env var correctly for task
    - added random short sleep time to start of tasks so tasks scheduled for same time don't all start at once
- updated diskover-autoclean plugin to v0.0.1-b.6
    - added seperate thread for es index updates
    - fixed issue where no latest index found if trailing / on path when using -l cli option
    - fixed issue with log showing WARNING - Connection pool is full, discarding connection
    - added config setting deletedirsrecursive, copy from default config to your config
        - control whether to delete directories recursively or just files in directory without removing the whole directory tree
        - defaults to just delete files in directory wihtout recursion
    - added stats at end to log items processed, size freed up, etc
- updated diskover-tagcopier plugin to v2.0-b.7
    - added additional logging for verbose
    - added excludeautotags setting to default config, copy to your config
- requirements-aws.txt elasticsearch to elasticsearch>=7.0.0,<7.14
    - ES client 7.14 introduced check and error message when connecting to AWS ES (OpenSearch)


# [2.0-b.9] - 2021-07-07
### fixed
- plugin errors causing indexing to fail and skip directories
- restore times enabled in config and using altscanner would cause error
- alt scanner directory docs additional metadata/ tags not getting added to doc
- excluded directory in diskover config with trailing slash not getting excluded
- index mapping issues for spaceinfo and indexinfo docs
- crawl thread locking issues
- issue with dir item counts when using excludes
### added
- name.text and parent_path.text text type fields
    - secondary fields for name and parent_path keyword fields
    - allows for full-text search including case-insensitive and token splitting on path characters like / - _ , etc
    - this should help to reduce heavy ES operations using wildcard * at start of queries
- enabled http gzip compression of bulk data uploads to Elasticsearch in AWS
- scripts/task-postcommands-example.sh bash script
    - example diskover-web task panel index task post command bash script
- custom exit code 64 if index completes successfully but with warnings
- directory count to crawl stats log output
- additional warnings log file when logging to file is enabled in config to log any warnings or errors
- diskover log file names now contain top dir args (directory basenames) as well as datestamp
- support for up to Elasticsearch v7.10.2, recommended to update/upgrade (now default install version)
- support for up to python client for Elasticsearch v7.13.1
    - upgrade by running "pip3 install --upgrade elasticsearch" in diskover directory
- skipped files/dirs are logged when using verbose options, as well as when running in debug logging
- --debug cli option to output in debug mode (overrides config setting)
### changed
- stat outputs inodes/sec instead of files/sec
- indexing plugins now require two new functions named init and close
- removed --usecache and --flushcache cli options
- removed cachedir and cacheexpiretime settings from default/sample diskover config, remove from your config
- updated mediainfo plugin to v0.0.8
    - added additional video extensions
    - added 20 second timeout for ffprobe subprocess since ffprobe would hang on very large files
    - added tagging for "bad files" which can not be properly opened by ffprobe
    - fixed issue where ffprobe error/exitcode 1 could cause indexing to fail and skip directories
    - added init and close functions
    - added verbose setting at top of plugin to enable more verbose logging
    - added media info sqlite3 db caching
- updated unixperms plugin to v0.0.3
    - added init and close functions
- updated diskoverd to v2.0-b.4
    - added running time
    - fixed issue with working time, successful task count and failed task count getting set incorrect
    - fixed issues with disabling task worker
    - fixed issue with DISKOVERDDIR env var config directory not getting set when using default config and another previous task set a different custom config directory
    - fixed issue with a successful retry attempt to run task setting the task status to failed
    - added kill signal SIGTERM check to cleanly quit worker
    - allows for {indexname} var in post-crawl command args in diskover-web index task
    - improved logging including daily log rotation
    - added api connection retry
    - other minor fixes and improvements
- updated diskover-tagcopier plugin to v2.0-b.4
    - added -a --autoindexfrom cli arg which finds index_from (previous index) based on index_to's top paths
    - fixed issue causing crash when no matching inode found in target index
    - minor updates and improvements
- updated diskover-cache to v0.0.4
    - fixed issue with disabling diskover file logging
    - minor improvements
- updated diskover-dupes-finder plugin to v2.0-b.9
    - made default output less verbose, use -v or -V for more verbose output
    - added cli option --useindexauto to auto-find previous index for file hash lookups based on index arg's top paths
    - minor updates and improvements
- updated diskover-autotag plugin to v2.0-b.5
    - minor updates and improvements
- updated scandir_s3 alt scanner to v0.0.5
    - fixed issue with logging and errors/warnings not getting added to end crawl stats


# [2.0-b.8] - 2021-05-11
### fixed
- permission issues scanning directories over cifs/smb causing indexing to fail
- es bulk upload unicode error from bad characters in file names causing indexing to fail
- memory leak caused by scan error
- scan error causing scan to never finish when exluding empty dirs and top root dir has only excluded files in excluded file list
- extra index mappings for plugins being added to index when plugin disabled or all plugins disabled
### added
- check if Elasticsearch is running and display error message if not
- requests python library to requirements.txt and requirements-win.txt, install using pip3 install requests
- added new config setting maxwalkthreads in default/sample diskover config file (copy to your diskover config)
- pywin32 py module added to requirements-win.txt, install with pip if crawling in Windows
- psutil py module added to requirements-win.txt, install with pip if crawling in Windows
- memory usage and scan thread info to log output
- can now stop a long crawl with keyboard interupt (ctrl+c) and have the index usable in diskover-web
- added --version to cli options to print version number for all py scripts
- added -v and -V cli options for --verbose and --vverbose to most py scripts
### changed
- no longer hardcoded 4 for tree dir threads, can be set using diskover config setting maxwalkthreads (for multiple tree_dir args)
- updated diskover_cache to v0.0.2
    - use md5 hashed paths instead of inode numbers in sqlite db (if previously using cache, old sqlite db are not compatible)
- alternate scanners now use size_du (allocated) size instead of always assigning size_du to size
- updated diskoverd to v2.0-b.2
    - fixed issue where tasks could get enqueued and ran multiple times for same scheduled time
    - reduced number of normal info log ouput
    - added new config settings in default/sample diskoverd config file (copy to your diskoverd config)
        - diskoverpath
        - sendemail
    - changed time to look for new tasks from 60 sec to 15 sec
    - fixed issue with scheduled tasks not getting ran more than first time
    - status emails now contain timezones for printed times
    - added support for alt scanner option on diskover-web new index task
- updated diskover-autotag to v2.0-b.4
    - fixed issue with muli-match rules not adding all tags
    - added -a --addtags cli option
- updated scandir_s3 alt scanner to v0.0.4
    - added st_sizedu to be compatible with change in diskover
    - fixed issue when scanning top prefix “directory” that is empty causes scan to crash
    - fixed issue when scanning top prefix "directory" that all items are excluded causes scan to crash
    - added ability to set endpoint url using env var S3_ENDPOINT_URL
- updated diskover-dupes-finder to v2.0-b.7
    - updated to work with new version of diskover_cache
- updated diskover-tagcopier to v2.0-b.2
    - a few minor updates


# [2.0-b.7] - 2021-03-08
### fixed
- issue with crawling Windows drive maps or unc paths and top path directory not getting indexed correctly
- diskover-dupes-finder Exception error if file in index being hashed not longer exists
### added
- diskoverd.py, a task daemon for running scheduled tasks on diskover-web
    - configs/diskoverd/config.yaml, copy to config directory, example on Linux ~/.config/diskoverd/config.yaml
- better error logging for restoring times when running dupes finder
- croniter py module requirement, install with pip3
- Docker files for getting running in Docker
- scanners/ directory for storing alternate python scanner modules, use with --altscanner cli option
- --altscanner cli option for using alternate scanner module, sample s3 scanner module in scanners/
- --verbose and --vverbose cli options
- diskover_cache.py, a module for sqlite3 db cacheing
- --usecache and --flushcache cli options, uses diskover_cache module for storing directory mtimes, use with --usecache previndexname
- cachedir and cacheexpiretime to diskover default/sample config, copy to your config the new changes
- scandir_s3 scanner module to scan s3 buckets, use with diskover.py --altscanner scandir_s3 s3://bucketname
    - you will need boto3 py module, install with pip3 install boto3
    - you will need to set up aws credentials for boto3
    - https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html
    - https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html
### changed
- updated diskover-dupes-finder to v2.0-b.6
    - removed -v cli option, just --verbose and --vverbose for verbose output
    - removed usecache from diskover-dupes-finder default/sample config, just uses --usecache cli option now
    - added cacheexpiretime to diskover-dupes-finder default/sample config, copy to your config the new changes
    - changed cli option -e --emptycahe to -f --flushcache
    - cache now uses diskover_cache module for cacheing hashes to db when using --usecache cli option


# [2.0-b.6] - 2021-02-09
- added -m --maxdepth for limiting maximum depth to descend down directory tree
- added Windows support for crawling UNC paths
- changed Windows drive map crawling to set different top/root path depending on drive being scanned, example /z_drive for Z:\
- updated diskover-dupes-finder to v2.0-b.5
    - added restoretimes (restore atime/mtime afer file checksum) config option, copy from default dupes-finder config
    - Windows support
    - added replacepaths section in config, copy from default dupes-finder config
    - added current directory output during dupes scanning when running in verbose mode -v
    - added --vverbose (more verbose output) cli option
    - set default config minsize (min file size) to 1 (prev was 0)
    - fixed issue with prev mtime not being compared to new mtime when using prev index for hashes with -U


# [2.0-b.5] - 2021-01-25
- added ability to use plugins (python) to add extra meta data to index and plugins/ directory (location of plugins)
- added plugins section to default diskover config, copy to your config
- added new cli option -l --listplugins to list plugins
- added config path output at start of crawl for diskover, diskover-dupes-finder and diskover-autotag
- added check for config file exists for diskover, diskover-dupes-finder and diskover-autotag
- added new config section "diskover > other" to default config file, copy to your config
- added restoretimes option to default config to restore atime/ctime during crawl (if using nfs, it's ideal to use ro,noatime,nodiratime mount options instead of this), copy to your config
- fixed bug which caused Exception when trying to index a directory with no items (empty dir)
- improved Windows crawling time
- removed dependency of pywin32 for Windows crawling
- changed Windows indices to just set owner and group fields to 0 (trying to get owner/group name doubled crawl time, pywin32 is slow)
- added diskover-tagcopier v2.0-b.1
    - copies tags from one index to another, copy default config file from configs/diskover-tagcopier/
- updated diskover-dupes-finder to v2.0-b.4
- updated diskover-autotag to v2.0-b.3


# [2.0-b.4] - 2021-01-20
- fixed bugs with crawling in Windows
- fixed bug with enabling skip empty dirs in config
- fixed bug with some directories showing incorrect stat info
- added min ctime/ max ctime and min atime/ max atime to default diskover config (copy to your config)
- set default config to exclude emptry dirs, empty files (0 byte), exclude certain folders and files to reduce index size/ crawl time (copy to your config)
- added keyboard interupt for Windows crawling
- added os warnings/error count to end crawl stats
- added better default index name when not using -i
- improved crawl performance
- diskover-dupes-finder updated to v2.0-b.3
    - many bug fixes and improvements
    - added ability to scan dupes across multiple indices
    - added export dupe results to csv
    - added ability to use existing index to get file hashes
    - improved file caching of file hashes
    - added option to update all file docs file hash instead of just found dupes


# [2.0-b.3] - 2021-01-03
- added -a option to crawler for adding to an existing index
- fixed issue connecting to AWS ES
- improved crawl performance
- Windows indexing now indexes real file owner names instead of just 0


# [2.0-b.2] - 2020-12-19
- added support for running crawler in Windows
- added ability to crawl multiple paths into single index


# [2.0-b.1] - 2020-12-15
- first v2.0 beta release
