#!/bin/bash
#
# diskover-web task panel index task post-crawl script example
#
# Usage:
# Post-Crawl Command input: /bin/bash
# Post-Crawl Command Args input: ./scripts/task-postcommands-example.sh {indexname}
#

# exit when any command fails
set -e

# exit if there are no args
if [ $# -eq 0 ]
  then
    echo "No index argument supplied"
    exit 1
fi

# get index name from arg 1
# arg 1 is {indexname} in diskover-web index task post-crawl command args
INDEXNAME=$1

echo Starting task post commands...

# run diskover tag copier
python3 ./plugins_postindex/diskover-tagcopier.py -a -v $INDEXNAME

# run diskover es field copier
#python3 ./plugins_postindex/diskover-esfieldcopier.py -a -v $INDEXNAME

# run diskover dupes finder
#python3 ./plugins_postindex/diskover-dupesfinder.py -u $INDEXNAME

echo Finished running task post commands.
