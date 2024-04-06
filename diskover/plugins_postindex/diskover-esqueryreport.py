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


diskover ES query report plugin

'''

import sys
import os
import signal
import optparse
import confuse
import logging
import warnings
import csv
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from zipfile import ZIP_DEFLATED, ZipFile
from datetime import datetime

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from diskover_elasticsearch import elasticsearch_connection, check_index_exists
from diskover_helpers import find_latest_index, convert_size
from diskover_lic import License, licfc

plugin_name = 'esqueryreport'
version = '0.1.6'
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
    print('Config file {0} not found! Copy from default config.'.format(config_filename))
    sys.exit(1)

# load diskover default config file
diskover_config_defaults = confuse.Configuration('diskover', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
scriptpath_parent = os.path.abspath(os.path.join(scriptpath, os.pardir))
default_diskover_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover/config.yaml')
diskover_config_defaults.set_file(default_diskover_config_filename)
# load es query report default config file
config_defaults = confuse.Configuration('diskover_{0}'.format(plugin_name), __name__)
default_config_filename = os.path.join(scriptpath_parent, 'configs_sample/diskover_esqueryreport/config.yaml')
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
    csvfile = config['csvfile'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    csvfile = config_defaults['csvfile'].get()
try:
    csvdir = config['csvdir'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    csvdir = config_defaults['csvdir'].get()
try:
    docfields = config['docfields'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    docfields = config_defaults['docfields'].get()
try:
    humansizes = config['humansizes'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    humansizes = config_defaults['humansizes'].get()
try:
    sendemail = config['sendemail'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    sendemail = config_defaults['sendemail'].get()
try:
    sender_email = config['emailfrom'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    sender_email = config_defaults['emailfrom'].get()
try:
    receiver_email = config['emailto'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    receiver_email = config_defaults['emailto'].get()
try:
    email_subject = config['emailsubject'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    email_subject = config_defaults['emailsubject'].get()
try:
    email_msg = config['emailmsg'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    email_msg = config_defaults['emailmsg'].get()
try:
    attachcsv = config['attachcsv'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    attachcsv = config_defaults['attachcsv'].get()
try:
    zipcsv = config['zipcsv'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    zipcsv = config_defaults['zipcsv'].get()
try:
    delcsv = config['delcsv'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    delcsv = config_defaults['delcsv'].get()
try:
    smtp_server = config['smtpserver'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    smtp_server = config_defaults['smtpserver'].get()
try:
    smtp_port = config['smtpport'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    smtp_port = config_defaults['smtpport'].get()
try:
    smtp_security = config['smtpsecurity'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    smtp_security = config_defaults['smtpsecurity'].get()
try:
    smtp_user = config['smtpuser'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    smtp_user = config_defaults['smtpuser'].get()
try:
    smtp_password = config['smtppassword'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    smtp_password = config_defaults['smtppassword'].get()


def log_setup():
    """Setup logging for diskover autotag."""
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


def index_search(es, indexname, query):
    """Searches Elasticsearch index."""
    docs = []
    
    logger.info('es query: {0}'.format(query))

    data = {
        'size': 0,
        'query': {
            'query_string': {
                'query': query,
                'analyze_wildcard': 'true'
            }
        }
    }
    
    es.indices.refresh(index=indexname)

    res = es.search(index=indexname, scroll='1m', size=es_scrollsize,
                    body=data, request_timeout=es_timeout)
    
    totaldocs = res['hits']['total']['value']
    
    logger.info('found {0} matching docs'.format(totaldocs))

    while res['hits']['hits'] and len(res['hits']['hits']) > 0:
        for hit in res['hits']['hits']:
            docsrc = []
            for d in docfields:
                try:
                    field = hit['_source'][d]
                except KeyError:
                     docsrc.append(None)
                     pass
                else:
                    if humansizes and (d == 'size' or d == 'size_du'):
                        docsrc.append(convert_size(field))
                    elif type(field) is list:
                        docsrc.append("; ".join(field))
                    else:
                        docsrc.append(field)
            docs.append(docsrc[:])
            del docsrc[:]

        res = es.scroll(scroll_id=res['_scroll_id'], scroll='1m',
                        request_timeout=es_timeout)
    
    logger.info('Finished searching all index docs matching query')
    return docs


def write_csv(docs):
    """Creates csv file of es docs."""
    global csvfile
    
    csvfile = csvfile.replace('%indexname', index)
    csvfile = datetime.now().strftime(csvfile)
    csvfile = os.path.join(csvdir, csvfile)
    
    row_list = [docfields]
    for docsrc in docs:
        row_list.append(docsrc)
    
    logger.info('Saving report to {0}'.format(csvfile))
    try:
        with open(csvfile, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(row_list)
        logger.info('Done.')
        if zipcsv:
            logger.info('Compressing report {0} ...'.format(csvfile))
            csvfilezip = csvfile + '.zip'
            with ZipFile(csvfilezip, mode='w', compression=ZIP_DEFLATED) as archive:
                archive.write(csvfile, os.path.basename(csvfile))
            logger.info('Done.')
            if delcsv:
                logger.info('Cleaning up csv file {0} ...'.format(csvfile))
                try:
                    os.remove(csvfile)
                    logger.info('Done.')
                except (OSError, IOError) as e:
                    logger.error('Error deleting file: {0}'.format(e))
        return csvfile
    except (OSError, IOError) as e:
        logger.error('Error saving file: {0}'.format(e))


def send_email(csvfile):
    global email_msg, email_subject, receiver_email
    
    msg = MIMEMultipart()
    email_msg = email_msg.replace('%esquery', options.esquery)
    if attachcsv:
        email_msg += '<br>report csv file attached: '
    else:
        email_msg += '<br>csv file: '
    if zipcsv:
        email_msg += csvfile + '.zip'
    else:
        email_msg += csvfile
    email_msg += '<br>'
    msgtext = MIMEText('%s' % (email_msg), 'html')
    msg.attach(msgtext)
    if attachcsv:
        if zipcsv:
            csvfilezip = csvfile + '.zip'
            logger.info('Attaching {0} to email'.format(csvfilezip))
            zip = MIMEApplication(open(csvfilezip, 'rb').read())
            zip.add_header('Content-Disposition', 'attachment', filename=os.path.basename(csvfilezip))
            msg.attach(zip)
            logger.info('Done.')
        else:
            logger.info('Attaching {0} to email'.format(csvfile))
            msg.attach(MIMEText(open(csvfile).read()))
            logger.info('Done.')
    if options.emailsubject:
        email_subject = options.emailsubject
    msg['Subject'] = '{0}'.format(email_subject)
    msg['From'] = sender_email
    if options.emailto:
        receiver_email = ",".join(options.emailto)
    msg['To'] = receiver_email
    logger.info('Emailing report to {0} ...'.format(msg['To']))

    context = ssl.create_default_context()
    try:
        if smtp_security == 'SSL':
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as s:
                s.login(sender_email, smtp_password)
                s.send_message(msg)
        elif smtp_security == 'TLS':
            with smtplib.SMTP(smtp_server, smtp_port) as s:
                s.starttls(context=context)
                s.login(sender_email, smtp_password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(smtp_server, smtp_port) as s:
                s.send_message(msg)
        logger.info('Done.')
    except smtplib.SMTPException as e:
        logger.error('Error sending email: {0}'.format(e))


def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), exiting...'.format(signal.Signals(signum).name))
    sys.exit(signum)


if __name__ == "__main__":
    usage = """Usage: diskover-esqueryreport.py [-h] [index]

diskover es query report v{0}
Searches a diskover Elasticsearch index and generates a csv report.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-q', '--esquery', metavar='ESQUERY', nargs=1, 
                        help='Elasticsearch query string (in quotes), example: "tags:(illegalname OR longname)"')
    parser.add_option('-e', '--emailto', metavar='EMAIL', action='append',  
                        help='Recipient email address, to send to multiple recipients use multiple -e, overrides config setting')
    parser.add_option('-s', '--emailsubject', metavar='SUBJECT',  
                        help='Email subject, overrides config setting')
    parser.add_option('-l', '--latestindex', metavar='TOPPATH',
                        help='auto-finds most recent index based on top path')
    parser.add_option('--version', action='store_true',
                        help='print diskover-esqueryreport version number and exit')
    options, args = parser.parse_args()
    
    if options.version:
        print('diskover-esqueryreport v{}'.format(version))
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
    
    logger.info('Starting diskover es query report ...')

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVER_ESQUERYREPORTDIR: {0}'.format(os.getenv('DISKOVER_ESQUERYREPORTDIR')))

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

    if not options.esquery:
        parser.error('ES query required, use -h for help.'.format(index))
        
    logger.info('Searching index {0}...'.format(index))
    docs = index_search(es, index, options.esquery)
    if docs:
        csvfile = write_csv(docs)
        if csvfile and sendemail:
            send_email(csvfile)
    else:
        logger.info('No docs found matching query!')