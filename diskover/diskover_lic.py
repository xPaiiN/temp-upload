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


License helper module

************************************************************************************
DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
************************************************************************************

"""

import os
import sys
import base64
import rsa
import optparse
import logging
import warnings
import hashlib
from datetime import datetime

logger = logging.getLogger(__name__)

class License:
    
    def __init__(self):
        self.lic_file = os.path.join(os.path.dirname(__file__), 'diskover.lic')
        self.pem_file = os.path.join(os.path.dirname(__file__), 'diskover_publickey.pem')

        # check license info from license file
        try:
            with open(self.lic_file,'r') as licfile:
                licdata = licfile.read()
        except OSError:
            print('Can\'t find diskover.lic, check license file exists.')
            sys.exit(1)
        
        licdata = licdata.split('\n')
        hwid = gen_hw_id()
        try:
            self.license_email = licdata[0]
            self.validity_period = datetime.strptime(licdata[1], '%Y-%m-%dT%H:%M:%S')
            self.product_name = licdata[2]
            self.product_code = licdata[3]
            self.lic_es_nodes = int(licdata[4])
            self.lic_hardware_id = licdata[5]
            self.license_key = licdata[6]
            self.license_signature = base64.b64decode(self.license_key)
            self.hardware_id = hwid
            self.data = self.license_email + licdata[1] + self.product_code + \
                str(self.lic_es_nodes) + self.hardware_id
        except Exception as e:
            print('Error reading diskover.lic license file. Error: {}'.format(e))
            sys.exit(1)
        
    def is_expired(self):
        if self.days_remaining() == 0:
            return True
        return False
    
    def days_remaining(self):
        dt = datetime.today()
        diff = self.validity_period - datetime.combine(dt, datetime.min.time())
        days_remain = diff.days
        if days_remain < 0:
            days_remain = 0
        if days_remain < 15 and days_remain > 0:
            msg = 'License expires in {} days.'.format(days_remain)
            logger.warn(msg)
        return days_remain
    
    def expiry_date(self):
        return self.validity_period
    
    def check_license(self):
        """
        validate license that it's not expired and key is valid
        """
        # check if expired
        if self.is_expired():
            print('License has expired, contact Diskover to obtain new license.')
            sys.exit(1)
        # check lic file hardware id same as hardware id
        if self.lic_hardware_id != gen_hw_id():
            print('License file hardware id does not match hardware id, contact Diskover to obtain new license.')
            print('License file hw id:')
            print(self.lic_hardware_id)
            print('Hardware id:')
            print(gen_hw_id())
            sys.exit(1)
        # check lic key
        try:
            with open(self.pem_file,'rb') as publicfile:
                keydata = publicfile.read()
        except OSError:
            print('Can\'t find diskover_publickey.pem, check file exists.')
            sys.exit(1)
        pubkey = rsa.PublicKey.load_pkcs1(keydata, format='PEM')
        try:
            rsa.verify(self.data.encode('utf-8'), self.license_signature, pubkey)
        except rsa.VerificationError as e:
            print('Invalid license key, check diskover.lic for valid license. Error: {}'.format(e))
            sys.exit(1)
            
    def check_cluster(self, es):
        """
        check Elasticsearch cluster nodes are licensed
        """
        from diskover_elasticsearch import get_es_cluster_health
        es_cluster_nodes = get_es_cluster_health(es)['number_of_nodes']
        # Check cluster nodes don't exceed licensed es nodes
        if es_cluster_nodes > self.lic_es_nodes:
            logger.error('License Elasticsearch Nodes less than nodes in Cluster.')
            sys.exit(1)
    
    def check_features(self, diskover_globals, diskover_helpers):
        """
        check Diskover features are licensed
        """
        if self.product_code == 'ESS':
            logger.warn('Auto Tag disabled, unlicensed feature.')
            diskover_globals['autotag'] = False
            logger.warn('Storage Cost disabled, unlicensed feature.')
            diskover_helpers.gen_cost = False
 
    def print_lic_info(self):
        print('-----DISKOVER LICENSE INFO-----')
        print('Email: {}'.format(self.license_email))
        print('Key: {}'.format(self.license_key))
        print('HW ID: {}'.format(self.lic_hardware_id))
        print('Product Name: {}'.format(self.product_name))
        print('Product Code: {}'.format(self.product_code))
        print('Elasticsearch Nodes: {}'.format(self.lic_es_nodes))
        print('Expiry Date: {}'.format(self.expiry_date()))
        print('Days Remaining: {}'.format(self.days_remaining()))
        print('Expired: {}'.format(self.is_expired()))
        print('-------------------------------')

def licfc(lic, minprodcode=None, featurename=None):
    """
    check Diskover plugin/altscanner/etc is licensed
    """
    prodidscope = {'ESS': ('ESS'),
                   'PRO': ('ESS', 'PRO'),
                   'ENT': ('ESS', 'PRO', 'ENT'),
                   'LSE': ('ESS', 'PRO', 'ENT', 'LSE'),
                   'ME': ('ESS', 'PRO', 'ENT', 'ME')}
    if minprodcode not in prodidscope[lic.product_code]:
        if featurename:
            logger.error('The {} feature is unlicensed.'.format(featurename))
        else:
            logger.error('This feature is unlicensed.')
        sys.exit(1)

def gen_hw_id():
    """
    generate hardware id
    get es cluster unique id (uuid)
    """
    from diskover_elasticsearch import elasticsearch_connection, get_es_cluster_stats
    # ignore any Elasticsearch warnings
    from elasticsearch import ElasticsearchWarning
    warnings.filterwarnings("ignore", category=ElasticsearchWarning)
    
    es = elasticsearch_connection()
    es_cluster_uuid = get_es_cluster_stats(es)['cluster_uuid']
    
    # set Elasticsearch warnings back to default
    warnings.filterwarnings("default", category=ElasticsearchWarning)
    
    return hashlib.md5(es_cluster_uuid.encode()).hexdigest()   


if __name__ == "__main__":
    usage = """Usage: diskover_lic.py [options]

diskover license helper"""
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-g', '--gethwid', action='store_true', 
                        help='get hardware id')
    parser.add_option('-l', '--licinfo', action='store_true',
                        help='print diskover license info')
    options, args = parser.parse_args()
    
    if not options and not args:
        print('use -h for help')
        sys.exit()
    
    if options.gethwid:
        hwid = gen_hw_id()
        print('-----DISKOVER HARDWARE ID-----')
        print(hwid)
        print('------------------------------')
        
    if options.licinfo:
        lic = License()
        lic.print_lic_info()