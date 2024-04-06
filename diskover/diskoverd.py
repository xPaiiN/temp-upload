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

import optparse
import os
import sys
import time
import logging
import logging.handlers
import confuse
import socket
import json
import shlex
import glob
import subprocess
import uuid
import getpass
import dateutil.tz
import smtplib
import ssl
import signal
import base64
import warnings
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from email.message import EmailMessage
from threading import Thread, Lock, Timer
from queue import Queue
from subprocess import CalledProcessError, TimeoutExpired
from croniter import croniter
from datetime import datetime

from diskover import version as diskover_ver
from diskover_helpers import get_time, get_load_avg, time_duration
from diskover_lic import License, licfc

version = '2.1.10'
__version__ = version


# Windows check
if os.name == 'nt':
    IS_WIN = True
    # Handle keyboard interupt for Windows
    def handler(a,b=None):
        logger.info('*** Received keyboard interrupt, shutting down worker... ***')
        for n in range(workthreads):
            task_q.put('ctrlc')
        stop_all_tasks()
        shutdown_worker()
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

# Python 3 check
IS_PY3 = sys.version_info >= (3, 5)
if not IS_PY3:
    print('Python 3.5 or higher required.')
    sys.exit(1)

"""Load yaml config file."""
config = confuse.Configuration('diskoverd', __name__)
config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
if not os.path.exists(config_filename):
    print('Config file {0} not found! Copy from default config.'.format(config_filename))
    sys.exit(1)
    
# load default config file
config_defaults = confuse.Configuration('diskoverd', __name__)
scriptpath = os.path.dirname(os.path.realpath(__file__))
defaultconfig_filename = os.path.join(scriptpath, 'configs_sample/diskoverd/config.yaml')
config_defaults.set_file(defaultconfig_filename)
    
def config_warn(e):
    warnings.warn('Config setting {}. Using default.'.format(e))

# laod config values
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
    timezone = config['timezone'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    timezone = config_defaults['timezone'].get()
finally:
    tz = dateutil.tz.gettz(timezone)
try:
    workthreads = config['workthreads'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    workthreads = config_defaults['workthreads'].get()
try:
    pythoncmd = config['pythoncmd'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    pythoncmd = config_defaults['pythoncmd'].get()
try:
    diskoverpath = config['diskoverpath'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    diskoverpath = config_defaults['diskoverpath'].get()
try:
    apiurl = config['apiurl'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    apiurl = config_defaults['apiurl'].get()
finally:
    if apiurl[-1] != '/':
        apiurl += '/'
try:
    api_user = config['apiuser'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    api_user = config_defaults['apiuser'].get()
finally:
    if not api_user:
        api_user = ''
try:
    api_pass = config['apipass'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    api_pass = config_defaults['apipass'].get()
finally:    
    if not api_pass:
        api_pass = ''
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
try:
    sender_email = config['senderemail'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    sender_email = config_defaults['senderemail'].get() 
try: 
    sendemail = config['sendemail'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    sendemail = config_defaults['sendemail'].get()
try: 
    sendemaillongruntask = config['sendemaillongruntask'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    sendemaillongruntask = config_defaults['sendemaillongruntask'].get()
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
    workerpools = config['workerpools'].get()
except confuse.NotFoundError as e:
    config_warn(e)
    workerpools = config_defaults['workerpools'].get()
    

def receive_signal(signum, frame):
    # handle kill
    logger.info('Received signal ({}), shutting down worker...'.format(signal.Signals(signum).name))
    for n in range(workthreads):
        task_q.put('ctrlc')
    stop_all_tasks()
    shutdown_worker()
    sys.exit(signum)


def close_app_critical_error():
    # handle cirtical error
    logger.critical('CRITICAL ERROR EXITING')
    for n in range(workthreads):
        task_q.put('ctrlc')
    stop_all_tasks()
    shutdown_worker()
    sys.exit(1)


def get_workername():
    # check env var
    if os.getenv('DISKOVERD_WORKERNAME'):
        workername = os.getenv('DISKOVERD_WORKERNAME')
    elif options.name:
        workername = options.name
    else:
        # set workername to a string containing <hostname>_<5 char unique id>
        workername = socket.gethostname() + '_' + str(uuid.uuid1()).split('-')[0]
    return workername


def banner():
    """Print the banner."""    
    print("""\u001b[36;1m
            _ _     _                       
           | (_)   | |                      
         __| |_ ___| | _______   _____ _ __ 
        / _` | / __| |/ / _ \ \ / / _ \ '__| /)___(\\
       | (_| | \__ \   < (_) \ V /  __/ |    (='.'=)
        \__,_|_|___/_|\_\___/ \_/ \___|_|   (\\")_(\\")

            diskoverd v{0} task worker daemon
            PID: {1}
            worker name: {2}
            https://diskoverdata.com

    \u001b[0m""".format(version, os.getpid(), get_workername()))
    sys.stdout.flush()


# shutdown signal sent by worker thread
shutdown_sig_sent = False
all_current_tasks = []
all_tasksproc = {}


class Worker:
    
    def __init__(self, name):
        self.name = name
        self.hostname = socket.gethostname()
        self.user = getpass.getuser()
        self.pid = os.getpid()
        self.current_tasks = []
        self.status = self.get_worker_status()
        self.successful_task_count = 0
        self.failed_task_count = 0
        self.total_working_time = 0
        self.total_running_time = 0
        self.load = get_load_avg()
        self.workerpools = workerpools
        self.tasksproc = {}
        self.stoptasks = []
        self.taskstimedout = {}
        self.longruntasks = []
        # register and update worker with api
        self.update_worker()
        
    def runtime_stats(self):
        time.sleep(60)
        while True:
            # get updated load,cpu,mem
            self.load = get_load_avg()
            # output stats every 60 seconds
            self.total_running_time += 60
            logger.info('[{0}][get_tasks] [summary] tasks : {1} running, {2} completed, {3} failed, {4} working time, {5} running time, resources : load avg {6}'.format(
                self.name, len(self.current_tasks), self.successful_task_count, self.failed_task_count, get_time(self.total_working_time),
                get_time(self.total_running_time), self.load))
            self.update_worker()
            time.sleep(60)
    
    def heartbeat(self):
        time.sleep(120)
        while True:
            # send heartbeat every 2 min to diskover-web api
            logger.debug('[{0}] Sending heartbeat to api..'.format(self.name))        
            data = {
                'name': self.name
            }
            data_json = json.dumps(data).encode('utf-8')
            res = api_req('heartbeat', data=data_json, method='PUT')
            if res is None:
                logger.warning('[{0}] No response for heartbeat'.format(self.name))
            else:
                logger.debug('[{0}] Got response for heartbeat {1}'.format(self.name, res))
            logger.debug('[{0}] Next heartbeat in 2 min'.format(self.name))
            time.sleep(120)
    
    def do_work(self, th_name, task_q, th_lock):
        global all_current_tasks, all_tasksproc
        while True:
            if options.verbose:
                logger.info('[{0}][{1}] Waiting for next task in queue...'.format(self.name, th_name))
            task = task_q.get()
            # check if worker shutting down
            if shutdown_sig_sent:
                if options.verbose:
                    logger.info('[{0}][{1}] Worker shutting down, stopping to look for tasks'.format(self.name, th_name))
                task_q.task_done()
                break
            # check for keyboard interupt
            if task == 'ctrlc':
                if options.verbose:
                    logger.info('[{0}][{1}] Found ctrlc in queue, stopping to look for tasks'.format(self.name, th_name))
                task_q.task_done()
                break
            logger.info('[{0}][{1}] Started working on task {2}...'.format(self.name, th_name, task['id']))
            with th_lock:
                if task['id'] not in self.current_tasks:
                    logger.info('[{0}][{1}] Adding task {2} to current tasks list'.format(self.name, th_name, task['id']))
                    self.current_tasks.append(task['id'])
                    all_current_tasks.append(task['id'])
                self.status['state'] = 'busy'
                if task['id'] in self.longruntasks:
                    self.longruntasks.remove(task['id'])
            start_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
            # update task
            task_status = 'starting'
            self.update_task(task, th_name, status=task_status, start_time=start_time)
            # update worker
            self.update_worker()
            # update task
            task_status = 'running'
            self.update_task(task, th_name, status=task_status, start_time=start_time)
            start = time.time()
            # run task and get result
            res, errmsg = self.run_task(task, th_name, th_lock)
            finish = time.time()
            finish_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
            elapsed_time = finish - start
            with th_lock:
                self.total_working_time += elapsed_time
            if res == 0:
                task_status = 'finished'
                with th_lock:
                    self.successful_task_count += 1
                self.update_task(task, th_name, status=task_status, finish_time=finish_time, success_finish_time=finish_time)
            elif res == 64:
                task_status = 'warning'
                with th_lock:
                    self.successful_task_count += 1
                self.update_task(task, th_name, status=task_status, finish_time=finish_time, success_finish_time=finish_time)
            else:
                task_status = 'failed'
                with th_lock:
                    self.failed_task_count += 1
                self.update_task(task, th_name, status=task_status, finish_time=finish_time, err_msg=errmsg)
            logger.info('[{0}][{1}] Finished task {2} in {3} (status {4})'.format(
                self.name, th_name, task['id'], get_time(elapsed_time), task_status.upper()))
            # add task to task log (task history)
            self.task_log(task, th_name, task_status, start_time, finish_time, elapsed_time, errmsg)
            # send task update email
            self.send_email(task, th_name, task_status, start_time, finish_time, elapsed_time, errmsg)
            # remove task from task list
            with th_lock:
                logger.info('[{0}][{1}] Removing task {2} from current tasks list'.format(self.name, th_name, task['id']))
                self.current_tasks = [i for i in self.current_tasks if i != task['id']]
                all_current_tasks = [i for i in all_current_tasks if i != task['id']]
            # set state to idle if task list is empty and not disabled
            if not self.current_tasks and not self.status['disabled']:
                with th_lock:
                    self.status['state'] = 'idle'
            self.update_worker()
            if options.verbose:
                logger.info('[{0}][{1}] Finished task {2}'.format(self.name, th_name, task['id']))
            task_q.task_done()

    def get_tasks(self, task_q, th_lock):
        """Gets tasks from diskover-web api and enqueues them to be worked on
        checks for new tasks every 10 sec
        """

        # start work loop
        while True:
            # check if worker is shutting down
            if shutdown_sig_sent:
                if options.verbose:
                    logger.info('[{0}][get_tasks] Worker is shutting down, stopping to look for tasks.'.format(self.name))
                break
            # get worker status from api
            worker_status = self.get_worker_status()
            with th_lock:
                self.status = worker_status
            # check if api returns no worker data
            if self.status is None:
                logger.critical('[{0}][get_tasks] No worker data from api, will try again in 10 sec...'.format(self.name))
                time.sleep(10)
                continue
            # check if worker is disabled
            if self.status['disabled']:
                if options.verbose:
                    logger.info('[{0}][get_tasks] Worker is disabled, will check again in 15 sec...'.format(self.name))
                time.sleep(15)
                continue
            # look for new task
            if options.verbose:
                logger.info('[{0}][get_tasks] Looking for new tasks...'.format(self.name))
            # get data from api
            res = api_req('tasks')
            logger.debug(res)
            if not res['message']['data']:
                logger.critical('[{0}][get_tasks] Error: No tasks data returned from api!'.format(self.name))
                close_app_critical_error()
            if options.verbose:
                logger.info('[{0}][get_tasks] Found {1} tasks'.format(self.name, len(res['message']['data']['tasks'])))
            # go through list of tasks and see if there are any we should work on
            for task in res['message']['data']['tasks']:
                id = task['id']
                # check which worker task is assigned to
                if task['assigned_worker'] in ("any", None, self.name) or task['assigned_worker'] in workerpools:
                    if options.verbose:
                        logger.info('[{0}][get_tasks] Found task id {1} for worker {2}'.format(
                            self.name, id, task['assigned_worker']))
                else:
                    if options.verbose:
                        logger.info('[{0}][get_tasks] Skipping task id {1}, task assigned to worker {2}'.format(
                            self.name, id, task['assigned_worker']))
                    continue
                # check if stop task sent
                if self.check_stop_task(task):
                    with th_lock:
                        if id not in self.stoptasks:
                            self.stoptasks.append(id)
                    continue
                else:
                    with th_lock:
                        if id in self.stoptasks:
                            try:
                                self.stoptasks.remove(id)
                            except ValueError:
                                pass
                # check if task taking a long time to run
                if self.check_task_running(task) and self.check_longrun_task(task):
                    with th_lock:
                        if id not in self.longruntasks:
                            self.longruntasks.append(id)
                # check if task is disabled
                if task['disabled']:
                    if options.verbose:
                        logger.info('[{0}][get_tasks] Skipping task id {1}, task is disabled'.format(self.name, id))
                    continue
                # check if already working on this task
                if self.check_task_running(task):
                    if options.verbose:
                        logger.info('[{0}][get_tasks] Skipping task id {1}, task is currently running'.format(
                            self.name, id))
                    continue
                # check task time
                if not self.check_task_time(task):
                    continue
                # check if task is in correct status to be worked on
                if self.check_task_status(task):
                    if options.verbose:
                        logger.info('[{0}][get_tasks] Skipping task id {1}, task status {2}'.format(
                            self.name, id, task['last_status']))
                    continue
                # check if another worker already working on or completed this task
                if self.check_task_worker(task):
                    if options.verbose:
                        logger.info('[{0}][get_tasks] Skpping task id {1}, already assigned to {2}'.format(
                            self.name, id, task['last_worker']))
                    continue
                # check if queue is full
                if task_q.full():
                    if options.verbose:
                        logger.info('[{0}][get_tasks] Skipping task id {1}, task queue full (queue size/maxsize (workthreads): {2}/{3})'.format(
                            self.name, id, task_q.qsize(), workthreads))
                    continue
                # add task to queue
                if options.verbose:
                    logger.info('[{0}][get_tasks] Enqueuing task id {1}'.format(self.name, id))
                task_q.put(task)
            if options.verbose:
                logger.info('[{0}][get_tasks] Waiting 10 sec to look for new tasks...'.format(self.name))
            time.sleep(10)


    def work(self):
        """Start threads for getting tasks, heartbeat, runtime stats, and doing work."""
        Thread(daemon=True, target=self.get_tasks, args=(task_q, th_lock,)).start()
        Thread(daemon=True, target=self.heartbeat).start()
        Thread(daemon=True, target=self.runtime_stats).start()
        # start n work threads
        threads = []
        for n in range(workthreads):
            th_name = 'do_work_thread_' + str(n)
            th = Thread(target=self.do_work, args=(th_name, task_q, th_lock,))
            threads.append(th)
            th.start()
        try:
            for thread in threads:
                thread.join()
        except KeyboardInterrupt:
            logger.info('Received keyboard interrupt, shutting down worker...')
            for n in range(workthreads):
                task_q.put('ctrlc')
            stop_all_tasks()
            shutdown_worker()
            sys.exit(1)

    
    def check_task_time(self, task):
        run_min = task['run_min']
        run_hour = task['run_hour']
        run_day_month = task['run_day_month']
        run_month = task['run_month']
        run_day_week = task['run_day_week']
        try:
            run_now = task['run_now']
        except KeyError:
            run_now = False
            pass
        
        if run_now:
            logger.info('[{0}][get_tasks] Task {1} set to run now (manual run/queued)'.format(self.name, task['id']))
            return True
        local_date = datetime.now(tz)
        if options.verbose:
            logger.info('[{0}][get_tasks] Time now {1}'.format(self.name, local_date))
        match = croniter.match('{} {} {} {} {}'.format(run_min, run_hour, run_day_month, run_month, run_day_week), local_date)
        next_time = croniter('{} {} {} {} {}'.format(run_min, run_hour, run_day_month, run_month, run_day_week), local_date).get_next(datetime)
        if options.verbose:
            logger.info('[{0}][get_tasks] Task {1} next run time scheduled for {2}'.format(self.name, task['id'], next_time))
        if match:
            if options.verbose:
                logger.info('[{0}][get_tasks] Task {1} matches time now'.format(self.name, task['id']))
            return True
        if options.verbose:
            logger.info('[{0}][get_tasks] Task {1} does not match time now'.format(self.name, task['id']))
        return False
    
    def check_task_worker(self, task):
        """Check if another worker already working on or completed this task."""
        # check if task has never been run (new task)
        if task['last_start_time'] is None:
            return False
        
        now = datetime.utcnow()
        last_start = datetime.strptime(task['last_start_time'], '%Y-%m-%dT%H:%M:%S')
    
        if now.day == last_start.day and now.hour == last_start.hour and now.minute == last_start.minute:
            match = True
        else:
            match = False
            
        if task['last_worker'] is not None and match:
            return True
        return False
    
    def check_task_status(self, task):
        """Check if task is in correct status to be worked on."""
        if options.verbose:
            logger.info('[{0}][get_tasks] Task {1} status is {2}'.format(self.name, task['id'], task['last_status']))
        if task['last_status'] in ('starting', 'running'):
            return True
        return False
    
    def check_task_queue(self, task):
        """Check if task is in queue."""
        for item in list(task_q.queue):
            if item['id'] == task['id']:
                return True
        return False
    
    def check_task_running(self, task):
        """Check if task is running."""
        if task['id'] in self.current_tasks:
            return True
        return False
    
    def update_task(self, task, th_name, status=None, start_time=None, finish_time=None, success_finish_time=None, 
                    err_msg=None):
        id = task['id']
        logger.debug('[{0}][{1}] Updating api for task id {2}'.format(self.name, th_name, id))   
        run_now = False
        stop_task = False
        stop_task_force = False
        data = {
            'id': id,
            'worker': self.name,
            'status': status,
            'start_time': start_time,
            'finish_time': finish_time,
            'success_finish_time': success_finish_time,
            'run_now': run_now,
            'stop_task': stop_task,
            'stop_task_force': stop_task_force, 
            'error': err_msg
        }
        data_json = json.dumps(data).encode('utf-8')
        res = api_req('updatetask', data=data_json, method='PUT')
        logger.debug(res)
        
    def update_worker(self):
        if self.status is None or shutdown_sig_sent:
            return
        logger.debug('[{0}] Updating api with worker info'.format(self.name))   
        data = {
            'name': self.name,
            'hostname': self.hostname,
            'user': self.user,
            'pid': self.pid,
            'state': self.status['state'],
            'current_tasks': self.current_tasks,
            'successful_task_count': self.successful_task_count,
            'failed_task_count': self.failed_task_count,
            'total_working_time': self.total_working_time,
            'total_running_time': self.total_running_time,
            'load_avg': self.load,
            'worker_pools': self.workerpools,
            'diskover_ver': diskover_ver,
            'diskoverd_ver': version
        }
        data_json = json.dumps(data).encode('utf-8')
        res = api_req('updateworker', data=data_json, method='PUT')
        if res is None:
            logger.warning('[{0}] No response for worker update'.format(self.name))
        else:
            logger.debug('[{0}] Got response for worker update {1}'.format(self.name, res))
        
    def task_log(self, task, th_name, status, start_time, finish_time, task_time, error_msg):
        id = task['id']
        logger.debug('[{0}][{1}] Updating api task log for task id {2}'.format(self.name, th_name, id))   
        data = {
            'task_id': id,
            'task_name': task['name'],
            'task_type': task['type'],
            'worker': self.name,
            'start_time': start_time,
            'finish_time': finish_time,
            'task_time': task_time,
            'status': status,
            'error': error_msg
        }
        data_json = json.dumps(data).encode('utf-8')
        res = api_req('tasklog', data=data_json, method='PUT')
        logger.debug(res)
        
    def send_email(self, task, th_name, status, start_time, finish_time, task_time, error):
        if not task['email'] or sendemail == 'none':
            return
        if (sendemail == 'fail' and status == 'finished') or \
            (sendemail == 'finish' and status == 'failed'):
            return
        # check email settings in config are set
        if ((smtp_security == 'SSL' or smtp_security == 'TLS') and (not smtp_server or not smtp_port or not sender_email or not smtp_password)) or \
            (not smtp_server or not smtp_port or not sender_email):
            logger.warning('[{0}][{1}] Not sending email, config email settings not set'.format(self.name, th_name))
            return
        receiver_email = task['email']
        id = task['id']
        if options.verbose:
            logger.info('[{0}][{1}] Sending email to {2} for task id {3}'.format(self.name, th_name, receiver_email, id))
        url = apiurl.replace('/api.php/', '/tasks/')
        message = """\
This message is sent from diskover task panel.
{}

Task details:

date ({}): {}
task id: {}
task name: {}
task type: {}
worker: {}
start time (utc): {}
finish time (utc): {}
task time: {}
status: {}
error: {}""".format(url, timezone, datetime.now().isoformat(), id, task['name'], task['type'], 
                     self.name, start_time, finish_time, get_time(task_time), status, error)
        msg = EmailMessage()
        msg.set_content(message)
        msg['Subject'] = 'diskoverd task update - {0} {1}'.format(status, task['name'])
        msg['From'] = sender_email
        msg['To'] = receiver_email

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
        except smtplib.SMTPException as e:
            logger.error('[{0}][{1}] Error sending email: {2}'.format(self.name, th_name, e))
        else:
            logger.error('[{0}][{1}] Email sent'.format(self.name, th_name))
        
    def get_worker_status(self):
        logger.debug('[{0}] Checking api for worker status'.format(self.name))   
        res = api_req('workerinfo?worker=' + self.name)
        logger.debug(res)
        if res is None:
            return None
        elif not res['message']['data']:
            logger.debug('[{0}] Registering new worker, setting state to idle'.format(self.name))
            return {'state': 'idle', 'disabled': False}
        state = res['message']['data']['state']
        disabled = res['message']['data']['disabled']
        # set worker state to idle if no current tasks
        if not self.current_tasks: state = 'idle'
        logger.debug('[{0}] Worker state is {1}, disabled is {2}'.format(self.name, state, disabled))
        return {'state': state, 'disabled': disabled}
    
    def run_shell_command(self, command_line, task, th_name, th_lock):
        with th_lock:
            self.taskstimedout[task['id']] = False
        
        def _timeout(p):
            with th_lock:
                self.taskstimedout[task['id']] = True
            if IS_WIN:
                p.terminate()
            else:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)

        # set any env vars
        env = self.set_env_vars(task, th_name)
        # set any custom index config
        if task['type'] == 'index':
            config_res = self.set_custom_config(task, th_name)
            if config_res is False:
                return 1
            elif config_res is not None:
                env['DISKOVERDIR'] = config_res
        args = shlex.split(command_line)
        try:
            tasktimeout = int(task['timeout'])
            if tasktimeout == 0:
                tasktimeout = None
        except KeyError:
            tasktimeout = None
        logger.info('[{0}][{1}] Running command... (cmd args: {2}, timeout: {3})'.format(self.name, th_name, args, tasktimeout))
        success = False
        retries = 1
        errormsg = None
        lastlogline = None
        while success is False:
            try:
                if logtofile:
                    logger_subproc.info('[{0}] run command: {1}'.format(th_name, command_line))
                    if IS_WIN:
                        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                        universal_newlines=True, close_fds=True, env=env)
                    else:
                        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                            universal_newlines=True, close_fds=True, env=env, preexec_fn=os.setsid)
                    logger_subproc.info('[{0}] pid: {1}'.format(th_name, p.pid))
                    with th_lock:
                        self.tasksproc[task['id']] = p
                        all_tasksproc[task['id']] = p
                    if tasktimeout is not None:
                        timer = Timer(tasktimeout, _timeout, args=(p,))
                        timer.start()
                    with p.stdout:
                        for line in iter(p.stdout.readline, ''):
                            lastlogline = line.strip()
                            logger_subproc.info('[{0}] {1}'.format(th_name, lastlogline))
                    p.wait()
                    if tasktimeout is not None:
                        timer.cancel()
                        if task['id'] in self.taskstimedout and self.taskstimedout[task['id']]:
                            raise TimeoutExpired(cmd=args, timeout=tasktimeout)
                else:
                    if IS_WIN:
                        p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, 
                                            close_fds=True, env=env)
                    else:
                        p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, 
                                            close_fds=True, env=env, preexec_fn=os.setsid)
                    with th_lock:
                        self.tasksproc[task['id']] = p
                        all_tasksproc[task['id']] = p
                    p.wait()
            except FileNotFoundError as e:
                logger.error('[{0}][{1}] File not found error running command {2} ({3})'.format(self.name, th_name, args, e))
                errormsg = 'File not found error running command {0} ({1})'.format(args, e)
                exitcode = 1
                with th_lock:
                    try:
                        del self.tasksproc[task['id']]
                    except KeyError:
                        pass
                    try:
                        del self.taskstimedout[task['id']]
                    except KeyError:
                        pass
                break
            except (OSError, CalledProcessError) as e:
                logger.error('[{0}][{1}] Error running command {2} ({3})'.format(self.name, th_name, args, e))
                errormsg = 'Error running command {0} ({1}) (Exit code: {2})'.format(args, e, p.returncode)
                exitcode = 1
                with th_lock:
                    try:
                        del self.tasksproc[task['id']]
                        del all_tasksproc[task['id']]
                    except KeyError:
                        pass
                    try:
                        del self.taskstimedout[task['id']]
                    except KeyError:
                        pass
                break
            except TimeoutExpired as e:
                logger.warning('[{0}][{1}] Timeout expired ({2} sec) running command {3} ({4})'.format(
                    self.name, th_name, tasktimeout, args, e))
                errormsg = 'Timeout expired ({0} sec) running command {1} ({2}) (Exit code: {3})'.format(tasktimeout, args, e, p.returncode)
                exitcode = 1
                with th_lock:
                    try:
                        del self.tasksproc[task['id']]
                        del all_tasksproc[task['id']]
                    except KeyError:
                        pass
                    try:
                        del self.taskstimedout[task['id']]
                    except KeyError:
                        pass
                break
            else:
                with th_lock:
                    try:
                        del self.tasksproc[task['id']]
                        del all_tasksproc[task['id']]
                    except KeyError:
                        pass
                    try:
                        del self.taskstimedout[task['id']]
                    except KeyError:
                        pass
                logger.info('[{0}][{1}] Command done (pid {2}, exit code {3})'.format(self.name, th_name, p.pid, p.returncode))
                exitcode = p.returncode
                if exitcode == 0:
                    success = True
                # special exit code for diskover index warnings
                elif exitcode == 64:
                    success = True
                else:
                    if lastlogline is None:
                        if p.returncode == -15:
                            lastlogline = 'Process was sent SIGTERM (stop)'
                        elif p.returncode == -9:
                            lastlogline = 'Process was sent SIGKILL (force stop)'
                        else:
                            lastlogline = 'An unknown error occurred'
                    errormsg = '{0} (Exit code: {1})'.format(lastlogline, p.returncode)
                    # don't retry if worker shutting down
                    if shutdown_sig_sent:
                        logger.info('[{0}][{1}] Not retrying command because worker shutting down (pid {2})'.format(self.name, th_name, p.pid))
                        exitcode = 1
                        break
                    # don't retry if stop sent
                    if task['id'] in self.stoptasks:
                        logger.info('[{0}][{1}] Not retrying command because stop sent (pid {2})'.format(self.name, th_name, p.pid))
                        # remove task id
                        with th_lock:
                            try:
                                self.stoptasks.remove(task['id'])
                            except ValueError:
                                pass
                            try:
                                del self.tasksproc[task['id']]
                                del all_tasksproc[task['id']]
                            except KeyError:
                                pass
                            try:
                                del self.taskstimedout[task['id']]
                            except KeyError:
                                pass
                        exitcode = 1
                        break
                    # retry
                    if int(task['retries']) > 0 and retries <= int(task['retries']):
                        logger.info('[{0}][{1}] Retrying command in {2} sec... (retry {3} of {4})'.format(
                            self.name, th_name, task['retry_delay'], retries, task['retries']))
                        time.sleep(int(task['retry_delay']))
                        retries += 1
                    else:
                        exitcode = 1
                        break
        return (exitcode, errormsg)
        
    def run_task(self, task, th_name, th_lock):
        # run task and return 0 if it completes with no warnings or errors, return 2 if any non-critical warnings,
        # or return 1 if there is some critical error  
        # run any pre command
        if task['pre_command']:
            command_line = task['pre_command']
            if task['pre_command_args']:
                command_line += ' ' + task['pre_command_args']
            pre_cmd_res, pre_cmd_errmsg = self.run_shell_command(command_line, task, th_name, th_lock)
            if pre_cmd_res == 1:
                return (1, pre_cmd_errmsg)
        # run command
        # check the task type, index, custom
        if task['type'] == 'index':
            command_line = pythoncmd + ' ' + os.path.join(diskoverpath, 'diskover.py')
            # check for overwrite index
            if (task['overwrite_existing']):
                command_line += ' -f'
            # check for custom index name
            if (task['custom_index_name']):
                indx = task['custom_index_name']
                # check for date vars in index name and translate to utc date
                utc_now = datetime.utcnow()
                indx = indx.replace('%Y', utc_now.strftime('%Y'))
                indx = indx.replace('%y', utc_now.strftime('%y'))
                indx = indx.replace('%m', utc_now.strftime('%m'))
                indx = indx.replace('%d', utc_now.strftime('%d'))
                indx = indx.replace('%H', utc_now.strftime('%H'))
                indx = indx.replace('%M', utc_now.strftime('%M'))
                indx = indx.replace('%S', utc_now.strftime('%S'))
                command_line += ' -i ' + indx
            # check for alt scanner
            try:
                if (task['alt_scanner']):
                    command_line += ' --altscanner ' + task['alt_scanner']
            except KeyError:
                pass
            # check for additional cli options/flags
            try:
                if (task['cli_options']):
                    command_line += ' ' + task['cli_options']
            except KeyError:
                pass
            # add crawl paths
            command_line += ' ' + task['crawl_paths']
        else:
            command_line = task['run_command']
            if task['run_command_args']:
                command_line += ' ' + task['run_command_args']
        run_cmd_res, run_cmd_errmsg = self.run_shell_command(command_line, task, th_name, th_lock)
        if run_cmd_res == 1:
            return (1, run_cmd_errmsg)
        # run any post command
        if task['post_command']:
            command_line = task['post_command']
            if task['post_command_args']:
                post_cmd_args = task['post_command_args']
                # replace {indexname} var with actual index name
                if task['type'] == 'index':
                    post_cmd_args = post_cmd_args.replace('{indexname}', indx)
                command_line += ' ' + post_cmd_args
            post_cmd_res, post_cmd_errmsg = self.run_shell_command(command_line, task, th_name, th_lock)
            if post_cmd_res == 1:
                return (1, post_cmd_errmsg)
        return (run_cmd_res, run_cmd_errmsg)
    
    def set_env_vars(self, task, th_name):
        env = os.environ.copy()
        if not task['env_vars']:
            return env
        logger.info('[{0}][{1}] Setting env vars {2}'.format(
            self.name, th_name, task['env_vars']))
        for var in task['env_vars'].split(','):
            var = var.strip()
            var_arr = var.split('=')
            env[str(var_arr[0])] = str(var_arr[1])
        return env
            
    def set_custom_config(self, task, th_name):
        # set env var DISKOVERDIR to directory containing alternate diskover config file
        if task['use_default_config'] or not task['alt_config_file']:
            logger.info('[{0}][{1}] Using default diskover config'.format(self.name, th_name))
            # unset env var to use default config
            return None
        # check custom config directory exists
        if not os.path.exists(task['alt_config_file']):
            logger.critical('Alt diskover config directory {0} not found!'.format(task['alt_config_file']))
            return False
        # check custom config file exists
        if not os.path.exists(os.path.join(task['alt_config_file'], 'config.yaml')):
            logger.critical('Alt diskover config directory {0} does not contain a config.yaml file!'.format(task['alt_config_file']))
            return False
        logger.info('[{0}][{1}] Using alternate diskover config file in {2}'.format(
            self.name, th_name, task['alt_config_file']))
        env_config = str(task['alt_config_file'])
        return env_config
        
    def add_tags(self, task, th_name):
        id = task['id']
        index = task['index_name']
        tags = task['tags'].replace(', ', ',').split(',')
        paths = task['paths'].split('\r\n')
        if not index or not tags:
            return
        logger.info('[{0}][{1}] Updating tags {2} in index {3} for task id {4}'.format(
            self.name, th_name, tags, index, id))
        files = []
        dirs = []
        for item in paths:
            if item[-1] == '/':
                dirs.append(item.rstrip('/'))
            else:
                # check for wildcard
                if '*' in item:
                    files_glob = glob.glob(item)
                    files += files_glob
                else:
                    files.append(item)
        # tag files
        if files:
            data = {
                'tags': tags,
                'files': files
            }
            logger.debug(data)
            data_json = json.dumps(data).encode('utf-8')
            res = api_req(index + '/' + 'tagfiles', data=data_json, method='PUT')
            logger.debug(res)
        # tag dirs
        if dirs:
            data = {
                'tags': tags,
                'dirs': dirs
            }
            logger.debug(data)
            data_json = json.dumps(data).encode('utf-8')
            res = api_req(index + '/' + 'tagdirs', data=data_json, method='PUT')
            logger.debug(res)
        logger.info('[{0}][{1}] Finished updating index {2} for task id {3}'.format(
            self.name, th_name, index, id))
        
    def check_stop_task(self, task):
        """Check if task was requested to stop."""
        try:
            process = self.tasksproc[task['id']]
        except KeyError:
            return False
        else:
            try:
                stop_task = task['stop_task']
            except KeyError:
                return False
            try:
                stop_task_force = task['stop_task_force']
            except KeyError:
                return False
            if stop_task_force:
                logger.info('[{0}][get_tasks] Task {1} set to forced stop (manual stop)'.format(self.name, task['id']))
                self.stop_task(task['id'], process, force=True)
                return True
            elif stop_task:
                logger.info('[{0}][get_tasks] Task {1} set to stop (manual stop)'.format(self.name, task['id']))
                self.stop_task(task['id'], process)
                return True
        return False
    
    def stop_task(self, id, process, force=False):
        if options.verbose:
            logger.info('[{0}][get_tasks] Stopping task id {1} pid {2}'.format(self.name, id, process.pid))
        if force:
            if IS_WIN:
                process.kill()
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            if IS_WIN:
                process.terminate()
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    def check_longrun_task(self, task):
        """Check if task is taking a long time to run and send email."""
        if sendemaillongruntask == 'none' or task['id'] in self.longruntasks:
            return False
        elapsed_time = time_duration(task['last_start_time'])
        elapsed_time_min = round(elapsed_time / 60, 3)
        if elapsed_time_min >= sendemaillongruntask:
            if options.verbose:
                logger.info('[{0}][get_tasks] Sending email for task id {1} and setting to error status, task running a long time ({2} min)'.format(self.name, task['id'], elapsed_time_min))
            errmsg = 'Task id {0} setting to error status, task running a long time ({1} min)'.format(task['id'], elapsed_time_min)
            # send task update email
            self.send_email(task, 'get_tasks', task['last_status'], task['last_start_time'], None, elapsed_time, errmsg)
            return True
        return False
    
    def get_task_info(self, id):
        """Get task info from api for a specific task id."""
        # get data from api
        res = api_req('tasks')
        logger.debug(res)
        if not res['message']['data']:
            return None
        for task in res['message']['data']['tasks']:
            if id == task['id']:
                return task
    

def api_req(params, data=None, method='GET'):
    fullurl = apiurl + params  
    res = None
    retries = 1
    success = False
    while not success and retries < 10:
        try:
            logger.debug('api req: {0}'.format(fullurl))
            req = Request(url=fullurl, data=data, method=method)
            # HTTP basic auth
            if api_user != '' and api_pass != '':
                base64string = base64.b64encode(bytes('{0}:{1}'.format(api_user, api_pass),'ascii'))
                req.add_header("Authorization", "Basic {0}".format(base64string.decode('utf-8')))
            with urlopen(req) as resp:
                logger.debug('[{0}] api status {1}, reason {2}'.format(workername, resp.status, resp.reason))
                res = json.loads(resp.read().decode())
                success = True
        except (HTTPError, URLError) as e:
            if hasattr(e, 'code') and e.code == 401:
                logger.error('[{0}] Unauthorized access to api, incorrect username or password, error code {1}'.format(workername, e.code))
                sys.exit(1)
            else:
                try:
                    wait = retries * 3
                    if hasattr(e, 'reason'):
                        logger.warning('[{0}] Failed to reach api, reason {1}, waiting {2} sec and re-trying...'.format(workername, e.reason, wait))
                    elif hasattr(e, 'code'):
                        logger.warning('[{0}] api couldn\'t fulfill the request, error code {1}, waiting {2} sec and re-trying...'.format(workername, e.code, wait))
                    time.sleep(wait)
                    retries += 1
                except KeyboardInterrupt:
                    raise SystemExit('Ctrl-c pressed, exiting')
        except json.decoder.JSONDecodeError:
            try:
                wait = retries * 3
                logger.warning('[{0}] api returned no valid response, waiting {1} sec and re-trying...'.format(workername, wait))
                time.sleep(wait)
                retries += 1
            except KeyboardInterrupt:
                raise SystemExit('Ctrl-c pressed, exiting')
    return res


def shutdown_worker():
    """Update api that worker is shutting down."""
    logger.debug('[{0}] Sending worker shutdown to api..'.format(workername)) 
    data = {
        'name': workername,
        'hostname': socket.gethostname(),
        'user': getpass.getuser(),
        'pid': os.getpid(),
        'state': 'shutdown',
        'current_tasks': []
    }
    data_json = json.dumps(data).encode('utf-8')
    res = api_req('updateworker', data=data_json, method='PUT')
    logger.debug(res)


def stop_all_tasks():
    """Stops all running tasks."""
    global shutdown_sig_sent
    shutdown_sig_sent = True
    
    if not all_current_tasks:
        return
    
    if options.verbose:
        logger.info('[{0}] Stopping all tasks...'.format(workername))
    for id in all_current_tasks:
        if id in all_tasksproc:
            force = False
            killed = False
            while not killed:
                process = all_tasksproc[id]                
                if options.verbose:
                    logger.info('[{0}] Stopping task id {1} pid {2}'.format(workername, id, process.pid))
                if force:
                    if IS_WIN:
                        process.kill()
                    else:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    killed = True
                    break
                else:
                    if IS_WIN:
                        process.terminate()
                    else:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    # check if process stopped after a few seconds
                    time.sleep(3)
                    if process.poll() is None:
                        if options.verbose:
                            logger.info('[{0}] Task id {1} pid {2} still running, will force stop in 10 sec'.format(workername, id, process.pid))
                        force = True
                        killed = False
                        time.sleep(10)
                        continue
                    else:
                        killed = True
                        break
            if options.verbose:
                logger.info('[{0}] Task id {1} stopped.'.format(workername, id))

    if options.verbose:
        logger.info('[{0}] Done stopping all tasks.'.format(workername))


if __name__ == "__main__":
    usage = """Usage: diskoverd.py [-h]

diskoverd v{0}
diskover task worker daemon.""".format(version)
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-n', '--name', 
                        help='optional worker name, default is hostname + unique id')
    parser.add_option('-v', '--verbose', action='store_true',
                        help='verbose output')
    parser.add_option('--version', action='store_true',
                        help='print diskoverd version number and exit')
    options, args = parser.parse_args()

    if options.version:
        print('diskoverd v{}'.format(version))
        sys.exit(0)

    banner()

    # DO NOT ALTER, REMOVE THIS CODE OR COMMENT IT OUT.
    # REMOVING THE LICENSE CHECK VIOLATES THE LICENSE AGREEMENT AND IS AN ILLEGAL OFFENCE.
    lic = License()
    lic.check_license()
    licfc(lic, 'ESS')
    
    """Set worker name."""
    workername = get_workername()

    """Setup logging for diskoverd."""
    logger = logging.getLogger('diskoverd')
    loglevel = config['logLevel'].get()
    if loglevel == 'DEBUG':
        loglevel = logging.DEBUG
    elif loglevel == 'INFO':
        loglevel = logging.INFO
    else:
        loglevel = logging.WARN
    logformat = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(format=logformat, level=loglevel)
    
    if logtofile:
        # create file handler for logger
        logfile = os.path.join(logdir, 'diskoverd_{0}.log').format(workername)   
        logger_handler_file = logging.handlers.TimedRotatingFileHandler(logfile, when='d', interval=1, backupCount=5, encoding='utf-8')
        formatter = logging.Formatter(logformat)
        logger_handler_file.setLevel(loglevel)
        logger_handler_file.setFormatter(formatter)
        # add handlers to logger
        logger.addHandler(logger_handler_file)
        
        # subprocess logging
        # create file handler for subproc logger
        logger_subproc = logging.getLogger('diskoverd_subproc')
        logfile_subproc = os.path.join(logdir, 'diskoverd_subproc_{0}.log').format(workername)
        logger_subproc_handler_file = logging.handlers.TimedRotatingFileHandler(logfile_subproc, when='d', interval=1, backupCount=5, encoding='utf-8')
        logger_subproc_handler_file.setLevel(loglevel)
        logger_subproc_handler_file.setFormatter(formatter)
        logger_subproc.addHandler(logger_subproc_handler_file)
    
    if IS_WIN:
        install_win_sig_handler()
    
    # register the signals to be caught
    signal.signal(signal.SIGTERM, receive_signal)
    
    logger.info('Starting diskoverd task worker {0}...'.format(workername))

    # print config being used
    config_filename = os.path.join(config.config_dir(), confuse.CONFIG_FILENAME)
    logger.info('Config file: {0}'.format(config_filename))
    logger.info('Config env var DISKOVERDDIR: {0}'.format(os.getenv('DISKOVERDDIR')))
    logger.info('Worker name: {}'.format(workername))
    logger.info('Worker pools: {}'.format(workerpools))
    
    # create task queue
    task_q = Queue(maxsize=workthreads)
    
    # create thread Lock
    th_lock = Lock()
    
    # create Worker
    w = Worker(workername)
    w.work()

    logger.info('Stopping diskoverd task worker {0}...'.format(workername))
    shutdown_worker()
    