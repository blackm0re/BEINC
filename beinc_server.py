#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import getpass
import json
import os
import sys

import cherrypy


__author__ = 'Simeon Simeonov'
__version__ = '1.0-beta'
__license__ = "GPL3"


BEINC_OSD_TYPE_NONE = 0
BEINC_OSD_TYPE_PYNOTIFY = 1



class BEINCInstance(object):
    """
    """
    
    def __init__(self, instance_dict):
        """
        """
        self.__instance_dict = instance_dict
        try:
            self.__name = instance_dict['name']
            self.__osd_type = BEINC_OSD_TYPE_NONE
            self.__password = instance_dict['password']
            self.__queue_size = int(instance_dict['queue_size'])
            self.__message_queue = list()
            self.__osd_notification = None
                
        except Exception as e:
            sys.stderr.write(
                'Instance processing error {0}:\n{1}\n'.format(self.__name,
                                                               e))
            sys.exit(1)


        if instance_dict['osd_system'].lower() == 'pynotify':
            if not pynotify:
                sys.stderr.write(
                    'This server does not possess pynotify capability\n')
                sys.stderr.write(
                    "Remove the instance {0} or define it with 'osd_system': 'none'")
                sys.exit(1)

            try:
                self.__osd_notification = pynotify.Notification(' ')
                self.__osd_notification.set_timeout(
                    instance_dict['osd_timeout'])
                self.__osd_notification.set_property(
                    'app_name', 
                    '{0} {1}'.format(sys.argv[0], __version__))
            except Exception as e:
                sys.stderr.write(
                    'Unable to set up a notification object for {0} ({1})\n')
                sys.exit(1)

            self.__osd_type = BEINC_OSD_TYPE_PYNOTIFY


    @property
    def name(self):
        """
        name-property for the server instance
        """
        return self.__name


    @property
    def queueable(self):
        """
        name-property for the server instance
        """
        return bool(self.__queue_size)


    def password_match(self, password):
        """
        Returns True if 'passowrd' matches the instance-password,
        otherwise - False
        """
        if self.__password == password:
            return True

        return False

    
    def send_message(self, title, message):
        """
        Displays or enqueues the message,
        depending on the instance's type in regard to the osd_system
        """
        if self.__osd_type == BEINC_OSD_TYPE_PYNOTIFY:
            self.__send_pynotify_messaage(title, message)
        else:
            self.____send_message_to_queue(title, message)


    def get_queue(self):
        """
        Reruens a json representation of the message queue
        """
        jstr = json.dumps(self.__message_queue)
        self.__message_queue = list()
        return jstr


    def __send_pynotify_messaage(self, title, message):
        """
        Displays pynotify message
        """

        self.__osd_notification.set_properties(summary=title, body=message)
        self.__osd_notification.show()


    def __send_message_to_queue(self, title, message):
        """
        Enqueues the message
        """

        if len(self.__message_queue) >= self.__queue_size:
            self.__message_queue.pop(0)

        self.__message_queue.append({'title': title, 'message': message})



def beinc_instance_login(method):
    """
    decorator for checking login credentials
    """

    def tmp_func(self, *args, **kwargs):

        if not args:
            raise cherrypy.HTTPError(400)

        print('args: {0}'.format(args))
        print('kwargs: {0}'.format(kwargs))
        print(cherrypy.request.config)

        try:
            instance = self.__instances(args[0])
        except Exception as e:
            raise cherrypy.HTTPError('403 Forbidden',
                                     'Wrong instance or password')
 
        if not instance.password_match(kwargs.get('password')):
            raise cherrypy.HTTPError('403 Forbidden', 
                                     'Wrong instance or password')

        method(self, *args, **kwargs)

    return tmp_func



class WebNotifyServer(object):

    def __init__(self, config):
        """
        """
        self.__config = config
        self.__instances = dict()

        try:
            for instance in self.__config['server']['instances']:
                self.__instances[instance['name']] = BEINCInstance(instance)

        except Exception as e:
            sys.stderr.write('Unable to initialize queues: {0}\n'.format(e))
            sys.exit(1)


    @cherrypy.expose
    def index(self):
        """
        default dispatcher
        """
        return 'index'


    @cherrypy.expose
    def default(self, *args):
        """
        default dispatcher
        """
        return 'default'


    @cherrypy.expose
    @beinc_instance_login
    def push(self, *args, **kwargs):

        instance = self.__instances(args[0])
        return 'OK'


    @cherrypy.expose
    @beinc_instance_login
    def pull(self, *args, **kwargs):

        instance = self.__instances(args[0])
        return 'OK'



def main():

    parser = argparse.ArgumentParser(description='The following options are available')

    
    parser.add_argument('-d',
                        action='store_true',
                        dest='daemonize',
                        default=False,
                        help='daemonize the server process')

    parser.add_argument('-H', '--hostname',
                        metavar='HOSTNAME',
                        type=str,
                        dest='hostname',
                        default='127.0.0.1',
                        help="Server IP / hostname")

    parser.add_argument('-p', '--port',
                        metavar='PORT',
                        type=int,
                        dest='port',
                        default=9998,
                        help="Server port")

    parser.add_argument('-c', '--config-file',
                        metavar='FILE',
                        type=str,
                        default=os.path.expanduser('~/.beinc_server.json'),
                        dest='config_file',
                        help="config file")

    parser.add_argument('-v', '--version',
                        action='version',
                        version='%(prog)s {0}'.format(__version__),
                        help='display program-version and exit')

    args = parser.parse_args()


    try:
        with open(args.config_file, 'r') as fp:
            config_dict = json.load(fp)

    except Exception as e:
        sys.stderr.write('Unable to parse {0}: {1}'.format(args.config_file, e))


    cherrypy.config.update({
        'server.socket_host': args.hostname,
        'server.socket_port': args.port,
        'server.ssl_module': config_dict['server']['general']['ssl_module'].encode('utf-8'),
        'server.ssl_certificate': config_dict['server']['general']['ssl_certificate'],
        'server.ssl_private_key': config_dict['server']['general']['ssl_private_key'],            
    })

    try:
        import pynotify
        if not pynotify.init("BEINC Notify"):
            sys.stderr.write('pynotify.init failed! Exiting...\n')
            sys.exit(1)
    except Exception as e:
        sys.stderr.write(
            'Notice: pynotify support unavailable ({0})\n'.format(e))
        pynotify = False

    try:
        cherrypy.quickstart(WebNotifyServer(config_dict))

    except Exception as e:
        sys.stderr.write("WebServer error: {0}".format(e))
        sys.exit(1)


    sys.exit(0)


if __name__ == "__main__":
    main()

