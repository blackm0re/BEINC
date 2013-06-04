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



class WebNotifyServer(object):

    def __init__(self, config):
        """
        """
        self.__config = config
        self.__instances = dict()
        self.__queues = dict()

        try:
            for instance in self.__config['server']['instances']:
                self.__queues[instance['name']] = list()
                self.__instances[instance['name']] = instance

        except Exception as e:
            sys.stderr.write('Unable to initialize queues: {0}'.format(e))
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
    def push(self, *args, **kwargs):

        if not args:
            raise cherrypy.HTTPError(400)

        print('args: {0}'.format(args))
        print('kwargs: {0}'.format(kwargs))

        instance = self.__get_instance(args[0])
 
        if not kwargs.get('password') == instance['password']:
            raise cherrypy.HTTPError('403 Forbidden', 
                                     'Wrong instance or password')

        return 'OK'


    def __get_instance(self, name):
        """
        returns a matching 'instance' dictionary
        
        cherrypy.HTTPError - "403 Forbidden" is raised if no 
        instance matches 'name'
        """

        try:
            for instance in self.__config['server']['instances']:
                if name == instance['name']:
                    return instance

        except Exception as e:
            raise cherrypy.HTTPError('403 Forbidden', 
                                     'Wrong instance or password: {0}'.format(e))
            
        raise cherrypy.HTTPError("403 Forbidden", "Wrong instance or password")


    # mappings = [
    #     (r'^/push/', push),
    #     (r'^.*$', default),
    #     ]


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
        cherrypy.quickstart(WebNotifyServer(config_dict))

    except Exception as e:
        sys.stderr.write("WebServer error: {0}".format(e))
        sys.exit(1)


    sys.exit(0)


if __name__ == "__main__":
    main()

