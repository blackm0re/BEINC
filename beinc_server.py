#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Blackmore's Enhanced IRC-Notification Collection (BEINC) v1.0
# Copyright (C) 2013-2014 Simeon Simeonov

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import errno
import getpass
import json
import os
import random
import sys

import cherrypy

try:
    import pynotify
except ImportError as e:
    pynotify = None

try:
    import pyosd
    pyosd_positions = {'top': pyosd.POS_TOP,
                       'middle': pyosd.POS_MID,
                       'bottom': pyosd.POS_BOT}
    pyosd_alignments = {'left': pyosd.ALIGN_LEFT,
                        'center': pyosd.ALIGN_CENTER,
                        'right': pyosd.ALIGN_RIGHT}
except ImportError as e:
    pyosd = None


__author__ = 'Simeon Simeonov'
__version__ = '1.0'
__license__ = 'GPL3'


BEINC_OSD_TYPE_NONE = 0
BEINC_OSD_TYPE_PYNOTIFY = 1
BEINC_OSD_TYPE_PYOSD = 2


class BEINCInstance(object):
    """
    Represents a single server-instance
    """

    def __init__(self, instance_dict):
        """
        instance_dict: the config-dictionary node that represents this instance
        """
        self.__message_queue = list()
        self.__osd_type = BEINC_OSD_TYPE_NONE
        self.__osd_notification = None

        self.__name = instance_dict.get('name')
        self.__password = instance_dict.get('password', '')
        self.__queue_size = int(instance_dict.get('queue_size', 3))
        if instance_dict['osd_system'].lower() == 'pynotify':
            self.__queue_size = 0  # disable queueing
            if not pynotify:
                sys.stderr.write(
                    'This server does not possess pynotify capability\n')
                sys.stderr.write(
                    'Remove the instance {0}'.format(self.__name))
                sys.stderr.write(
                    'or define it with "osd_system": "none" '
                    'or other available backend\n')
                sys.exit(errno.EPERM)
            try:
                self.__osd_notification = pynotify.Notification(' ')
                self.__osd_notification.set_timeout(
                    1000 * int(instance_dict.get('osd_timeout', 5)))
                self.__osd_notification.set_property(
                    'app_name',
                    '{0} {1}'.format(sys.argv[0], __version__))
            except Exception as e:
                sys.stderr.write(
                    'Unable to set up a notification object for {0} ({1})\n')
                sys.exit(errno.EPERM)
            self.__osd_type = BEINC_OSD_TYPE_PYNOTIFY
        elif instance_dict['osd_system'].lower() == 'pyosd':
            self.__queue_size = 0  # disable queueing
            if not pyosd:
                sys.stderr.write(
                    'This server does not possess pyosd capability\n')
                sys.stderr.write(
                    'Remove the instance {0}'.format(self.__name))
                sys.stderr.write(
                    'or define it with "osd_system": "none" '
                    'or other available backend\n')
                sys.exit(errno.EPERM)
            try:
                self.__osd_notification = pyosd.osd()
                self.__osd_notification.set_timeout(
                    int(instance_dict.get('osd_timeout', 5)))
                pyosd_font = instance_dict.get('pyosd_font')
                if pyosd_font:
                    self.__osd_notification.set_font(pyosd_font)
                self.__osd_notification.set_vertical_offset(
                    instance_dict.get('pyosd_vertical_offset', 120))
                self.__osd_notification.set_horizontal_offset(
                    instance_dict.get('pyosd_horizontal_offset', 30))
                align_str = instance_dict.get('pyosd_align', 'left')
                self.__osd_notification.set_align(
                    pyosd_alignments.get(align_str, pyosd.ALIGN_LEFT))
                position_str = instance_dict.get('pyosd_position', 'bottom')
                self.__osd_notification.set_pos(
                    pyosd_positions.get(position_str, pyosd.POS_BOT))
                self.__osd_notification.set_colour(
                    instance_dict.get('pyosd_color', 'blue'))
            except Exception as e:
                sys.stderr.write(
                    'Unable to set up a notification object for {0} ({1})\n')
                sys.exit(errno.EPERM)
            self.__osd_type = BEINC_OSD_TYPE_PYOSD

    @property
    def name(self):
        """
        name-property for the server instance
        """
        return self.__name

    @property
    def queueable(self):
        """
        True if this instance has a queueing capability
        """
        return bool(self.__queue_size)

    def password_match(self, password):
        """
        Returns True if 'passowrd' matches the instance-password,
        otherwise - False
        """
        return True if self.__password == password else False

    def send_message(self, title, message):
        """
        Displays or enqueues the message,
        depending on the instance's type in regard to the osd_system
        """
        if self.__osd_type == BEINC_OSD_TYPE_PYNOTIFY:
            self.__send_pynotify_messaage(title, message)
        elif self.__osd_type == BEINC_OSD_TYPE_PYOSD:
            self.__send_pyosd_message(title, message)
        else:
            self.__send_message_to_queue(title, message)

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

    def __send_pyosd_message(self, title, message):
        """
        Displays pyosd message
        """
        self.__osd_notification.display(title, line=0)
        self.__osd_notification.display(message, line=1)

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

    def wrapper(self, *args, **kwargs):
        if not args:
            raise cherrypy.HTTPError(status=404)
        try:
            instance = self.instances[args[0]]
        except Exception as e:
            raise cherrypy.HTTPError(status=401,
                                     message='Wrong instance or password')
        if not instance.password_match(kwargs.get('password')):
            raise cherrypy.HTTPError(status=401,
                                     message='Wrong instance or password')
        return method(self, *args, **kwargs)

    return wrapper


class WebNotifyServer(object):

    def __init__(self, config):
        """
        """
        self.__config = config
        self.__instances = dict()
        # initialize pynotify if the module exists and if needed
        if pynotify:
            for instance in self.__config['server']['instances']:
                # check if we have at least one instance that uses pynotify
                # before initializing it
                if instance.get('osd_system', '').lower() == 'pynotify':
                    if not pynotify.init('BEINC Notify'):
                        sys.stderr.write('pynotify.init failed! Exiting...\n')
                        sys.exit(1)
                    break
        try:
            for instance in self.__config['server']['instances']:
                self.__instances[instance['name']] = BEINCInstance(instance)
                print('Instance "{0}" added'.format(instance['name']))
        except Exception as e:
            sys.stderr.write('Unable to create instance "{0}": {1}\n'.format(
                instance['name'],
                e))
            sys.exit(1)

    @property
    def instances(self):
        return self.__instances

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
        instance = self.__instances[args[0]]
        ##print('**kwargs: {0}'.format(str(kwargs)))
        title = kwargs.get('title', '')
        message = kwargs.get('message', '')
        try:
            instance.send_message(title, message)
            return 'OK'
        except Exception as e:
            sys.stderr.write(
                'Unable to handle message in {0}: ({1})\n'.format(
                    instance.name,
                    e))
            raise cherrypy.HTTPError(500, 'Unable to send message')

    @cherrypy.expose
    @beinc_instance_login
    def pull(self, *args, **kwargs):
        instance = self.__instances[args[0]]
        if not instance.queueable:
            raise cherrypy.HTTPError(
                status=405,
                message='BEINC instance "{0}" does not support queuing'.format(
                    instance.name))
        return instance.get_queue()


def main():

    parser = argparse.ArgumentParser(
        description='The following options are available')
    parser.add_argument(
        '-d',
        action='store_true',
        dest='daemonize',
        default=False,
        help='Run the BEINC-server in the background')
    parser.add_argument(
        '-H', '--hostname',
        metavar='HOSTNAME',
        type=str,
        dest='hostname',
        default='127.0.0.1',
        help='BEINC server IP / hostname (default: 127.0.0.1)')
    parser.add_argument(
        '-p', '--port',
        metavar='PORT',
        type=int,
        dest='port',
        default=9998,
        help='BEINC server port (default: 9998)')
    parser.add_argument(
        '-f', '--config-file',
        metavar='FILE',
        type=str,
        default=os.path.expanduser('~/.beinc_server.json'),
        dest='config_file',
        help='BEINC config file (default: ~/.beinc_server.json)')
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s {0}'.format(__version__),
        help='Display program-version and exit')
    args = parser.parse_args()
    try:
        with open(args.config_file, 'r') as fp:
            config_dict = json.load(fp)
    except Exception as e:
        sys.stderr.write('Unable to parse {0}: {1}'.format(args.config_file,
                                                           e))
        sys.exit(errno.EIO)
    ssl_module = config_dict['server']['general']['ssl_module'].encode('utf-8')
    ssl_certificate = config_dict['server']['general']['ssl_certificate']
    ssl_private_key = config_dict['server']['general']['ssl_private_key']
    cherrypy.config.update({
        'server.socket_host': args.hostname,
        'server.socket_port': args.port,
        'server.ssl_module': ssl_module,
        'server.ssl_certificate': ssl_certificate,
        'server.ssl_private_key': ssl_private_key,
        'tools.encode.on': True,
        'tools.encode.encoding': 'utf-8',
        'tools.log_tracebacks.on': False,
        'request.show_tracebacks': False
    })
    try:
        cherrypy.quickstart(WebNotifyServer(config_dict))
    except Exception as e:
        sys.stderr.write("WebServer error: {0}".format(e))
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
