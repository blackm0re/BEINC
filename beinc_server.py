#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Blackmore's Enhanced IRC-Notification Collection (BEINC) v3.0
# Copyright (C) 2013-2017 Simeon Simeonov

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
import cgi
import errno
import getpass
import http.server
import json
import logging
import os
import ssl
import sys

from functools import wraps
from logging.config import fileConfig

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
__version__ = '3.0'
__license__ = 'GPL3'


BEINC_OSD_TYPE_NONE = 0
BEINC_OSD_TYPE_PYNOTIFY = 1
BEINC_OSD_TYPE_PYOSD = 2

BEINC_CURRENT_CONFIG_VERSION = 3


class BEINCError401(Exception):
    pass


class BEINCError403(Exception):
    pass


class BEINCError404(Exception):
    pass


class BEINCError405(Exception):
    pass


def beinc_login_required(method):
    """
    Decorator for checking login credentials
    """

    @wraps(method)
    def wrapper(self, data, *args, **kwargs):
        if data.get('resource_name') is None:
            raise BEINCError403('Resource-name missing')
        if data.get('password') is None:
            raise BEINCError401('Password missing')
        try:
            instance = self.server.instances[data.get('resource_name')]
        except Exception as e:
            raise BEINCError401('Wrong instance or password')
        if not instance.password_match(data.get('password')):
            raise BEINCError401('Wrong instance or password')
        return method(self, data, *args, **kwargs)
    return wrapper


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
                    'Unable to set up a '
                    'pynotify notification object for "{0}" ({1})\n'.format(
                        self.__name,
                        e))
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
                    'Unable to set up a pyosd '
                    'notification object for "{0}" ({1})\n'.format(
                        self.__name,
                        e))
                sys.exit(errno.EPERM)
            self.__osd_type = BEINC_OSD_TYPE_PYOSD

    @property
    def name(self):
        """
        name-property for the server instance (read-only)
        """
        return self.__name

    @property
    def queueable(self):
        """
        True if this instance has a queueing capability (read-only)
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
        Returns a list of dict representation of the message queue
        """
        r_value = self.__message_queue
        self.__message_queue = list()
        return r_value

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


class BEINCCustomHandler(http.server.BaseHTTPRequestHandler):
    """
    """
    def do_POST(self):
        """
        Handle POST requests
        """
        if self.path.strip('/') not in ('beinc/push', 'beinc/pull'):
            self.__generate_json_error(404, 'Invalid resource path')
            return
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type']})
        # extract all known fields
        POST_data = dict(
            resource_name=form.getvalue('resource_name'),
            password=form.getvalue('password'),
            title=form.getvalue('title', ''),
            message=form.getvalue('message', ''))
        try:
            result = {}
            if self.path.strip('/') == 'beinc/push':
                result = self.__handle_push(POST_data)
            elif self.path.strip('/') == 'beinc/pull':
                result = self.__handle_pull(POST_data)
            self.__render_to_JSON_response(result)
        except BEINCError401 as e:
            self.__generate_json_error(401, str(e))
        except BEINCError403 as e:
            self.__generate_json_error(403, str(e))
        except BEINCError404 as e:
            self.__generate_json_error(404, str(e))
        except BEINCError405 as e:
            self.__generate_json_error(405, str(e))
        except Exception as e:
            self.__generate_json_error(500,
                                       'Unexpected error: {}'.format(str(e)))

    def do_GET(self):
        """
        Handle GET Requests
        """
        self.__generate_json_error(405, 'Unsupported method')

    @beinc_login_required
    def __handle_push(self, data):
        """
        """
        instance = self.server.instances[data.get('resource_name')]
        try:
            instance.send_message(data.get('title'), data.get('message'))
            return {'message': 'OK. Sent.'}
        except Exception as e:
            self.__generate_json_error(500, str(e))

    @beinc_login_required
    def __handle_pull(self, data):
        """
        """
        return {}

    def __generate_json_error(self, code, message):
        """
        Generates response header and json content for errors

        Keyword Arguments:
        :param code: the HTTP code
        :type code: int

        :param message: the return message set in the .json response
        :type message: str
        """
        self.send_response(code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()
        msg = {'code': code, 'message': message, 'data': {}}
        self.wfile.write(json.dumps(msg,
                                    sort_keys=True,
                                    indent=4).encode('utf-8'))

    def __render_to_JSON_response(self, context):
        """
        Keyword Arguments:
        :param context: the context-dict to be converted to json
        :type context: dict
        """
        response = {'code': 200, 'message': 'OK', 'data': {}}
        response.update(context)
        self.send_response(200)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(response,
                                    sort_keys=True,
                                    indent=4).encode('utf-8'))


class BEINCNotifyServer(http.server.HTTPServer):
    """
    """
    def set_config(self, config):
        """
        Sets the configuration dict for the server, instantiates
        the BEINC instances and initiates the defined OSD backends
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
                logger.info('Instance "{0}" added'.format(instance['name']))
        except Exception as e:
            sys.stderr.write('Unable to create instance "{0}": {1}\n'.format(
                instance['name'],
                e))
            sys.exit(1)

    @property
    def instances(self):
        """
        a property that returns the instance list (read-only)
        """
        return self.__instances


if __name__ == '__main__':
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
        '-L', '--logger-name',
        metavar='NAME',
        type=str,
        dest='logger_name',
        default='',
        help="BEINC logger name (default: 'beinc')")
    parser.add_argument(
        '-l', '--logger-config',
        metavar='CONFIG',
        type=str,
        dest='logger_config',
        default=os.path.expanduser('~/.beinc_server_logger.ini'),
        help=('BEINC logger config (.ini) '
              '(default: ~/.beinc_server_logger.ini)'))
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
        sys.stderr.write('Unable to parse {0}: {1}\n'.format(args.config_file,
                                                             e))
        sys.exit(errno.EIO)
    try:
        if os.path.isfile(args.logger_config):
            fileConfig(args.logger_config)
            logger = logging.getLogger(args.logger_name)
        else:
            logging.basicConfig(
                format='%(asctime)s - %(levelname)s - %(message)s',
                level=logging.DEBUG)
            logger = logging.getLogger('beinc')
        logger.info('BEINC starting. Loading config...')
        if config_dict.get('config_version') != BEINC_CURRENT_CONFIG_VERSION:
            sys.stderr.write(
                'WARNING: The version of the config-file: {0} ({1}) '
                'does not correspond to the latest version supported '
                'by this program ({2})\nCheck beinc_config_sample.json '
                'for the newest features!\n'.format(
                    args.config_file,
                    config_dict.get('config_version', 'Not set'),
                    BEINC_CURRENT_CONFIG_VERSION))
        ssl_certificate = config_dict['server']['general'].get(
            'ssl_certificate')
        ssl_private_key = config_dict['server']['general'].get(
            'ssl_private_key')
        ssl_acceptable_ciphers_str = config_dict['server']['general'].get(
            'ssl_ciphers')
        beinc_server = BEINCNotifyServer((args.hostname, args.port),
                                         BEINCCustomHandler)
        beinc_server.set_config(config_dict)
        if ssl_certificate and ssl_private_key:
            beinc_server.socket = ssl.wrap_socket(
                beinc_server.socket,
                keyfile=ssl_private_key,
                certfile=ssl_certificate,
                server_side=True,
                ssl_version=ssl.PROTOCOL_TLSv1_2,
                ciphers=ssl_acceptable_ciphers_str)
        logger.info('Done!')
        beinc_server.serve_forever()
    except Exception as e:
        sys.stderr.write('BEINCServer critical error: {0}\n'.format(e))
        sys.exit(1)
    sys.exit(0)
