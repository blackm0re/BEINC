#!/usr/bin/env python

# Blackmore's Enhanced IRC-Notification Collection (BEINC)
# Copyright (C) 2013-2024 Simeon Simeonov

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
"""BEINC standalone server implementation"""

import argparse
import contextlib
import errno
import io
import json
import logging
import os
import pathlib
import ssl
import sys
import urllib.parse
from functools import wraps
from http.server import BaseHTTPRequestHandler, HTTPServer
from logging.config import fileConfig

try:
    import notify2 as pynotify
except ImportError:
    pynotify = None


__author__ = 'Simeon Simeonov'
__version__ = '4.4'
__license__ = 'GPL3'


BEINC_OSD_TYPE_NONE = 0
BEINC_OSD_TYPE_PYNOTIFY = 1

BEINC_CURRENT_CONFIG_VERSION = 3


class BEINC400Error(Exception):
    """BEINC400Error"""


class BEINC401Error(Exception):
    """BEINC401Error"""


class BEINC403Error(Exception):
    """BEINC403Error"""


class BEINC404Error(Exception):
    """BEINC404Error"""


class BEINC405Error(Exception):
    """BEINC405Error"""


def eprint(*arg, **kwargs):
    """stdderr print wrapper"""
    print(*arg, file=sys.stderr, flush=True, **kwargs)


def beinc_login_required(method):
    """Decorator for checking login credentials"""

    @wraps(method)
    def wrapper(self, data, *arg, **kwargs):
        if data.get('resource_name') is None:
            raise BEINC403Error('Resource-name missing')
        if data.get('password') is None:
            raise BEINC401Error('Password missing')
        try:
            instance = self.server.instances[data.get('resource_name')]
        except Exception:
            raise BEINC401Error('Wrong instance or password') from None
        if not instance.password_match(data.get('password')):
            raise BEINC401Error('Wrong instance or password')
        return method(self, data, *arg, **kwargs)

    return wrapper


class BEINCInstance:
    """Represents a single server-instance"""

    def __init__(self, instance_dict):
        """
        instance_dict: the config-dictionary node that represents this instance
        """
        self._message_queue = []
        self._osd_type = BEINC_OSD_TYPE_NONE
        self._osd_notification = None

        self._name = instance_dict.get('name')
        self._password = instance_dict.get('password', '')
        self._queue_size = int(instance_dict.get('queue_size', 3))
        if instance_dict['osd_system'].lower() == 'pynotify':
            self._queue_size = 0  # disable queueing
            if pynotify is None:
                eprint('This server does not possess pynotify capability')
                eprint(
                    f'Remove the instance {self._name} or define it with '
                    f'"osd_system": "none"  or other '
                    f'available backend'
                )
                sys.exit(errno.EPERM)
            try:
                self._osd_notification = pynotify.Notification(' ')
                self._osd_notification.timeout = 1000 * int(
                    instance_dict.get('osd_timeout', 5)
                )
                self._osd_notification.set_category('im.received')
                self._osd_type = BEINC_OSD_TYPE_PYNOTIFY
            except Exception as exp:
                eprint(
                    f'Unable to set up a pynotify notification object '
                    f'for "{self._name}" ({exp})'
                )
                sys.exit(errno.EPERM)

    @property
    def name(self):
        """name-property for the server instance (read-only)"""
        return self._name

    @property
    def queueable(self):
        """True if this instance has a queueing capability (read-only)"""
        return bool(self._queue_size)

    def password_match(self, password):
        """
        Returns True if 'passowrd' matches the instance-password,
        otherwise - False

        :param password: The password to compare
        :type password: str

        :return: True if the password matches, False otherwise
        :rtype: bool
        """
        return self._password == password

    def send_message(self, title, message):
        """
        Displays or enqueues the message,
        depending on the instance's type in regard to the osd_system

        :param title: The title
        :type title: str

        :param message: The message
        :type message: str
        """
        if self._osd_type == BEINC_OSD_TYPE_PYNOTIFY:
            self._send_pynotify_messaage(title, message)
        else:
            self._send_message_to_queue(title, message)

    def get_queue(self):
        """Returns a list of dict representation of the message queue"""
        r_value = self._message_queue
        self._message_queue = []
        return r_value

    def _send_pynotify_messaage(self, title, message):
        """
        Displays pynotify message

        :param title: The title
        :type title: str

        :param message: The message
        :type message: str
        """
        self._osd_notification.update(summary=title, message=message)
        self._osd_notification.show()

    def _send_message_to_queue(self, title, message):
        """
        Enqueues the message

        :param title: The title
        :type title: str

        :param message: The message
        :type message: str
        """
        if len(self._message_queue) >= self._queue_size:
            self._message_queue.pop(0)
        self._message_queue.append({'title': title, 'message': message})


class BEINCCustomHandler(BaseHTTPRequestHandler):
    """Custom handler"""

    @staticmethod
    def parse_raw_POST_data(fp, headers):
        """
        Parses the POST data the way the deprecated cgi.FieldStorage used to
        """
        try:
            clen = -1
            if headers is None:
                headers = {}
            if 'content-length' in headers:
                with contextlib.suppress(ValueError):
                    clen = int(headers['content-length'])
            return dict(urllib.parse.parse_qsl(fp.read(clen).decode('utf-8')))
        except Exception as exp:
            raise BEINC400Error('Invalid POST request') from exp

    def do_POST(self):
        """Handle POST requests"""
        if self.path.strip('/') not in ('beinc/push', 'beinc/pull'):
            self._generate_json_error(404, 'Invalid resource path')
            return
        try:
            form = self.parse_raw_POST_data(self.rfile, self.headers)
            # extract all known fields
            POST_data = {
                'resource_name': form.get('resource_name'),
                'password': form.get('password'),
                'title': form.get('title', ''),
                'message': form.get('message', ''),
            }
            result = {}
            if self.path.strip('/') == 'beinc/push':
                result = self._handle_push(POST_data)
            elif self.path.strip('/') == 'beinc/pull':
                result = self._handle_pull(POST_data)
            self._render_to_JSON_response(result)
        except BEINC400Error as err:
            self._generate_json_error(400, str(err))
        except BEINC401Error as err:
            self._generate_json_error(401, str(err))
        except BEINC403Error as err:
            self._generate_json_error(403, str(err))
        except BEINC404Error as err:
            self._generate_json_error(404, str(err))
        except BEINC405Error as err:
            self._generate_json_error(405, str(err))
        except Exception as exp:
            self._generate_json_error(500, f'Unexpected error: {exp}')

    def do_GET(self):
        """Handle GET Requests"""
        self._generate_json_error(405, 'Unsupported method')

    @beinc_login_required
    def _handle_push(self, data):
        """Handle push"""
        instance = self.server.instances[data.get('resource_name')]
        instance.send_message(data.get('title'), data.get('message'))
        return {'message': 'OK. Sent.'}

    @beinc_login_required
    def _handle_pull(self, data):
        """Handle pull"""
        instance = self.server.instances[data.get('resource_name')]
        if not instance.queueable:
            raise BEINC405Error('This instance does not support queuing')
        return {
            'message': 'OK. Fetched.',
            'data': {'messages': instance.get_queue()},
        }

    def _generate_json_error(self, code, message):
        """
        Generates response header and json content for errors

        :param code: the HTTP code
        :type code: int

        :param message: the return message set in the .json response
        :type message: str
        """
        self.send_response(code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()
        msg = {'code': code, 'message': message, 'data': {}}
        self.wfile.write(
            json.dumps(msg, sort_keys=True, indent=4).encode('utf-8')
        )

    def _render_to_JSON_response(self, context):
        """
        :param context: the context-dict to be converted to json
        :type context: dict
        """
        response = {'code': 200, 'message': 'OK', 'data': {}}
        response.update(context)
        self.send_response(200)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(
            json.dumps(response, sort_keys=True, indent=4).encode('utf-8')
        )


class BEINCNotifyServer(HTTPServer):
    """BEINCNotifyServer class"""

    def __init__(self, *arg, **kwargs):
        """Default constructor"""
        super().__init__(*arg, **kwargs)
        self._config = None
        self._instances = {}

    def set_config(self, config):
        """
        Sets the configuration dict for the server, instantiates
        the BEINC instances and initiates the defined OSD backends
        """
        self._config = config
        # initialize pynotify if the module exists and if needed
        if pynotify:
            for instance in self._config['server']['instances']:
                # check if we have at least one instance that uses pynotify
                # before initializing it
                if instance.get('osd_system', '').lower() == 'pynotify':
                    if not pynotify.init('BEINC Notify'):
                        eprint('pynotify.init failed! Exiting...')
                        sys.exit(1)
                    break
        instance = {'name': 'Invalid'}
        try:
            for instance in self._config['server']['instances']:
                self._instances[instance['name']] = BEINCInstance(instance)
                logger.info('Instance %s added', instance['name'])
        except Exception as exp:
            eprint(f"Unable to create instance \"{instance['name']}\": {exp}")
            sys.exit(1)

    @property
    def instances(self):
        """a property that returns the instance list (read-only)"""
        return self._instances


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='The following options are available'
    )
    parser.add_argument(
        '-H',
        '--hostname',
        metavar='HOSTNAME',
        type=str,
        dest='hostname',
        default='127.0.0.1',
        help='BEINC server IP / hostname (default: 127.0.0.1)',
    )
    parser.add_argument(
        '-L',
        '--logger-name',
        metavar='NAME',
        type=str,
        dest='logger_name',
        default='',
        help="BEINC logger name (default: 'beinc')",
    )
    parser.add_argument(
        '-l',
        '--logger-config',
        metavar='CONFIG',
        type=str,
        dest='logger_config',
        default=os.path.expanduser('~/.beinc_server_logger.ini'),
        help=(
            'BEINC logger config (.ini) '
            '(default: ~/.beinc_server_logger.ini)'
        ),
    )
    parser.add_argument(
        '-p',
        '--port',
        metavar='PORT',
        type=int,
        dest='port',
        default=9998,
        help='BEINC server port (default: 9998)',
    )
    parser.add_argument(
        '-f',
        '--config-file',
        metavar='FILE',
        type=str,
        default=os.path.expanduser('~/.beinc_server.json'),
        dest='config_file',
        help='BEINC config file (default: ~/.beinc_server.json)',
    )
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=f'%(prog)s {__version__}',
        help='Display program-version and exit',
    )
    args = parser.parse_args()
    try:
        with io.open(args.config_file, 'r', encoding='utf-8') as fp:
            config_dict = json.load(fp)
    except Exception as exp:
        eprint(f'Unable to parse {args.config_file}: {exp}')
        sys.exit(errno.EIO)
    try:
        if pathlib.Path(args.logger_config).is_file():
            fileConfig(args.logger_config)
            logger = logging.getLogger(args.logger_name)
        else:
            logging.basicConfig(
                format='%(asctime)s - %(levelname)s - %(message)s',
                level=logging.DEBUG,
            )
            logger = logging.getLogger('beinc')
        logger.info('BEINC starting. Loading config...')
        if config_dict.get('config_version') != BEINC_CURRENT_CONFIG_VERSION:
            eprint(
                f'WARNING: The version of the config-file: {args.config_file} '
                f'({config_dict.get("config_version", "Not set")}) does not '
                'correspond to the latest version supported by this program '
                f'({BEINC_CURRENT_CONFIG_VERSION})\n'
                'Check beinc_config_sample.json for the newest features!'
            )
        ssl_certificate = config_dict['server']['general'].get(
            'ssl_certificate'
        )
        ssl_private_key = config_dict['server']['general'].get(
            'ssl_private_key'
        )
        ssl_acceptable_ciphers_str = config_dict['server']['general'].get(
            'ssl_ciphers'
        )
        beinc_server = BEINCNotifyServer(
            (args.hostname, args.port), BEINCCustomHandler
        )
        beinc_server.set_config(config_dict)
        if ssl_certificate and ssl_private_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                certfile=ssl_certificate, keyfile=ssl_private_key
            )
            if ssl_acceptable_ciphers_str is not None:
                context.set_ciphers(ssl_acceptable_ciphers_str)
            beinc_server.socket = context.wrap_socket(
                beinc_server.socket, server_side=True
            )
        logger.info('Done!')
        beinc_server.serve_forever()
    except KeyboardInterrupt:
        print('\n\nTerminating...')
    except Exception as exp:
        eprint(f'BEINCServer critical error: {exp}')
        sys.exit(1)
    sys.exit(0)
