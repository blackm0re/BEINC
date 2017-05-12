#!/usr/bin/env python
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
import errno
import getpass
import httplib
import os
import sched
import socket
import ssl
import sys
import time

try:
    import notify2 as pynotify
except ImportError as e:
    pynotify = None


__author__ = 'Simeon Simeonov'
__version__ = '3.0'
__license__ = 'GPL3'


class BEINCCustomHTTPSConnection(httplib.HTTPConnection):
    """
    This class allows communication via SSL.

    It is a reimplementation of httplib.HTTPSConnection and
    allows the server certificate to be validated against CA
    This functionality lacks in Python < 2.7.9
    """
    default_port = httplib.HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, custom_ssl_options={}):
        httplib.HTTPConnection.__init__(self, host, port, strict, timeout,
                                        source_address)
        self.key_file = key_file
        self.cert_file = cert_file
        self.custom_ssl_options = custom_ssl_options

    def connect(self):
        "Connect to a host on a given (SSL) port."
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock,
                                    self.key_file,
                                    self.cert_file,
                                    **self.custom_ssl_options)


class BEINCCustomSafeTransport(xmlrpclib.Transport):
    """
    Provides an alternative HTTPS transport for clients running on Python<2.7.9
    """

    def __init__(self, use_datetime=0, custom_ssl_options={}):
        xmlrpclib.Transport.__init__(self, use_datetime=use_datetime)
        self.custom_ssl_options = custom_ssl_options

    def make_connection(self, host):
        if self._connection and host == self._connection[0]:
            return self._connection[1]
        try:
            HTTPS = BEINCCustomHTTPSConnection
        except AttributeError:
            raise NotImplementedError(
                "your version of httplib doesn't support HTTPS"
            )
        else:
            chost, self._extra_headers, x509 = self.get_host_info(host)
            self._connection = host, HTTPS(
                chost,
                None,
                custom_ssl_options=self.custom_ssl_options,
                **(x509 or {}))
            return self._connection[1]


def display_notification(args, title, message):
    """
    A wrapper function for displaying a single notification

    args: the argparse processed command-line arguments
    title: notification title
    message: notification message
    """
    if args.osd_sys == 'pynotify':
        if not pynotify:
            raise Exception(
                'Could not load "pynotify".\n'
                'Please install "pynotify" or use a different osd-system!\n'
                'Terminating...\n')
        if not pynotify.init('BEINC Notify'):
            raise Exception('There was a problem with libnotify\n')
        notification_obj = pynotify.Notification(' ')
        notification_obj.timeout = 1000 * args.osd_timeout
        notification_obj.set_category('im.received')
        notification_obj.show()
    else:
        raise Exception(
            'Unsupported osd-system: {0}\n'.format(args.osd_sys))


def poll_notifications(scheduler, args):
    """
    the core function initiated by the scheduler performing a single poll

    scheduler: scheduler object
    args: the argparse processed command-line arguments
    """
    try:
        ssl_version = BEINC_SSL_METHODS.get(args.ssl_version,
                                            ssl.PROTOCOL_SSLv23)
        if sys.hexversion >= 0x20709f0:
            # Python >= 2.7.9
            context = ssl.SSLContext(ssl_version)
            context.verify_mode = ssl.CERT_NONE
            if args.cert:
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(os.path.expanduser(args.cert))
                context.check_hostname = bool(not args.disable_hostname_check)
            if args.ciphers:
                context.set_ciphers(args.ciphers)
            transport = xmlrpclib.SafeTransport(context=context)
        else:
            # Python < 2.7.9
            ssl_options = {}
            ssl_options['ssl_version'] = ssl_version
            if args.cert:
                ssl_options['ca_certs'] = os.path.expanduser(args.cert)
                ssl_options['cert_reqs'] = ssl.CERT_REQUIRED
            if args.ciphers:
                ssl_options['ciphers'] = args.ciphers
            transport = BEINCCustomSafeTransport(
                custom_ssl_options=ssl_options)
        server = xmlrpclib.ServerProxy(args.url,
                                       transport=transport)
        res_list = server.pull(args.rname, args.password)
        for entry in res_list:
            title = entry.get('title', '')
            message = entry.get('message', '')
            display_notification(args, title, message)
        scheduler.enter(args.frequency,
                        1,
                        poll_notifications,
                        (scheduler, args))
    except xmlrpclib.Fault as fault:
        sys.stderr.write(
            'BEINC server answered with errorCode={0}: {1}\n'.format(
                fault.faultCode,
                fault.faultString))
    except ssl.SSLError as e:
        sys.stderr.write('BEINC SSL/TLS error: {0}\n'.format(e))
        sys.exit(errno.EPERM)
    except socket.error as e:
        sys.stderr.write('BEINC connection error: {0}\n'.format(e))
        sys.exit(errno.EPERM)
    except Exception as e:
        sys.stderr.write('BEINC generic client error: {0}\n'.format(e))
        sys.exit(errno.EPERM)


def main():
    parser = argparse.ArgumentParser(
        description='The following options are available')
    parser.add_argument(
        'url',
        metavar='URL',
        type=str,
        help='BEINC server destination URL')
    parser.add_argument(
        '-c', '--cert-file',
        metavar='FILE',
        type=str,
        dest='cert',
        default='',
        help='CA-cert to check the server-cert against '
        '(default: Check disabled)')
    parser.add_argument(
        '--ciphers',
        metavar='CIPHERS',
        type=str,
        dest='ciphers',
        default='',
        help='Preferred ciphers list (default: auto)')
    parser.add_argument(
        '--disable-hostname-check',
        action='store_true',
        dest='disable_hostname_check',
        default=False,
        help='Do not check whether server cert matches server hostname')
    parser.add_argument(
        '-f', '--frequency',
        metavar='SECONDS',
        type=int,
        dest='frequency',
        default=10,
        help='Polling frequency in seconds (default: 10)')
    parser.add_argument(
        '-n', '--resource-name',
        metavar='NAME',
        type=str,
        dest='rname',
        required=True,
        help='The name of the BEINC-resource on the remote server')
    parser.add_argument(
        '-o', '--osd-system',
        metavar='SYSTEM',
        type=str,
        dest='osd_sys',
        default='pynotify',
        help='BEINC osd-system: "pynotify" (default)')
    parser.add_argument(
        '-p', '--password',
        metavar='PASSWORD[FILE]',
        type=str,
        dest='password',
        default='',
        help='BEINC taget-password / text-file containing the target password'
        ' (default & recommended: prompt for passwd)')
    parser.add_argument(
        '-T', '--socket-timeout',
        metavar='SECONDS',
        type=int,
        dest='socket_timeout',
        default=3,
        help='Socket timeout in seconds (0=Python default) (default: 3)')
    parser.add_argument(
        '-t', '--osd-timeout',
        metavar='SECONDS',
        type=int,
        dest='osd_timeout',
        default=5,
        help='OSD timeout (default: 5)')
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s {0}'.format(__version__),
        help='display program-version and exit')
    args = parser.parse_args()
    if not args.password:
        try:
            args.password = getpass.getpass()
        except Exception as e:
            sys.stderr.write('Prompt terminated\n')
            sys.exit(errno.EACCES)
    elif os.path.isfile(args.password):
        try:
            with open(args.password, 'r') as fp:
                passwd = fp.readline()
                if passwd.strip():
                    args.password = passwd.strip()
        except Exception as e:
            sys.stderr.write('Unable to open password file: {0}'.format(e))
            sys.exit(1)
    if args.socket_timeout:
        socket.setdefaulttimeout(args.socket_timeout)
    scheduler = sched.scheduler(time.time, time.sleep)
    scheduler.enter(args.frequency,
                    1,
                    poll_notifications,
                    (scheduler, args))
    scheduler.run()


if __name__ == '__main__':
    main()
