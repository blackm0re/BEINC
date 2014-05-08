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
import httplib
import json
import os
import sched
import socket
import ssl
import sys
import time
import urllib
import urllib2

try:
    import pynotify
except ImportError as e:
    sys.stderr.write('A working pynotify library is required by BEINC-poller\n')
    sys.exit(1)


__author__ = 'Simeon Simeonov'
__version__ = '1.0'
__license__ = 'GPL3'


class ValidHTTPSConnection(httplib.HTTPConnection):
    """
    Implements a simple CERT verification functionality
    """

    default_port = httplib.HTTPS_PORT

    def __init__(self, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock,
                                    ca_certs=global_beinc_cert_file,
                                    cert_reqs=ssl.CERT_REQUIRED)


class ValidHTTPSHandler(urllib2.HTTPSHandler):
    """
    Implements a simple CERT verification functionality
    """

    def https_open(self, req):
        return self.do_open(ValidHTTPSConnection, req)


def poll_notifications(scheduler, args):
    """
    """
    try:
        post_values = {'password': args.password}
        data = urllib.urlencode(post_values)
        req = urllib2.Request(args.url, data)
        if args.cert:  # check for cert validity
            global global_beinc_cert_file  # ugly hack
            global_beinc_cert_file = args.cert
            opener = urllib2.build_opener(ValidHTTPSHandler)
            response = opener.open(req)
        else:  # ... or don't
            response = urllib2.urlopen(req)
        res_code = response.code
        res_str = response.read()
        if res_code == 200 and args.debug:
            print('Server responded: OK')
            print('Body:\n{0}'.format(res_str))
        res_list = json.loads(res_str)
        print(type(res_list))
        response.close()
        scheduler.enter(args.frequency,
                        1, 
                        poll_notifications,
                        (scheduler, args))
    except urllib2.HTTPError as e:
        sys.stderr.write('BEINC-server error ({0} - {1})\n'.format(e.code,
                                                                   e.reason))
    except Exception as e:
        sys.stderr.write('BEINC-poller error: {0}\n'.format(e))
        sys.exit(errno.EPERM)


def main():
    parser = argparse.ArgumentParser(
        description='The following options are available')
    parser.add_argument(
        'url',
        metavar='URL',
        type=str,
        help='BEINC destination URL')
    parser.add_argument(
        '-c', '--cert-file',
        metavar='FILE',
        type=str,
        dest='cert',
        default='',
        help='BEINC CA-cert to check the server-cert against (default: None)')
    parser.add_argument(
        '-d',
        action='store_true',
        dest='daemonize',
        default=False,
        help='Run the poller-process in the background')
    parser.add_argument(
        '-D', '--debug',
        action='store_true',
        dest='debug',
        default=False,
        help='Run the poller-process in debug-mode (disables daemonize)')
    parser.add_argument(
        '-f', '--frequency',
        metavar='SECONDS',
        type=int,
        dest='frequency',
        default=10,
        help='Polling frequency in seconds (default: 10)')
    parser.add_argument(
        '-p', '--password',
        metavar='PASSWORD',
        type=str,
        dest='password',
        default='',
        help='BEINC taget-password (default & recommended: prompt for passwd)')
    parser.add_argument(
        '-t', '--osd-timeout',
        metavar='MILLISECONDS',
        type=int,
        dest='osd_timeout',
        default=5000,
        help='OSD timeout (default: 5000)')
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

    if not pynotify.init('BEINC Notify'):
        sys.stderr.write('There was a problem with libnotify\n')
        sys.exit(1)

    sc = sched.scheduler(time.time, time.sleep)
    sc.enter(args.frequency, 1, poll_notifications, (sc, args))
    sc.run()


if __name__ == '__main__':
    main()
