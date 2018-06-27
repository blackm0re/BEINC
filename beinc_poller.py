#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Blackmore's Enhanced IRC-Notification Collection (BEINC) v3.0
# Copyright (C) 2013-2018 Simeon Simeonov

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
import sched
import socket
import ssl
import sys
import time

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY3:
    from urllib.parse import urlencode
    from urllib.request import urlopen
else:
    from urllib import urlencode
    from urllib2 import urlopen

try:
    if PY3:
        import notify2 as pynotify
    else:
        import pynotify
except ImportError as e:
    pynotify = None


__author__ = 'Simeon Simeonov'
__version__ = '3.0'
__license__ = 'GPL3'


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
        notification_obj = pynotify.Notification(summary=title,
                                                 message=message)
        if PY3:
            notification_obj.timeout = 1000 * args.osd_timeout
            notification_obj.set_category('im.received')
        else:
            notification_obj.set_timeout(1000 * args.osd_timeout)
            notification_obj.set_property(
                'app_name',
                '{0} {1}'.format(sys.argv[0], __version__))
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
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        if args.cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=os.path.expanduser(args.cert))
            context.check_hostname = bool(not args.disable_hostname_check)
        if args.ciphers:
            context.set_ciphers(args.ciphers)
        response = urlopen(
            args.url,
            data=urlencode(
                (
                    ('resource_name', args.rname),
                    ('password', args.password)
                )).encode('utf-8'),
            timeout=args.socket_timeout,
            context=context)
        response_dict = json.loads(response.read().decode('utf-8'))
        if response.code != 200:
            raise socket.error(response_dict.get('message', ''))
        for entry in response_dict['data']['messages']:
            display_notification(args,
                                 entry.get('title', ''),
                                 entry.get('message', ''))
        scheduler.enter(args.frequency,
                        1,
                        poll_notifications,
                        (scheduler, args))
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
    scheduler = sched.scheduler(time.time, time.sleep)
    scheduler.enter(args.frequency,
                    1,
                    poll_notifications,
                    (scheduler, args))
    scheduler.run()


if __name__ == '__main__':
    main()
