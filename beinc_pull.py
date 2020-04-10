#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Blackmore's Enhanced IRC-Notification Collection (BEINC) v4.0
# Copyright (C) 2013-2020 Simeon Simeonov

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
"""A simple client that pulls notifications from a BEINC server"""
import argparse
import errno
import getpass
import io
import json
import os
import sched
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

try:
    import notify2 as pynotify
except ImportError:
    pynotify = None


__author__ = 'Simeon Simeonov'
__version__ = '4.0'
__license__ = 'GPL3'


def eprint(*arg, **kwargs):
    """stdderr print wrapper"""
    print(*arg, file=sys.stderr, flush=True, **kwargs)


def fetch_password(args_password):
    """
    Fetches the password from the provided `args_password`

    :param args_password: The password coming from argparse
    :type args_password: str

    :return: The password string
    :rtype: str
    """
    if not args_password:
        try:
            return getpass.getpass()
        except KeyboardInterrupt:
            eprint(os.linesep + 'Prompt terminated')
            sys.exit(errno.EACCES)
    elif os.path.isfile(args_password):
        try:
            with io.open(args_password, 'r') as fp:
                passwd = fp.readline()
                if passwd.strip():
                    return passwd.strip()
        except Exception as e:
            eprint(f'Unable to open password file: {e}')
            sys.exit(1)
    return args_password


def display_notification(args, title, message):
    """
    A wrapper function for displaying a single notification

    :param args: The arguments assigned from argparse
    :type args: argparse.Namespace

    :param title: The title
    :type title: str

    :param message: The message
    :type message: str
    """
    if args.osd_sys == 'pynotify':
        if not pynotify:
            raise Exception(
                'Could not load "pynotify".'
                'Please install "pynotify" or use a different osd-system!'
                'Terminating...')
        if not pynotify.init('BEINC Notify'):
            raise Exception('There was a problem with libnotify')
        notification_obj = pynotify.Notification(summary=title,
                                                 message=message)
        notification_obj.timeout = 1000 * args.osd_timeout
        notification_obj.set_category('im.received')
        notification_obj.show()
    else:
        raise Exception(f'Unsupported osd-system: {args.osd_sys}')


def pull_notifications(scheduler, args):
    """
    The core function initiated by the scheduler performing a single pull

    :param scheduler: Scheduler object
    :type scheduler: sched.scheduler

    :param args: The arguments assigned from argparse
    :type args: argparse.Namespace
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
        response = urllib.request.urlopen(
            args.url,
            data=urllib.parse.urlencode(
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
        response.close()
        scheduler.enter(args.frequency,
                        1,
                        pull_notifications,
                        (scheduler, args))
    except ssl.SSLError as e:
        eprint(f'BEINC SSL/TLS error: {e}')
        sys.exit(errno.EPERM)
    except socket.error as e:
        eprint(f'BEINC connection error: {e}')
        sys.exit(errno.EPERM)
    except Exception as e:
        eprint(f'BEINC generic client error: {e}')
        sys.exit(errno.EPERM)


def main(inargs=None):
    """main entry"""
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
        help='Pulling frequency in seconds (default: 10)')
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
        version=f'%(prog)s {__version__}',
        help='display program-version and exit')
    args = parser.parse_args(inargs)
    args.password = fetch_password(args.password)
    scheduler = sched.scheduler(time.time, time.sleep)
    scheduler.enter(args.frequency,
                    1,
                    pull_notifications,
                    (scheduler, args))
    scheduler.run()


if __name__ == '__main__':
    main()
