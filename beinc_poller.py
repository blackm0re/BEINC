#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Blackmore's Enhanced IRC-Notification Collection (BEINC) v1.0
# Copyright (C) 2013-2015 Simeon Simeonov

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


def display_notification(args, title, message):
    """
    A wrapper function for displaying a single notification

    args: the argparse processed command-line arguments
    title: notification title
    message: notification message
    """
    if args.osd_sys == 'pyosd':
        if not pyosd:
            raise Exception(
                'Could not load "pyosd".\n'
                'Please install "pyosd" or use a different osd-system!\n'
                'Terminating...\n')
        notification_obj = pyosd.osd()
        notification_obj.set_timeout(args.osd_timeout)
        if args.font:
            notification_obj.set_font(args.font)
        notification_obj.set_vertical_offset(args.voffset)
        notification_obj.set_horizontal_offset(args.hoffset)
        notification_obj.set_align(
            pyosd_alignments.get(args.alignment, pyosd.ALIGN_LEFT))
        notification_obj.set_pos(
            pyosd_positions.get(args.position, pyosd.POS_BOT))
        notification_obj.set_colour(args.color)
        notification_obj.display(title, line=0)
        notification_obj.display(message, line=1)
    elif args.osd_sys == 'pynotify':
        if not pynotify:
            raise Exception(
                'Could not load "pynotify".\n'
                'Please install "pynotify" or use a different osd-system!\n'
                'Terminating...\n')
        if not pynotify.init('BEINC Notify'):
            raise Exception('There was a problem with libnotify\n')
        notification_obj = pynotify.Notification(' ')
        notification_obj.set_timeout(1000 * args.osd_timeout)
        notification_obj.set_property(
            'app_name',
            '{0} {1}'.format(sys.argv[0], __version__))
        notification_obj.set_properties(
            summary=title,
            body=message)
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
        response.close()
        res_list = json.loads(res_str)
        for entry in res_list:
            title = entry.get('title', '')
            message = entry.get('message', '')
            display_notification(args, title, message)
        scheduler.enter(args.frequency,
                        1,
                        poll_notifications,
                        (scheduler, args))
    except urllib2.HTTPError as e:
        sys.stderr.write('BEINC-server error ({0} - {1})\n'.format(e.code,
                                                                   e.reason))
    except Exception as e:
        sys.stderr.write('BEINC-poller error: {0}\nTerminating...'.format(e))
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
        '-a', '--align',
        metavar='ALIGNMENT',
        type=str,
        dest='alignment',
        default='left',
        help='Alignment for "pyosd" (default: "left")')
    parser.add_argument(
        '-c', '--cert-file',
        metavar='FILE',
        type=str,
        dest='cert',
        default='',
        help='BEINC CA-cert to check the server-cert against (default: None)')
    parser.add_argument(
        '-C', '--color',
        metavar='COLOR',
        type=str,
        dest='color',
        default='blue',
        help='Color for "pyosd" (default: "blue")')
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        dest='debug',
        default=False,
        help='Run the poller-process in debug-mode')
    parser.add_argument(
        '-f', '--frequency',
        metavar='SECONDS',
        type=int,
        dest='frequency',
        default=10,
        help='Polling frequency in seconds (default: 10)')
    parser.add_argument(
        '--font',
        metavar='FONT',
        type=str,
        dest='font',
        default=None,
        help='Custom font for "pyosd" (default: Default font)')
    parser.add_argument(
        '--h-offset',
        metavar='OFFSET',
        type=int,
        dest='hoffset',
        default=30,
        help='Horizontal offset for "pyosd" (default: 30)')
    parser.add_argument(
        '-o', '--osd-system',
        metavar='SYSTEM',
        type=str,
        dest='osd_sys',
        default='pynotify',
        help='BEINC osd-system ("pynotify" or "pyosd") (default: pynotify)')
    parser.add_argument(
        '-P', '--password',
        metavar='PASSWORD[FILE]',
        type=str,
        dest='password',
        default='',
        help='BEINC taget-password / text-file containing the target password'
        ' (default & recommended: prompt for passwd)')
    parser.add_argument(
        '-p', '--position',
        metavar='POSITION',
        type=str,
        dest='position',
        default='bottom',
        help='Position for "pyosd" (default: "bottom")')
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
    parser.add_argument(
        '--v-offset',
        metavar='OFFSET',
        type=int,
        dest='voffset',
        default=120,
        help='Vertical offset for "pyosd" (default: 120)')
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
