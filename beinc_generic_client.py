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
import socket
import ssl
import sys
import urllib
import urllib2


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



def action_push(args):
    """
    """
    try:
        post_values = {'title': args.title,
                       'message': args.message,
                       'password': args.password}
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
        if res_code == 200:
            print('Server responded: OK')
        else:
            print('Server responded: {0}'.format(res_code))
        print('Body:\n{0}'.format(response.read()))
        response.close()
    except urllib2.HTTPError as e:
        sys.stderr.write('BEINC-server error ({0} - {1})\n'.format(e.code, e.reason))
    except Exception as e:
        sys.stderr.write('BEINC generic client error: {0}\n'.format(e))
        sys.exit(errno.EPERM)


def main():
    
    parser = argparse.ArgumentParser(
        description='The following options are available')

    parser.add_argument('url',
                        metavar='URL',
                        type=str,
                        #dest='url',
                        #required=True,
                        help='Destination URL')

    parser.add_argument('-c', '--cert-file',
                        metavar='FILE',
                        type=str,
                        dest='cert',
                        default='',
                        help='BEINC CA-cert to check the server-cert against')

    parser.add_argument('-m', '--message',
                        metavar='MESSAGE',
                        type=str,
                        dest='message',
                        default='BEINC message',
                        help='BEINC message')

    parser.add_argument('-p', '--password',
                        metavar='PASSWORD',
                        type=str,
                        dest='password',
                        default='',
                        help='Password')

    parser.add_argument('-t', '--title',
                        metavar='TITLE',
                        type=str,
                        dest='title',
                        default='BEINC title',
                        help='BEINC title')

    parser.add_argument('-v', '--version',
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

    action_push(args)
    sys.exit(0)


if __name__ == '__main__':
    main()
