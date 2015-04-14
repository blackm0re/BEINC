#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Blackmore's Enhanced IRC-Notification Collection (BEINC) v2.0
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
import httplib  # for Python < 2.7.9
import os
import socket  # for Python < 2.7.9
import ssl
import sys
import xmlrpclib


__author__ = 'Simeon Simeonov'
__version__ = '1.0'
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
                 source_address=None, ca_cert=None):
        httplib.HTTPConnection.__init__(self, host, port, strict, timeout,
                                        source_address)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_cert = ca_cert

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
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=self.ca_cert)

class BEINCCustomSafeTransport(xmlrpclib.Transport):

    def __init__(self, use_datetime=0, ca_cert=None):
        xmlrpclib.Transport.__init__(self, use_datetime=use_datetime)
        self.ca_cert = ca_cert
                            
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
            self._connection = host, HTTPS(chost,
                                           None,
                                           ca_cert=self.ca_cert,
                                           **(x509 or {}))
            return self._connection[1]


def action_execute(args):
    """
    """
    try:
        if sys.hexversion >= 0x20709f0:
            # Python >= 2.7.9
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False
            context.load_verify_locations(os.path.expanduser(args.cert))
            transport = xmlrpclib.SafeTransport(context=context)
        else:
            # Python < 2.7.9
            transport = BEINCCustomSafeTransport(
                ca_cert=os.path.expanduser(args.cert))
        server = xmlrpclib.ServerProxy(args.url,
                                       transport=transport)
        if args.pull:
            print(server.pull(args.rname, args.password))
        else:
            print(server.push(args.rname,
                              args.password,
                              args.title,
                              args.message))
    except xmlrpclib.Fault as fault:
        sys.stderr.write(
            'BEINC server answered with errorCode={0}: {1}\n'.format(
                fault.faultCode,
                fault.faultString))
    except Exception as e:
        sys.stderr.write('BEINC generic client error: {0}\n'.format(e))
        sys.exit(errno.EPERM)


def main():
    parser = argparse.ArgumentParser(
        description='The following options are available')
    parser.add_argument('url',
                        metavar='URL',
                        type=str,
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
    parser.add_argument('-n', '--resource-name',
                        metavar='NAME',
                        type=str,
                        dest='rname',
                        required=True,
                        help='The name of the BEINC-resource on '
                        'the remote server')
    parser.add_argument('-p', '--password',
                        metavar='PASSWORD',
                        type=str,
                        dest='password',
                        default='',
                        help='Password')
    parser.add_argument('--pull',
                        action='store_true',
                        dest='pull',
                        default=False,
                        help='Perform a pull operation (default: push)')
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
    action_execute(args)
    sys.exit(0)

    
if __name__ == '__main__':
    main()
