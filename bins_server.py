#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import getpass
import json
import os
import sys

import cherrypy

import settings


class CustomSocketServer(SocketServer.TCPServer):

    def __init__(self, server_address, RequestHandlerClass, queue):
        SocketServer.TCPServer.__init__(self,
                                        server_address,
                                        RequestHandlerClass)
        self.queue = queue


class MyTCPHandler(SocketServer.StreamRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):

        data = self.rfile.readline().strip()

        if self.server.queue.qsize() > 3:
            self.server.queue.get()

        self.server.queue.put(data)
        #print(self.data)


class WebNotifyServer(object):

    def __init__(self, queue):
        self.queue = queue

    @cherrypy.expose
    def notifications(self):

        entry_list = list()
        
        while not self.queue.empty():
            entry_list.append(self.queue.get(False))

        #print (json.dumps(entry_list, sort_keys=True, indent=4))
        return json.dumps(entry_list)


def socket_server(queue):
    
    try:
        server = CustomSocketServer((settings.SOCKET_SERVER_HOST,
                                     settings.SOCKET_SERVER_PORT), 
                                    MyTCPHandler, 
                                    queue)
        server.serve_forever()

    except Exception as e:
        sys.stderr.write("SocketServer error: {0}".format(e))
        sys.exit(1)

    sys.exit(0)



def web_server(queue):

    cherrypy.config.update({
            'server.socket_host': settings.WEB_SERVER_HOST,
            'server.socket_port': settings.WEB_SERVER_PORT,
            'server.ssl_module': 'pyopenssl',
            'server.ssl_certificate': settings.WEB_SERVER_CERT,
            'server.ssl_private_key': settings.WEB_SERVER_KEY,            
            })

    try:

        cherrypy.quickstart(WebNotifyServer(queue))

    except Exception as e:
        sys.stderr.write("WebServer error: {0}".format(e))
        sys.exit(1)

    sys.exit(0)


def main():

    parser = argparse.ArgumentParser(description='The following options are available')

    
    parser.add_argument('-d',
                        action='store_true',
                        dest='daemonize',
                        default=False,
                        help='daemonize the server process')

    parser.add_argument('-H', '--hostname',
                        metavar='HOSTNAME',
                        type=str,
                        dest='hostname',
                        default='127.0.0.1',
                        help="Server IP / hostname")

    parser.add_argument('-P', '--port',
                        metavar='PORT',
                        type=int,
                        dest='port',
                        default='9998',
                        help="Server port")

    parser.add_argument('-p', '--password',
                        metavar='PASSWORD',
                        type=str,
                        dest='password',
                        help="Access password for the BOINS server")

    parser.add_argument('-v', '--version',
                        action='version',
                        version='%(prog)s {0}'.format(__VERSION__),
                        help='display program-version and exit')



    sys.exit(0)

if __name__ == "__main__":
    main()
