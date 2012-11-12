#!/usr/bin/env python
# -*- coding: utf-8 -*-

import SocketServer
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from bpynotify_orm import NotificationEntry


class CustomSocketServer(SocketServer.TCPServer):

    def __init__(self, server_address, RequestHandlerClass, session):
        print "Done"
        SocketServer.TCPServer.__init__(self,
                                        server_address,
                                        RequestHandlerClass)
        self.session = session


class MyTCPHandler(SocketServer.StreamRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        ##self.data = self.request.recv(1024).strip()
        ##print "{} wrote:".format(self.client_address[0])
        ##print self.data

        self.data = self.rfile.readline().strip()

        entry = NotificationEntry(unicode(self.data))
        self.server.session.add(entry)
        self.server.session.commit()


def main():
    
    HOST, PORT = "localhost", 9999

    try:
        engine = create_engine('sqlite:///notifications.db')
        Session = sessionmaker(bind=engine) # bound session
        session = Session()

        server = CustomSocketServer((HOST, PORT), MyTCPHandler, session)
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()

    except Exception as e:
        sys.stderr.write("Server error: {0}".format(e))
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
