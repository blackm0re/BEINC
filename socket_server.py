#!/usr/bin/env python
# -*- coding: utf-8 -*-

import SocketServer
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from bpynotify_orm import NotificationEntry, notification_entry_table


class CustomSocketServer(SocketServer.TCPServer):

    def __init__(self, server_address, RequestHandlerClass, session):
        #super(CustomSocketServer, self).__init__(server_address, 
        #                                         RequestHandlerClass)
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

        self.data = self.rfile.readline().decode('utf8').strip()
        #print(self.data)
        entry = NotificationEntry(self.data)
        self.server.session.add(entry)
        self.server.session.commit()


def main():
    
    HOST, PORT = "localhost", 9997

    if len(sys.argv) == 2 and sys.argv[1] == '-d':
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except Exception as e:
            sys.stderr.write("Unable to daemonize. Fork error: {0}".format(e))
            sys.exit(1)

    try:

        engine = create_engine('sqlite:///notifications.db')
        Session = sessionmaker(bind=engine) # bound session
        session = Session()

        server = CustomSocketServer((HOST, PORT), MyTCPHandler, session)

        # clean all previous entries #
        notification_entry_table.delete(bind=engine).execute()

        server.serve_forever()

    except Exception as e:
        sys.stderr.write("Server error: {0}".format(e))
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
