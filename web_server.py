#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

import cherrypy

class WebNotifyServer(object):

    def __init__(self):
        self.counter = 0

    @cherrypy.expose
    def notifications(self, **kwargs):
        self.counter += 1
        print(str(kwargs))
        print(self.counter)
        return ("called")


    @cherrypy.expose
    def other(self, **kwargs):
        self.counter += 1
        print(str(kwargs))
        print(self.counter)
        return ("called")


def main():

    cherrypy.config.update({
            'server.socket_host': '10.0.0.4',
            'server.socket_port': 40003,
            })

    try:
        cherrypy.quickstart(WebNotifyServer())

    except Exception as e:
        sys.stderr.write("WebServer error: {0}".format(e))
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
