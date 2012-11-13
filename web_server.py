#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import sys

import cherrypy

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from bpynotify_orm import NotificationEntry, notification_entry_table


class WebNotifyServer(object):

    def __init__(self, session):
        self.session = session

    @cherrypy.expose
    def notifications(self):
        query = self.session.query(NotificationEntry)\
            .filter(NotificationEntry.viewed==False)\
            .order_by(NotificationEntry.id)
        entries = query.all()
        entry_list = list()
        for entry in entries:
            #print(entry.message)
            entry_list.append(entry.message)
            entry.viewed = True
        self.session.commit()
        print (json.dumps(entry_list, sort_keys=True, indent=4))
        return json.dumps(entry_list, sort_keys=True, indent=4)


def main():

    cherrypy.config.update({
            'server.socket_host': '10.0.0.4',
            'server.socket_port': 40004,

            'server.ssl_module': 'pyopenssl',
            'server.ssl_certificate': '/home/blackmore/gitprogs/bpynotify/cert.crt',
            'server.ssl_private_key': '/home/blackmore/gitprogs/bpynotify/key.pem',            
            })

    try:
        engine = create_engine('sqlite:///notifications.db')
        Session = sessionmaker(bind=engine) # bound session
        session = Session()

        cherrypy.quickstart(WebNotifyServer(session))

    except Exception as e:
        sys.stderr.write("WebServer error: {0}".format(e))
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
