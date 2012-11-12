# -*- coding: utf-8 -*-

import datetime

from sqlalchemy import schema, types
from sqlalchemy.orm import mapper

metadata = schema.MetaData()

notification_entry_table = schema.Table('notification_entries', metadata,
                                 schema.Column('id', types.Integer, primary_key=True),
                                 schema.Column('timestamp', types.DateTime),
                                 schema.Column('message', types.Unicode(), default = u'Empty message'),
                                 schema.Column('viewed', types.Boolean, default=False)
                                 )



class NotificationEntry(object):

    def __init__(self, message):

        self.timestamp = datetime.datetime.now()
        self.message = message


    def __repr__(self):
        
        return message


mapper(NotificationEntry, notification_entry_table)
