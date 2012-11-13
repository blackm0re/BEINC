#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import urllib2
import sched
import sys
import time

import pynotify

POLLING_FREQUENCY = 10
NOTIFICATION_URL = 'https://simeon.simeonov.no:40004/notifications/'
TIMEOUT_SEC = 3

def poll_notifications(scheduler):
    """
    """
    try:
        req = urllib2.Request(NOTIFICATION_URL)
        response = urllib2.urlopen(req)
        response_str = response.read()
    
        entries = json.loads(response_str)
        for entry in entries:
            n = pynotify.Notification('IRC', entry, 'dialog-information')
            n.set_timeout(TIMEOUT_SEC)
            n.show()

    except Exception as e:
        sys.stderr.write("Client error: {0}".format(e))
        sys.exit(1)

    scheduler.enter(POLLING_FREQUENCY, 1, poll_notifications, (scheduler,))


def main():

    if not pynotify.init("Weechat Notify"):
        sys.stderr.write("There was a problem with libnotify")
        sys.exit(1)

    sc = sched.scheduler(time.time, time.sleep)
    sc.enter(POLLING_FREQUENCY, 1, poll_notifications, (sc,))
    sc.run()

if __name__ == '__main__':
    main()
