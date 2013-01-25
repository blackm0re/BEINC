#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
import urllib2

import weechat

#### CONFIG ####
enabled = True

notify_channels = [
    "RedpillLinpro.#python",
    "Exile.#hin",
    "RedpillLinpro.#adult",
    "Exile.#pichove"
    ]

connections = [ {'bosd_url': 'https://127.0.0.1:9999/npush/',
                 'bosd_password': '1234'},

#                {'bosd_url': 'https://pichove.org:9999/npush/',
#                 'bosd_port':  9999,
#                 'bosd_password': 'foo'},
                ]
################

__VERSION__ = '2.0'

def bosd_send_message(header='', message=''):
    for conn in connections:
        try:
            conn['nheader'] = header  # notification header
            conn['nmessage'] = message  # notification message

            data = urllib.urlencode(conn)

            req = urllib2.Request(url, data)
            urllib2.urlopen(req)
            #weechat.prnt("", message)
        except:
            continue

    return True


def bosd_command(data, buffer, args):
    global enabled
    if args == 'on':
        enabled = True
        weechat.prnt(weechat.current_buffer(), "bosd on")
    elif args == 'off':
        enabled = False
        weechat.prnt(weechat.current_buffer(), "bosd off")
    else:
        bosd_send_message('BOSD generic', args)

    return weechat.WEECHAT_RC_OK


def bosd_privmsg_handler(data, signal, signal_data):
    if not enabled:
        return weechat.WEECHAT_RC_OK

    prvmsg_dict = weechat.info_get_hashtable("irc_message_parse",
                                  { "message": signal_data })


    server = signal.split(",")[0]
    
    # channel = signal_data.split(":")[-1]
    # my_nick = weechat.info_get("irc_nick_from_host", signal_data)
   
    my_nick = weechat.info_get("irc_nick", server)
    channel = prvmsg_dict['arguments'].split(":")[0].strip()
    nick = prvmsg_dict['nick']
    message = ':'.join(prvmsg_dict['arguments'].split(':')[1:]).strip()
    
    if (my_nick in message) or ('{0}.{1}'.format(server,channel) in notify_channels):
        template_msg = '{0} @ {1} - {2}: {3}'.format(channel, 
                                                     server, 
                                                     nick, 
                                                     message)
        bosd_send_xosd_message(template_msg)

    if my_nick in channel:
        template_msg = '{0} @ {1}: {2}'.format(nick, server, message)
        bosd_send_xosd_message(template_msg)

    #my_str = "%s - %s - %s - %s" % (my_nick, server, channel, message)
    #weechat.prnt("", my_str)

    return weechat.WEECHAT_RC_OK



weechat.register('bosd', 'Simeon Simeonov', '1.0', 'GPL3', 'Socket notification script', "", "")
weechat.hook_command("bosd", "bosd on off toggle", "<on | off>", "description...", "None", "bosd_command", "")
weechat.hook_signal("*,irc_in2_privmsg", "bosd_privmsg_handler", "")

weechat.prnt("", "bosd initiated!")
