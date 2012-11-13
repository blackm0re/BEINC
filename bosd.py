#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import weechat

#### CONFIG ####
enabled = True

notify_channels = [
    "RedpillLinpro.#python",
    "Exile.#hin",
    "RedpillLinpro.#adult",
    "Exile.#pichove"
    ]

connections = [ {'sbosdd_ip': '127.0.0.1',
                 'sbosdd_port':  9999},
#                {'sbosdd_ip': "10.0.0.2",
#                 'sbosdd_port':  9999}
                ]
################

def bosd_send_xosd_message(message):
    for conn in connections:
        try:
            #weechat.prnt("", message)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((conn['sbosdd_ip'], conn['sbosdd_port']))
            s.send(message)
            s.close()
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
        bosd_send_xosd_message(args)

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
