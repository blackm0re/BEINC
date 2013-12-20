#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import socket
import sys

import weechat

enabled = True

class WeechatTarget(object):
    """
    """
    
    def __init__(self, target_dict):
        """
        target_dict: the config-dictionary node that represents this instance
        """

        self.__name = target_dict['name']
        self.__url = target_dict['target_url']
        self.__password = target_dict['target_password']
        self.__title_template = target_dict['title_template']
        self.__message_template = target_dict['message_template']
        self.__failed = False
        



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
        weechat.prnt(weechat.current_buffer(), 'bosd on')
    elif args == 'off':
        enabled = False
        weechat.prnt(weechat.current_buffer(), 'bosd off')
    elif args == 'reload':
        weechat.prnt(weechat.current_buffer(), '{0} reloaded')
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
    
    if (my_nick.lower() in message.lower()) or ('{0}.{1}'.format(server,channel.lower()) in notify_channels):
        template_msg = '{0} @ {1} - {2}: {3}'.format(channel, 
                                                     server, 
                                                     nick, 
                                                     message)
        bosd_send_xosd_message(template_msg)

    if my_nick.lower() in channel.lower():
        template_msg = '{0} @ {1}: {2}'.format(nick, server, message)
        bosd_send_xosd_message(template_msg)

    # weechat.prnt("", 
    #              'DEBUG: my_nick - {0}, server - {1}, channel - {2}'.format(my_nick, 
    #                                                                         server, 
    #                                                                         channel))

    return weechat.WEECHAT_RC_OK


def beinc_init():

    global enabled
    global target_list

    custom_error = ''

    try:
        beinc_config_file_str = os.path.join(weechat.info_get('weechat_dir',
                                                              ''),
                                             'beinc.json')
        weechat.prnt('', 'Parsing {0}...'.format(beinc_config_file_str))

        custom_error = 'load error'
        with open(beinc_config_file_str, 'r') as fp:
            config_dict = json.load(fp)

        # clear the target-list
        target_list = []

        custom_error = 'target parse error'
        for target in config_dict['irc_client']['targets']:
            new_target = WeechatTarget(target)
            target_list.append(new_target)

        weechat.prnt('', 'Done!!!')

    except Exception as e:
        weechat.prnt('', 'ERROR: unable to parse {0}: {1} - {2}'.format(
            beinc_config_file_str, custom_error, e))
        enabled = False

        # do not return error / exit the script
        # in order to give a smoother opportunity to fix a 'broken' config
        return weechat.WEECHAT_RC_OK
    
    return weechat.WEECHAT_RC_OK


weechat.register('beinc_weechat', 'Simeon Simeonov', '1.0', 'GPL3', 'Blackmore\'s Extended IRC Notification Collection (Weechat Client)', '', '')
weechat.hook_command('beinc', 'beinc on off toggle', '<on | off | reload>', 'description...', 'None', 'beinc_command', '')
weechat.hook_signal('*,irc_in2_privmsg', 'beinc_privmsg_handler', '')

beinc_init()

weechat.prnt('', 'beinc initiated!')
