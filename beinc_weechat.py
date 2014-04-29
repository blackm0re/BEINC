#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import httplib
import json
import os
import random
import socket
import ssl
import sys
import urllib
import urllib2

import weechat

enabled = True
global_values = dict()

# few constants #
BEINC_POLICY_NONE = 0
BEINC_POLICY_ALL = 1
BEINC_POLICY_LIST_ONLY = 2



class ValidHTTPSConnection(httplib.HTTPConnection):
    """
    """

    default_port = httplib.HTTPS_PORT

    def __init__(self, cert_file, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)
        self.__cert_file = cert_file


    def connect(self):
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock,
                                    ca_certs=self.__cert_file,
                                    cert_reqs=ssl.CERT_REQUIRED)



class ValidHTTPSHandler(urllib2.HTTPSHandler):

    def __init__(self, cert_file, *args, **kwargs):
        urllib2.HTTPSHandler.__init__(self, *args, **kwargs)
        self.__cert_file = cert_file

    def https_open(self, req):
            return self.do_open(ValidHTTPSConnection(self.__cert_file), req)



class WeechatTarget(object):
    """
    """
    
    def __init__(self, target_dict):
        """
        target_dict: the config-dictionary node that represents this instance
        """
        self.__name = target_dict.get(
            'name',
            ''.join([chr(random.randrange(97, 123)) for x in range(4)]))
        self.__url = target_dict.get('target_url')
        self.__password = target_dict.get('target_password')

        self.__pm_title_template = target_dict.get('pm_title_template',
                                                   '%s @ %S')
        self.__pm_message_template = target_dict.get('pm_message_template',
                                                     '%m')

        self.__cm_title_template = target_dict.get('cm_title_template',
                                                   '%c @ %S')
        self.__cm_message_template = target_dict.get('cm_message_template',
                                                     '%s -> %m')

        self.__nm_title_template = target_dict.get('nm_title_template',
                                                   '%c @ %S')
        self.__nm_message_template = target_dict.get('nm_message_template',
                                                     '%s -> %m')

        self.__chans = set(target_dict.get('channel_list', list()))
        self.__nicks = set(target_dict.get('nick_list', list()))
        self.__chan_messages_policy = int(target_dict.get(
            'channel_messages_policy',
            BEINC_POLICY_LIST_ONLY))
        self.__priv_messages_policy = int(target_dict.get(
            'private_messages_policy',
            BEINC_POLICY_ALL))
        self.__notifications_policy = int(target_dict.get(
            'notifications_policy',
            BEINC_POLICY_ALL))
        self.__cert_file = target_dict.get('target_cert_file')
        self.__timestamp_format = target_dict.get('target_timestamp_format',
                                                  '%H:%M:%S')


    @property
    def name(self):
        """
        """
        return self.__name


    @property
    def chans(self):
    	"""
    	"""
        return self.__chans
    
    
    @property
    def nicks(self):
    	"""
    	"""
        return self.__nicks
    

    @property
    def channel_messages_policy(self):
    	"""
    	"""
        return self.__chan_messages_policy


    @property
    def private_messages_policy(self):
    	"""
    	"""
        return self.__priv_messages_policy


    @property
    def notifications_policy(self):
    	"""
    	"""
        return self.__notifications_policy
    
        
    def __repr__(self):
        """
        """
        
        return 'name: {0}\nurl: {1}\nchannel_list: {2}\nnick_list: {3}'\
            'channel_messages_policy: {4}\nprivate_messages_policy: {5}'\
            'notifications_policy: {6}'.format(self.__name,
                                               self.__url,
                                               ', '.join(self.__chans),
                                               ', '.join(self.__nicks),
                                               self.__chan_message_policy,
                                               self.__priv_message_policy,
                                               self.__notifications_policy)


    def send_private_message_notification(self, message, values):
        """
        """
        pass


    def send_channel_message_notification(self, message, values):
        """
        """
        pass

        
    def send_notify_message_notification(self, message, values):
        """
        """
        pass


    def __fetch_formatted_str(self, template, values):
        """
        """
        replacements = {'%S': values['server'],
                        '%s': values['source_nick'],
                        '%c': values['channel'],
                        '%m': values['message'],
                        '%t': values['timestamp'],
                        '%p': 'BEINC',
                        '%n': values['own_nick']}
        for key, value in replacements.items():
            template = template.replace(key, value)
        return template


    def __send_beinc_message(self, data):
        """
        the function implements the BEINC "protocol" by generating a simple
        HTTP request
        """

        try:
            req = urllib2.Request(self.__url, data)
            opener = urllib2.build_opener(ValidHTTPSHandler)
            
            response = opener.open(req)
            res_code = response.code
            response.close()
            if res_code == 200:
                return True
        except Exception as e:
            weechat.prnt(weechat.current_buffer(),
                         'DEBUG: send_beinc_message-ERROR: {0}'.format(e))
        return False



def beinc_send_message(message):
     weechat.prnt(weechat.current_buffer(), 'beinc message: {0}'.format(message))


def beinc_command(data, buffer, args):
    global enabled
    if args == 'on':
        enabled = True
        weechat.prnt(weechat.current_buffer(), 'beinc on')
    elif args == 'off':
        enabled = False
        weechat.prnt(weechat.current_buffer(), 'beinc off')
    elif args == 'reload':
        beinc_config_file_str = os.path.join(
            weechat.info_get('weechat_dir', ''),
            'beinc.json')
        weechat.prnt(weechat.current_buffer(), '{0} reloaded'.format(
            beinc_config_file_str))
    else:
        beinc_send_message(args)

    return weechat.WEECHAT_RC_OK


def beinc_privmsg_handler(data, signal, signal_data):
    if not enabled:
        return weechat.WEECHAT_RC_OK

    prvmsg_dict = weechat.info_get_hashtable('irc_message_parse',
                                             {'message': signal_data })

    # packing the privmsg handler values
    ph_values = dict()
    ph_values['server'] = signal.split(',')[0]
    ph_values['own_nick'] = weechat.info_get('irc_nick', server)
    ph_values['channel'] = prvmsg_dict['arguments'].split(':')[0].strip()
    ph_values['source_nick'] = prvmsg_dict['nick']
    ph_values['message'] = ':'.join(
        prvmsg_dict['arguments'].split(':')[1:]).strip()
    ph_values['timestamp'] = datetime.datetime.now().strftime(
        self.__timestamp_format)

    if ph_values['channel'] == ph_values['own_nick']:
        # priv messages are handled here
        if not global_values['global_channel_messages_policy']:
            return weechat.WEECHAT_RC_OK

        for target in target_list:
            if target.private_messages_policy == 1 or (
                    target.private_messages_policy == 2 \
                    and '{0}.{1}'.format(
                        ph_values['server'],
                        ph_values['source_nick'].lower()) in target.nicks):
                weechat.prnt(weechat.current_buffer(),
                             'DEBUG: priv message - {0}'.format(
                                 ph_values['message']))

    elif privmsg_handler_values['own_nick'].lower() in ph_values['message'].lower():  
        # notify messages are handled here
        weechat.prnt(weechat.current_buffer(),
                     'DEBUG: notify message - {0}'.format(ph_values['message']))
        if not global_values['global_notifications_policy']:
            return weechat.WEECHAT_RC_OK

    elif global_values['global_channel_messages_policy']:  
        # chan messages are handled here
        weechat.prnt(weechat.current_buffer(),
                     'DEBUG: chan message - {0}'.format(ph_values['message']))

    return weechat.WEECHAT_RC_OK


def beinc_init():

    global enabled
    global target_list
    global global_values

    global_values['global_chans'] = set()
    global_values['global_nicks'] = set()
    custom_error = ''

    global_values['global_channel_messages_policy'] = False
    global_values['global_private_messages_policy'] = False
    global_values['global_notifications_policy'] = False
    
    try:
        beinc_config_file_str = os.path.join(
            weechat.info_get('weechat_dir', ''),
            'beinc.json')
        weechat.prnt('', 'Parsing {0}...'.format(beinc_config_file_str))

        custom_error = 'load error'
        with open(beinc_config_file_str, 'r') as fp:
            config_dict = json.load(fp)

        # clear the target-list
        target_list = []

        custom_error = 'target parse error'
        for target in config_dict['irc_client']['targets']:
            try:
                new_target = WeechatTarget(target)
            except Exception as e:
                weechat.prnt('', 'Unable to add target: {0}'.format(e))
                continue
            global_values['global_chans'].update(new_target.chans)
            global_values['global_nicks'].update(new_target.nicks)
            if new_target.channel_messages_policy:
                global_values['global_channel_messages_policy'] = True
            if new_target.private_messages_policy:
                global_values['global_private_messages_policy'] = True
            if new_target.notifications_policy:
                global_values['global_notifications_policy'] = True

            target_list.append(new_target)
            weechat.prnt('', 'BEINC target {0} added'.format(new_target.name))

        weechat.prnt('', 'Done!!!')

    except Exception as e:
        weechat.prnt('', 'ERROR: unable to parse {0}: {1} - {2}'.format(
            beinc_config_file_str, custom_error, e))
        enabled = False

        # do not return error / exit the script
        # in order to give a smoother opportunity to fix a 'broken' config
        return weechat.WEECHAT_RC_OK
    
    return weechat.WEECHAT_RC_OK



weechat.register('beinc_weechat',
                 'Simeon Simeonov',
                 '1.0',
                 'GPL3',
                 'Blackmore\'s Extended IRC Notification Collection (Weechat Client)',
                 '',
                 '')
version = weechat.info_get('version_number', '') or 0
if int(version) < 0x00040000:
    weechat.prnt('', 'WeeChat version >= 0.4.0 is required to run beinc')
else:
    weechat.hook_command('beinc',
                         'beinc on off toggle', '<on | off | reload>',
                         'description...',
                         'None',
                         'beinc_command',
                         '')
    weechat.hook_signal('*,irc_in2_privmsg', 'beinc_privmsg_handler', '')
    beinc_init()
    weechat.prnt('', 'beinc initiated!')
