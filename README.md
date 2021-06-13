Copyright (C) 2014-2020 - Simeon Simeonov
See the end of the file for license conditions.


## What is BEINC?

Blackmore's Enchanced IRC Notification Collection (BEINC) is a free set of
components that aims to provide a complete system for different
on-screen-display notification scenarios.

The current version of BEINC contains the following components:
beinc_server.py - server used for queueing or providing on-screen-display (OSD)
beinc_pull.py - client used to fetch enqueued messages from beinc_server.py
                and provide OSD
beinc_weechat.py - a complete script / client for the Weechat IRC client >=0.4.0
                   used to push notification messages to beinc_server.py
beinc_generic_client.py - a simple client used to push notification messages
                          to beinc_server.py
                          Its main purpose is to provide a convenient way to 
                          test beinc_server.py (and beinc_pull.py) as well as
                          to serve as an example for how to develop BEINC-clients
+ documentation and a sample configuration file (beinc_config_sample.json)


## Why should I use BEINC and what has it done for me lately?

BEINC is a free-software, licensed under the GPL3. It gives you the freedoms
of using it, studying it and modifying it.

BEINC is designed to assist you two common scenarios. 
As an example we will consider the case of an IRC client, although BEINC can be
used by any client that conforms with BEINC's "messaging protocol".

We have the common situation where a user is accessing an IRC client located on
a different computer (typically: weechat, irssi, etc. running on a remote server)
The IRC client receives a private message (or any event that requires the user's
attention) and the user has to be notified.
No matter which of the two scenarios applies to your needs, you should start by
 - setting up a BEINC client similar to beinc_generic_client.py on the server
   If you are running weechat >=0.4.0, this version of BEINC comes with 
   a complete weechat BEINC-client: beinc_weechat.py
   Configure the client to send notifications to the beinc_server.py
N.B. Using encryption is important in these days and age.


### Scenario one

The user's computer can be reached by the server running the IRC client.
If the server (running the IRC client) is able to connect to 
a specified TCP port on the user's computer, this is sufficient for BEINC to
directly notify the user. Solution:
 - set up the beinc_server.py on the desktop workstation (the computer where the
   notification-message should be displayed). Define an unprivileged port for 
   beinc_server.py to listen on and enable its OSD capabilities 
   (through pynotify)


### Scenario two

The user's computer can NOT be reached by the server running the IRC client.
This scenario is typical for users that are working on computers that can not
be reached from outside.

Solution:
 - find a server that can be reached by the server running the IRC client.
 - set up the beinc_server.py on it. No OSD capabilities are needed (no X11).
   Define instance(s) for queueing. Define a queue size 
   (how many notifications to store) for each of them.
 - set up beinc_pull.py on the desktop workstation (the computer where the
   notification-message should be displayed).
   beinc_pull.py should be able to access the server running beinc_server.py
   Pulling interval of 5 seconds should be enough for most users.

Read beinc_config_sample.json.readme for details on how to setup 
beinc_server.py and beinc_weechat.py!
Use "-h" command line parameter to display the available options for
beinc_pull.py and beinc_generic_client.py
Each configured beinc_server.py instance has an unique name.
There are 2 operations that can be done on an instance:
 - push - a client is sending a notification to the BEINC server.
          A push is available for all instances.
 - pull - a pull (f.i. beinc_pull.py) is fetching data from the instance-queue.
          A pull is available only for instances defined for queueing. 
          (read beinc_config_sample.json.readme for details!)
Example:
If you defined a beinc_server.py instance with SSL-support,
your URL will be: https://hostname:port


## Supported systems & requirements

Any system running the software required for the selected components.
All components tested on: Gentoo GNU/Linux,
                          Ubuntu GNU/Linux 18.4,
                          FreeBSD 12.x


### Requirements
All components: Python >= 3.6.*

beinc_server.py: pynotify >= 0.1 (optional)
beinc_weechat.py: Weechat >= 0.4.0
beinc_pull.py: pynotify >= 0.1
beinc_generic_client.py: No additional software required

Read INSTALL in this very same folder for more details about installing the requirements!


## Support and contributing

BEINC is hosted on GitHub: https://github.com/blackm0re/BEINC


## Author

Simeon Simeonov - sgs @ LiberaChat


## License

This file is part of BEINC.

BEINC is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
