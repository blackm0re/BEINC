# Installation Instructions

Refer to README for a basic information about the different BEINC components
and their software requirements!


## Installing the dependencies

### Gentoo GNU/Linux

   ```bash
   emerge -va dev-python/notify2
   ```


### Ubuntu GNU/Linux

   ```bash
   apt-get install python-notify2
   ```


### FreeBSD 12

   ```bash
   cd /usr/ports/devel/py-notify
   make install clean
   ```


### Intallation using virtualenv and pip

Very often you are not the administrator of the server hosting your BEINC server
This is where virtualenv may become handy (provided that it has been installed):
$ virtualenv beinc_installation
$ cd beinc_installation
$ source bin/activate
$ cd beinc-<version>
$ ./beinc_server.py -h


### Installing and setting up BEINC

Unpack the latest version of BEINC
$ tar zxvf beinc-<version>.tar.gz

$cd beinc-<version>
Read the README file

You should now have a basic understanding about the different BEINC components
and how they interact with each other.
beinc_server.py and beinc_weechat.py are using a .json configuration file.
Read beinc_config_sample.json.readme where every configuration option is explined.
Decide on a use-strategy and place the different components to their locations:

beinc_server.py:
Create a configuration file based on beinc_config_sample.json, defining your instances
Start the BEINC server:
$ ./beinc_server.py -H 10.0.0.44 -p 9678
The example loads the server listening on 10.0.0.44, port 9678 using the default
~/.beinc_server.json as a configuration file and usually gives you the Twisted
log console

beinc_pull.py:
$ ./beinc_pull.py -h
The example lists all available command options
$ ./beinc_pull.py -n weechat -t 10 -f 7 --cert-file /home/sgs/weechat_cert.crt \
  -p /home/sgs/.weechat_beinc_passwd https://10.0.0.44:9678
Starts pulling from the instance (target) defined above,
defining an OSD timeout of 10 seconds, pulling frequency of 7 seconds,
checking whether the server's SSL certificate was signed (issued) by /home/sgs/weechat_cert.crt,
extracting the target's password from /home/sgs/.weechat_beinc_passwd

beinc_generic_client.py:
$ ./beinc_generic_client.py -h
The example lists all available command options

beinc_weechat.py:
Create a configuration file based on beinc_config_sample.json, defining your targets
and copy it (or symlink it) to ~/<weechat-dir>/beinc_weechat.json
(weechat-dir is usually ~/.weechat)
Copy (or symlink) beinc_weechat.py to ~/<weechat-dir>/python/autoload/
Load the script in Weechat by typing: /python load beinc_weechat.py
Make sure that all your targets look as they should: /beinc target list
Test if your targets are displaying / relaying your messages: /beinc broadcast Test
