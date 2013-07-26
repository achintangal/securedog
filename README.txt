Installing
==========

Prereqs:
PyQt
pycrypto

cmdline usage
=============

mkdir messages
mkdir messages/inbox/me
mkdir messages/sent

python cmdline.py <private_key_path> 2525
edit sent file
>>> send <alias>

(edit known hosts file)

Securedog
=========

A 1 - 1 crypto messager and file server.

Encrypted messages are send between trusted parties.

Todo
====

* QtGUI for tests -- done
* QtGUI for sending one message -- done
* QtGUI for Inbox, Index, Content-Views
    * Conetent is txt, image, video, html

* Polish up the json protocol
* Make it NAT possible

* Send Message -- done
* Signature checks
* Message Forward
* Trusted Pubkeys
* Spam block
* Caching Repo
* OnionRoutingServer + DHT

