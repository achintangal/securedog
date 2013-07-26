"""
RSA encryption 2048

json protocol:

recv -- "req_type" : "pubkey"
send -- "pubkey" : filestring

recv -- "req_type" : "message"
        "message" : string
        "sha" : string
        "signature": string
send -- "OK"
"""
import SocketServer
import socket
import json
import sys
import base64
import threading
import signal
import Queue

from pubsub import pub
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

privatekey = sys.argv[1]
port = sys.argv[2]
port = int(port)
pubkey = privatekey + ".pub"
pubkey_text = open(pubkey).read()
privatekey_text = open(privatekey).read()
RSA_pubkey = RSA.importKey(pubkey_text)
RSA_privatekey = RSA.importKey(privatekey_text)

print_queue = Queue.Queue()

try:
    with open('config.json'):
        pass
except IOError:
    print 'Oh dear. You must diddle with config.json.sample'
    exit(1)

config = json.load(open("config.json", "r"))
known_hosts = json.load(open("known_hosts.json", "r"))
me = None
for known_host in known_hosts:
    if "me" == known_host["alias"]:
        me = known_host

if not me:
    print 'Oh dear. You must add yourself as `me` to known_hosts'


def listener_for_msg(arg, request):
    data = arg
    enc_msg = data["message"]
#    sig = data["signature"]
    msg = RSA_privatekey.decrypt(base64.b64decode(enc_msg))
    sha = SHA256.new()
    sha.update(msg)
    if sha.hexdigest() != data["sha"]:
        request.sendall("OK")
        return

    confirmed_known_host = None
    for known_host in known_hosts:
        if known_host["host"] == data["from"]:
            confirmed_known_host = known_host
            break

    if confirmed_known_host:
        alias = confirmed_known_host["alias"]
        print_queue.put("You have received 1 message " + alias)
        msg_handle = open("messages/inbox/" + alias + "/" + data["sha"], "w")
        print >>msg_handle, msg
        msg_handle.close()
    else:
        # spam
        pass

    request.sendall("OK")


def listener_for_pubkey(arg, request):
    global pubkey_text
    request.sendall(json.dumps({"pubkey": pubkey_text}))


def listener_for_new(arg, request):
    data = eval(json.loads(arg))
    if data.get('req_type', "") == "pubkey":
        pub.sendMessage("pubkey", arg=data, request=request)
    elif data.get('req_type', "") == "message":
        pub.sendMessage("message", arg=data, request=request)
    else:
        request.sendall(json.dumps({"status": "OK"}))


pub.subscribe(listener_for_new, 'new')
pub.subscribe(listener_for_pubkey, 'pubkey')
pub.subscribe(listener_for_msg, 'message')


class RequestHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        total_data = []
        while True:
            data = self.request.recv(1500)
            if not data:
                break
            total_data.append(data)
        data = ''.join(total_data)
        pub.sendMessage("new", arg=data, request=self.request)


server = SocketServer.TCPServer(('127.0.0.1', port), RequestHandler, False)  # Do not automatically bind
server.allow_reuse_address = True # Prevent 'cannot bind to address' errors on restart
server.server_bind()     # Manually bind, to support allow_reuse_address
server.server_activate() # (see above comment)

print "Server Started"
t = threading.Thread(target=server.serve_forever)
t.start()


def signal_handler(signal, frame):
    print "Shutdown"
    server.socket.close()
    server.shutdown()
    exit(0)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGABRT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def print_server():
    while(1):
        print print_queue.get(block=True)

t = threading.Thread(target=print_server)
t.start()

while(1):
    sys.stdout.write(">>> ")
    line = sys.stdin.readline()
    if line.startswith("exit"):
        print "Shutdown"
        server.socket.close()
        server.shutdown()
        exit(0)
    elif line.startswith("send"):
        to = line.split(" ")
        msg = open("sent").read()
        sha = SHA256.new()
        sha.update(msg)
        msg_handle = open("messages/sent/" + sha.hexdigest(), "w")
        print >>msg_handle, msg
        msg_handle.close()
        enc_msg = RSA_pubkey.encrypt(msg, 32)
        msg_dict = json.dumps({"req_type": "message",
                               "message": base64.b64encode(enc_msg[0]),
                               "from": me["host"],
                               "sha": sha.hexdigest()})

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_port = me["host"].split(":")
        sock.connect((host_port[0], int(host_port[1])))
        sock.sendall(json.dumps(msg_dict))
        sock.shutdown(socket.SHUT_WR)
        ok = sock.recv(1024)
        print_queue.put("\n" + ok)
        sock.close()
