"""
RSA encryption

json protocol:

recv -- "req_type" : "pubkey"
send -- "pubkey" : filestring

recv -- "req_type" : "message"
        "message" : string
        "signature": string
send -- "OK"

"""

import SocketServer
import json
import sys
import base64

from pubsub import pub
from Crypto.PublicKey import RSA

privatekey = sys.argv[1]
pubkey = privatekey + ".pub"
pubkey_text = open(pubkey).read()
privatekey_text = open(privatekey).read()
RSA_pubkey = RSA.importKey(pubkey_text)
RSA_privatekey = RSA.importKey(privatekey_text)


def listener_for_msg(arg, request):
    data = arg
    msg = data["message"]
#    sig = data["signature"]
    print RSA_privatekey.decrypt(base64.b64decode(msg))


def listener_for_pubkey(arg, request):
    global pubkey_text
    request.sendall(json.dumps({"pubkey": pubkey_text}))


def listener_for_new(arg, request):
    data = arg
    if data.get('req_type', "") == "pubkey":
        pub.sendMessage("pubkey", arg=data, request=request)
    elif data.get('req_type', "") == "message":
        pub.sendMessage("message", arg=data, request=request)
    else:
        request.sendall("OK")

pub.subscribe(listener_for_new, 'new')
pub.subscribe(listener_for_pubkey, 'pubkey')
pub.subscribe(listener_for_msg, 'message')


class RequestHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        total_data = []
        while True:
            data = self.request.recv(8192)
            if not data:
                break
            total_data.append(data)
        data = ''.join(total_data)
        pub.sendMessage("new", arg=json.loads(data), request=self.request)


try:
    server = SocketServer.TCPServer(("localhost", 2525), RequestHandler)
    print "Server Started"
    server.serve_forever()

except KeyboardInterrupt:
    print "Received Interrupt"
    server.socket.close()
    server.shutdown()
    exit(1)

print "Shutdown"
server.socket.close()
server.shutdown()
exit(1)
