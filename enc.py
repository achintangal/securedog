from Crypto.PublicKey import RSA
import base64
import sys
import json

privatekey = sys.argv[1]
pubkey = privatekey + ".pub"
pubkey_text = open(pubkey).read()
Rkey = RSA.importKey(pubkey_text)

msg = sys.argv[2]

enc_msg = Rkey.encrypt(msg, 32)
print json.dumps({"message": base64.b64encode(enc_msg[0])})
