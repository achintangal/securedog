from Crypto.PublicKey import RSA

privatekey = "sample_key_pair1/id_rsa"
pubkey = privatekey + ".pub"
pubkey_text = open(pubkey).read()
privatekey_text = open(privatekey).read()
RSA_pubkey = RSA.importKey(pubkey_text)
RSA_privatekey = RSA.importKey(privatekey_text)

other_privatekey = "sample_key_pair2/id_rsa"
other_pubkey = privatekey + ".pub"
other_pubkey_text = open(other_pubkey).read()
other_privatekey_text = open(other_privatekey).read()
other_RSA_pubkey = RSA.importKey(pubkey_text)
other_RSA_privatekey = RSA.importKey(privatekey_text)

msg = "Foo"
enc_msg = RSA_pubkey.encrypt(msg, 32)
final_msg = RSA_privatekey.decrypt(enc_msg)

if msg == final_msg:
    print "Great Success"


