from PyQt4 import QtGui as qt
import socket
import json
from Crypto.PublicKey import RSA
from pubsub import pub
import base64
import sys

class QtSecureDog(qt.QMainWindow):
    def __init__(self, port):
        super(QtSecureDog, self).__init__()
        self.friends = [{"addr": "192",
                         "alias": "foo",
                         "pubkey": "zxx"
                        },
                        {"addr": "193",
                         "alias": "bar",
                         "pubkey": "xxz"
                        }]
        self.port = port
        self.initUI()

    def test_function(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        sock.sendall(json.dumps({"req_type": "pubkey"}))
        sock.shutdown(socket.SHUT_WR)
        pubkey_text = sock.recv(4096)
        RSA_pubkey = RSA.importKey(json.loads(pubkey_text)["pubkey"])
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.port))
        enc_msg = RSA_pubkey.encrypt("Hello World", 32)
        sock.sendall(json.dumps({"req_type": "echo", "message": base64.b64encode(enc_msg[0])}))
        sock.shutdown(socket.SHUT_WR)
        msg = sock.recv(1024)
        qt.QMessageBox.about(self, "Received Data", msg)

    def new_friend(self):
        pass

    def mod_friends(self):
        self.friends.remove(str(self.cbox.currentText()))
        self.cbox.removeItem(self.cbox.currentIndex())

    def compose_message(self):
        cd = ComposeDialog(self.port)
        cd.exec_()

    def initUI(self):
        menu = qt.QMenu("&Main", self)
        mhelp = qt.QAction("&Help", menu)
        test = qt.QAction("Self test", menu)
        test.triggered.connect(self.test_function)
        menu.addAction(mhelp)
        menu.addAction(test)
        self.menuBar().addMenu(menu)

        # Centeral Widget
        v = qt.QVBoxLayout()
        cw = qt.QWidget(self)
        cw.setLayout(v)
        self.setCentralWidget(cw)

        cbox = qt.QComboBox(self)
        for friend in self.friends:
            cbox.addItem(friend["alias"])
        h = qt.QHBoxLayout()
        mod = qt.QPushButton("Mod")
        mod.clicked.connect(self.mod_friends)
        h.addWidget(mod)
        compose = qt.QPushButton("Compose")
        compose.clicked.connect(self.compose_message)
        h.addWidget(compose)
        v.addLayout(h)
        v.addWidget(cbox)

        cb = qt.QTextEdit(self)
        v.addWidget(cb)

        self.statusBar().showMessage("I'm Listening")
        self.resize(960,720)
        self.move(0, 0)
        self.setWindowTitle('SecureDOG')

class ComposeDialog(qt.QDialog):

    def send_message(self):
        msg = str(self.me.toPlainText())
        pubkey_text = open(sys.argv[1] + ".pub").read()
        RSA_pubkey = RSA.importKey(pubkey_text)
        enc_msg = RSA_pubkey.encrypt(msg, 32)
        json_string = json.dumps({"req_type": "message", "message" : base64.b64encode(enc_msg[0]) })
        print json_string
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", self.port))
            sock.send(json_string)
            sock.shutdown(socket.SHUT_WR)
            ok_ack = sock.recv(256)
            sock.close()
        except socket.error:
            qt.QMessageBox.error(self, "Error", "Could Not Open Socket")


    def initUI(self):
        h = qt.QHBoxLayout()
        label = qt.QLabel("To", self)
        cbox = qt.QComboBox(self)
        for friend in self.friends:
            cbox.addItem(friend["alias"])
        h.addWidget(label)
        h.addWidget(cbox)

        v = qt.QVBoxLayout()
        self.me = qt.QTextEdit(self)

        sb = qt.QPushButton("Send Message")
        sb.clicked.connect(self.send_message)

        v.addLayout(h)
        v.addWidget(self.me)
        v.addWidget(sb)

        self.setLayout(v)
        self.resize(660, 360)

    def __init__(self, port):
        super(ComposeDialog, self).__init__()
        self.friends = [{"addr": "192",
                         "alias": "foo",
                         "pubkey": "zxx"
                        },
                        {"addr": "193",
                         "alias": "bar",
                         "pubkey": "xxz"
                        }]

        self.port = port
        self.initUI()


