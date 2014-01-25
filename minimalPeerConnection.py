import struct
import socket

import utils
import msgUtils


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("184.155.9.47", 8333))

sock.send(msgUtils.getVersionMsg())

while 1:
    sock.recv(1000) # Throw away data
    print 'got packet'
    
