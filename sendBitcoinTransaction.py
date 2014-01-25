import struct
import socket

import utils
import msgUtils


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.connect(("50.151.108.133", 8333))
#sock.connect(("64.237.43.178", 8333))
sock.connect(("24.255.210.44", 8333))

sock.send(msgUtils.getVersionMsg())

want = 0
buf = ''

step = 0
while 1:
    header = sock.recv(24)
    if len(header) == 0: break
    magic, cmd, payload_len, checksum = struct.unpack('L12sL4s', header)
    buf = ''
    while payload_len > 0:
        chunk = sock.recv(payload_len)
        if len(chunk) == 0: break
        buf += chunk
        payload_len -= len(chunk)
        print 'got chunk of', len(chunk)
    msgUtils.processChunk(header, buf)
        
    #if step == 0:
    #   sock.send(msg_getblocks)
    step += 1

    if step == 5:
        msg = msgUtils.getAddrMsg()
        sock.send(msg)
        print 'SENT', msg.encode('hex')




