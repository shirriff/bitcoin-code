import hashlib
import random
import struct
import time
import socket
import unittest

import utils

    
#https://en.bitcoin.it/wiki/Protocol_specification#version
magic = 0xd9b4bef9

def makeMessage(magic, command, payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
    return struct.pack('L12sL4s', magic, command, len(payload), checksum) + payload

addrCount = 0 
def processChunk(header, payload):
    """ Processes a response from a peer."""
    magic, cmd, payload_len, checksum = struct.unpack('L12sL4s', header)
    if len(payload) != payload_len:
        print 'BAD PAYLOAD LENGTH', len(payload), payload_len
        
    cmd = cmd.replace('\0', '') # Remove null termination
    print '--- %s ---' % cmd
    
    if cmd == 'version':
        version, services, timestamp, addr_recv, addr_from, nonce = struct.unpack('<LQQ26s26sQ', payload[:80])
        agent, agent_len = utils.processVarStr(payload[80:])

        start_height = struct.unpack('<L', payload[80 + agent_len:84 + agent_len])[0]
        print '%d %x %x %s %s %x %s %x' % (
            version, services, timestamp, utils.processAddr(addr_recv), utils.processAddr(addr_from),
            nonce, agent, start_height)
    elif cmd == 'inv':
        count, offset = utils.processVarInt(payload)
        result = []
        for i in range(0, count):
            type, hash = struct.unpack('<L32s', payload[offset:offset+36])
            # Note: hash is reversed
            print type, hash[::-1].encode('hex')
            if type == 2:
                sys.exit(0)
            result.append([type, hash])
            offset += 36
        print '---\n'
        return result
    elif cmd == 'addr':
        global addrCount
        count, offset = utils.processVarInt(payload)
        for i in range(0, count):
            timestamp, = struct.unpack('<L', payload[offset:offset+4])
            addr = utils.processAddr(payload[offset+4:offset+30])
            offset += 30
            print addrCount, time.ctime(timestamp), addr
            addrCount += 1
    else:
        dump(payload)
    print '---\n'


def dump(s):
    print ':'.join(x.encode('hex') for x in s)


def getVersionMsg():
    # version(4), services(8), timestamp(8), addr_me(26), addr_you(26), nonce(8)
    # sub_version_num (var_str), start_height(4)
    version = 60002
    services = 1
    timestamp = int(time.time())
    addr_me = utils.netaddr(socket.inet_aton("127.0.0.1"), 8333)
    addr_you = utils.netaddr(socket.inet_aton("127.0.0.1"), 8333)
    nonce = random.getrandbits(64)
    sub_version_num = utils.varstr('')
    start_height = 0

    payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me,
        addr_you, nonce, sub_version_num, start_height)
    return makeMessage(magic, 'version', payload)

def getGetblockMsg():
    genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    genesis_str = genesis.decode('hex')[::-1] # reversed
    recent = "000000000000000592f4797aab7c1fd891a4cacd300d2115f25fa5afab547cdf"
    recent_str = recent.decode('hex')[::-1] # reversed

    hash_stop_str = '\0' * 32
    payload_getblocks = struct.pack('<L', version) + utils.varint(2) + recent_str + genesis_str + hash_stop_str
    return makeMessage(magic, 'getblocks', payload_getblocks)

def getGetdataMsg():
    payload_getdata = utils.varint(1) + struct.pack('<L', 2) + recent_str
    return makeMessage(magic, 'getdata', payload_getdata)

def getInvMsg():
    inv_hash = "235402020007000592f4797a567c1fd89144cacd300d2115f12fa53fab547abc"
    payload_inv = utils.varint(1) + struct.pack('<L', 2) + inv_hash.decode('hex')[::-1]
    return makeMessage(magic, 'inv', payload_inv)

def getTxMsg(payload):
    return makeMessage(magic, 'tx', payload)

def getAddrMsg():
    return makeMessage(magic, 'getaddr', '')

class TestParsing(unittest.TestCase):        
    def test_processChunk(self):
        header = ('\xf9\xbe\xb4\xd9\x76\x65\x72\x73\x69\x6f\x6e\x00\x00\x00\x00\x00' +
                '\x66\x00\x00\x00\x85\xe6\xaa\x94')
        payload = ('\x71\x11\x01\x00\x01\x00\x00\x00' +
               '\x00\x00\x00\x00\xa2\x31\xa0\x52\x00\x00\x00\x00\x01\x00\x00\x00' +
               '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' +
               '\x6c\x51\xe0\xee\xd8\x73\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
               '\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x62\x91\x98\x16\x20\x8d' +
               '\xf4\x7d\x37\xbf\xe4\xe7\x1f\xd2\x11\x2f\x53\x61\x74\x6f\x73\x68' +
               '\x69\x3a\x30\x2e\x38\x2e\x32\x2e\x32\x2f\x02\x2b\x04\x00')
        processChunk(header, payload)

    def test_processInv(self):
        header = ('\xf9\xbe\xb4\xd9\x69\x6e\x76\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                  '\x25\x00\x00\x00\x73\x3b\xf4\x95')
        payload = ('\x01\x01\x00\x00\x00\xd4\xe5\xc2' +
                   '\x8b\x09\x45\x05\xce\xec\x7c\x61\x34\xd1\xbd\x16\x80\x69\xc8\xc9' +
                   '\xc3\x31\x93\xb5\x87\x27\xd9\xda\x7d\xa2\x80\x23\x20')
        chunks = processChunk(header, payload)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0][0], 1) # MSG_TX
        self.assertEqual(chunks[0][1], ('\xd4\xe5\xc2\x8b\x09\x45\x05\xce\xec\x7c\x61\x34\xd1\xbd\x16\x80' +
'\x69\xc8\xc9\xc3\x31\x93\xb5\x87\x27\xd9\xda\x7d\xa2\x80\x23\x20'))
        

if __name__ == '__main__':
    unittest.main()
    
