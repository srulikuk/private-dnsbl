#!/usr/bin/env python3

# Add, remove or query IP addresses in DNSBL zone.
#
# Requires Debian packages: python-dnspython python-tz

import argparse
import sys
import dns.update
import dns.query
import dns.tsigkeyring
import dns.resolver
import dns.zone
import ipaddress
import time
import datetime
import pytz
import _myvars

############### re-written by srulikuk (github.com/srulikuk) ###############
##                    --  CREDIT TO ORIGINAL AUTHOR  --                   ##
# __author__ = "Niccolo Rigacci"                                           #
# __copyright__ = "Copyright 2020 Niccolo Rigacci <niccolo@rigacci.org>"   #
# __license__ = "GPLv3-or-later"                                           #
# __email__ = "niccolo@rigacci.org"                                        #
# __version__ = "0.3.1"                                                    #
############################################################################


DNSBL_ZONE = (_myvars.DNSBL_ZONE)
DNS_HOSTNAME = (_myvars.DNS_HOSTNAME)
RNDC_KEY = (_myvars.RNDC_KEY)

def parg():
    parser = argparse.ArgumentParser(description='Add, remove or query IP addresses in DNSBL zone.')
    parser.add_argument(
        '-t', choices=['a', 'r', 'q', 'x'],
        required=True, action="store", dest="type",
        help='a for add - r for remove - q for query'
    )
    parser.add_argument(
        '-i', type=ipaddress.ip_address,
        required='-t x' not in sys.argv, action="store", dest="ip",
        help='ip address to action'
    )
    parser.add_argument(
        '-tr', required=False, action="store", dest="trap",
        help='email address that triggered the trap'
    )
    parser.add_argument(
        '-hs', required=False, action="store", dest="host",
        help='host that triggered the trap'
    )
    parser.add_argument(
        '-s', required=False, action="store", dest="sender",
        help='host that triggered the trap'
    )

    args = parser.parse_args()
    parg.type = args.type
    parg.ip = str(args.ip)
    parg.trap = args.trap
    parg.host = args.host
    parg.sender = args.sender


#---------------------------------------------------------------
#---------------------------------------------------------------

def reverse_address(ip):
    if ':' in ip:
        ipv6_address = ipaddress.ip_address(ip)
        return ipv6_address.reverse_pointer.replace(".ip6.arpa", "")
    else:
        return '.'.join(reversed(ip.split(".")))

#---------------------------------------------------------------
#---------------------------------------------------------------

def AddDNS(ip, rev_address, trap, host, sender, value='127.0.0.1'):
    print('Adding type A record "%s" for %s.%s :' % (value, rev_address, DNSBL_ZONE)),
    timestamp = int(time.time())
    date = datetime.datetime.fromtimestamp(timestamp, tz=pytz.utc).strftime('%Y-%m-%dZ%H:%M:%S')
    keyring = dns.tsigkeyring.from_text(RNDC_KEY)
    update = dns.update.Update(DNSBL_ZONE, keyring = keyring, keyalgorithm = 'hmac-md5.sig-alg.reg.int')
    update.replace(rev_address, 8600, 'A', value)
    update.replace(rev_address, 8600, 'TXT', '"Address %s added at %d (%s)"' % (ip, timestamp, date))
    response = dns.query.tcp(update, DNS_HOSTNAME)
    if response.rcode() == dns.rcode.NOERROR:
        print('NOERROR, Adding to log file')
        # write to log file
        with open("/var/log/dnsbl_spamtrap.log", "a") as log:
            log.write(
            '{},IP-BANNED={},TRAP={},SENDER-HOST={},SENDER-EMAIL={}\n'.format(
                date,ip,trap,host,sender
            )
        )
        return 0
    elif response.rcode() == dns.rcode.REFUSED:
        print('REFUSED')
        return 1
    else:
        print('Response: %s' % (response,))
        return 2

#---------------------------------------------------------------
#---------------------------------------------------------------

def DeleteDNS(rev_address):
    print('Removing type A record %s.%s :' % (rev_address, DNSBL_ZONE)),
    keyring = dns.tsigkeyring.from_text(RNDC_KEY)
    update = dns.update.Update(DNSBL_ZONE, keyring = keyring, keyalgorithm = 'hmac-md5.sig-alg.reg.int')
    update.delete(rev_address, 'A')
    update.delete(rev_address, 'TXT')
    response = dns.query.tcp(update, DNS_HOSTNAME)
    if response.rcode() == dns.rcode.NOERROR:
        print('NOERROR')
        return 0
    elif response.rcode() == dns.rcode.REFUSED:
        print('REFUSED')
        return 1
    else:
        print('Response: %s' % (response,))
        return 2

#---------------------------------------------------------------
#---------------------------------------------------------------

def QueryDNS(ip, rev_address):
    query = rev_address + "." + DNSBL_ZONE
    resolver = dns.resolver.Resolver()
    resolver.timeout = 8
    resolver.lifetime = 8
    try:
        answers = resolver.query(query, 'A')
        a_record = answers[0]
    except:
        a_record = None
    try:
        answers = resolver.query(query, 'TXT')
        txt_record = answers[0]
    except:
        txt_record = None
    if txt_record != None:
        print("Address %s: TXT record for %s.%s => %s" % (ip, rev_address, DNSBL_ZONE, txt_record))
    if a_record != None:
        print("Address %s: A record for %s.%s => %s" % (ip, rev_address, DNSBL_ZONE, a_record))
        return 1
    else:
        print("Address %s is not listed." % (ip,))
        return 0

#---------------------------------------------------------------
#---------------------------------------------------------------

def XfrDNS():
    print('===== AXFR from zone %s =====' % (DNSBL_ZONE,))
    z = dns.zone.from_xfr(dns.query.xfr(DNS_HOSTNAME, DNSBL_ZONE))
    for n in z.nodes.keys():
        record = z[n].to_text(n)
        if ' IN A 127' in record:
            print(record)
    return

#---------------------------------------------------------------
#---------------------------------------------------------------

def main():

    # create empty vars incase they are not passed in parser
    ip = None
    trap = None
    host = None
    sender = None

    parg()
    type = parg.type
    ip = str(parg.ip)
    trap = parg.trap
    host = parg.host
    sender = parg.sender

    # address = parg.ip
    if type == 'x':
        sys.exit(XfrDNS())

    rev_address = reverse_address(ip)

    if type == 'a':
        # address = parg.ip
        # rev_address = reverse_address(parg.ip)
        sys.exit(AddDNS(ip, rev_address, trap, host, sender))

    elif type == 'r':
        # address = parg.ip
        # rev_address = reverse_address(address)
        sys.exit(DeleteDNS(rev_address))

    elif type == 'q':
        # address = parg.ip
        # rev_address = reverse_address(address)
        sys.exit(QueryDNS(ip, rev_address))

if __name__ == '__main__':
    main()
