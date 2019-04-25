#!/usr/bin/env python
####################
#
# Copyright (c) 2019 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Tool to interact with ADIDNS over LDAP
#
####################
from __future__ import print_function
import sys
import argparse
import getpass
import re
import socket
import codecs
from struct import unpack, pack
from impacket.structure import Structure
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE
import ldap3
from impacket.ldap import ldaptypes
import dns.resolver
import datetime
from builtins import str
from future.utils import itervalues, iteritems, native_str

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))



class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    """
    structure = (
        ('ipv6Address', '16s'),
    )

class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = int(self['entombedTime'] / 10)
        try:
            return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)
        except OverflowError:
            return None

def get_dns_zones(connection, root, debug=False):
    connection.search(root, '(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'])
    zones = []
    for entry in connection.response:
        if entry['type'] != 'searchResEntry':
            continue
        if debug:
            print(entry['dn'])
        zones.append(entry['attributes']['dc'])
    return zones

def get_dns_resolver(server):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    # Is our host an IP? In that case make sure the server IP is used
    # if not assume lookups are working already
    try:
        socket.inet_aton(server)
        dnsresolver.nameservers = [server]
    except socket.error:
        pass
    return dnsresolver

def ldap2domain(ldap):
    return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]

def print_record(record, ts=False):
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'
    print_o('Record entry:')
    if ts:
        print('Record is tombStoned (inactive)')
    print(' - Type: %d (%s) (Serial: %d)' % (record['Type'], rtype, record['Serial']))
    if record['Type'] == 0:
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        print(' - Tombstoned at: %s' % tstime.toDatetime())
    # A record
    if record['Type'] == 1:
        address = DNS_RPC_RECORD_A(record['Data'])
        print(' - Address: %s' % address.formatCanonical())
    # NS record or CNAME record
    if record['Type'] == 2 or record['Type'] == 5:
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        # address.dump()
        print(' - Address: %s' %  address['nameNode'].toFqdn())
    # SRV record
    if record['Type'] == 33:
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        # record_data.dump()
        print(' - Priority: %d' %  record_data['wPriority'])
        print(' - Weight: %d' %  record_data['wWeight'])
        print(' - Port: %d' %  record_data['wPort'])
        print(' - Name: %s' %  record_data['nameTarget'].toFqdn())
    # SOA record
    if record['Type'] == 6:
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        # record_data.dump()
        print(' - Serial: %d' %  record_data['dwSerialNo'])
        print(' - Refresh: %d' %  record_data['dwRefresh'])
        print(' - Retry: %d' %  record_data['dwRetry'])
        print(' - Expire: %d' %  record_data['dwExpire'])
        print(' - Minimum TTL: %d' %  record_data['dwMinimumTtl'])
        print(' - Primary server: %s' %  record_data['namePrimaryServer'].toFqdn())
        print(' - Zone admin email: %s' %  record_data['zoneAdminEmail'].toFqdn())

def new_record(rtype, serial):
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = serial
    nr['TtlSeconds'] = 180
    # From authoritive zone
    nr['Rank'] = 240
    return nr

def print_operation_result(result):
    if result['result'] == 0:
        print_o('LDAP operation completed successfully')
        return True
    else:
        print_f('LDAP operation failed. Message returned from server: %s %s' %  (result['description'], result['message']))
        return False

RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    33: 'SRV'
}

def main():
    parser = argparse.ArgumentParser(description='Query/modify DNS records for Active Directory integrated DNS via LDAP')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    #maingroup = parser.add_argument_group("Main options")
    parser.add_argument("host", type=native_str,metavar='HOSTNAME',help="Hostname/ip or ldap://host:port connection string to connect to")
    parser.add_argument("-u","--user",type=native_str,metavar='USERNAME',help="DOMAIN\\username for authentication.")
    parser.add_argument("-p","--password",type=native_str,metavar='PASSWORD',help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("--forest", action='store_true', help="Search the ForestDnsZones instead of DomainDnsZones")
    parser.add_argument("--zone", help="Zone to search in (if different than the current domain)")
    parser.add_argument("--print-zones", action='store_true', help="Only query all zones on the DNS server, no other modifications are made")
    parser.add_argument("-v", "--verbose", action='store_true', help="Show verbose info")
    parser.add_argument("-d", "--debug", action='store_true', help="Show debug info")
    parser.add_argument("-r", "--resolve", action='store_true', help="Resolve hidden recoreds via DNS")
    parser.add_argument("--dns-tcp", action='store_true', help="Use DNS over TCP")
    parser.add_argument("--include-tombstoned", action='store_true', help="Include tombstoned (deleted) records")


    args = parser.parse_args()
    #Prompt for password if not set
    authentication = None
    if args.user is not None:
        authentication = NTLM
        if not '\\' in args.user:
            print_f('Username must include a domain, use: DOMAIN\\username')
            sys.exit(1)
        if args.password is None:
            args.password = getpass.getpass()

    # define the server and the connection
    s = Server(args.host, get_info=ALL)
    print_m('Connecting to host...')
    c = Connection(s, user=args.user, password=args.password, authentication=authentication, auto_referrals=False)
    print_m('Binding to host')
    # perform the Bind operation
    if not c.bind():
        print_f('Could not bind with specified credentials')
        print_f(c.result)
        sys.exit(1)
    print_o('Bind OK')
    domainroot = s.info.other['defaultNamingContext'][0]
    forestroot = s.info.other['rootDomainNamingContext'][0]
    if args.forest:
        dnsroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % forestroot
    else:
        dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % domainroot

    if args.print_zones:
        zones = get_dns_zones(c, dnsroot, args.verbose)
        if len(zones) > 0:
            print_m('Found %d domain DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        forestroot = 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % s.info.other['rootDomainNamingContext'][0]
        zones = get_dns_zones(c, forestroot, args.verbose)
        if len(zones) > 0:
            print_m('Found %d forest DNS zones:' % len(zones))
            for zone in zones:
                print('    %s' % zone)
        return

    if args.zone:
        zone = args.zone
    else:
        # Default to current domain
        zone = ldap2domain(domainroot)

    searchtarget = 'DC=%s,%s' % (zone, dnsroot)
    print_m('Querying zone for records')
    c.extend.standard.paged_search(searchtarget, '(objectClass=*)', search_scope=LEVEL, attributes=['dnsRecord','dNSTombstoned','name'], paged_size=500, generator=False)
    targetentry = None
    dnsresolver = get_dns_resolver(args.host)
    outdata = []
    for targetentry in c.response:
        if targetentry['type'] != 'searchResEntry':
            print(targetentry)
            continue
        if not targetentry['attributes']['name']:
            # No permission to view those records
            recordname = targetentry['dn'][3:targetentry['dn'].index(searchtarget)-1]
            if not args.resolve:
                outdata.append({'name':recordname, 'type':'?', 'ip': '?'})
                if args.verbose:
                    print_o('Found hidden record %s' % recordname)
            else:
                # Resolve A query
                try:
                    res = dnsresolver.query('%s.%s.' % (recordname, zone), 'A', tcp=args.dns_tcp)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
                    if args.verbose:
                        print_f(str(e))
                    print_m('Could not resolve node %s (probably no A record assigned to name)' % recordname)
                    outdata.append({'name':recordname, 'type':'?', 'ip': '?'})
                    continue
                ipv4 = str(res.response.answer[0][0])
                if args.verbose:
                    print_o('Resolved hidden record %s' % recordname)
                outdata.append({'name':recordname, 'type':'A', 'ip': ipv4})
        else:
            recordname = targetentry['attributes']['name']
            if args.verbose:
                print_o('Found record %s' % targetentry['attributes']['name'])

        # Skip tombstoned records unless requested
        if targetentry['attributes']['dNSTombstoned'] and not args.include_tombstoned:
            continue

        for record in targetentry['raw_attributes']['dnsRecord']:
            dr = DNS_RECORD(record)
            # dr.dump()
            # print targetentry['dn']
            if args.debug:
                print_record(dr, targetentry['attributes']['dNSTombstoned'])
            if dr['Type'] == 1:
                address = DNS_RPC_RECORD_A(dr['Data'])
                outdata.append({'name':recordname, 'type':'A', 'ip': address.formatCanonical()})
            continue
    print_o('Found %d records' % len(outdata))
    with codecs.open('records.csv', 'w', 'utf-8') as outfile:
        outfile.write('type,name,ip\n')
        for row in outdata:
            outfile.write('{type},{name},{ip}\n'.format(**row))

if __name__ == '__main__':
    main()
