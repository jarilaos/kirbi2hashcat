#!/usr/bin/env python

# Based on the Kerberoast script from Tim Medin to extract the Kerberos tickets
# from a kirbi file (https://github.com/nidem/kerberoast).
# https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/kirbi2john.py
# Modified by Laox to use with hashcat
from pyasn1.codec.ber import decoder
import sys

if __name__ == '__main__':
    m = "exported mimikatz kerberos tickets"

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <%s>\n" % (sys.argv[0], m))
        sys.exit(-1)

    for f in sys.argv[1:]:
        with open(f, 'rb') as fd:
            data = fd.read()
            if data[0] == '\x76':  # process .kirbi
                # rem dump
                etype = str(decoder.decode(data)[0][2][0][3][0])
                if etype != "23":
                    sys.stderr.write("Unsupported etype %s seen! Please report this to us.\n" % etype)
                et = str(decoder.decode(data)[0][2][0][3][2])
                sys.stdout.write("$krb5tgs$%s$" % etype + et[:16].encode("hex") +
                                 "$" + et[16:].encode("hex") + "\n")
            elif data[:2] == '6d':
                for ticket in data.strip().split('\n'):
                    etype = str(decoder.decode(ticket.decode('hex'))[0][4][3][0])
                    if etype != "23":
                        sys.stderr.write("Unsupported etype %s seen! Please report this to us.\n" % etype)
                    et = str(decoder.decode(ticket.decode('hex'))[0][4][3][2])
                    sys.stdout.write("$krb5tgs$%s$" % etype + et[:16].encode("hex") +
                                     "$" + et[16:].encode("hex") + "\n")
