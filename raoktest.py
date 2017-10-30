#!/usr/bin/python
from __future__ import print_function
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import socket
import sys
import pyrad.packet

authport = 1812
if len(sys.argv) > 1:
    authport = int(sys.argv[1])

srv = Client(server="localhost", secret=b"fortinet", dict=Dictionary("dictionary"),authport=authport)

req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name="rasta")

req["NAS-IP-Address"] = "192.168.1.10"
req["NAS-Port"] = 0
req["Service-Type"] = "Login-User"
req["NAS-Identifier"] = "trillian"
req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
req["Framed-IP-Address"] = "10.0.0.100"
req["User-Password"] = req.PwCrypt("password")

try:
    print("Sending authentication request")
    reply = srv.SendPacket(req)
except pyrad.client.Timeout:
    print("RADIUS server does not reply")
    sys.exit(1)
except socket.error as error:
    print("Network error: " + error[1])
    sys.exit(1)

if reply.code == pyrad.packet.AccessAccept:
    print("Access accepted")
else:
    print("Access denied")


if len(reply.keys()) > 0:
    print("Attributes returned by server:")
    for i in reply.keys():
        print("%s: %s" % (i, reply[i]))
