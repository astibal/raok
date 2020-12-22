#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import print_function

import json
import os
import socket
import sys

import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary


class Rasta:
    def __init__(self):
        self.cfg = None

    def load_config(self, config_file):

        fnm = config_file

        try:
            f = open(fnm, 'r')
            self.cfg = json.load(f)

        except IOError as e:
            print("Failed to open config file: %s" % (str(e),))
            sys.exit(-1)

        return True

    def create_client(self, dictfile):
        self.server = Client(
            server=str(self.cfg["settings"]["acct"]['host']),
            secret=bytes(self.cfg["settings"]["acct"]["secret"], encoding="ascii"),
            dict=Dictionary(dictfile))

    def create_packets(self, username, packet_type):
        reqs = []
        if username in self.cfg["users"].keys():
            # print("user " + username + " in database")

            req = self.server.CreateAcctPacket(User_Name=str(username))

            req[r"Acct-Status-Type"] = str(packet_type)

            for att in self.cfg["users"][username]["Acct"][packet_type].keys():
                val = self.cfg["users"][username]["Acct"][packet_type][att]
                if req.dict[att].type == "octets":
                    req[str(att)] = bytes(val, encoding="ascii")
                else:
                    req[str(att)] = val

            reqs.append(req)
        else:
            pass
            # print("user " + username + " NOT in database")

        return reqs

    def send_one(self, req):
        try:
            print("Sending accounting start packet")
            self.server.SendPacket(req)

        except pyrad.client.Timeout:
            print("RADIUS server does not reply")
            return False

        except socket.error as error:
            print("Network error: " + error[1])
            return False

        return True

    def send_all(self, reqs):
        for req in reqs:
            self.send_one(req)


if __name__ == "__main__":
    try:
        phase = 'Start'
        username = None

        if len(sys.argv) > 1:
            username = sys.argv[1]

        if len(sys.argv) > 2:
            phase = sys.argv[2]

        else:
            print("RASTA: Radius Simple Testing Accounter")
            print("... by Ales Stibal, TAC Prague")
            print("")
            print("Usage: progname <user> <Start|Interim-Update|Stop>")
            print("Radius users and attributes are loaded from etc/raok.cfg.")
            sys.exit(-1)

        r = Rasta()
        syscfg = "/etc/raok/raok.cfg"
        if os.path.isfile(syscfg):
            print("loading config from %s" % (syscfg,))
            r.load_config(syscfg)
        else:
            curcfg = "etc/raok.cfg"
            print("loading config from %s" % (curcfg,))
            r.load_config(curcfg)

        sysdick = "/etc/raok/dictionary"
        dick = None
        if os.path.isfile(sysdick):
            print("loading dictionary from %s" % (sysdick,))
            r.create_client(sysdick)
        else:
            curdic = "etc/dictionary"
            print("loading dictionary from %s" % (curdic,))
            r.create_client(curdic)

        p = r.create_packets(username, phase)
        r.send_all(p)

    except KeyboardInterrupt:
        print("Ctrl-C hit. Terminating.")
