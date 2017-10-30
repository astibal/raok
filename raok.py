#!/usr/bin/python
# -*- coding: utf-8 -*-

from pyrad import dictionary, packet, server, tools

import socket, hashlib, base64
import re
import sys
import json

from raoklog import raoklog,hexdump


class RaokServer(server.Server):

    def load_config(self,config_file=None):
        
        fnm = config_file
        if not fnm:
            fnm = 'etc/raok.cfg'
      
        try:
            f = open(fnm,'r')
            self.cfg = json.load(f)

        except IOError as e:
            print "Failed to open config file: %s" % (str(e),)
            sys.exit(-1)
        
        return True

    def init_hosts(self):
        for h in self.cfg['settings']['hosts'].keys():
            s = self.cfg['settings']['hosts'][h]['secret']
            raoklog.info("Intialize host %s with secret `%s'" % (h,s));	    
            self.hosts[h]=server.RemoteHost(h,str(s),"localhost")
            
            raoklog.info("   done.")     
            

    def pap_decrypt(self, pkt):
        if "User-Password" in pkt:
            raoklog.debug("Received PAP encrypted password: \'%s\'" % pkt["User-Password"])
            clean_pwd = pkt["User-Password"][0]
            clean_pwd = pkt.PwDecrypt(clean_pwd)
            raoklog.debug("Decrypted password: \'%s\'" % clean_pwd)

            return (True, clean_pwd)
        return (False, "")

    def auth_accept(self, orig_pkt):
        raoklog.info("=> Creating response for user \'%s\'" % orig_pkt["User-Name"][0])

        reply=self.CreateReplyPacket(orig_pkt)
        ret_challenge = False
        ret_reject = False
        
        
        try:
            u = orig_pkt["User-Name"][0]
            if u not in self.cfg['users']:
                if 'default' not in self.cfg['users']:
                    u = None
                else:
                    u = 'default'
            
            
            
            if u:

                if 'Auth' in self.cfg['users'][u]:
                    raoklog.info("Loading specific attributes for '%s' " % (u,))
                    for a in self.cfg['users'][u]['Auth']:
                        v = self.cfg['users'][u]['Auth'][a]
                        raoklog.info("   %s = \'%s\' " % (a,v))
                        
                        reply[str(a)]=str(v)
                    if 'Access' in self.cfg['users'][u]:
                        if self.cfg['users'][u]['Access'] == False:
                            ret_reject = True
                        
                if'Challenge' in self.cfg['users'][u]:
                    raoklog.info("Using challenge: %s" % self.cfg['users'][u]['Challenge'])

                    if 'State' not in orig_pkt:
                        raoklog.info("This is original access request, sending challenge")
                        ret_challenge = self.cfg['users'][u]['Challenge'].split(':')                    
                        reply['Reply-Message'] = str(ret_challenge[0])
                        reply['State'] = str(ret_challenge[0])
                    else:
                        raoklog.info("This challenge reply, sending accept")
            
        except KeyError as e:
            raoklog.error("Error adding specific attributes for '%s': %s " % (orig_pkt["User-Name"][0],str(e)))
        
        
        
        reply.code=packet.AccessAccept
        r_str= 'Accept'
        if ret_reject:
            reply.code=packet.AccessReject
            r_str = "Reject (explicit)"

        if ret_challenge:
            reply.code = packet.AccessChallenge
            r_str = 'Challenge'
        
        self.SendReplyPacket(orig_pkt.fd, reply)

        raoklog.info("=> Access-%s sent for user '%s' " % (r_str,orig_pkt["User-Name"][0],))
        raoklog.info("...")

        return reply

    def auth_reject(self, orig_pkt):
        raoklog.info("=> Authentication failed for user \'%s\'" % orig_pkt["User-Name"][0])

        reply=self.CreateReplyPacket(orig_pkt)
        reply.code=packet.AccessReject
        self.SendReplyPacket(orig_pkt.fd, reply)

        raoklog.info("...")
        return reply


    def authenticate_plain(self, user, password, pkt=None):
        return True
    
    def authenticate_chap(self, user, chap_ident, challenge, response, pkt=None):
        return True

    def HandleAuthPacket(self, pkt):
        username = ""

        raoklog.info("=> Received an authentication request from %s" % pkt.source[0])
        raoklog.info("   Attributes:")
        for at in pkt.keys():
            if at == "User-Password":
                raoklog.info("      %s = <removed>" % (str(at),))
            else:
                raoklog.info("      %s = \'%s\'" % (str(at),(pkt[at][0])))

        if not "User-Name" in pkt:
            raoklog.warning("RADIUS: client violates RFC: User-Name attribute missing in authentication packet.")
            self.auth_reject(pkt)
            return
        else:
            username = pkt["User-Name"][0]

        if username[0] == '-':
            raoklog.warning("RADIUS: explicitly blocking user " + username[1:])
            self.auth_reject(pkt)
            return

        if "User-Password" in pkt and "CHAP-Password" in pkt:
            raoklog.warning("RADIUS: client violates RFC: both CHAP and PAP authentication request in packet.")
            self.auth_reject(pkt)
            return

        elif "CHAP-Password" in pkt:
            ### Testing block
            import struct

            attr_missing = False

            try: 
                user = pkt["User-Name"][0]
                chal = pkt["CHAP-Challenge"][0]
                resp = pkt["CHAP-Password"][0]
            except KeyError,e:
                raoklog.warning("some attributes are missing")
                attr_missing = True
                self.auth_reject(pkt)
                return

            sec  = "test"

            (resp_chap_ident,foo) = struct.unpack_from("BB",resp)
            resp_octets=resp[1:]
            raoklog.debug("RADIUS: Chap-Ident=%d, Challende-Octets=%s, Response-Octets=%s" % 
                         (resp_chap_ident,hexdump(chal),hexdump(resp_octets)),'HandleAuthPacket')

            if self.authenticate_chap(user,resp_chap_ident,chal, resp_octets, pkt):
                self.auth_accept(pkt)
                return
            else:
                self.auth_reject(pkt)
                return

        elif "User-Password" in pkt:
            retcode = None
            clean_pwd = None
            try:
                (retcode,clean_pwd) = self.pap_decrypt(pkt)
            except UnicodeDecodeError as e:
                raoklog.error("RADIUS: Password decryption failed")
                raoklog.error("RADIUS: open mode: allowed in")
                retcode = True
                clean_pws = "<failed-to-decrypt>"
            
            # Successful decryption
            if retcode:
                raoklog.debug("RADIUS: Attributes: ", 'HandleAuthPacket')
                for attr in pkt.keys():
                    raoklog.debug("RADIUS: %s: %s" % (attr, pkt[attr]))
                
                if self.authenticate_plain(username, clean_pwd, pkt):
                    self.auth_accept(pkt)
                    return
                else:
                    self.auth_reject(pkt)
                    return

            # Decryption failed!
            else:
                raoklog.error("RADIUS: Password decryption failed (dumping packet): ")
                raoklog.debug("RADIUS: Attributes: ")
                for attr in pkt.keys():
                    raoklog.debug("RADIUS: %s: %s" % (attr, pkt[attr]))
                self.auth_reject(pkt)

        else:
            self.auth_reject(pkt)




    def _HandleAcctPacket(self, pkt):
        server.Server._HandleAcctPacket(self, pkt)

        raoklog.info("=> Received an accounting request from %s" % pkt.source[0])
        raoklog.info("   Attributes: ")
        for attr in pkt.keys():
            raoklog.info("       %s = \'%s\'" % (attr, pkt[attr][0]))
        
        try:
            reply=self.CreateReplyPacket(pkt)
            self.SendReplyPacket(pkt.fd, reply)

        except Exception as e:
            raoklog.error("Error replying accounting request: %s" % str(e))

        raoklog.info("...")
        return True


VERSION="0.3.2"

def runRaok():

    raoklog.info("RAOK %s: testing RADIUS server" % (VERSION,))    
    raoklog.info("RAOK %s: !! DON'T USE IN PRODUCTION !!" % (VERSION,))    
    raoklog.info("...")
    
    
    srv=RaokServer(dict=dictionary.Dictionary("dictionary"))
    
    srv.load_config()
    srv.init_hosts()

    if len(sys.argv) > 1:
        for l in sys.argv[1:]:
            raoklog.info("Binding to: %s" % (l,))
            srv.BindToAddress(l)
    else:
        srv.BindToAddress("0.0.0.0")

    srv.Run()

runRaok()
