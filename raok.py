#!/usr/bin/python
# -*- coding: utf-8 -*-

from pyrad import dictionary, packet, server, tools

import socket, hashlib, base64
import re
import sys
import json

from raoklog import raoklog,hexdump


VERSION="0.3.2"


# this function is pure workaround for unicode decoding issue in pyrad.
# since there is no convenience method in pyrad to "just damn get the string of bytes" from STRING radius attribute,
# we need to temporarily change dictionary type for it. It's totally ugly, but what we can do if we got OCTETS containing non-UTF8 data?
def pyrad_str_value(pkt,attr):

    ret = []
    i = 0
    
    while True:
       
        try:
            ret.append(pkt[attr][i])
            
        # as it with current implementation of pyrad goes, this index error won't be thrown, but it should (see "nested" catch comment in next lines).
        # keep it here for the bright future.
        except IndexError:
            return ret
        
        except UnicodeDecodeError, e:

            t = pkt.dict.attributes[attr].type
            if t == 'string':
                pkt.dict.attributes[attr].type = 'octets'
                
                ## this is ugly, but it reflects how pyrad throws exceptions. First unicode is thrown, then index
                ## keeping aside that, it's safe to return, since we can't go beyond list boundaries.
                try:
                    ret.append(pkt[attr][i])
                except IndexError:
                    return ret
                finally:
                    pkt.dict.attributes[attr].type = 'string'    
                
        
        i = i + 1
        
    return ret


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

            raoklog.debug("Received PAP encrypted password: \'%s\'" % pyrad_str_value(pkt,"User-Password")[0])
            clean_pwd = pyrad_str_value(pkt,"User-Password")[0]
            
            try:
                clean_pwd = pkt.PwDecrypt(clean_pwd)
                raoklog.debug("Decrypted password: \'%s\'" % clean_pwd)
                return (True, clean_pwd)
            
            except UnicodeDecodeError:
                raoklog.info("   cannot convert decrypted password to UTF8")

        return (False, "")

    def auth_accept(self, orig_pkt):
        raoklog.info("   Response for user \'%s\'" % orig_pkt["User-Name"][0])

        reply=self.CreateReplyPacket(orig_pkt)
        ret_challenge = False
        ret_reject = False
        ret_reason = "policy"
        
        
        try:
            u = orig_pkt["User-Name"][0]
            if u not in self.cfg['users']:
                if 'default' not in self.cfg['users']:
                    u = None
                else:
                    u = 'default'
            
            
            
            if u:

                if'Challenge' in self.cfg['users'][u]:
                    ret_challenge = True
                    
                    chal_setup_list = self.cfg['users'][u]['Challenge']
                    raoklog.debug("   Loading challenge settings: %s" % chal_setup_list)
                    
                    
                    # load challenge setup, so we know which state are we in
                    # mapping is state => index
                    i = 0
                    chal_setup_list = chal_setup_list.split(":")
                    chal_setup = {}
                    
                    for chsi in chal_setup_list:
                        chal_setup[chsi] = i
                        i = i + 1
                        

                    if 'State' not in orig_pkt:
                        raoklog.debug("   'State' attribute not present")
                        raoklog.info("   initial request, initiate challenge")
                        
                        reply['Reply-Message'] = str(chal_setup_list[0])
                        reply['State'] = str(chal_setup_list[0])
                    else:
                        state = orig_pkt['State'][0]
                        raoklog.debug("   current challenge state: " + state)

                        # debug output for challenge index table
                        raoklog.debug("   challenge table:")
                        raoklog.debug("   " + str(chal_setup_list))
                        for deb_chsi in chal_setup.keys():
                            raoklog.debug("   [%s] %s" % (deb_chsi,chal_setup[chsi]))
                        
                        try:
                            cur_idx = chal_setup[state]
                            if cur_idx + 1 >= len(chal_setup_list):
                                raoklog.debug("   challenge finished: " + state)
                                ret_challenge = False
                            else:
                                
                                reply['Reply-Message'] = str(chal_setup_list[cur_idx+1])
                                reply['State'] = str(chal_setup_list[cur_idx+1])
                            
                            
                        except KeyError:
                            ret_challenge = False
                            raoklog.info("   unknown challenge state received")
                            ret_reject = True
                            ret_reason = "challenge state error"

                            
                if 'Auth' in self.cfg['users'][u] and not ret_challenge and ret_reject:
                    raoklog.info("   Loading attributes for '%s' " % (u,))
                    for a in self.cfg['users'][u]['Auth']:
                        v = self.cfg['users'][u]['Auth'][a]
                        raoklog.info("      %s = \'%s\' " % (a,v))
                        
                        reply[str(a)]=str(v)
                        
                if 'Access' in self.cfg['users'][u]:
                    if self.cfg['users'][u]['Access'] == False:
                        ret_reject = True                            
                            
            
        except KeyError as e:
            raoklog.error("Error adding specific attributes for '%s': %s " % (orig_pkt["User-Name"][0],str(e)))
        
        
        
        reply.code=packet.AccessAccept
        r_str= "Accept (%s)" % (ret_reason,)
        if ret_reject:
            reply.code=packet.AccessReject
            r_str = "Reject (%s)" % (ret_reason,)

        if ret_challenge:
            reply.code = packet.AccessChallenge
            r_str = "Challenge (%s)" % (ret_reason,)
         
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
                dec_status,pwd = self.pap_decrypt(pkt)
                if dec_status:
                    raoklog.info("      %s = %s  (decrypted: '%s')" % (str(at),pyrad_str_value(pkt,at),pwd))
                else:
                    raoklog.info("      %s = %s  (decryption failed)" % (str(at),pyrad_str_value(pkt,at)))
            else:
                    raoklog.info("      %s = %s" % (str(at),pyrad_str_value(pkt,at)))
                

        if not "User-Name" in pkt:
            raoklog.warning("RADIUS: client violates RFC: User-Name attribute missing in authentication packet.")
            self.auth_reject(pkt)
            return
        else:
            username = pkt["User-Name"][0]

        if username[0] == '-':
            raoklog.info("=> blocking user " + username)
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
                raoklog.warning("   some chap attributes missing, rejecting")
                attr_missing = True
                self.auth_reject(pkt)
                return

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
                
                if self.authenticate_plain(username, clean_pwd, pkt):
                    self.auth_accept(pkt)
                    return
                else:
                    self.auth_reject(pkt)
                    return

            # Decryption failed!
            else:
                raoklog.error("RADIUS: Password decryption failed (dumping packet): ")
                raoklog.info("RADIUS: Attributes: ")
                for attr in pkt.keys():
                    raoklog.info("RADIUS: %s: %s" % (attr, pyrad_str_value(pkt,attr)))
                self.auth_reject(pkt)

        else:
            self.auth_reject(pkt)




    def _HandleAcctPacket(self, pkt):
        server.Server._HandleAcctPacket(self, pkt)

        raoklog.info("=> Received an accounting request from %s" % pkt.source[0])
        raoklog.info("   Attributes: ")
        for attr in pkt.keys():
            raoklog.info("       %s = %s" % (attr, pyrad_str_value(pkt,attr)))
        
        try:
            reply=self.CreateReplyPacket(pkt)
            self.SendReplyPacket(pkt.fd, reply)

        except Exception as e:
            raoklog.error("Error replying accounting request: %s" % str(e))

        raoklog.info("...")
        return True


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
