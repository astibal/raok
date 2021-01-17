#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import logging.config
import os
import os.path
import sys
import time
import binascii
import hashlib
import struct

import argparse

from pyrad import dictionary, packet, server

VERSION = "0.5.4"


class Config:
    SERIOUS = False
    have_redis = False


try:
    import redis
    Config.have_redis = True
except ImportError:
    pass

__vis_filter = b"""................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""


def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []
    while buf:
        line, buf = bytes(buf[:length]), bytes(buf[length:])
        hexa = ' '.join(['%02x' % x for x in line])
        line = line.translate(__vis_filter)
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line.decode(encoding='latin1')))
        n += length
    return '\n'.join(res)


class RaokLog:
    level = logging.INFO
    logger = None
    separator = ": "

    def __init__(self):
        self.configure()

    def configure(self):
        try:
            # logging.config.fileConfig('etc/nlog.conf')
            self.logger = logging.getLogger("raok")
            hdlr = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
            hdlr.setFormatter(formatter)
            self.logger.handlers = []
            self.logger.addHandler(hdlr)
            self.logger.setLevel(RaokLog.level)
            return True
        except Exception as e:
            print("LOGGER INIT FAILURE: " + str(e))
            return False

    def debug(self, msg, pfx=""):
        self.logger.debug(pfx + self.separator + msg)

    def info(self, msg, pfx=""):
        self.logger.info(pfx + self.separator + msg)

    def warning(self, msg, pfx=""):
        self.logger.warning(pfx + self.separator + msg)

    def error(self, msg, pfx=""):
        self.logger.error(pfx + self.separator + msg)

    def critical(self, msg, pfx=""):
        self.logger.critical(pfx + self.separator + msg)

    def hexdump(self, msg, pfx=""):
        self.logger.debug(pfx + self.separator + "\n" + hexdump(msg))


raoklog = None

# this function is pure workaround for unicode decoding issue in pyrad.
# since there is no convenience method in pyrad to "just damn get the string of bytes" from STRING radius attribute,
# we need to temporarily change dictionary type for it. It's totally ugly, but what we can do
# if we got OCTETS containing non-UTF8 data?

def pyrad_str_value(pkt, attr):
    ret = []
    i = 0

    while True:

        try:
            ret.append(pkt[attr][i])

        # as it with current implementation of pyrad goes, this index error won't be thrown, but it should
        # (see "nested" catch comment in next lines).
        # keep it here for the bright future.
        except IndexError:
            return ret

        except UnicodeDecodeError:

            t = pkt.dict.attributes[attr].type
            if t == 'string':
                pkt.dict.attributes[attr].type = 'octets'

                # this is ugly, but it reflects how pyrad throws exceptions. First unicode is thrown, then index
                # keeping aside that, it's safe to return, since we can't go beyond list boundaries.
                try:
                    ret.append(pkt[attr][i])
                except IndexError:
                    return ret
                finally:
                    pkt.dict.attributes[attr].type = 'string'

        i = i + 1


class RaokServer(server.Server):

    def __init__(self, dictionary_file):
        super().__init__(dict=dictionary_file)
        self.cfg = None
        self.redis_instance = None

    def load_config(self, config_file):

        fnm = config_file

        try:
            f = open(fnm, 'r')
            self.cfg = json.load(f)

        except IOError as e:
            raoklog.error("Failed to open config file: %s" % (str(e),))
            sys.exit(-1)

        return True

    def init_hosts(self):
        for h in self.cfg['settings']['hosts'].keys():
            s = self.cfg['settings']['hosts'][h]['secret']

            if not Config.SERIOUS:
                raoklog.info("Initialize host %s with secret `%s'" % (h, s))
            else:
                raoklog.info("Initialize host %s" % (h,))

            self.hosts[h] = server.RemoteHost(h, bytes(s, encoding="ascii"), "localhost")

            raoklog.debug("   done.")

    def init_redis(self):
        if not Config.have_redis:
            raoklog.info("redis support not installed")
            return False

        try:
            self.redis_instance = redis.Redis(host=self.cfg['settings']['redis']['host'],
                                              port=int(self.cfg['settings']['redis']['port']), db=0)
        except Exception as e:
            Config.have_redis = False
            raoklog.error("cannot create redis instance: " + str(e))

    @staticmethod
    def chap_generate(id_hex, password, challenge):

        result = bytes([id_hex]) + bytes(password, encoding="ascii") + challenge
        response = hashlib.md5(result).digest()

        return response

    @staticmethod
    def pap_decrypt(pkt):
        if "User-Password" in pkt:

            raoklog.debug("Received PAP encrypted password: \'%s\'" % pyrad_str_value(pkt, "User-Password")[0])
            clean_pwd = pyrad_str_value(pkt, "User-Password")[0]

            try:
                clean_pwd = pkt.PwDecrypt(clean_pwd)
                raoklog.debug("Decrypted password: \'%s\'" % clean_pwd)
                return True, clean_pwd

            except UnicodeDecodeError:
                raoklog.info("   cannot convert decrypted password to UTF8")
            except Exception:
                raoklog.info("   error in password decryption")

        return False, ""

    def auth_accept(self, orig_pkt, additionals_dict: dict = None):
        raoklog.info("   Response for user \'%s\'" % orig_pkt["User-Name"][0])

        reply = self.CreateReplyPacket(orig_pkt)
        ret_challenge = False
        ret_reject = False
        ret_reason = "policy"

        username = "default"
        try:
            username = orig_pkt["User-Name"][0]
            if username not in self.cfg['users']:
                if 'default' not in self.cfg['users']:
                    username = None
                else:
                    username = 'default'

            if username:

                if 'Challenge' in self.cfg['users'][username]:
                    ret_challenge = True

                    chal_setup_list = self.cfg['users'][username]['Challenge']
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

                        reply['Reply-Message'] = chal_setup_list[0].encode("ascii")
                        reply['State'] = chal_setup_list[0].encode("ascii")
                    else:
                        state = orig_pkt['State'][0].decode("ascii")
                        raoklog.debug("   current challenge state: " + state)

                        # debug output for challenge index table
                        raoklog.debug("   challenge table:")
                        raoklog.debug("   " + str(chal_setup_list))

                        for deb_chsi in chal_setup.keys():
                            raoklog.debug("   [%s] %s" % (deb_chsi, chal_setup[deb_chsi]))

                        try:
                            cur_idx = chal_setup[state]
                            if cur_idx + 1 >= len(chal_setup_list):
                                raoklog.debug("   challenge finished: " + state)
                                ret_challenge = False
                            else:

                                reply['Reply-Message'] = chal_setup_list[cur_idx + 1].encode("ascii")
                                reply['State'] = chal_setup_list[cur_idx + 1].encode("ascii")

                        except KeyError:
                            ret_challenge = False
                            raoklog.info("   unknown challenge state received")
                            ret_reject = True
                            ret_reason = "challenge state error"

                if 'Auth' in self.cfg['users'][username] and not ret_challenge and not ret_reject:
                    raoklog.info("   Loading attributes for '%s' " % (username,))
                    for a in self.cfg['users'][username]['Auth']:
                        v = self.cfg['users'][username]['Auth'][a]
                        raoklog.info("      %s = \'%s\' " % (a, v))

                        if isinstance(v, list):
                            try:
                                reply[str(a)] = v
                            except TypeError:
                                raoklog.error("     ! this version of pyrad doesn't support repeated attributes")
                                reply[str(a)] = str(v[-1])

                        else:
                            if str(a) in reply:
                                reply[str(a)] = str(v)

                if 'Access' in self.cfg['users'][username]:
                    if not self.cfg['users'][username]['Access']:
                        ret_reject = True

        except KeyError as e:
            raoklog.error("Error adding specific attributes for '%s': %s " % (orig_pkt["User-Name"][0], str(e)))

        reply.code = packet.AccessAccept
        r_str = "Accept (%s)" % (ret_reason,)
        if ret_reject:
            reply.code = packet.AccessReject
            r_str = "Reject (%s)" % (ret_reason,)

        if ret_challenge:
            reply.code = packet.AccessChallenge
            r_str = "Challenge (%s)" % (ret_reason,)

        ###
        self.delay_packet(username, r_str)

        reply = RaokServer.packet_apply_additionals(reply, additionals_dict)
        self.SendReplyPacket(orig_pkt.fd, reply)

        raoklog.info("=> Access-%s sent for user '%s' " % (r_str, orig_pkt["User-Name"][0],))
        raoklog.info("...")

        return reply

    def delay_packet(self, u, typ):
        # process delay
        delay = 0
        try:
            delay = self.cfg['users']['default']['Settings']['Delay']
        except KeyError:
            pass

        try:
            delay = self.cfg['users'][u]['Settings']['Delay']
        except KeyError:
            pass

        if delay > 0:
            raoklog.info("=> Access-%s for user '%s' delayed by %ds" % (typ, u, delay))
            time.sleep(delay)

    @staticmethod
    def packet_apply_additionals(reply, additionals_dict: dict = None):
        if additionals_dict:
            raoklog.debug("adding additional codes to reject packet")
            for add in additionals_dict.keys():
                raoklog.debug(str(add) + ": " + str(additionals_dict[add]))
                reply[add] = additionals_dict[add]
        return reply

    def send_reply(self, orig_pkt, response_type: int, additionals_dict: dict = None):

        reply = self.CreateReplyPacket(orig_pkt)
        reply = RaokServer.packet_apply_additionals(reply, additionals_dict)

        reply.code = response_type
        self.SendReplyPacket(orig_pkt.fd, reply)

        raoklog.info("...")
        return reply

    def auth_reject(self, orig_pkt, additionals_dict: dict = None):
        raoklog.info("=> Authentication failed for user \'%s\'" % orig_pkt["User-Name"][0])

        reply = self.CreateReplyPacket(orig_pkt)
        reply = RaokServer.packet_apply_additionals(reply, additionals_dict)

        reply.code = packet.AccessReject
        self.delay_packet(orig_pkt["User-Name"][0], "Reject")
        self.SendReplyPacket(orig_pkt.fd, reply)

        raoklog.info("...")
        return reply

    def find_user_auth_attr(self, user: str, section: str, attribute: str):
        try:
            # traverse all, we want to have a nice logging
            if user in self.cfg["users"]:
                if "Auth" in self.cfg["users"][user]:
                    if attribute in self.cfg["users"][user][section]:
                        return self.cfg["users"][user][section][attribute]
                    else:
                        raoklog.debug("no '" + attribute + "' set for user")
                else:
                    raoklog.debug("'" + section + "' section not present for user")
            else:
                raoklog.debug("user not in database")
        except KeyError as e:
            raoklog.debug("error in reading user in db: " + str(e))

        return ""

    def find_user_password(self, user: str) -> str:
        pw = self.find_user_auth_attr(user, "Auth", "Password")
        if not pw and self.redis_instance:

            resp = None
            try:
                resp = self.redis_instance.get(user)
            except redis.exceptions.RedisError as redis_error:
                raoklog.error("redis error: " + str(redis_error))
            if resp:
                return resp.decode('utf8')
            return ""

    def authenticate_plain(self, user, password):

        correct_password = self.find_user_password(user)
        if not correct_password:

            if not Config.SERIOUS:
                raoklog.info(">>>  user " + user + " PAP password check skipped")
            return Config.SERIOUS is False

        if correct_password == password:
            raoklog.info(">>>  user '" + user + "' PAP password check OK")
            return True
        else:
            raoklog.info(">>>  user '" + user + "' PAP password check failed")
            if correct_password:
                return False

        return Config.SERIOUS is False

    def authenticate_chap(self, user, chap_ident, challenge, response):

        correct_password = self.find_user_password(user)
        if not correct_password:
            if not Config.SERIOUS:
                raoklog.info(">>>  user " + user + " CHAP password check skipped")

            return Config.SERIOUS is False

        correct_response = RaokServer.chap_generate(chap_ident, correct_password, challenge)

        raoklog.debug("      sent response: " + binascii.hexlify(response).decode("ascii"))
        raoklog.debug("      corr response: " + binascii.hexlify(correct_response).decode("ascii"))

        if correct_response == response:
            raoklog.info(">>>  user '" + user + "' CHAP password check OK")
            return True
        else:
            raoklog.info(">>>  user '" + user + "' CHAP password check failed")
            if correct_password:
                return False

        return Config.SERIOUS is False

    def process_pap(self, pkt):
        try:
            username = pkt["User-Name"][0]

            retcode, clean_pwd = self.pap_decrypt(pkt)

            # Successful decryption
            if retcode:

                if self.authenticate_plain(username, clean_pwd):
                    self.auth_accept(pkt)
                else:
                    self.auth_reject(pkt)

            # Decryption failed!
            else:
                raoklog.error("RADIUS: Password decryption failed (dumping packet): ")
                RaokServer.do_packet_dump(pkt)

                self.auth_reject(pkt)

        except KeyError:
            raoklog.warning("   some chap attributes missing, rejecting")
            self.auth_reject(pkt)

        except UnicodeDecodeError:
            raoklog.error("RADIUS: Password decoding failed")
            self.auth_reject(pkt)

        return Config.SERIOUS is False

    def process_chap(self, pkt):

        try:
            chap_challenge = pkt["CHAP-Challenge"][0]
        except KeyError:
            raoklog.warning("   CHAP-Challenge is missing, using packet authenticator.")
            if pkt.authenticator:
                chap_challenge = pkt.authenticator
            else:
                attr_missing = True
                self.auth_reject(pkt)
                return True

        try:
            user = pkt["User-Name"][0]
            resp = pkt["CHAP-Password"][0]
        except KeyError:
            raoklog.warning("   some chap attributes missing, rejecting")
            attr_missing = True
            self.auth_reject(pkt)
            return True

        (resp_chap_ident, foo) = struct.unpack_from("BB", resp)

        resp_octets = resp[1:]
        raoklog.debug("RADIUS: Chap-Ident=%d, Challenge-Octets=%s, Response-Octets=%s" %
                      (resp_chap_ident, hexdump(bytes(chap_challenge)), hexdump(bytes(resp_octets))),
                      'HandleAuthPacket')

        if self.authenticate_chap(user, resp_chap_ident, chap_challenge, resp_octets):
            self.auth_accept(pkt)
            return True
        else:
            self.auth_reject(pkt)
            return True

    def do_reject_filter(self, pkt):

        # User-Name must be in radius packet
        if not "User-Name" in pkt:
            raoklog.warning("RADIUS: client violates RFC: User-Name attribute missing in authentication packet.")
            self.auth_reject(pkt)
            return True

        try:
            username = pkt["User-Name"][0]

            if username[0] == '-':
                raoklog.info("=> blocking user " + username)
                self.auth_reject(pkt)
                return True

            if "User-Password" in pkt and "CHAP-Password" in pkt:
                raoklog.warning("RADIUS: client violates RFC: both CHAP and PAP authentication request in packet.")
                self.auth_reject(pkt)
                return True

        except KeyError:

            raoklog.warning("RADIUS: client violates RFC: both CHAP and PAP authentication request in packet.")
            self.auth_reject(pkt)

        return False

    @staticmethod
    def do_packet_dump(pkt):
        if Config.SERIOUS and RaokLog.level > logging.INFO:
            return

        raoklog.info("   Attributes:")
        for at in pkt.keys():
            if at == "User-Password":
                dec_status, pwd = RaokServer.pap_decrypt(pkt)
                if dec_status:
                    raoklog.info("      %s = %s  (decrypted: '%s')" % (str(at), pyrad_str_value(pkt, at), pwd))
                else:
                    raoklog.info("      %s = %s  (decryption failed)" % (str(at), pyrad_str_value(pkt, at)))
            else:
                raoklog.info("      %s = %s" % (str(at), pyrad_str_value(pkt, at)))

    # def chap_generate(id_hex, password, challenge):
    #
    #     result = bytes([id_hex]) + bytes(password, encoding="ascii") + challenge
    #     response = hashlib.md5(result).digest()

    @staticmethod
    def lmhash_generate(id_hex, password, challenge):
        hash = hashlib.new('md4', "password".encode('utf-16le')).digest()
        binascii.hexlify(hash)

    def process_mschap2(self, pkt) -> dict:

        # set challenge : either it's attribute or authenticator
        try:
            triage = "MS-CHAP-Challenge"
            chap_challenge = pkt[triage][0]
        except KeyError:
            raoklog.warning("   MS-CHAP-Challenge is missing, using packet authenticator.")
            if pkt.authenticator:
                chap_challenge = pkt.authenticator
            else:
                self.auth_reject(pkt)
                return {}

        try:
            user = pkt["User-Name"][0]
            resp = pkt["MS-CHAP2-Response"][0]
        except KeyError:
            raoklog.warning("   some chap attributes missing, rejecting")
            self.auth_reject(pkt)
            return {}

        (resp_chap_ident, ) = struct.unpack_from("B", resp[49:])

        nt_response = resp[26:50]
        peer_challenge = resp[2:18]

        userpass = self.find_user_password(user)
        if userpass:
            from py3mschap import mschap
            nt_correct_resp = mschap.generate_nt_response_mschap2(
                chap_challenge,
                peer_challenge,
                user,
                userpass,
            )

            if nt_correct_resp == nt_response:
                raoklog.info(">>>  user '" + user + "' MS-CHAPv2 NT password check OK")
                auth_resp = mschap.generate_authenticator_response(
                    userpass,
                    nt_response,
                    peer_challenge,
                    chap_challenge,
                    user
                )

                test_gen_incorrect_response = False
                test_gen_mppe_response = False

                if test_gen_incorrect_response:
                    # Let's check if NAS verifies the response
                    auth_resp = "\x00"*25 + auth_resp[25:]

                ret = {
                    'MS-CHAP2-Success': auth_resp,
                }

                if test_gen_mppe_response:
                    # MPPE stuff
                    from py3mschap import mppe

                    mppeSendKey, mppeRecvKey = mppe.mppe_chap2_gen_keys(userpass, nt_response)
                    send_key, recv_key = mppe.gen_radius_encrypt_keys(
                        mppeSendKey,
                        mppeRecvKey,
                        b"radpass",
                        chap_challenge)

                    # We can send MPPE creds if desired
                    ret['MS-MPPE-Encryption-Policy'] = b'\x00\x00\x00\x01'
                    ret['MS-MPPE-Encryption-Type'] = b'\x00\x00\x00\x06'
                    ret['MS-MPPE-Send-Key'] = send_key
                    ret['MS-MPPE-Recv-Key'] = recv_key

                return ret
        else:

            if Config.SERIOUS:
                return {}

            raoklog.info(">>>  user " + user + " MS-CHAP2 password check skipped")

            # return True :)
            ret = {
                'Reply-Message': "default authentication",
            }
            return ret

    def process_mschap(self, pkt):

        try:
            chap_challenge = pkt["MS-CHAP-Challenge"][0]
        except KeyError:
            raoklog.warning("   MS-CHAP-Challenge is missing, using packet authenticator.")
            if pkt.authenticator:
                chap_challenge = pkt.authenticator
            else:
                self.auth_reject(pkt)
                return True
        try:
            user = pkt["User-Name"][0]
            resp = pkt["MS-CHAP-Response"][0]
        except KeyError:
            raoklog.warning("   some chap attributes missing, rejecting")
            self.auth_reject(pkt)
            return True

        (resp_chap_ident, ) = struct.unpack_from("B", resp[49:])

        resp_octets = resp[1:]

        lm_resp = resp_octets[0:24]
        nt_resp = resp_octets[25:]

        raoklog.debug("RADIUS: Chap-Ident=%d,\n    LM_challenge=\n%s\n    NT_challenge=\n%s" %
                     (resp_chap_ident,
                      hexdump(bytes(lm_resp)),
                      hexdump(bytes(nt_resp))))

        userpass = self.find_user_password(user)
        if userpass:
            from py3mschap import mschap

            nt_correct_resp = mschap.generate_nt_response_mschap(chap_challenge, userpass)
            lm_correct_resp = mschap.generate_lm_response_mschap(chap_challenge, userpass)

            raoklog.debug("RADIUS: received NT response: \n" + hexdump(bytes(nt_resp)))
            raoklog.debug("RADIUS: correct NT response: \n" + hexdump(bytes(nt_correct_resp)))
            raoklog.debug("RADIUS: received LM response: \n" + hexdump(bytes(lm_resp)))
            raoklog.debug("RADIUS: correct LM response: \n" + hexdump(bytes(lm_correct_resp)))

            if nt_correct_resp == nt_resp:
                raoklog.info(">>>  user '" + user + "' MS-CHAP NT password check OK")
                return True
            else:
                raoklog.info(">>>  user '" + user + "' MS-CHAP NT password check failed")
                return False

        if Config.SERIOUS is False:
            raoklog.info(">>>  user '" + user + "' MS-CHAP password check skipped")
            return True
        else:
            return False

    def HandleAuthPacket(self, pkt):

        raoklog.info("=> Received an authentication request from %s" % pkt.source[0])

        RaokServer.do_packet_dump(pkt)

        # check and return if something's wrong
        if self.do_reject_filter(pkt):
            return

        if "User-Password" in pkt:
            if self.process_pap(pkt):
                return

        elif "CHAP-Password" in pkt:
            if self.process_chap(pkt):
                return

        elif "MS-CHAP-Response" in pkt and "MS-CHAP-Challenge" in pkt:
            if self.process_mschap(pkt):
                if self.find_user_auth_attr(pkt["User-Name"][0], "Auth", "Password-Change"):
                    additionals_dict = {
                        "MS-CHAP-Error": "E=648 R=1 V=2",
                        "Reply-Message": "E=648 R=1 V=2",
                    }
                    self.send_reply(pkt, packet.AccessReject, additionals_dict)
                    raoklog.info(">>> password change request sent")
                    return True

                self.auth_accept(pkt)
                return True
            else:
                self.auth_reject(pkt)
                return True

        elif "MS-CHAP2-Response" in pkt and "MS-CHAP-Challenge" in pkt:
            ret = self.process_mschap2(pkt)
            if ret:
                self.auth_accept(pkt, additionals_dict=ret)
                return True
            else:
                self.auth_reject(pkt, additionals_dict=ret)
                return True

        else:
            raoklog.error("unknown authentication method")
            self.auth_reject(pkt)

    def _HandleAcctPacket(self, pkt):
        server.Server._HandleAcctPacket(self, pkt)

        raoklog.info("=> Received an accounting request from %s" % pkt.source[0])

        RaokServer.do_packet_dump(pkt)

        try:
            reply = self.CreateReplyPacket(pkt)
            self.delay_packet(pkt["User-Name"][0], "acct")
            self.SendReplyPacket(pkt.fd, reply)

        except Exception as e:
            raoklog.error("Error replying accounting request: %s" % str(e))

        raoklog.info("...")
        return True


def runRaok(bind_address="0.0.0.0"):

    raoklog.info("RAOK %s: testing RADIUS server" % (VERSION,))
    if not Config.SERIOUS:
        raoklog.info("RAOK %s: !! DON'T USE IN PRODUCTION !!" % (VERSION,))
    else:
        raoklog.info("RAOK %s: running in strict mode" % (VERSION,))
    raoklog.info("...")

    # load dictionary
    sysdick = "/etc/raok/dictionary"
    dick = None

    if os.path.isfile(sysdick):
        raoklog.info("loading dictionary from %s" % (sysdick,))
        dick = dictionary.Dictionary(sysdick)
    else:
        curdic = "etc/dictionary"
        raoklog.info("loading dictionary from %s" % (curdic,))
        dick = dictionary.Dictionary(curdic)

    srv = RaokServer(dick)

    # load config, fallback from /etc/raok to curr dir
    syscfg = "/etc/raok/raok.cfg"
    if os.path.isfile(syscfg):
        raoklog.info("loading config from %s" % (syscfg,))
        srv.load_config(syscfg)
    else:
        curcfg = "etc/raok.cfg"
        raoklog.info("loading config from %s" % (curcfg,))
        srv.load_config(curcfg)

    srv.init_hosts()
    srv.init_redis()

    srv.BindToAddress(bind_address)

    srv.Run()


if __name__ == "__main__":

    try:
        parser = argparse.ArgumentParser(description=" raok server " + VERSION + " by Ales Stibal <astib@mag0.net>")
        parser.add_argument('-S', '--serious',
                            action='store_true',
                            help="fail-close: specify to require existing user and password")
        parser.add_argument('-v', '--verbose',
                            action='store_true',
                            help="print out debugging information")

        args = parser.parse_args(sys.argv[1:])

        if args.serious:
            Config.SERIOUS = True

        if args.verbose:
            RaokLog.level = logging.DEBUG

        raoklog = RaokLog()
        runRaok()
    except KeyboardInterrupt:
        raoklog.info("Ctrl-C hit. Terminating.")
