import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import untangle
from pypacker.layer3 import ip
from pypacker.layer12 import ethernet

# from pypacker.layer567 import smb
from . import smbHeader
from .satoriCommon import BaseProcesser, OsFingerprint, SatoriResult, TimedSatoriResult

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/tcp.xml -O tcp.xml
#
# looking for new fingerprints
# python3 satori.py > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


def parseBuffer(buf, unicode):
    val = ""
    if unicode == False:
        for i in range(0, len(buf)):
            if buf[i] == 0:
                val = val + ","
            else:
                val = val + chr(buf[i])
    else:
        for i in range(0, len(buf), 2):
            if buf[i] == 0:
                val = val + ","
            else:
                val = val + chr(buf[i])

    return val


class SatoriResultSmbBrowser(SatoriResult):
    protocol: str = "SMBBROWSER"
    os_version: str
    browser_version: str

    def dump(self):
        return self.model_dump()


class SmbUdpProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.partial: Dict[str, List[OsFingerprint]] = defaultdict(list)

    def load_fingerprints(self):
        # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
        satoriPath = str(Path(__file__).resolve().parent)
        obj = untangle.parse(satoriPath + "/fingerprints/browser.xml")
        fingerprintsCount = len(obj.SMBBROWSER.fingerprints)
        for x in range(0, fingerprintsCount):
            os = obj.SMBBROWSER.fingerprints.fingerprint[x]["name"]
            testsCount = len(obj.SMBBROWSER.fingerprints.fingerprint[x].smbbrowser_tests)
            test = {}
            for y in range(0, testsCount):
                test = obj.SMBBROWSER.fingerprints.fingerprint[x].smbbrowser_tests.test[y]
                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.SMBBROWSER.fingerprints.fingerprint[x].smbbrowser_tests.test
                weight = test["weight"]
                matchtype = test["matchtype"]
                osversion = test["osversion"]
                browserversion = test["browserversion"]
                fingerprint = osversion + ";" + browserversion
                if matchtype == "exact":
                    self.exact[fingerprint].append(OsFingerprint(os=os, weight=weight))
                else:
                    self.exact[fingerprint].append(OsFingerprint(os=os, weight=weight))

    def process(self, pkt, layer, ts):
        if layer == "eth":
            src_mac = pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"

        ip4 = pkt.upper_layer
        udp1 = ip4.upper_layer
        if udp1.sport != 138:  # should I look at more than port 138 here?
            return []

        nbds1 = smbHeader.NBDS_Header(udp1.body_bytes)
        smb = smbHeader.UDPSMB_Header(nbds1.body_bytes)
        if smb.command == 0x25:
            trans = smbHeader.transRequest_Header(smb.body_bytes)
            mail = smbHeader.SMBMailSlot_Header(trans.body_bytes)
            mailname = ""
            i = 0
            while True:  # since this is variable length have to look through it until 0x00
                mailname = mailname + chr(mail.body_bytes[i])
                i = i + 1
                if mail.body_bytes[i] == 0x00:
                    break
            if (mail.body_bytes[i + 1] == 0x01) or (mail.body_bytes[i + 1] == 0x0F):
                announce = smbHeader.MWBP_HostAnnounce(mail.body_bytes[i + 1 :])
                osVersion = str(announce.osMajorVer) + "." + str(announce.osMinVer)
                browVersion = str(announce.browMajorVer) + "." + str(announce.browMinVer)

                if (osVersion != "") and (browVersion != ""):
                    smbFingerprint = osVersion + ";" + browVersion
                    osGuess = smb_fingerprint_lookup(self.exact, self.partial, smbFingerprint)
                    if osGuess:
                        return [
                            TimedSatoriResult(
                                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
                                fingerprint=SatoriResultSmbBrowser(
                                    client_addr=ip4.src_s,
                                    client_mac=src_mac,
                                    fingerprint=osGuess,
                                    os_version=osVersion,
                                    browser_version=browVersion,
                                ),
                            )
                        ]
        return []


class SatoriResultSmbNative(SatoriResult):
    protocol: str = "SMBNATIVE"
    native_type: str
    native_version: str

    def dump(self):
        return self.model_dump()


class SmbTcpProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.native_exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.native_partial: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.lanman_exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.lanman_partial: Dict[str, List[OsFingerprint]] = defaultdict(list)

    def process(self, pkt, layer, ts) -> List[TimedSatoriResult]:
        if layer == "eth":
            src_mac = pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"

        ip4 = pkt.upper_layer
        tcp1 = ip4.upper_layer
        x = len(smbHeader.netbiosSessionService())

        fingerprintOS = None
        fingerprintLanMan = None

        timeStamp = datetime.fromtimestamp(ts, tz=timezone.utc)
        result: List[TimedSatoriResult] = []
        if len(tcp1.body_bytes) >= x:
            nbss1 = smbHeader.netbiosSessionService(tcp1.body_bytes)
            smb1 = smbHeader.tcpSMB(nbss1.body_bytes)
            if smb1.proto == 0xFF534D42:
                if (
                    smb1.cmd == 0x73
                ):  # may look at others later, but for now, this is the only one of use for fingerprinting
                    flags2 = struct.unpack("@H", smb1.flags2)[0]
                    if (
                        "{0:>16b}".format(flags2)[0] == "1"
                    ):  # probably a better way to do this with bit shifting, but this works for now  *in pascal had:  (_tcp_smb.flags2 and 32768)
                        unicode = True
                    else:  # 0 or space
                        unicode = False
                    nativeOS = ""
                    nativeLanMan = ""

                    # smb1.body_bytes[0] = Word Count under Session Setup and Request
                    if smb1.body_bytes[0] == 0x0:
                        pass
                    elif smb1.body_bytes[0] == 0x3:
                        SS1 = smbHeader.SSAndRequestHeader_w3(smb1.body_bytes)
                        if len(SS1.body_bytes) % 2 == 0:
                            buffer = SS1.body_bytes[1:]
                        else:
                            buffer = SS1.body_bytes
                        # Native OS; Native LAN Manager; Primary Domain
                        info = parseBuffer(buffer, unicode)
                        info = info.split(",")
                        nativeOS = info[0]
                        nativeLanMan = info[1]
                        primaryDomain = info[2]
                    elif smb1.body_bytes[0] == 0x4:
                        SS1 = smbHeader.SSAndRequestHeader_w4(smb1.body_bytes)
                        x = struct.unpack("@h", SS1.SecurityBlobLen)[0]
                        securityBlob = SS1.body_bytes[0:x]
                        #          if x > 0:
                        #            if securityBlob[0:7] == b'NTLMSSP':
                        #              print(securityBlob[8])
                        #              if securityBlob[8] == 1:
                        #                version = smbHeader.NTLMSecurityBlobType1(securityBlob)
                        #                major = struct.unpack('@s',version.major)[0]
                        #                minor = struct.unpack('@s',version.minor)[0]
                        #                build = struct.unpack('@h',version.build)[0]
                        #                revision = struct.unpack('@s',version.revision)[0]
                        #                print(str(major) + '.' + str(minor) + ' ' + str(build) + ' ' + str(revision))
                        #          if x % 2 == 0:
                        #            buffer = SS1.body_bytes[x:]
                        #          else:
                        #            buffer = SS1.body_bytes[x:]
                        buffer = SS1.body_bytes[x:]
                        # Native OS; Native LAN Manager
                        info = parseBuffer(buffer, unicode)
                        info = info.split(",")
                        nativeOS = info[0]
                        nativeLanMan = info[1]
                    elif smb1.body_bytes[0] == 0xC:
                        SS1 = smbHeader.SSAndRequestHeader_w12(smb1.body_bytes)
                        x = struct.unpack("@h", SS1.SecurityBlobLen)[0]
                        securityBlob = SS1.body_bytes[0:x]
                        #          if x > 0:
                        #            if securityBlob[0:7] == b'NTLMSSP':
                        #              print(securityBlob[8])
                        #              if securityBlob[8] == 1:
                        #                version = smbHeader.NTLMSecurityBlobType1(securityBlob)
                        #                major = struct.unpack('@b',version.major)[0]
                        #                minor = struct.unpack('@b',version.minor)[0]
                        #                build = struct.unpack('@h',version.build)[0]
                        #                revision = struct.unpack('@b',version.revision)[0]
                        #                print(str(major) + '.' + str(minor) + ' ' + str(build) + ' ' + str(revision))
                        #          if x % 2 == 0:
                        #            buffer = SS1.body_bytes[x:]
                        #          else:
                        #            buffer = SS1.body_bytes[x+1:]
                        buffer = SS1.body_bytes[x:]
                        # Native OS; Native LAN Manager
                        info = parseBuffer(buffer, unicode)
                        info = info.split(",")
                        nativeOS = info[0]
                        nativeLanMan = info[1]
                    elif smb1.body_bytes[0] == 0xD:
                        SS1 = smbHeader.SSAndRequestHeader_w13(smb1.body_bytes)
                        buffer = SS1.body_bytes
                        # Account; Primary Domain; Native OS; Native LAN Manager
                        ansi = struct.unpack("@h", SS1.ANSIPasswordLen)[0]
                        uni = struct.unpack("@h", SS1.UniCodePassLen)[0]
                        info = parseBuffer(buffer[ansi + uni :], unicode)
                        info = info.split(",")
                        nativeOS = info[2]
                        nativeLanMan = info[3]
                    if nativeOS != "":
                        osGuess = smb_fingerprint_lookup(self.native_exact, self.native_partial, nativeOS)
                        if osGuess:
                            result.append(
                                TimedSatoriResult(
                                    timestamp=timeStamp,
                                    fingerprint=SatoriResultSmbNative(
                                        client_addr=ip4.src_s,
                                        client_mac=src_mac,
                                        fingerprint=osGuess,
                                        native_type="NativeOS",
                                        native_version=nativeOS,
                                    ),
                                )
                            )
                    if nativeLanMan != "":
                        osGuess = smb_fingerprint_lookup(self.lanman_exact, self.lanman_partial, nativeLanMan)
                        if osGuess:
                            result.append(
                                TimedSatoriResult(
                                    timestamp=timeStamp,
                                    fingerprint=SatoriResultSmbNative(
                                        client_addr=ip4.src_s,
                                        client_mac=src_mac,
                                        fingerprint=osGuess,
                                        native_type="NativeLanMan",
                                        native_version=nativeLanMan,
                                    ),
                                )
                            )

        return result

    def load_fingerprints(self):
        # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup

        satoriPath = str(Path(__file__).resolve().parent)
        obj = untangle.parse(satoriPath + "/fingerprints/smb.xml")
        fingerprintsCount = len(obj.SMB.fingerprints)
        for x in range(0, fingerprintsCount):
            os = obj.SMB.fingerprints.fingerprint[x]["name"]
            testsCount = len(obj.SMB.fingerprints.fingerprint[x].smb_tests)
            for y in range(0, testsCount):
                test = obj.SMB.fingerprints.fingerprint[x].smb_tests.test[y]
                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.SMB.fingerprints.fingerprint[x].smb_tests.test
                weight = test["weight"]
                matchtype = test["matchtype"]
                smbnativename = test["smbnativename"]
                smbnativelanman = test["smbnativelanman"]
                if matchtype == "exact":
                    if smbnativename is not None:
                        self.native_exact[smbnativename].append(OsFingerprint(os=os, weight=weight))
                    elif smbnativelanman is not None:
                        self.lanman_exact[smbnativelanman].append(OsFingerprint(os=os, weight=weight))
                else:
                    if smbnativename is not None:
                        self.native_partial[smbnativename].append(OsFingerprint(os=os, weight=weight))
                    elif smbnativelanman is not None:
                        self.lanman_partial[smbnativelanman].append(OsFingerprint(os=os, weight=weight))


def smb_fingerprint_lookup(exactList, partialList, value) -> List[OsFingerprint]:
    # same as DHCP one, may be able to look at combining in the future?
    fingerprint = []
    if value in exactList:
        fingerprint.extend(exactList.get(value))

    for key, val in partialList.items():
        if value.find(key) > -1:
            fingerprint.extend(val)

    fingerprint.sort(key=lambda item: item.weight)

    return fingerprint
