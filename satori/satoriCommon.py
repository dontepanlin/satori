"""Common functions"""

import importlib.metadata
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel

VERSION_pypacker = importlib.metadata.version("pypacker")


class OsFingerprint(BaseModel):
    os: str
    weight: int


class SatoriResult(BaseModel):
    client_addr: str
    client_mac: str
    protocol: str
    fingerprint: List[OsFingerprint]


class TimedSatoriResult(BaseModel):
    timestamp: datetime
    fingerprint: SatoriResult


class BaseProcesser:
    """Abstract processer"""

    def load_fingerprints(self):
        """Load fingerprints from xml file"""
        raise NotImplementedError("Need to implement")

    def process(self, pkt, layer, ts) -> Optional[TimedSatoriResult]:
        """Process packet"""
        raise NotImplementedError("Need to implement")


def findDupes(path):
    tree = ET.parse(path)
    root = tree.getroot()

    for fingerprints in root:
        for fingerprint in fingerprints:
            for testtype in fingerprint:
                setOfElems = set()
                for test in testtype:
                    val = str(test.attrib)
                    if val in setOfElems:
                        print("found duplicate in: %s; %s:%s" % (path, fingerprint.attrib["name"], test.attrib))
                    else:
                        setOfElems.add(val)


def Dupes():
    print("Checking for Dupes")
    satoriPath = str(Path(__file__).resolve().parent)

    findDupes(satoriPath + "/fingerprints/browser.xml")
    findDupes(satoriPath + "/fingerprints/dhcp.xml")
    findDupes(satoriPath + "/fingerprints/dhcpv6.xml")
    findDupes(satoriPath + "/fingerprints/dns.xml")
    findDupes(satoriPath + "/fingerprints/icmp.xml")
    findDupes(satoriPath + "/fingerprints/ntp.xml")
    findDupes(satoriPath + "/fingerprints/sip.xml")
    findDupes(satoriPath + "/fingerprints/smb.xml")
    findDupes(satoriPath + "/fingerprints/ssh.xml")
    findDupes(satoriPath + "/fingerprints/ssl.xml")
    findDupes(satoriPath + "/fingerprints/tcp.xml")
    findDupes(satoriPath + "/fingerprints/web.xml")
    findDupes(satoriPath + "/fingerprints/webuseragent.xml")


def sort_key(val):
    return int(val[1])


def sortFingerprint(fp):
    if "|" in fp:
        fingerprints = fp.split("|")

        list = []
        listOfFingerprints = []
        for fingerprint in fingerprints:
            parts = fingerprint.split(":")
            list = [parts[0], parts[1]]
            listOfFingerprints.append(list)
        listOfFingerprints.sort(key=sort_key, reverse=True)

        fp = ""
        for fingerprint in listOfFingerprints:
            info = ""
            for val in fingerprint:
                info = info + ":" + val
            fp = fp + "|" + info[1:]

        if fp[0] == "|":
            fp = fp[1:]

    return fp
