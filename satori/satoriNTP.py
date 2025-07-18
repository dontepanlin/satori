from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, List, Optional

import untangle
from pypacker import pypacker
from pypacker.layer3 import ip
from pypacker.layer12 import ethernet
from pypacker.layer567 import ntp

from .satoriCommon import (BaseProcesser, OsFingerprint, SatoriResult,
                           TimedSatoriResult)

# https://datatracker.ietf.org/doc/html/rfc5905
# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/dhcp.xml -O dhcp.xml
#
# looking for new fingerprints
# python3 satori.py -r dhcp.pcap -m dhcp > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


class SatoriResultNtp(SatoriResult):
    protocol: str = "NTP"
    signature: str


class NtpProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.ntp_exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.ntp_partial: Dict[str, List[OsFingerprint]] = defaultdict(list)

    def load_fingerprints(self):
        satori_path = str(Path(__file__).resolve().parent)
        obj = untangle.parse(satori_path + "/fingerprints/ntp.xml")
        for x in range(0, len(obj.NTP.fingerprints)):
            os = obj.NTP.fingerprints.fingerprint[x]["name"]
            for y in range(0, len(obj.NTP.fingerprints.fingerprint[x].ntp_tests)):
                test = obj.NTP.fingerprints.fingerprint[x].ntp_tests.test[y]
                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.NTP.fingerprints.fingerprint[x].ntp_tests.test
                matchtype = test["matchtype"]
                ntp = test["ntp"]
                weight = test["weight"]
                if matchtype == "exact":
                    self.ntp_exact[ntp].append(OsFingerprint(os=os, weight=weight))
                else:
                    self.ntp_partial[ntp].append(OsFingerprint(os=os, weight=weight))

    def process(self, pkt, layer, ts):
        if layer == "eth":
            src_mac = pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"

        ip4 = pkt.upper_layer
        udp1 = pkt.upper_layer.upper_layer
        ntp1 = pkt[ntp.NTP]

        sport = udp1.sport

        leap = ntp1.li
        version = ntp1.v
        mode = ntp1.mode

        stratum = ntp1.stratum
        poll = ntp1.interval
        precision = ntp1.precision
        delay = ntp1.delay

        dispersion = ntp1.dispersion

        id = pypacker.ip4_bytes_to_str(ntp1.id)

        [referenceTime, referenceVal] = ntpTimeConvert(ntp1.update_time, ts)
        [originateTime, originateVal] = ntpTimeConvert(ntp1.originate_time, ts)
        [receiveTime, receiveVal] = ntpTimeConvert(ntp1.receive_time, ts)
        [transmitTime, transmitVal] = ntpTimeConvert(ntp1.transmit_time, ts)

        # sport needs to be either 123 or 1024+
        if sport > 1024:
            sport = 1025

        if id != "0.0.0.0":
            idVal = "set"
        else:
            idVal = "unset"

        # ones with no value that I can find:
        # stratum, precision, delay

        # minimal use?
        # dispersion, it switches based on who it is talking to for time
        # mode
        # 1 = symmetric active
        # 2 = symmetric passive
        # 3 = client
        # 4 = server
        # 5 = broadcastServer
        # 6 = broadcastClient

        if mode == 1:
            fingerprint = (
                "active;"
                + str(sport)
                + ","
                + str(leap)
                + ","
                + str(version)
                + ","
                + str(poll)
                + ","
                + idVal
                + ","
                + referenceVal
                + ","
                + transmitVal
                + ","
                + str(get16bitSecs(dispersion))
            )
        elif mode == 2:
            # probably will remove this one?
            fingerprint = (
                "passive;"
                + str(sport)
                + ","
                + str(leap)
                + ","
                + str(version)
                + ","
                + str(poll)
                + ","
                + idVal
                + ","
                + referenceVal
                + ","
                + transmitVal
                + ","
                + str(get16bitSecs(dispersion))
            )
        elif mode == 3:
            fingerprint = (
                "client;"
                + str(sport)
                + ","
                + str(leap)
                + ","
                + str(version)
                + ","
                + str(poll)
                + ","
                + idVal
                + ","
                + referenceVal
                + ","
                + transmitVal
                + ","
                + str(get16bitSecs(dispersion))
            )
        else:
            return None
        #  elif mode == 4:
        # poll seemed to be from client it was replying too
        #    fingerprint = 'server;' + str(sport) + ',' + str(leap) + ',' + str(version) + ',' + str(get16bitSecs(dispersion)) + ',' + idVal + ',' + referenceVal + ',' + transmitVal

        ntpFingerprint = None
        if fingerprint != "":
            ntpFingerprint = ntp_fingerprint_lookup(self.ntp_exact, self.ntp_partial, fingerprint)

        if not ntpFingerprint:
            return None
        return TimedSatoriResult(
            timestamp=datetime.fromtimestamp(ts, UTC),
            fingerprint=SatoriResultNtp(
                client_addr=ip4.src_s,
                client_mac=src_mac,
                signature=fingerprint,
                fingerprint=ntpFingerprint,
            ),
        )


def get16bitSecs(value):
    return value >> 16


def get16bitFrac(value):
    return value & 0xFFFF


def ntpTimeConvert(ntpTime, packetTime):
    value = ""
    # why we need an offset and only part of the info  https://tickelton.gitlab.io/articles/ntp-timestamps/
    offset = 2208988800
    time = int.from_bytes(ntpTime[0:4], "big")
    if time > offset:
        time = time - offset

    if time == 0:
        value = "0"
    else:
        randomAssValue = 2000
        secDiff = packetTime - time
        if secDiff < -randomAssValue:
            value = "random"  # past
        elif secDiff < randomAssValue:
            value = "current"
        else:
            value = "random"  # future
    timeStamp = datetime.utcfromtimestamp(time).strftime("%Y-%m-%dT%H:%M:%S")

    return (timeStamp, value)


def ntp_fingerprint_lookup(exact, partial, signature):
    fingerprint = []
    if signature in exact:
        fingerprint.extend(exact.get(signature))

    for key, val in partial.items():
        if signature.find(key) > -1:
            fingerprint.extend(val)

    fingerprint.sort(key=lambda item: item.weight)
    return fingerprint
