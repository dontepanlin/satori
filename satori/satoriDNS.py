from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import untangle
from pypacker import pypacker
from pypacker.layer3 import ip
from pypacker.layer12 import ethernet
from pypacker.layer567 import dns

from .satoriCommon import BaseProcesser, OsFingerprint, SatoriResult, TimedSatoriResult, Packet, PacketLayer

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/dhcp.xml -O dhcp.xml
#
# looking for new fingerprints
# python3 satori.py -r dhcp.pcap -m dhcp > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


# due to the sheer number of DNS entries this will display we'll default to only displaying if there is a known fingerprint
# people may want to change this to collect all DNS lookups
displayKnownFingerprintsOnly = True
# displayKnownFingerprintsOnly = False


class SatoriResultDns(SatoriResult):
    protocol: str = "DNS"
    domain: str

    def dump(self):
        return self.model_dump()


class DnsProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.partial: Dict[str, List[OsFingerprint]] = defaultdict(list)

    @classmethod
    def name(cls):
        return "dns"
    
    def load_fingerprints(self):
        # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup

        satoriPath = str(Path(__file__).resolve().parent)
        obj = untangle.parse(satoriPath + "/fingerprints/dns.xml")
        for x in range(0, len(obj.DNS.fingerprints)):
            os = obj.DNS.fingerprints.fingerprint[x]["name"]
            for y in range(0, len(obj.DNS.fingerprints.fingerprint[x].dns_tests)):
                test = obj.DNS.fingerprints.fingerprint[x].dns_tests.test[y]
                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.DNS.fingerprints.fingerprint[x].dns_tests.test
                matchtype = test["matchtype"]
                dns = test["dns"]
                weight = test["weight"]
                if matchtype == "exact":
                    self.exact[dns].append(OsFingerprint(os=os, weight=weight))
                else:
                    self.partial[dns].append(OsFingerprint(os=os, weight=weight))

    def process(self, pkt) -> List[TimedSatoriResult]:
        if pkt.layer == PacketLayer.eth:
            src_mac = pkt.pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"

        ip4 = pkt.pkt.upper_layer

        dnsAnswer = ""
        dns1 = pkt.pkt[dns.DNS]
        for x in range(0, dns1.questions_amount):
            if dns1.answers_amount == 0 and dns1.authrr_amount == 0:
                if dns1.flags == 256 or dns1.flags == 33152:
                    dnsAnswer = pypacker.dns_name_decode(dns1.queries[x].name)[:-1]

        if dnsAnswer == "":
            return []

        dnsFingerprint = dns_fingerprint_lookup(self.exact, self.partial, dnsAnswer)
        if not dnsFingerprint:
            return []

        return [
            TimedSatoriResult(
                timestamp=datetime.fromtimestamp(pkt.ts, tz=timezone.utc),
                fingerprint=SatoriResultDns(
                    client_addr=ip4.src_s, client_mac=src_mac, fingerprint=dnsFingerprint, domain=dnsAnswer
                ),
            )
        ]


def dns_fingerprint_lookup(exactList, partialList, value) -> List[OsFingerprint]:
    fingerprint = []
    if value in exactList:
        fingerprint.extend(exactList.get(value))

    for key, val in partialList.items():
        if value.find(key) > -1:
            fingerprint.extend(val)
    fingerprint.sort(key=lambda item: item.weight)
    return fingerprint
