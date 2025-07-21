from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import untangle
from pypacker.layer3 import ip
from pypacker.layer12 import ethernet

from .satoriCommon import BaseProcesser, OsFingerprint, SatoriResult, TimedSatoriResult, Packet, PacketLayer

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/tcp.xml -O tcp.xml
#
# looking for new fingerprints
# python3 satori.py > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


class SatoriResultSsh(SatoriResult):
    protocol: str = "SSH"
    banner: str

    def dump(self):
        return self.model_dump()


class SshProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.partial: Dict[str, List[OsFingerprint]] = defaultdict(list)

    @classmethod
    def name(cls):
        return "ssh"

    def load_fingerprints(self):
        satoriPath = str(Path(__file__).resolve().parent)
        obj = untangle.parse(satoriPath + "/fingerprints/ssh.xml")
        for x in range(0, len(obj.SSH.fingerprints)):
            os = obj.SSH.fingerprints.fingerprint[x]["name"]
            for y in range(0, len(obj.SSH.fingerprints.fingerprint[x].ssh_tests)):
                test = obj.SSH.fingerprints.fingerprint[x].ssh_tests.test[y]
                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.SSH.fingerprints.fingerprint[x].ssh_tests.test
                matchtype = test["matchtype"]
                ssh = test["ssh"]
                weight = test["weight"]
                if matchtype == "exact":
                    self.exact[ssh].append(OsFingerprint(os=os, weight=weight))
                else:
                    self.partial[ssh].append(OsFingerprint(os=os, weight=weight))

    def process(self, pkt: Packet):
        if pkt.layer == PacketLayer.eth:
            src_mac = pkt.pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"

        ip4 = pkt.pkt.upper_layer
        tcp1 = pkt.pkt.upper_layer.upper_layer

        ssh = ""

        temp = tcp1.body_bytes.decode("utf-8").strip()
        # may need to expand this test in the future, but don't want to only do port 22 for example, so simple test for now.
        if temp[0:3] == "SSH":
            ssh = temp

        if ssh == "":
            return []
        sshFingerprint = ssh_fingerprint_lookup(self.exact, self.partial, ssh)
        if not sshFingerprint:
            return []

        return [
            TimedSatoriResult(
                timestamp=datetime.fromtimestamp(pkt.ts, tz=timezone.utc),
                fingerprint=SatoriResultSsh(
                    client_addr=ip4.src_s, client_mac=src_mac, fingerprint=sshFingerprint, banner=ssh
                ),
            )
        ]


def ssh_fingerprint_lookup(exactList, partialList, value) -> List[OsFingerprint]:
    # same as DHCP one, may be able to look at combining in the future?
    fingerprint = []
    if value in exactList:
        fingerprint.extend(exactList.get(value))

    for key, val in partialList.items():
        if value.find(key) > -1:
            fingerprint.extend(val)

    fingerprint.sort(key=lambda item: item.weight)

    return fingerprint
