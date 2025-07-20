from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, List

import untangle
from pypacker import pypacker
from pypacker.layer3 import ip
from pypacker.layer12 import ethernet
from pypacker.layer567 import dhcp

from .satoriCommon import BaseProcesser, OsFingerprint, SatoriResult

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/dhcp.xml -O dhcp.xml
#
# looking for new fingerprints
# python3 satori.py -r dhcp.pcap -m dhcp > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


@dataclass
class DhcpOption:
    exact: Dict[str, List[OsFingerprint]] = field(default_factory=lambda : defaultdict(list))
    partial: Dict[str, List[OsFingerprint]] = field(default_factory=lambda : defaultdict(list))


DhcpOptions = Dict[str, DhcpOption]


class DhcpMessageType(Enum):
    Undefined = 0
    Discover = 1
    Offer = 2
    Request = 3
    Decline = 4
    ACK = 5
    NAK = 6
    Release = 7
    Inform = 8

    @classmethod
    def _missing_(cls, value):
        for member in cls:
            if member.value == value:
                return member
        return cls.Undefined


class TestResult(Enum):
    options = 1
    options55 = 2
    ttl = 3
    vendor = 4


key_transform = {
    TestResult.options: lambda x: x,
    TestResult.options55: lambda x: x + "Options55",
    TestResult.ttl: lambda x: x + "TTL",
    TestResult.vendor: lambda x: x + "VendorCode",
}

# Discover DiscoverOptionsExactList

class SatoriResultDhcp(SatoriResult):
    protocol: str = "DHCP"
    message_type: str
    option_type: TestResult
    options: str

    def dump(self):
        return self.model_dump()


class DhcpProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.syn_exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.options: DhcpOptions = defaultdict(DhcpOption)

    def load_fingerprints(self):
        # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
        # this got much larger than I thought it would!
        # need to decide how to deal with ; in dhcpvendorcode

        satori_path = str(Path(__file__).resolve().parent)
        obj = untangle.parse(satori_path + "/fingerprints/dhcp.xml")
        fingerprintsCount = len(obj.DHCP.fingerprints)

        for x in range(0, fingerprintsCount):
            os = obj.DHCP.fingerprints.fingerprint[x]["name"]
            testsCount = len(obj.DHCP.fingerprints.fingerprint[x].dhcp_tests)
            test = {}

            for y in range(0, testsCount):
                test = obj.DHCP.fingerprints.fingerprint[x].dhcp_tests.test[y]

                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.DHCP.fingerprints.fingerprint[x].dhcp_tests.test

                matchtype = test["matchtype"]
                dhcptype = test["dhcptype"]
                weight = test["weight"]
                # some won't exist each time, is that going to be a problem??
                dhcpoption55 = test["dhcpoption55"]
                dhcpvendorcode = test["dhcpvendorcode"]
                dhcpoptions = test["dhcpoptions"]
                ipttl = test["ipttl"]

                if dhcpoptions is not None:
                    test_options = dhcpoptions
                    test_type = TestResult.options
                elif dhcpoption55 is not None:
                    test_options = dhcpoption55
                    test_type = TestResult.options55
                elif ipttl is not None:
                    test_options = ipttl
                    test_type = TestResult.ttl
                elif dhcpvendorcode is not None:
                    test_options = dhcpvendorcode
                    test_type = TestResult.vendor
                else:
                    continue

                if matchtype == "exact":
                    match_exact(dhcptype, self.options, os, weight, test_type, test_options)
                elif matchtype == "partial":
                    match_partial(dhcptype, self.options, os, weight, test_type, test_options)

    def process(self, pkt, layer, ts):
        if layer == "eth":
            src_mac = pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"
        ip4 = pkt.upper_layer
        udp1 = pkt.upper_layer.upper_layer

        timeStamp = datetime.fromtimestamp(ts, tz=timezone.utc)

        dhcp1 = pkt[dhcp.DHCP]
        message_type = getDHCPMessageType(dhcp1.op)
        client_addr = dhcp1.ciaddr_s
        your_addr = dhcp1.yiaddr_s
        next_server_addr = dhcp1.siaddr_s
        relay_server_addr = dhcp1.giaddr_s
        client_mac = pypacker.mac_bytes_to_str(dhcp1.chaddr[0:6])  # dump the padding is pypacker copies it all together

        [options_data, message_type, option55, vendor_code] = getDHCPOptions(dhcp1.opts)
        message_type = message_type.name
        result = []
        if options_data:
            fingerprint = dhcp_fingerprint_lookup(
                self.options[key_transform[TestResult.options](message_type)].exact,
                self.options[key_transform[TestResult.options](message_type)].partial,
                options_data,
            )
            if fingerprint:
                result.append(
                    SatoriResultDhcp(
                        client_addr=client_addr,
                        client_mac=client_mac,
                        fingerprint=fingerprint,
                        message_type=message_type,
                        option_type=TestResult.options,
                        options=options_data,
                    )
                )
        elif option55:
            fingerprint = dhcp_fingerprint_lookup(
                self.options[key_transform[TestResult.options55](message_type)].exact,
                self.options[key_transform[TestResult.options55](message_type)].partial,
                option55,
            )
            if fingerprint:
                result.append(
                    SatoriResultDhcp(
                        client_addr=client_addr,
                        client_mac=client_mac,
                        fingerprint=fingerprint,
                        message_type=message_type,
                        option_type=TestResult.options55,
                        options=options_data,
                    )
                )
        elif vendor_code:
            fingerprint = dhcp_fingerprint_lookup(
                self.options[key_transform[TestResult.vendor](message_type)].exact,
                self.options[key_transform[TestResult.vendor](message_type)].partial,
                option55,
            )
            if fingerprint:
                result.append(
                    SatoriResultDhcp(
                        client_addr=client_addr,
                        client_mac=client_mac,
                        fingerprint=fingerprint,
                        message_type=message_type,
                        option_type=TestResult.options55,
                        options=vendor_code,
                    )
                )
        return result

        # need to revisit this when not printing them as this just makes noise right now.
        #  if messageType != None:  #last ditch check against the 'any' field ones
        #    if options != '':
        #      osGuessOptions = DHCPFingerprintLookup(AnyOptionsExactList, AnyOptionsPartialList, options)
        #      print("%s;%s;%s;DHCP;%s;Options;%s;%s" % (timeStamp, clientAddr, clientMAC, messageType, options, osGuessOptions))
        #    if option55 != '':
        #      osGuessOption55 = DHCPFingerprintLookup(AnyOption55ExactList, AnyOption55PartialList, option55)
        #      print("%s;%s;%s;DHCP;%s;Option55;%s;%s" % (timeStamp, clientAddr, clientMAC, messageType, option55, osGuessOption55))
        #    if vendorCode != '':
        #      osGuessVendorCode = DHCPFingerprintLookup(AnyVendorCodeExactList, AnyVendorCodePartialList, vendorCode)
        #      print("%s;%s;%s;DHCP;%s;VendorCode;%s;%s" % (timeStamp, clientAddr, clientMAC, messageType, vendorCode, osGuessVendorCode))


def insert_or_append(storage: Dict[str, List[OsFingerprint]], key: str, os: str, weight: int):
    storage[key].append(OsFingerprint(os=os, weight=weight))


def match_exact(dhcptype, result: DhcpOptions, os, weight, test_type, test):
    insert_or_append(result[key_transform[test_type](dhcptype)].exact, test, os, weight)


def match_partial(dhcptype, result: DhcpOptions, os, weight, test_type, test):
    insert_or_append(result[key_transform[test_type](dhcptype)].partial, test, os, weight)


def dhcp_fingerprint_lookup(exactList, partialList, value):
    fingerprint: List[OsFingerprint] = []
    if value in exactList:
        fingerprint.extend(exactList.get(value))
    for key, val in partialList.items():
        if value.find(key) > -1:
            fingerprint.extend(val)
    fingerprint.sort(key=lambda item: item.weight)
    return fingerprint


def getDHCPMessageType(value):
    res = ""

    if value == 1:
        res = "Request"
    elif value == 2:
        res = "Reply"
    else:
        res = "Unknown Message Type: " + value

    return res


def getDHCPOptions(value):
    options = ""
    option55 = ""
    vendorCode = ""
    messageType = DhcpMessageType.Undefined

    for i in range(len(value)):
        try:
            options = options + str(value[i].type) + ","
            if value[i].type == 53:
                messageType = getDHCPOption53(value[i].body_bytes)
            if value[i].type == 55:
                option55 = getDHCPOption55(value[i].body_bytes)
            if value[i].type == 60:
                vendorCode = getDHCPOption60(value[i].body_bytes)
        except:
            pass

    if len(options) > 0:
        options = options[:-1]
    return (options, messageType, option55, vendorCode)


def getDHCPOption60(value):
    try:
        res = value.decode("utf-8", "strict").rstrip("\x00")
    except Exception as e:
        print(f"Error decoding DHCP option 60: {e}")
        res = value
    return res


def getDHCPOption55(value):
    res = ",".join(str(v) for v in value)
    return res


def getDHCPOption53(value) -> DhcpMessageType:
    value = ord(value)
    return DhcpMessageType(value)
