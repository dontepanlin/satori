import untangle
from .satoriCommon import OsFingerprint, SatoriResult, BaseProcesser, TimedSatoriResult
from pathlib import Path
from datetime import datetime, timezone
from pypacker.layer12 import ethernet
from typing import Dict, List, Optional
from collections import defaultdict

# grab the latest fingerprint files:
# wget chatteronthewire.org/download/updates/satori/fingerprints/tcp.xml -O tcp.xml
#
# looking for new fingerprints
# python3 satori.py > output.txt
# cat output.txt | awk -F';' '{print $3, $4, $5, $6, $7}' | sort -u > output2.txt
# cat output.txt | awk -F';'  '{print $5";"$6";"$7}' | sort -u > output2.txt
#


class SatoriResultHttpServer(SatoriResult):
    protocol: str = "HTTP"
    server_header: str

    def dump(self):
        return self.model_dump()


class SatoriResultHttpUserAgent(SatoriResult):
    protocol: str = "HTTP"
    useragent_header: str

    def dump(self):
        return self.model_dump()


class HttpServerProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.partial: Dict[str, List[OsFingerprint]] = defaultdict(list)

    def load_fingerprints(self):
        # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup
        satoriPath = str(Path(__file__).resolve().parent)

        obj = untangle.parse(satoriPath + "/fingerprints/web.xml")
        for x in range(0, len(obj.WEBSERVER.fingerprints)):
            os = obj.WEBSERVER.fingerprints.fingerprint[x]["name"]
            test = {}
            for y in range(0, len(obj.WEBSERVER.fingerprints.fingerprint[x].webserver_tests)):
                test = obj.WEBSERVER.fingerprints.fingerprint[x].webserver_tests.test[y]
                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.WEBSERVER.fingerprints.fingerprint[x].webserver_tests.test
                matchtype = test["matchtype"]
                webserver = test["webserver"]
                weight = test["weight"]
                if matchtype == "exact":
                    self.exact[webserver].append(OsFingerprint(os=os, weight=weight))
                else:
                    self.partial[webserver].append(OsFingerprint(os=os, weight=weight))

    def process(self, pkt, layer, ts):
        if layer == "eth":
            src_mac = pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"

        ip4 = pkt.upper_layer
        tcp1 = pkt.upper_layer.upper_layer
        http1 = pkt.upper_layer.upper_layer.upper_layer

        hdrServer = ""
        bodyServer = ""

        result: List[TimedSatoriResult] = []

        try:
            if (http1.hdr is not None) and (http1.hdr):
                hdr = dict(http1.hdr)
                hdrServer = hdr[b"Server"].decode("utf-8", "strict")
            if http1.body_bytes:
                body = http1.body_bytes.decode("utf-8", "strict")
                i = body.find("Server: ")
                if i > 1:
                    v = body[i:]
                    i = v.find("\n")
                    v = v[:i]
                    i = v.find(":")
                    bodyServer = v[i + 1 :].strip()
        except Exception:
            pass

        timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)

        if hdrServer:
            fingerprint = http_fingerprint_lookup(self.exact, self.partial, hdrServer)
            if fingerprint:
                result.append(
                    TimedSatoriResult(
                        timestamp=timestamp,
                        fingerprint=SatoriResultHttpServer(
                            client_addr=ip4.src_s, client_mac=src_mac, fingerprint=fingerprint, server_header=hdrServer
                        ),
                    )
                )

        if bodyServer:
            fingerprint = http_fingerprint_lookup(self.exact, self.partial, bodyServer)
            if fingerprint:
                result.append(
                    TimedSatoriResult(
                        timestamp=timestamp,
                        fingerprint=SatoriResultHttpServer(
                            client_addr=ip4.src_s, client_mac=src_mac, fingerprint=fingerprint, server_header=bodyServer
                        ),
                    )
                )
        return result


class HttpUserAgentProcesser(BaseProcesser):
    def __init__(self, xml_path: Optional[str] = None):
        self.xml_path = xml_path
        self.exact: Dict[str, List[OsFingerprint]] = defaultdict(list)
        self.partial: Dict[str, List[OsFingerprint]] = defaultdict(list)

    def load_fingerprints(self):
        # converting from the xml format to a more flat format that will hopefully be faster than walking the entire xml every FP lookup

        satoriPath = str(Path(__file__).resolve().parent)
        obj = untangle.parse(satoriPath + "/fingerprints/webuseragent.xml")

        for x in range(0, len(obj.WEBUSERAGENT.fingerprints)):
            os = obj.WEBUSERAGENT.fingerprints.fingerprint[x]["name"]
            for y in range(0, len(obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests)):
                test = obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests.test[y]
                if test is None:  # if testsCount = 1, then untangle doesn't allow us to iterate through it
                    test = obj.WEBUSERAGENT.fingerprints.fingerprint[x].webuseragent_tests.test
                matchtype = test["matchtype"]
                webuseragent = test["webuseragent"]
                weight = test["weight"]
                if matchtype == "exact":
                    self.exact[webuseragent].append(OsFingerprint(os=os, weight=weight))
                else:
                    self.partial[webuseragent].append(OsFingerprint(os=os, weight=weight))

    def process(self, pkt, layer, ts):
        if layer == "eth":
            src_mac = pkt[ethernet.Ethernet].src_s
        else:
            # fake filler mac for all the others that don't have it, may have to add some elif above
            src_mac = "00:00:00:00:00:00"

        ip4 = pkt.upper_layer
        http1 = pkt.upper_layer.upper_layer.upper_layer

        hdrUserAgent = ""
        bodyUserAgent = ""

        result: List[TimedSatoriResult] = []

        try:
            if (http1.hdr != None) and (http1.hdr):
                hdr = dict(http1.hdr)
                hdrUserAgent = hdr[b"User-Agent"].decode("utf-8", "strict")
            if http1.body_bytes:
                body = http1.body_bytes.decode("utf-8", "strict")
                i = body.find("User-Agent: ")
                if i > 1:
                    v = body[i:]
                    i = v.find("\n")
                    v = v[:i]
                    i = v.find(":")
                    bodyUserAgent = v[i + 1 :].strip()
        except Exception:
            pass

        timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)

        if hdrUserAgent:
            fingerprint = http_fingerprint_lookup(self.exact, self.partial, hdrUserAgent)
            if fingerprint:
                result.append(
                    TimedSatoriResult(
                        timestamp=timestamp,
                        fingerprint=SatoriResultHttpUserAgent(
                            client_addr=ip4.src_s,
                            client_mac=src_mac,
                            fingerprint=fingerprint,
                            useragent_header=hdrUserAgent,
                        ),
                    )
                )
        if bodyUserAgent:
            fingerprint = http_fingerprint_lookup(self.exact, self.partial, bodyUserAgent)
            if fingerprint:
                result.append(
                    TimedSatoriResult(
                        timestamp=timestamp,
                        fingerprint=SatoriResultHttpUserAgent(
                            client_addr=ip4.src_s,
                            client_mac=src_mac,
                            fingerprint=fingerprint,
                            useragent_header=bodyUserAgent,
                        ),
                    )
                )

        return result


def http_fingerprint_lookup(exactList, partialList, value) -> List[OsFingerprint]:
    # same as DHCP one, may be able to look at combining in the future?
    fingerprint = []
    if value in exactList:
        fingerprint.extend(exactList.get(value))

    for key, val in partialList.items():
        if value.find(key) > -1:
            fingerprint.extend(val)

    fingerprint.sort(key=lambda item: item.weight)

    return fingerprint
