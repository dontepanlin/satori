import argparse
import datetime
import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Optional, Set, List
import logging
import orjson
from pypacker import ppcap, pypacker
from pypacker.layer3 import ip
from pypacker.layer4 import ssl, tcp, udp
from pypacker.layer12 import ethernet, linuxcc
from pypacker.layer567 import dhcp, dns, http, ntp
from collections import defaultdict
from . import satoriCommon, satoriDHCP, satoriDNS, satoriHTTP, satoriNTP, satoriSMB, satoriSSH, satoriSSL, satoriTCP

from .satoriCommon import Packet, PacketLayer

# import satoriICMP


class FingerprintFormat(Enum):
    Raw = "RAW"
    Json = "JSON"


FORMAT = FingerprintFormat.Json
TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%S"


class Dumper:
    def __init__(self, output_file: Optional[str] = None):
        self.output_file = output_file
        self._file = None
        if self.output_file:
            self._file = open(self.output_file, "a", encoding="utf-8")
        else:
            self._file = sys.stdout

    def close(self):
        if self._file and self._file is not sys.stdout:
            self._file.close()
            self._file = None

    def __del__(self):
        self.close()

    def dump(self, data):
        raise NotImplementedError("This method should be overridden by subclasses")


class RawDumper(Dumper):
    def dump(self, data: dict):
        formatted_data = ";".join(v for v in data.values())
        self._file.write(formatted_data + "\n")


class JsonDumper(Dumper):
    def dump(self, data: dict):
        formatted_data = orjson.dumps(data).decode("utf-8")
        self._file.write(formatted_data + "\n")


def make_parser():
    parser = argparse.ArgumentParser(prog="Satori")
    parser.add_argument(
        "-d",
        "--directory",
        action="store",
        dest="directory",
        help="directory to read all pcaps in (does NOT do sub directories); example: -d /pcaps",
        default="",
    )
    parser.add_argument(
        "-r",
        "--read",
        action="store",
        dest="readpcap",
        help="pcap to read in; example: -r tcp.pcap",
        default="",
    )
    parser.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="interface",
        help="interface to listen to; example: -i eth0",
        default="",
    )
    parser.add_argument(
        "-m",
        "--modules",
        action="store",
        dest="modules",
        help="modules to load; example: -m tcp,dhcp,smb,http",
        default="",
    )
    parser.add_argument(
        "-f",
        "--filter",
        action="store",
        dest="filter",
        help='bpf filter to apply (only implemented in live capture processing); example: -f "tcp port 80 or tcp port 8080"',
        default="",
    )
    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        action="store",
        dest="limit",
        help="limit the number of same events written in a time period (in minutes); example -l 1",
        default=0,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        help="verbose logging, mostly just telling you where/what we're doing, not recommended if want to parse output typically",
        default=False,
    )
    parser.add_argument(
        "--version",
        action="store_true",
        dest="version",
        help="print dates for the different modules and 3rd party tools used",
        default="",
    )
    parser.add_argument(
        "--dupes",
        action="store_true",
        dest="dupes",
        help="check for dupes in the fingerprint files",
        default="",
    )
    parser.add_argument(
        "--ja3update",
        action="store_true",
        dest="ja3update",
        help="download latest ja3er.com json fingerprint file",
        default="",
    )
    parser.add_argument(
        "--trisulnsm",
        action="store_true",
        dest="trisulnsm",
        help="download latest trisulnsm json fingerprint file",
        default="",
    )
    parser.add_argument(
        "--format",
        action="store",
        help="Output format RAW,JSON",
        default=FingerprintFormat.Json.value,
        choices=[mode.value for mode in FingerprintFormat],
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        dest="output_file",
        help="Output file to write fingerprints in JSON format; example: -o output.json",
        default="",
    )
    return parser


## Parse Arguments
@dataclass
class Config:
    verbose = False
    proceed = False
    readpcap = ""
    interface = ""
    directory = ""
    modules: List[str] = field(default_factory=list)
    format: FingerprintFormat = FingerprintFormat.Json
    limit: int = 0
    filter = ""

    @classmethod
    def from_args(cls, args: argparse.Namespace):
        result = cls()
        if args.readpcap != "":
            if args.interface != "":
                logging.error("Cannot operate in interface and readpcap mode simultaneously, please select only one.")
                sys.exit()
            if not os.path.isfile(args.readpcap):
                logging.error('File "%s" does not appear to exist, please verify pcap file name.', args.readpcap)
                sys.exit()
            else:
                result.proceed = True
                result.readpcap = args.readpcap
        if args.interface != "":
            if args.readpcap != "":
                logging.error("Cannot operate in interface and readpcap mode simultaneously, please select only one.")
                sys.exit()
            result.interface = args.interface
            result.proceed = True

        if args.directory != "":
            if not os.path.isdir(args.directory):
                logging.error('Dir "%s" does not appear to exist, please verify directory name.', args.directory)
                sys.exit()
            else:
                result.proceed = True
                result.directory = args.directory

        if args.filter != "":
            if args.directory != "":
                logging.critical("Filter not implemented in directory processing, please remove and try again")
                sys.exit(1)
            if args.readpcap != "":
                logging.critical("Filter not implemented in pcap file read processing, please remove and try again")
                sys.exit(1)
            result.filter = args.filter
        if args.modules != "":
            result.modules = args.modules.split(",")
        result.format = FingerprintFormat(args.format)
        result.limit = args.limit
        result.verbose = args.verbose
        return result


class PacketType(Enum):
    TCP = 1 << 0  # 1
    DHCP = 1 << 1  # 2
    HTTP = 1 << 2  # 4
    UDP = 1 << 3  # 8
    SSL = 1 << 4  # 16
    SMB = 1 << 5  # 32
    DNS = 1 << 6  # 64
    NTP = 1 << 7  # 128
    SSH = 1 << 8  # 256
    QUIC = 1 << 9  # 512


class PacketHandlerMap:
    def __init__(self):
        # Словарь для хранения обработчиков для всех подмножеств флагов
        self.handlers: Dict[int, List[satoriCommon.BaseProcesser]] = defaultdict(list)

    def add_handler(self, flags: int, handler: satoriCommon.BaseProcesser):
        """Добавляем обработчик для определенной комбинации флагов."""
        self.handlers[flags].append(handler)

    def get_handlers(self, packet_type: int) -> List[satoriCommon.BaseProcesser]:
        """Возвращаем обработчики для всех подходящих комбинаций флагов."""
        matched_handlers = []
        # Перебираем все подмножества флагов для данного типа пакета
        subset = packet_type
        while subset:
            if subset in self.handlers:
                matched_handlers.extend(self.handlers[subset])
            subset = (subset - 1) & packet_type  # Следующее подмножество
        return matched_handlers


def packetType(buf, ts) -> Optional[Packet]:
    # try to determine what type of packets we have, there is the chance that 0x800 may be in the spot we're checking, may want to add better testing in future
    eth = ethernet.Ethernet(buf)
    pkt = None
    if hex(eth.type) == "0x800":
        pkt = Packet(eth, PacketLayer.eth, ts)
        if eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None:
            if eth[tcp.TCP] is not None:
                pkt.packet_type |= PacketType.TCP.value
                if eth[ethernet.Ethernet, ip.IP, tcp.TCP, ssl.SSL] is not None:
                    if eth[ssl.SSL] is not None:
                        pkt.packet_type |= PacketType.SSL.value
                if eth[ethernet.Ethernet, ip.IP, tcp.TCP, http.HTTP] is not None:
                    if eth[http.HTTP] is not None:
                        pkt.packet_type |= PacketType.HTTP.value
                if eth[ethernet.Ethernet, ip.IP, tcp.TCP, dns.DNS] is not None:
                    if eth[dns.DNS] is not None:
                        pkt.packet_type |= PacketType.DNS.value
                # attempt to tell if it is SMB, kludgy!
                tcp1 = eth[ip.IP].upper_layer
                if (
                    (tcp1.sport == 138)
                    or (tcp1.dport == 138)
                    or (tcp1.sport == 139)
                    or (tcp1.dport == 138)
                    or (tcp1.sport == 445)
                    or (tcp1.dport == 445)
                ):
                    pkt.packet_type |= PacketType.SMB.value
                # attempt to tell if it is RDP to run through SSL test, kludgy!
                if tcp1.dport == 3389:
                    pkt.packet_type |= PacketType.SSL.value
                # attempt to tell if it is SSH, kludgy!
                try:
                    if "SSH" in tcp1.body_bytes.decode("utf-8"):
                        pkt.packet_type |= PacketType.SSH.value
                except Exception as exc:
                    pass

        if eth[ethernet.Ethernet, ip.IP, udp.UDP] is not None:
            if eth[udp.UDP] is not None:
                pkt.packet_type |= PacketType.UDP.value
                if eth[ethernet.Ethernet, ip.IP, udp.UDP, dhcp.DHCP] is not None:
                    if eth[dhcp.DHCP] is not None:
                        pkt.packet_type |= PacketType.DHCP.value
                if eth[ethernet.Ethernet, ip.IP, udp.UDP, dns.DNS] is not None:
                    if eth[dns.DNS] is not None:
                        pkt.packet_type |= PacketType.DNS.value
                if eth[ethernet.Ethernet, ip.IP, udp.UDP, ntp.NTP] is not None:
                    if eth[ntp.NTP] is not None:
                        pkt.packet_type |= PacketType.NTP.value
                # attempt to tell if it is SMB, kludgy!
                udp1 = eth[ip.IP].upper_layer
                if (
                    (udp1.sport == 138)
                    or (udp1.dport == 138)
                    or (udp1.sport == 139)
                    or (udp1.dport == 138)
                    or (udp1.sport == 445)
                    or (udp1.dport == 445)
                ):
                    pkt.packet_type |= PacketType.SMB.value
                # attempt to tell if it is quic, kludgy!
                if udp1.dport == 443:
                    pkt.packet_type |= PacketType.QUIC.value

    lcc = linuxcc.LinuxCC(buf)
    if hex(lcc.type) == "0x800":
        pkt = Packet(eth, PacketLayer.lcc, ts)

        if lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP] is not None:
            if lcc[tcp.TCP] is not None:
                pkt.packet_type |= PacketType.TCP.value
                if lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, ssl.SSL] is not None:
                    if lcc[ssl.SSL] is not None:
                        pkt.packet_type |= PacketType.SSL.value
                if lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, http.HTTP] is not None:
                    if lcc[http.HTTP] is not None:
                        pkt.packet_type |= PacketType.HTTP.value
                if lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP, dns.DNS] is not None:
                    if lcc[dns.DNS] is not None:
                        pkt.packet_type |= PacketType.DNS.value
                # attempt to tell if it is SMB, kludgy!  For TCP I probably only need 139 and 445
                tcp1 = lcc[ip.IP].upper_layer
                if (
                    (tcp1.sport == 138)
                    or (tcp1.dport == 138)
                    or (tcp1.sport == 139)
                    or (tcp1.dport == 138)
                    or (tcp1.sport == 445)
                    or (tcp1.dport == 445)
                ):
                    pkt.packet_type |= PacketType.SMB.value
                # attempt to tell if it is RDP to run through SSL test, kludgy!
                if tcp1.dport == 3389:
                    sslPacket = True
                # attempt to tell if it is SSH, kludgy!
                try:
                    if "SSH" in tcp1.body_bytes.decode("utf-8"):
                        sshPacket = True
                except:
                    pass

        if lcc[linuxcc.LinuxCC, ip.IP, udp.UDP] is not None:
            if lcc[udp.UDP] is not None:
                udpPacket = True
                if lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, dhcp.DHCP] is not None:
                    if lcc[dhcp.DHCP] is not None:
                        dhcpPacket = True
                if lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, dns.DNS] is not None:
                    if lcc[dns.DNS] is not None:
                        dnsPacket = True
                if lcc[linuxcc.LinuxCC, ip.IP, udp.UDP, ntp.NTP] is not None:
                    if lcc[ntp.NTP] is not None:
                        dnsPacket = True
                # attempt to tell if it is SMB, kludgy!  For UDP I probably only need 138
                udp1 = lcc[ip.IP].upper_layer
                if (
                    (udp1.sport == 138)
                    or (udp1.dport == 138)
                    or (udp1.sport == 139)
                    or (udp1.dport == 138)
                    or (udp1.sport == 445)
                    or (udp1.dport == 445)
                ):
                    smbPacket = True
                # attempt to tell if it is quic, kludgy!
                if udp1.dport == 443:
                    quicPacket = True

    return pkt


def printCheck(dumper: Dumper, time_stamp, fingerprint):
    if fingerprint is None:
        return
    serialized = {"timestamp": time_stamp, "fingerprint": fingerprint}
    if historyTime != 0:
        if fingerprint in historyCheck:
            value = historyCheck[fingerprint]

            tdelta = datetime.datetime.strptime(time_stamp, TIMESTAMP_FMT) - datetime.datetime.strptime(
                value, TIMESTAMP_FMT
            )
            if tdelta > datetime.timedelta(minutes=historyTime):
                dumper.dump(serialized)
                historyCheck[fingerprint] = time_stamp
        else:
            dumper.dump(serialized)
            historyCheck[fingerprint] = time_stamp
    else:
        dumper.dump(serialized)


def print_result(dumper: Dumper, result: satoriCommon.TimedSatoriResult):
    dumper.dump(result.dump())


def process_packet(pkt: Packet, processers: PacketHandlerMap, dumper: Dumper):
    for processer in processers.get_handlers(pkt.packet_type):
        try:
            fingerprints = processer.process(pkt)
            for fingerprint in fingerprints:
                print_result(dumper, fingerprint)
        except Exception as exc:
            logging.error("%s: %s", processer.name(), exc.with_traceback())


@dataclass
class Counter:
    count: int = 0

    def increment(self):
        self.count += 1


def process_directory(directory, handlers, dumper, counter: Counter):
    onlyfiles = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    for f in onlyfiles:
        preader = ppcap.Reader(filename=directory + "/" + f)

        for ts, buf in preader:
            try:
                counter.increment()
                ts = ts / 1000000000
                pkt = packetType(buf, ts)
                if pkt:
                    process_packet(pkt, handlers, dumper)
            except (KeyboardInterrupt, SystemExit):
                raise
            except ValueError:
                pass
            except Exception:
                pass
            except:
                pass


def process_readpcap(pcap, handlers, dumper, counter: Counter):
    try:
        preader = ppcap.Reader(filename=pcap)
    except:
        print("File was not pcap format", end="\n", flush=True)
        sys.exit(1)

    for ts, buf in preader:
        try:
            counter.increment()
            ts = ts / 1000000000
            pkt = packetType(buf, ts)
            if pkt:
                process_packet(pkt, handlers, dumper)
        except (KeyboardInterrupt, SystemExit):
            raise
        except ValueError:
            pass
        except Exception:
            pass
        except:
            pass


def process_interface(interface, handlers, dumper, counter: Counter):
    try:
        preader = pcapy.open_live(interface, 65536, False, 1)
        # highly recommended to add something like this for a bpf filter on a high throughput connection (4 Gb/s link script sorta died on me in testing)
        if len(filter) > 0:
            preader.setfilter(filter)
    except Exception as e:
        print(e, end="\n", flush=True)
        sys.exit(1)
    while True:
        try:
            counter.increment()
            (header, buf) = preader.next()
            ts = header.getts()[0]
            pkt = packetType(buf, ts)
            if pkt:
                process_packet(pkt, handlers, dumper)
        except (KeyboardInterrupt, SystemExit):
            raise
        except ValueError:
            pass
        except Exception:
            pass
        except:
            pass


def process(config: Config):
    # override some warning settings in pypacker.  May need to change this to .CRITICAL in the future, but for now we're trying .ERROR
    # without this when parsing http for example we get "WARNINGS" when packets aren't quite right in the header.
    pypacker.logger.setLevel(pypacker.logging.ERROR)
    startTime = time.time()

    dumper = RawDumper() if config.format == FingerprintFormat.Raw else JsonDumper()
    config.modules

    # read in fingerprints
    tcpProcess = satoriTCP.TcpProcesser()
    ntpProcess = satoriNTP.NtpProcesser()
    sslProcess = satoriSSL.SslProcesser()
    dhcpProcess = satoriDHCP.DhcpProcesser()
    httpServerProcess = satoriHTTP.HttpServerProcesser()
    httpUserAgentProcess = satoriHTTP.HttpUserAgentProcesser()
    dnsProcess = satoriDNS.DnsProcesser()
    sshProcess = satoriSSH.SshProcesser()
    smbTCPProcess = satoriSMB.SmbTcpProcesser()
    smbUDPProcess = satoriSMB.SmbUdpProcesser()

    tcpProcess.load_fingerprints()
    ntpProcess.load_fingerprints()
    sslProcess.load_fingerprints()
    dhcpProcess.load_fingerprints()
    httpServerProcess.load_fingerprints()
    httpUserAgentProcess.load_fingerprints()
    dnsProcess.load_fingerprints()
    sshProcess.load_fingerprints()
    smbTCPProcess.load_fingerprints()
    smbUDPProcess.load_fingerprints()

    processers = PacketHandlerMap()
    processers.add_handler(PacketType.TCP.value, tcpProcess)
    processers.add_handler(PacketType.NTP.value, ntpProcess)
    processers.add_handler(PacketType.SSL.value, sslProcess)
    processers.add_handler(PacketType.DHCP.value, dhcpProcess)
    processers.add_handler(PacketType.HTTP.value, httpUserAgentProcess)
    processers.add_handler(PacketType.HTTP.value, httpServerProcess)
    processers.add_handler(PacketType.DNS.value, dnsProcess)
    processers.add_handler(PacketType.SSH.value, sshProcess)
    processers.add_handler(PacketType.SMB.value | PacketType.TCP.value, smbTCPProcess)
    processers.add_handler(PacketType.SMB.value | PacketType.UDP.value, smbUDPProcess)

    # [icmpExactList, icmpDataExactList, icmpPartialList, icmpDataPartialList] = satoriICMP.BuildICMPFingerprintFiles()
    counter = Counter()
    if config.directory:
        process_directory(config.directory, processers, dumper, counter)
    elif config.readpcap:
        process_readpcap(config.readpcap, processers, dumper, counter)
    elif config.interface != "":
        process_interface(config.interface, processers, dumper, counter)

    endTime = time.time()
    totalTime = endTime - startTime

    if config.verbose:
        print(f"Total Time: {totalTime}, Total Packets: {counter.count}, Packets/s: {counter.count / totalTime}")


def main():
    parser = make_parser()
    args = parser.parse_args()

    if args.dupes:
        satoriCommon.Dupes()
        sys.exit()
    if args.ja3update:
        satoriSSL.ja3erUpdate()
        sys.exit()
    if args.trisulnsm:
        satoriSSL.trisulnsmUpdate()
        sys.exit()

    config = Config.from_args(args)
    if config.proceed:
        process(config)
    else:
        print(
            "Need to provide a pcap to read in, a directory to read, or an interface to watch!",
            end="\n",
            flush=True,
        )
        parser.print_help()


if __name__ == "__main__":
    main()
