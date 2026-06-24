import ctypes
import socket
import subprocess
import sys
import time
from dataclasses import dataclass

MULTICAST_GROUP = "239.255.0.1"
UDP_PORT = 5000
DEST1_SUBNET = "10.10.0.0"
DEST1_MASK = "255.255.255.0"
DEST2_SUBNET = "10.20.0.0"
DEST2_MASK = "255.255.255.0"

POLL_INTERVAL_SECONDS = 2

AF_INET = 2
ERROR_BUFFER_OVERFLOW = 111
NO_ERROR = 0
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
IF_TYPE_ETHERNET_CSMACD = 6
IF_OPER_STATUS_UP = 1
IP_ADAPTER_DHCP_ENABLED = 0x00000004
MAX_ADAPTER_ADDRESS_LENGTH = 8


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int),
    ]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS_PTR = ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)

IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Next", IP_ADAPTER_UNICAST_ADDRESS_PTR),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", ctypes.c_ulong),
    ("PreferredLifetime", ctypes.c_ulong),
    ("LeaseLifetime", ctypes.c_ulong),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


IP_ADAPTER_ADDRESSES_PTR = ctypes.POINTER(IP_ADAPTER_ADDRESSES)

IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", IP_ADAPTER_ADDRESSES_PTR),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", IP_ADAPTER_UNICAST_ADDRESS_PTR),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Mtu", ctypes.c_ulong),
    ("IfType", ctypes.c_ulong),
    ("OperStatus", ctypes.c_int),
]


@dataclass
class AdapterInfo:
    if_index: int
    prefix_length: int
    has_ipv4: bool
    ipv4_text: str
    ipv4_host: int
    friendly_name: str


def prefix_to_mask(prefix_length):
    if prefix_length <= 0:
        return 0
    if prefix_length >= 32:
        return 0xFFFFFFFF
    return (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF


def same_subnet(left_ip, right_ip, prefix_length):
    mask = prefix_to_mask(prefix_length)
    return (left_ip & mask) == (right_ip & mask)


def read_ipv4_from_unicast(first_unicast):
    unicast = first_unicast
    while bool(unicast):
        address = unicast.contents.Address
        if address.lpSockaddr and address.iSockaddrLength >= 8:
            family = int.from_bytes(ctypes.string_at(address.lpSockaddr, 2), "little")
            if family == AF_INET:
                raw_ip = ctypes.string_at(address.lpSockaddr + 4, 4)
                if raw_ip != b"\x00\x00\x00\x00":
                    ipv4_text = socket.inet_ntoa(raw_ip)
                    ipv4_host = int.from_bytes(raw_ip, "big")
                    prefix_length = int(unicast.contents.OnLinkPrefixLength)
                    return True, ipv4_text, ipv4_host, prefix_length
        unicast = unicast.contents.Next

    return False, "", 0, 0


def get_adapters_addresses():
    iphlpapi = ctypes.WinDLL("Iphlpapi.dll")
    get_addresses = iphlpapi.GetAdaptersAddresses
    get_addresses.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        IP_ADAPTER_ADDRESSES_PTR,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    get_addresses.restype = ctypes.c_ulong

    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    size = ctypes.c_ulong(15000)

    while True:
        buffer = ctypes.create_string_buffer(size.value)
        addresses = ctypes.cast(buffer, IP_ADAPTER_ADDRESSES_PTR)
        result = get_addresses(AF_INET, flags, None, addresses, ctypes.byref(size))
        if result == ERROR_BUFFER_OVERFLOW:
            continue
        if result != NO_ERROR:
            raise OSError(f"GetAdaptersAddresses failed with error {result}.")
        return buffer, addresses


def find_first_active_ethernet():
    adapter_buffer, addresses = get_adapters_addresses()
    adapter = addresses
    _ = adapter_buffer

    while bool(adapter):
        item = adapter.contents
        dhcp_enabled = (item.Flags & IP_ADAPTER_DHCP_ENABLED) != 0
        is_active_ethernet = (
            item.OperStatus == IF_OPER_STATUS_UP
            and item.IfType == IF_TYPE_ETHERNET_CSMACD
            and item.PhysicalAddressLength > 0
        )

        if is_active_ethernet and dhcp_enabled:
            has_ipv4, ipv4_text, ipv4_host, prefix_length = read_ipv4_from_unicast(item.FirstUnicastAddress)
            return AdapterInfo(
                if_index=int(item.IfIndex),
                prefix_length=prefix_length,
                has_ipv4=has_ipv4,
                ipv4_text=ipv4_text,
                ipv4_host=ipv4_host,
                friendly_name=item.FriendlyName or "",
            )

        adapter = item.Next

    return None


def wait_for_initial_dhcp_ipv4():
    current = find_first_active_ethernet()
    if current is None:
        raise RuntimeError("No active DHCP-enabled Ethernet adapter was found.")

    if current.has_ipv4:
        print(f"DHCP IPv4 address detected: {current.ipv4_text}.")
        return current

    print("Monitoring adapter IPv4 address. No IPv4 address is currently assigned.")

    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        current = find_first_active_ethernet()
        if current is None or not current.has_ipv4:
            continue
        print(f"DHCP IPv4 address detected: {current.ipv4_text}.")
        return current


def wait_for_dhcp_ipv4_change(previous):
    print("Waiting for DHCP IPv4 address change.")

    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        current = find_first_active_ethernet()
        if current is None or not current.has_ipv4:
            continue
        if current.ipv4_host != previous.ipv4_host:
            print(f"New DHCP IPv4 address detected: {current.ipv4_text}.")
            return current


def receive_multicast_source(adapter):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", UDP_PORT))

        membership = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(adapter.ipv4_text)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)

        print(f"Listening on multicast group {MULTICAST_GROUP} UDP port {UDP_PORT}.")
        _, sender = sock.recvfrom(2048)
        source_ip_text = sender[0]
        source_ip_host = int.from_bytes(socket.inet_aton(source_ip_text), "big")
        return source_ip_text, source_ip_host


def run_route_add(destination, mask, gateway, if_index):
    command = [
        "route.exe",
        "-p",
        "add",
        destination,
        "mask",
        mask,
        gateway,
        "if",
        str(if_index),
    ]
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"route failed for destination {destination} with exit code {result.returncode}.")


def main():
    if sys.platform != "win32":
        print("This program must be run on Windows 11.", file=sys.stderr)
        return 1

    try:
        adapter = None

        while True:
            if adapter is None:
                adapter = wait_for_initial_dhcp_ipv4()
            else:
                adapter = wait_for_dhcp_ipv4_change(adapter)

            source_ip_text, source_ip_host = receive_multicast_source(adapter)

            if not same_subnet(adapter.ipv4_host, source_ip_host, adapter.prefix_length):
                print("The source IP is not on the same subnet as the incoming interface.")
                return 1

            run_route_add(DEST1_SUBNET, DEST1_MASK, source_ip_text, adapter.if_index)
            run_route_add(DEST2_SUBNET, DEST2_MASK, source_ip_text, adapter.if_index)
            print("Persistent routes were added successfully.")
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except socket.error as exc:
        print(f"Socket error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
