import base64
import ctypes
import ipaddress
import os
import select
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
IP_PREFIX_ORIGIN_DHCP = 3
IP_DAD_STATE_PREFERRED = 4
MAX_ADAPTER_ADDRESS_LENGTH = 8
IP_PKTINFO = 19
SIO_GET_EXTENSION_FUNCTION_POINTER = 0xC8000006
WSAID_WSARECVMSG = (0xF689D7C8, 0x6F1F, 0x436B, (0x8A, 0x53, 0xE5, 0x4F, 0xE3, 0x51, 0xC3, 0x22))
WSAEWOULDBLOCK = 10035
SOCKET_ERROR = -1


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


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WSABUF(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ulong), ("buf", ctypes.c_void_p)]


class WSACMSGHDR(ctypes.Structure):
    _fields_ = [
        ("cmsg_len", ctypes.c_uint),
        ("cmsg_level", ctypes.c_int),
        ("cmsg_type", ctypes.c_int),
    ]


class WSAMSG(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("namelen", ctypes.c_int),
        ("lpBuffers", ctypes.POINTER(WSABUF)),
        ("dwBufferCount", ctypes.c_ulong),
        ("Control", WSABUF),
        ("dwFlags", ctypes.c_ulong),
    ]


class IN_PKTINFO(ctypes.Structure):
    _fields_ = [
        ("ipi_addr", ctypes.c_ubyte * 4),
        ("ipi_ifindex", ctypes.c_ulong),
    ]


@dataclass
class AdapterInfo:
    adapter_name: str
    if_index: int
    prefix_length: int
    has_ipv4: bool
    ipv4_text: str
    ipv4_host: int
    friendly_name: str


class AdapterStateChanged(Exception):
    def __init__(self, adapter):
        super().__init__("The selected Ethernet adapter changed.")
        self.adapter = adapter


def prefix_to_mask(prefix_length):
    if prefix_length < 0 or prefix_length > 32:
        return None
    if prefix_length == 0:
        return 0
    return (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF


def same_subnet(left_ip, right_ip, prefix_length):
    mask = prefix_to_mask(prefix_length)
    return mask is not None and (left_ip & mask) == (right_ip & mask)


def is_usable_gateway(adapter, source_ip_text):
    address = ipaddress.IPv4Address(source_ip_text)
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_reserved
        or address.packed[0] == 0
    ):
        return False
    if int(address) == adapter.ipv4_host:
        return False

    network = ipaddress.IPv4Network((adapter.ipv4_host, adapter.prefix_length), strict=False)
    if adapter.prefix_length <= 30 and address in (network.network_address, network.broadcast_address):
        return False
    return True


def read_ipv4_from_unicast(first_unicast):
    unicast = first_unicast
    while bool(unicast):
        item = unicast.contents
        address = item.Address
        if address.lpSockaddr and address.iSockaddrLength >= 8:
            family = int.from_bytes(ctypes.string_at(address.lpSockaddr, 2), "little")
            if family == AF_INET:
                raw_ip = ctypes.string_at(address.lpSockaddr + 4, 4)
                prefix_length = int(item.OnLinkPrefixLength)
                if (
                    raw_ip != b"\x00\x00\x00\x00"
                    and item.PrefixOrigin == IP_PREFIX_ORIGIN_DHCP
                    and item.DadState == IP_DAD_STATE_PREFERRED
                    and 1 <= prefix_length <= 32
                ):
                    ipv4_text = socket.inet_ntoa(raw_ip)
                    ipv4_host = int.from_bytes(raw_ip, "big")
                    return True, ipv4_text, ipv4_host, prefix_length
        unicast = item.Next

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
            adapter_name = item.AdapterName.decode("ascii", errors="replace") if item.AdapterName else ""
            return AdapterInfo(
                adapter_name=adapter_name,
                if_index=int(item.IfIndex),
                prefix_length=prefix_length,
                has_ipv4=has_ipv4,
                ipv4_text=ipv4_text,
                ipv4_host=ipv4_host,
                friendly_name=item.FriendlyName or "",
            )

        adapter = item.Next

    return None


def same_adapter_state(left, right):
    return (
        left is not None
        and right is not None
        and left.adapter_name == right.adapter_name
        and left.if_index == right.if_index
        and left.has_ipv4 == right.has_ipv4
        and left.ipv4_host == right.ipv4_host
        and left.prefix_length == right.prefix_length
    )


def _refresh_selected_adapter(selected):
    current = find_first_active_ethernet()
    if current is None or not same_adapter_state(selected, current):
        raise AdapterStateChanged(current)
    return current


def wait_for_initial_dhcp_ipv4():
    print("Monitoring for an active DHCP-enabled Ethernet adapter with a DHCP IPv4 address.")
    while True:
        current = find_first_active_ethernet()
        if current is not None and current.has_ipv4:
            print(f"DHCP IPv4 address detected: {current.ipv4_text}.")
            return current
        time.sleep(POLL_INTERVAL_SECONDS)


def wait_for_dhcp_ipv4_change(previous):
    print("Waiting for DHCP IPv4 address or adapter change.")
    address_was_unavailable = False

    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        current = find_first_active_ethernet()
        if current is None or not current.has_ipv4:
            address_was_unavailable = True
            continue
        if address_was_unavailable or not same_adapter_state(previous, current):
            print(f"New DHCP IPv4 address detected: {current.ipv4_text}.")
            return current


def _make_wsarecvmsg(sock):
    ws2_32 = ctypes.WinDLL("Ws2_32.dll", use_last_error=True)
    wsa_ioctl = ws2_32.WSAIoctl
    wsa_ioctl.argtypes = [
        ctypes.c_size_t,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    wsa_ioctl.restype = ctypes.c_int

    guid_values = WSAID_WSARECVMSG
    guid = GUID(guid_values[0], guid_values[1], guid_values[2], (ctypes.c_ubyte * 8)(*guid_values[3]))
    function_address = ctypes.c_void_p()
    bytes_returned = ctypes.c_ulong()
    result = wsa_ioctl(
        sock.fileno(),
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        ctypes.byref(guid),
        ctypes.sizeof(guid),
        ctypes.byref(function_address),
        ctypes.sizeof(function_address),
        ctypes.byref(bytes_returned),
        None,
        None,
    )
    if result == SOCKET_ERROR:
        error = ws2_32.WSAGetLastError()
        raise OSError(error, f"WSAIoctl for WSARecvMsg failed with error {error}.")

    recvmsg_type = ctypes.WINFUNCTYPE(
        ctypes.c_int,
        ctypes.c_size_t,
        ctypes.POINTER(WSAMSG),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    return recvmsg_type(function_address.value), ws2_32


def _receive_packet_info(sock, recvmsg, ws2_32):
    payload = ctypes.create_string_buffer(2048)
    sender = ctypes.create_string_buffer(128)
    control = ctypes.create_string_buffer(128)
    data_buffer = WSABUF(len=len(payload), buf=ctypes.cast(payload, ctypes.c_void_p))
    control_buffer = WSABUF(len=len(control), buf=ctypes.cast(control, ctypes.c_void_p))

    message = WSAMSG()
    message.name = ctypes.cast(sender, ctypes.c_void_p)
    message.namelen = len(sender)
    message.lpBuffers = ctypes.pointer(data_buffer)
    message.dwBufferCount = 1
    message.Control = control_buffer
    message.dwFlags = 0
    received = ctypes.c_ulong()

    result = recvmsg(sock.fileno(), ctypes.byref(message), ctypes.byref(received), None, None)
    if result == SOCKET_ERROR:
        error = ws2_32.WSAGetLastError()
        if error == WSAEWOULDBLOCK:
            return None
        raise OSError(error, f"WSARecvMsg failed with error {error}.")

    control_length = message.Control.len
    header_size = ctypes.sizeof(WSACMSGHDR)
    alignment = ctypes.sizeof(ctypes.c_size_t)
    data_offset = (header_size + alignment - 1) & ~(alignment - 1)
    offset = 0
    while offset + header_size <= control_length:
        header = WSACMSGHDR.from_buffer(control, offset)
        if header.cmsg_len < header_size or header.cmsg_len > control_length - offset:
            break
        if header.cmsg_level == socket.IPPROTO_IP and header.cmsg_type == IP_PKTINFO:
            info_offset = offset + data_offset
            if header.cmsg_len >= data_offset + ctypes.sizeof(IN_PKTINFO):
                packet_info = IN_PKTINFO.from_buffer(control, info_offset)
                source_ip = socket.inet_ntoa(sender.raw[4:8])
                destination_ip = socket.inet_ntoa(bytes(packet_info.ipi_addr))
                return source_ip, destination_ip, int(packet_info.ipi_ifindex)
        offset += (header.cmsg_len + alignment - 1) & ~(alignment - 1)

    return None


def receive_multicast_source(adapter):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.bind(("", UDP_PORT))
        sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)

        membership = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(adapter.ipv4_text)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setblocking(False)
        recvmsg, ws2_32 = _make_wsarecvmsg(sock)

        print(f"Listening on multicast group {MULTICAST_GROUP} UDP port {UDP_PORT}.")
        last_adapter_check = time.monotonic()
        while True:
            readable, _, _ = select.select([sock], [], [], POLL_INTERVAL_SECONDS)
            if not readable:
                _refresh_selected_adapter(adapter)
                last_adapter_check = time.monotonic()
                continue

            packet = _receive_packet_info(sock, recvmsg, ws2_32)
            if packet is None:
                continue
            now = time.monotonic()
            if now - last_adapter_check >= POLL_INTERVAL_SECONDS:
                _refresh_selected_adapter(adapter)
                last_adapter_check = now
            source_ip_text, destination_ip_text, incoming_if_index = packet
            if destination_ip_text != MULTICAST_GROUP or incoming_if_index != adapter.if_index:
                continue
            _refresh_selected_adapter(adapter)
            source_ip_host = int.from_bytes(socket.inet_aton(source_ip_text), "big")
            return source_ip_text, source_ip_host


def _get_windows_directory():
    buffer = ctypes.create_unicode_buffer(32768)
    get_windows_directory = ctypes.windll.kernel32.GetWindowsDirectoryW
    get_windows_directory.argtypes = [ctypes.POINTER(ctypes.c_wchar), ctypes.c_uint]
    get_windows_directory.restype = ctypes.c_uint
    length = get_windows_directory(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        error = ctypes.get_last_error()
        raise OSError(error, f"GetWindowsDirectoryW failed with error {error}.")
    return buffer.value


def _route_prefix(subnet, mask):
    try:
        network = ipaddress.IPv4Network(f"{subnet}/{mask}", strict=True)
        if network.prefixlen == 0:
            raise ValueError("default routes are not supported")
        return str(network)
    except ValueError as exc:
        raise RuntimeError(f"Invalid configured route {subnet} mask {mask}: {exc}") from exc


def run_route_reconcile(gateway, if_index):
    gateway = str(ipaddress.IPv4Address(gateway))
    prefixes = (_route_prefix(DEST1_SUBNET, DEST1_MASK), _route_prefix(DEST2_SUBNET, DEST2_MASK))
    quoted_prefixes = ", ".join(f"'{prefix}'" for prefix in prefixes)
    script = f"""
$ErrorActionPreference = 'Stop'
$managedPrefixes = @({quoted_prefixes})
$routeExe = Join-Path ([Environment]::SystemDirectory) 'route.exe'
function Remove-ManagedRoutes([string]$store) {{
    foreach ($prefix in $managedPrefixes) {{
        $routes = @(Get-NetRoute -DestinationPrefix $prefix -PolicyStore $store -ErrorAction Stop | Where-Object {{ [string]$_.Protocol -eq 'NetMgmt' }})
        foreach ($route in $routes) {{
            $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        }}
    }}
}}
try {{
    Remove-ManagedRoutes 'ActiveStore'
    Remove-ManagedRoutes 'PersistentStore'
}} catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}}
try {{
    & $routeExe -p add '{DEST1_SUBNET}' mask '{DEST1_MASK}' '{gateway}' if {int(if_index)}
    if ($LASTEXITCODE -ne 0) {{ throw "route.exe failed for {prefixes[0]} with exit code $LASTEXITCODE" }}
    & $routeExe -p add '{DEST2_SUBNET}' mask '{DEST2_MASK}' '{gateway}' if {int(if_index)}
    if ($LASTEXITCODE -ne 0) {{ throw "route.exe failed for {prefixes[1]} with exit code $LASTEXITCODE" }}
}} catch {{
    $failure = $_.Exception.Message
    foreach ($store in @('ActiveStore', 'PersistentStore')) {{
        try {{ Remove-ManagedRoutes $store }} catch {{ }}
    }}
    [Console]::Error.WriteLine($failure)
    exit 1
}}
"""
    encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    powershell = os.path.join(
        _get_windows_directory(),
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        if detail:
            raise RuntimeError(f"Persistent route reconciliation failed: {detail}")
        raise RuntimeError(f"Persistent route reconciliation failed with exit code {result.returncode}.")


def main():
    if sys.platform != "win32":
        print("This program must be run on Windows 11.", file=sys.stderr)
        return 1

    try:
        adapter = wait_for_initial_dhcp_ipv4()

        while True:
            try:
                source_ip_text, source_ip_host = receive_multicast_source(adapter)
            except AdapterStateChanged as changed:
                adapter = changed.adapter
                if adapter is None or not adapter.has_ipv4:
                    adapter = wait_for_initial_dhcp_ipv4()
                continue

            if not same_subnet(adapter.ipv4_host, source_ip_host, adapter.prefix_length):
                print("The source IP is not on the same subnet as the incoming interface.")
                return 1
            if not is_usable_gateway(adapter, source_ip_text):
                print("The source IP is not a usable gateway address.")
                return 1

            run_route_reconcile(source_ip_text, adapter.if_index)
            print("Persistent routes were reconciled successfully.")
            adapter = wait_for_dhcp_ipv4_change(adapter)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
