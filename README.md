# Static Route Subsystem

This repository contains two Windows 11 implementations of the same static route listener:

- `c/static_route_subsystem.c`
- `python/static_route_subsystem.py`

Both programs monitor the first active DHCP-enabled physical Ethernet adapter. They wait until it has a preferred IPv4 address assigned by DHCP, then join the configured multicast group on that adapter.

The listener verifies that each accepted datagram was addressed to the configured multicast group and arrived on the selected adapter. It ignores other datagrams. For an accepted packet, the program checks that its source address is on the adapter subnet. If it is outside that subnet, the program prints:

```text
The source IP is not on the same subnet as the incoming interface.
```

If the source is on the subnet but is not a usable host gateway address, the program prints:

```text
The source IP is not a usable gateway address.
```

and exits. If the source is usable and on the same subnet, the program reconciles two persistent routes through that source address. The configured destination prefixes are managed by this program. Existing NetMgmt (manually managed) static routes for those prefixes are removed from the active and persistent route stores on all interfaces before the current routes are created. Routes with other protocols are left alone. If route creation fails, the program removes the partial new set.

The listener checks adapter identity, interface index, DHCP IPv4 address, and prefix length while receiving. It reopens the multicast socket when any of those change, and waits for DHCP to return if the selected adapter temporarily loses its address.

## Security assumption

The packet source is not authenticated. Any host that can send to the configured multicast group on the trusted Ethernet network can influence the route gateway. Use this listener only on a network where multicast senders are trusted.

## Configuration

Each implementation has constants near the top of the source file:

- `MULTICAST_GROUP`
- `UDP_PORT`
- `DEST1_SUBNET`
- `DEST1_MASK`
- `DEST2_SUBNET`
- `DEST2_MASK`

The two configured destination prefixes are owned by this program. Matching NetMgmt static routes on any interface are replaced when routes are reconciled.

Each subnet and mask must describe an IPv4 prefix from /1 through /32. Default routes are not supported.

## Requirements

- Windows 11
- Administrator terminal
- Windows PowerShell with the built-in NetTCPIP module
- DHCP-enabled physical Ethernet adapter
- Multicast sender using the configured multicast group and UDP port

## Implementation guides

- [C README](c/README.md)
- [Python README](python/README.md)
