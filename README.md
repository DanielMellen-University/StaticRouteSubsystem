# Static Route Subsystem

This repository contains two Windows 11 implementations of the same static route listener:

- `c/static_route_subsystem.c`
- `python/static_route_subsystem.py`

Both programs monitor the first active DHCP-enabled physical Ethernet adapter. If the adapter already has a DHCP IPv4 address when the program starts, multicast listening begins immediately. If no DHCP IPv4 address is assigned, the program waits until one appears.

After a multicast UDP packet is received, the program checks whether the packet source IP is on the same subnet as the Ethernet interface. If it is not, the program prints:

```text
The source IP is not on the same subnet as the incoming interface.
```

If the source IP is on the same subnet, the program creates two persistent static routes through that source IP. After the routes are created, the program waits for the DHCP IPv4 address to change, then repeats the multicast listening and route creation flow.

## Configuration

Each implementation has constants near the top of the source file:

- `MULTICAST_GROUP`
- `UDP_PORT`
- `DEST1_SUBNET`
- `DEST1_MASK`
- `DEST2_SUBNET`
- `DEST2_MASK`

Edit these constants before building or running.

## Requirements

- Windows 11
- Administrator terminal
- DHCP-enabled physical Ethernet adapter
- Multicast sender using the configured multicast group and UDP port

## Implementation Guides

Use the implementation-specific README for build and run instructions:

- [C README](c/README.md)
- [Python README](python/README.md)
