# C Static Route Listener

This program is for Windows 11. Run it from an Administrator Developer Command Prompt because it reconciles persistent routes.

## Configure

Edit these constants near the top of `static_route_subsystem.c`:

```c
#define MULTICAST_GROUP "239.255.0.1"
#define UDP_PORT 5000
#define DEST1_SUBNET "10.10.0.0"
#define DEST1_MASK "255.255.255.0"
#define DEST2_SUBNET "10.20.0.0"
#define DEST2_MASK "255.255.255.0"
```

Each destination and mask must describe a valid IPv4 network prefix from /1 through /32. Default routes are not supported.

## Build

Open an MSVC Developer Command Prompt in this folder and run:

```bat
cl /W4 /EHsc static_route_subsystem.c /link Ws2_32.lib Iphlpapi.lib Crypt32.lib
```

## Run

```bat
static_route_subsystem.exe
```

The program:

1. Finds the first active DHCP-enabled physical Ethernet adapter.
2. Waits for an IPv4 address assigned by DHCP and marked preferred by Windows.
3. Joins the configured multicast group on that adapter and monitors adapter state while receiving.
4. Accepts only packets addressed to the configured group and received on the selected interface. Other UDP datagrams are ignored.
5. Checks that the packet source is a usable host address on the adapter subnet.
6. Prints this exact message and exits if the packet source is outside that subnet:

```text
The source IP is not on the same subnet as the incoming interface.
```

7. Reconciles persistent routes through the packet source address:

```text
DEST1_SUBNET/DEST1_PREFIX_LENGTH
DEST2_SUBNET/DEST2_PREFIX_LENGTH
```

The two configured destination prefixes are managed by this program. Existing static routes for either prefix are removed from the active and persistent route stores on all interfaces before the routes are recreated. If creating the new routes fails, any partially created set is removed.

8. Restarts multicast listening when the adapter identity, interface index, DHCP address, or prefix changes. It waits for a preferred DHCP IPv4 address if the selected adapter temporarily loses one.

The route manager uses the Windows PowerShell NetTCPIP module. It locates PowerShell under the Windows system directory and does not search the working directory or `PATH` for the executable.

## Security assumption

The sender is not authenticated. Any host that can send to the configured multicast group on the trusted Ethernet network can influence the route gateway. Use the listener only on a network where multicast senders are trusted.

## Troubleshooting

- Run as Administrator. Route reconciliation requires elevation.
- Confirm the Ethernet adapter is active, physical, and DHCP-enabled.
- If the program waits at startup, confirm DHCP assigned a preferred IPv4 address to the Ethernet adapter.
- If multicast packets are not received, confirm the sender uses the configured group and UDP port on the selected interface.
- If route reconciliation fails, verify the destination subnets and masks and confirm the NetTCPIP module is available.
