# Python Static Route Listener

This program is for Windows 11. Run it from an Administrator terminal because it creates persistent routes with `route -p add`.

## Configure

Edit these constants near the top of `static_route_subsystem.py`:

```python
MULTICAST_GROUP = "239.255.0.1"
UDP_PORT = 5000
DEST1_SUBNET = "10.10.0.0"
DEST1_MASK = "255.255.255.0"
DEST2_SUBNET = "10.20.0.0"
DEST2_MASK = "255.255.255.0"
```

## Run

Use Python 3.9 or newer from an Administrator terminal:

```bat
py static_route_subsystem.py
```

The program uses only the Python standard library.

## Behavior

The program:

1. Finds the first active DHCP-enabled physical Ethernet adapter.
2. Starts multicast listening immediately if a DHCP IPv4 address is already assigned.
3. Waits for a DHCP IPv4 address if no IPv4 address is currently assigned.
4. Joins the configured multicast group on the configured UDP port.
5. Receives one multicast UDP packet and reads the packet source IP.
6. Exits with this exact message if the packet source IP is not in the adapter subnet:

```text
The source IP is not on the same subnet as the incoming interface.
```

7. Adds these persistent routes if the packet source IP is in the adapter subnet:

```bat
route -p add DEST1_SUBNET mask DEST1_MASK SIP if IF_INDEX
route -p add DEST2_SUBNET mask DEST2_MASK SIP if IF_INDEX
```

8. Waits for the DHCP IPv4 address to change, then repeats multicast listening and route creation.

## Troubleshooting

- Run as Administrator. Without elevation, `route -p add` will fail.
- Confirm the Ethernet adapter is active, physical, and DHCP-enabled.
- If the program waits at startup, confirm DHCP assigned an IPv4 address to the Ethernet adapter.
- If multicast packets are not received, confirm the sender uses the configured multicast group and UDP port.
- If route creation fails, verify the destination subnets and masks are valid IPv4 route values.
