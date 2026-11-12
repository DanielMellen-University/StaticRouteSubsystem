import contextlib
import base64
import ctypes
import io
import socket
import unittest
from dataclasses import replace
from unittest import mock

import static_route_subsystem as srs


class PortableHelperTests(unittest.TestCase):
    PREFIX_CASES = (
        (0, 0x00000000, True),
        (1, 0x80000000, True),
        (24, 0xFFFFFF00, True),
        (31, 0xFFFFFFFE, True),
        (32, 0xFFFFFFFF, True),
        (33, 0x00000000, False),
    )

    GATEWAY_CASES = (
        (0xC0A8010A, 24, 0xC0A80114, True),
        (0xC0A8010A, 24, 0xC0A80100, False),
        (0xC0A8010A, 24, 0xC0A801FF, False),
        (0xC0A8010A, 24, 0xC0A8010A, False),
        (0xC0A80110, 31, 0xC0A80111, True),
        (0xC0A80110, 32, 0xC0A80111, True),
        (0x0A000001, 8, 0x00000001, False),
        (0x0A000001, 8, 0x7F000001, False),
        (0x0A000001, 8, 0xE0000001, False),
        (0x0A000001, 8, 0x0A000002, True),
        (0x0A000001, 0, 0x0A000002, False),
        (0x0A000001, 33, 0x0A000002, False),
    )

    def test_prefix_and_subnet_cases(self):
        left = 0xC0A8010A
        same_24 = 0xC0A801FE
        other_24 = 0xC0A80201
        for prefix, expected_mask, valid in self.PREFIX_CASES:
            with self.subTest(prefix=prefix):
                self.assertEqual(srs.prefix_to_mask(prefix), expected_mask if valid else None)
                self.assertEqual(srs.same_subnet(left, left, prefix), valid)
        self.assertTrue(srs.same_subnet(left, same_24, 24))
        self.assertFalse(srs.same_subnet(left, other_24, 24))
        self.assertTrue(srs.same_subnet(left, other_24, 16))

    def test_gateway_cases(self):
        for adapter_ip, prefix, source_ip, expected in self.GATEWAY_CASES:
            adapter = srs.AdapterInfo("adapter", 3, prefix, True, "", adapter_ip, "Ethernet")
            source_text = ".".join(str((source_ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))
            with self.subTest(source=source_text, prefix=prefix):
                self.assertEqual(srs.is_usable_gateway(adapter, source_text), expected)

    def test_prefix_length_and_canonical_network_cases(self):
        cases = (
            ("10.0.0.0", "255.0.0.0", True),
            ("10.0.0.1", "255.0.0.0", False),
            ("10.0.0.0", "255.0.255.0", False),
            ("0.0.0.0", "0.0.0.0", False),
        )
        for address, mask, valid in cases:
            with self.subTest(address=address, mask=mask):
                try:
                    network = srs.ipaddress.IPv4Network(f"{address}/{mask}", strict=True)
                    actual = network.prefixlen > 0
                except ValueError:
                    actual = False
                self.assertEqual(actual, valid)

    def test_route_prefix_validation(self):
        valid_cases = (
            ("10.0.0.0", "255.0.0.0", "10.0.0.0/8"),
            ("192.0.2.0", "255.255.255.254", "192.0.2.0/31"),
            ("192.0.2.1", "255.255.255.255", "192.0.2.1/32"),
        )
        for subnet, mask, expected in valid_cases:
            with self.subTest(subnet=subnet, mask=mask):
                self.assertEqual(srs._route_prefix(subnet, mask), expected)

        invalid_cases = (
            ("10.0.0.1", "255.0.0.0"),
            ("10.0.0.0", "255.0.255.0"),
            ("0.0.0.0", "0.0.0.0"),
            ("999.0.0.0", "255.0.0.0"),
        )
        for subnet, mask in invalid_cases:
            with self.subTest(subnet=subnet, mask=mask):
                with self.assertRaisesRegex(RuntimeError, "Invalid configured route"):
                    srs._route_prefix(subnet, mask)


class AdapterStateTests(unittest.TestCase):
    def setUp(self):
        self.adapter = srs.AdapterInfo("adapter", 3, 24, True, "192.0.2.10", 0xC000020A, "Ethernet")

    def test_adapter_state_tracks_route_relevant_fields(self):
        self.assertTrue(srs.same_adapter_state(self.adapter, replace(self.adapter)))
        self.assertTrue(srs.same_adapter_state(self.adapter, replace(self.adapter, friendly_name="Renamed")))
        changes = (
            {"adapter_name": "other"},
            {"if_index": 4},
            {"has_ipv4": False},
            {"ipv4_host": 0xC000020B},
            {"prefix_length": 25},
        )
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(srs.same_adapter_state(self.adapter, replace(self.adapter, **change)))
        self.assertFalse(srs.same_adapter_state(None, self.adapter))
        self.assertFalse(srs.same_adapter_state(self.adapter, None))

    def test_refresh_selected_adapter_returns_same_or_carries_change(self):
        with mock.patch.object(srs, "find_first_active_ethernet", return_value=self.adapter):
            self.assertIs(srs._refresh_selected_adapter(self.adapter), self.adapter)

        changed = replace(self.adapter, if_index=9)
        for current in (changed, None):
            with self.subTest(current=current):
                with mock.patch.object(srs, "find_first_active_ethernet", return_value=current):
                    with self.assertRaises(srs.AdapterStateChanged) as raised:
                        srs._refresh_selected_adapter(self.adapter)
                    self.assertIs(raised.exception.adapter, current)

    def test_initial_wait_skips_missing_and_unaddressed_adapters(self):
        no_address = replace(self.adapter, has_ipv4=False, ipv4_text="", ipv4_host=0, prefix_length=0)
        with mock.patch.object(srs, "find_first_active_ethernet", side_effect=(None, no_address, self.adapter)), \
                mock.patch.object(srs.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()):
            self.assertIs(srs.wait_for_initial_dhcp_ipv4(), self.adapter)
        self.assertEqual(sleep.call_count, 2)

    def test_change_wait_returns_after_adapter_disappears_or_changes(self):
        changed = replace(self.adapter, ipv4_host=0xC0000214, ipv4_text="192.0.2.20")
        with mock.patch.object(srs, "find_first_active_ethernet", side_effect=(self.adapter, None, changed)), \
                mock.patch.object(srs.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()):
            self.assertIs(srs.wait_for_dhcp_ipv4_change(self.adapter), changed)
        self.assertEqual(sleep.call_count, 3)


class UnicastAddressTests(unittest.TestCase):
    def make_unicast_chain(self, cases):
        items = (srs.IP_ADAPTER_UNICAST_ADDRESS * len(cases))()
        buffers = []
        for index, (raw_ip, family, prefix, origin, dad_state) in enumerate(cases):
            sockaddr = ctypes.create_string_buffer(family.to_bytes(2, "little") + b"\x00\x00" + raw_ip)
            buffers.append(sockaddr)
            items[index].Address = srs.SOCKET_ADDRESS(ctypes.addressof(sockaddr), len(sockaddr) - 1)
            items[index].OnLinkPrefixLength = prefix
            items[index].PrefixOrigin = origin
            items[index].DadState = dad_state
            if index + 1 < len(cases):
                items[index].Next = ctypes.pointer(items[index + 1])
        return items, buffers

    def test_reads_first_eligible_dhcp_preferred_ipv4_address(self):
        invalid = (
            (socket.inet_aton("192.0.2.3"), srs.AF_INET, 24, 1, srs.IP_DAD_STATE_PREFERRED),
            (socket.inet_aton("192.0.2.4"), srs.AF_INET, 24, srs.IP_PREFIX_ORIGIN_DHCP, 3),
            (socket.inet_aton("0.0.0.0"), srs.AF_INET, 24, srs.IP_PREFIX_ORIGIN_DHCP, srs.IP_DAD_STATE_PREFERRED),
            (socket.inet_aton("192.0.2.5"), 23, 24, srs.IP_PREFIX_ORIGIN_DHCP, srs.IP_DAD_STATE_PREFERRED),
            (socket.inet_aton("192.0.2.6"), srs.AF_INET, 0, srs.IP_PREFIX_ORIGIN_DHCP, srs.IP_DAD_STATE_PREFERRED),
            (socket.inet_aton("192.0.2.7"), srs.AF_INET, 33, srs.IP_PREFIX_ORIGIN_DHCP, srs.IP_DAD_STATE_PREFERRED),
        )
        valid = (socket.inet_aton("192.0.2.8"), srs.AF_INET, 25,
                 srs.IP_PREFIX_ORIGIN_DHCP, srs.IP_DAD_STATE_PREFERRED)
        items, buffers = self.make_unicast_chain(invalid + (valid,))
        self.assertEqual(
            srs.read_ipv4_from_unicast(ctypes.pointer(items[0])),
            (True, "192.0.2.8", 0xC0000208, 25),
        )
        self.assertEqual(len(buffers), len(invalid) + 1)

    def test_empty_or_ineligible_unicast_list_has_no_address(self):
        items, buffers = self.make_unicast_chain((
            (socket.inet_aton("192.0.2.8"), srs.AF_INET, 24,
             srs.IP_PREFIX_ORIGIN_DHCP, 3),
        ))
        self.assertEqual(srs.read_ipv4_from_unicast(ctypes.pointer(items[0])), (False, "", 0, 0))
        self.assertEqual(srs.read_ipv4_from_unicast(srs.IP_ADAPTER_UNICAST_ADDRESS_PTR()), (False, "", 0, 0))
        self.assertEqual(len(buffers), 1)


class AdapterEnumerationTests(unittest.TestCase):
    def make_adapter_chain(self, records):
        adapters = (srs.IP_ADAPTER_ADDRESSES * len(records))()
        for index, record in enumerate(records):
            adapters[index].IfIndex = record.get("if_index", index + 1)
            adapters[index].AdapterName = record.get("name", f"adapter-{index}".encode("ascii"))
            adapters[index].FriendlyName = record.get("friendly_name", f"Ethernet {index}")
            adapters[index].PhysicalAddressLength = record.get("physical_length", 6)
            adapters[index].Flags = record.get("flags", srs.IP_ADAPTER_DHCP_ENABLED)
            adapters[index].IfType = record.get("if_type", srs.IF_TYPE_ETHERNET_CSMACD)
            adapters[index].OperStatus = record.get("status", srs.IF_OPER_STATUS_UP)
            if index + 1 < len(records):
                adapters[index].Next = ctypes.pointer(adapters[index + 1])
        return adapters

    def test_selects_first_adapter_that_passes_all_filters(self):
        adapters = self.make_adapter_chain((
            {"status": 2},
            {"if_type": 24},
            {"physical_length": 0},
            {"flags": 0},
            {"if_index": 88, "name": b"chosen", "friendly_name": "Chosen adapter"},
            {"if_index": 99, "name": b"later"},
        ))
        with mock.patch.object(srs, "get_adapters_addresses", return_value=(object(), ctypes.pointer(adapters[0]))):
            actual = srs.find_first_active_ethernet()
        self.assertEqual(actual, srs.AdapterInfo("chosen", 88, 0, False, "", 0, "Chosen adapter"))

    def test_empty_adapter_list_returns_none(self):
        with mock.patch.object(srs, "get_adapters_addresses", return_value=(object(), srs.IP_ADAPTER_ADDRESSES_PTR())):
            self.assertIsNone(srs.find_first_active_ethernet())

    def test_address_query_retries_buffer_overflow_and_returns_buffer(self):
        calls = []

        class FakeFunction:
            def __call__(self, family, flags, reserved, addresses, size_pointer):
                size = ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_ulong)).contents
                calls.append((family, flags, size.value))
                if len(calls) == 1:
                    size.value = 30000
                    return srs.ERROR_BUFFER_OVERFLOW
                return srs.NO_ERROR

        class FakeLibrary:
            GetAdaptersAddresses = FakeFunction()

        with mock.patch.object(srs.ctypes, "WinDLL", return_value=FakeLibrary(), create=True):
            buffer, addresses = srs.get_adapters_addresses()
        self.assertEqual([call[2] for call in calls], [15000, 30000])
        self.assertEqual(len(buffer), 30000)
        self.assertTrue(bool(addresses))

    def test_address_query_reports_api_error(self):
        class FakeFunction:
            def __call__(self, family, flags, reserved, addresses, size_pointer):
                return 5

        class FakeLibrary:
            GetAdaptersAddresses = FakeFunction()

        with mock.patch.object(srs.ctypes, "WinDLL", return_value=FakeLibrary(), create=True):
            with self.assertRaisesRegex(OSError, "GetAdaptersAddresses failed with error 5"):
                srs.get_adapters_addresses()


class PacketInfoParsingTests(unittest.TestCase):
    @staticmethod
    def fake_socket():
        sock = mock.Mock()
        sock.fileno.return_value = 5
        return sock

    def receive_with_control(self, control_kind):
        def recvmsg(fd, message_pointer, received_pointer, overlapped, completion):
            message = ctypes.cast(message_pointer, ctypes.POINTER(srs.WSAMSG)).contents
            sender = b"\x02\x00\x13\x88" + socket.inet_aton("192.0.2.19") + b"\x00" * 8
            ctypes.memmove(message.name, sender, len(sender))
            if control_kind == "absent":
                message.Control.len = 0
                return 0

            header_size = ctypes.sizeof(srs.WSACMSGHDR)
            alignment = ctypes.sizeof(ctypes.c_size_t)
            data_offset = (header_size + alignment - 1) & ~(alignment - 1)
            header = srs.WSACMSGHDR.from_address(message.Control.buf)
            header.cmsg_level = socket.IPPROTO_IP
            header.cmsg_type = srs.IP_PKTINFO
            if control_kind == "too_short":
                header.cmsg_len = header_size - 1
                message.Control.len = header_size
            elif control_kind == "truncated":
                header.cmsg_len = header_size + 100
                message.Control.len = header_size
            elif control_kind == "other_type":
                header.cmsg_len = data_offset + ctypes.sizeof(srs.IN_PKTINFO)
                header.cmsg_type = 99
                message.Control.len = header.cmsg_len
            else:
                header.cmsg_len = data_offset + ctypes.sizeof(srs.IN_PKTINFO)
                info = srs.IN_PKTINFO.from_address(message.Control.buf + data_offset)
                info.ipi_addr[:] = (239, 255, 0, 1)
                info.ipi_ifindex = 12
                message.Control.len = header.cmsg_len
            return 0

        return recvmsg

    def test_parses_valid_packet_info(self):
        packet = srs._receive_packet_info(self.fake_socket(), self.receive_with_control("valid"), object())
        self.assertEqual(packet, ("192.0.2.19", "239.255.0.1", 12))

    def test_ignores_absent_and_malformed_packet_info(self):
        for control_kind in ("absent", "too_short", "truncated", "other_type"):
            with self.subTest(control_kind=control_kind):
                packet = srs._receive_packet_info(self.fake_socket(), self.receive_with_control(control_kind), object())
                self.assertIsNone(packet)

    def test_would_block_returns_none_and_other_errors_are_reported(self):
        class FakeWinsock:
            def __init__(self, error):
                self.error = error

            def WSAGetLastError(self):
                return self.error

        def failed_recvmsg(fd, message, received, overlapped, completion):
            return srs.SOCKET_ERROR

        self.assertIsNone(srs._receive_packet_info(
            self.fake_socket(), failed_recvmsg, FakeWinsock(srs.WSAEWOULDBLOCK)))
        with self.assertRaisesRegex(OSError, "WSARecvMsg failed with error 10022"):
            srs._receive_packet_info(self.fake_socket(), failed_recvmsg, FakeWinsock(10022))


class MulticastReceiveTests(unittest.TestCase):
    def setUp(self):
        self.adapter = srs.AdapterInfo("chosen", 12, 24, True, "192.0.2.10", 0xC000020A, "Ethernet")
        self.sock = mock.MagicMock()
        self.sock.__enter__.return_value = self.sock

    def run_receive(self, packets, refresh_side_effect=None):
        select_results = [([self.sock], [], []) for _ in packets]
        with mock.patch.object(srs.socket, "socket", return_value=self.sock) as create_socket, \
                mock.patch.object(srs, "_make_wsarecvmsg", return_value=(object(), object())), \
                mock.patch.object(srs, "_receive_packet_info", side_effect=packets) as receive_packet, \
                mock.patch.object(srs.select, "select", side_effect=select_results), \
                mock.patch.object(srs, "_refresh_selected_adapter", side_effect=refresh_side_effect) as refresh, \
                mock.patch.object(srs.time, "monotonic", return_value=1.0), \
                contextlib.redirect_stdout(io.StringIO()):
            result = srs.receive_multicast_source(self.adapter)
        return result, create_socket, receive_packet, refresh

    def test_ignores_other_group_and_interface_then_accepts_matching_packet(self):
        result, create_socket, receive_packet, refresh = self.run_receive((
            ("192.0.2.1", "239.255.0.2", 12),
            ("192.0.2.2", "239.255.0.1", 99),
            ("192.0.2.3", "239.255.0.1", 12),
        ))
        self.assertEqual(result, ("192.0.2.3", 0xC0000203))
        create_socket.assert_called_once_with(srs.socket.AF_INET, srs.socket.SOCK_DGRAM, srs.socket.IPPROTO_UDP)
        self.assertEqual(receive_packet.call_count, 3)
        refresh.assert_called_once_with(self.adapter)
        self.sock.bind.assert_called_once_with(("", srs.UDP_PORT))
        self.sock.setsockopt.assert_any_call(srs.socket.IPPROTO_IP, srs.IP_PKTINFO, 1)
        self.sock.setsockopt.assert_any_call(
            srs.socket.IPPROTO_IP,
            srs.socket.IP_ADD_MEMBERSHIP,
            srs.socket.inet_aton(srs.MULTICAST_GROUP) + srs.socket.inet_aton(self.adapter.ipv4_text),
        )
        self.sock.setblocking.assert_called_once_with(False)

    def test_refreshes_adapter_when_idle_and_propagates_changed_state(self):
        changed = srs.AdapterStateChanged(None)
        with mock.patch.object(srs.socket, "socket", return_value=self.sock), \
                mock.patch.object(srs, "_make_wsarecvmsg", return_value=(object(), object())), \
                mock.patch.object(srs.select, "select", side_effect=[([], [], []), ([self.sock], [], [])]), \
                mock.patch.object(srs, "_receive_packet_info", return_value=("192.0.2.3", srs.MULTICAST_GROUP, 12)), \
                mock.patch.object(srs, "_refresh_selected_adapter", side_effect=[self.adapter, changed]), \
                mock.patch.object(srs.time, "monotonic", return_value=1.0), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(srs.AdapterStateChanged) as raised:
                srs.receive_multicast_source(self.adapter)
        self.assertIs(raised.exception, changed)
        self.sock.__exit__.assert_called_once()


class RouteReconcileTests(unittest.TestCase):
    def run_reconcile(self, result):
        with mock.patch.object(srs, "_get_windows_directory", return_value=r"C:\Windows"), \
                mock.patch.object(srs.subprocess, "run", return_value=result) as run:
            srs.run_route_reconcile("192.0.2.1", 12)
        return run

    def test_builds_encoded_command_without_running_powershell(self):
        run = self.run_reconcile(srs.subprocess.CompletedProcess([], 0, "", ""))
        args = run.call_args.args[0]
        self.assertEqual(args[0], srs.os.path.join(
            r"C:\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
        self.assertEqual(args[1:5], ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"])
        self.assertEqual(run.call_args.kwargs, {"check": False, "capture_output": True, "text": True})
        script = base64.b64decode(args[5]).decode("utf-16le")
        for expected in (
            "$managedPrefixes = @('10.10.0.0/24', '10.20.0.0/24')",
            "[string]$_.Protocol -eq 'NetMgmt'",
            "Remove-ManagedRoutes 'ActiveStore'",
            "Remove-ManagedRoutes 'PersistentStore'",
            "route.exe",
            "'10.10.0.0' mask '255.255.255.0' '192.0.2.1' if 12",
            "'10.20.0.0' mask '255.255.255.0' '192.0.2.1' if 12",
            "PersistentStore",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, script)

    def test_failure_reports_stderr_then_stdout_or_exit_status(self):
        errors = (
            (srs.subprocess.CompletedProcess([], 1, "stdout detail", "stderr detail"), "stderr detail"),
            (srs.subprocess.CompletedProcess([], 2, "stdout detail", ""), "stdout detail"),
            (srs.subprocess.CompletedProcess([], 7, "", ""), "exit code 7"),
        )
        for result, detail in errors:
            with self.subTest(detail=detail):
                with mock.patch.object(srs, "_get_windows_directory", return_value=r"C:\Windows"), \
                        mock.patch.object(srs.subprocess, "run", return_value=result):
                    with self.assertRaises(RuntimeError) as raised:
                        srs.run_route_reconcile("192.0.2.1", 12)
                    self.assertTrue(str(raised.exception).startswith("Persistent route reconciliation failed"))
                    self.assertIn(detail, str(raised.exception))

    def test_process_start_failure_has_clear_context_without_execution(self):
        with mock.patch.object(srs, "_get_windows_directory", return_value=r"C:\Windows"), \
                mock.patch.object(srs.subprocess, "run", side_effect=FileNotFoundError("missing powershell")):
            with self.assertRaisesRegex(RuntimeError, "Failed to start system PowerShell:.*missing powershell"):
                srs.run_route_reconcile("192.0.2.1", 12)


if __name__ == "__main__":
    unittest.main()
