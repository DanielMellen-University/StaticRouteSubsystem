import contextlib
import io
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


if __name__ == "__main__":
    unittest.main()
