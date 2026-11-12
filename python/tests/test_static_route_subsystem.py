import unittest

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


if __name__ == "__main__":
    unittest.main()
