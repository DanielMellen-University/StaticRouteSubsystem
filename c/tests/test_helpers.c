#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "../srs_helpers.h"

typedef struct PrefixCase {
    unsigned prefix;
    uint32_t expected_mask;
    int valid_subnet_prefix;
} PrefixCase;

static const PrefixCase prefix_cases[] = {
    {0, UINT32_C(0x00000000), 1},
    {1, UINT32_C(0x80000000), 1},
    {24, UINT32_C(0xffffff00), 1},
    {31, UINT32_C(0xfffffffe), 1},
    {32, UINT32_C(0xffffffff), 1},
    {33, UINT32_C(0x00000000), 0}
};

typedef struct GatewayCase {
    uint32_t adapter_ip;
    unsigned prefix;
    uint32_t source_ip;
    int expected;
} GatewayCase;

static const GatewayCase gateway_cases[] = {
    {UINT32_C(0xc0a8010a), 24, UINT32_C(0xc0a80114), 1},
    {UINT32_C(0xc0a8010a), 24, UINT32_C(0xc0a80100), 0},
    {UINT32_C(0xc0a8010a), 24, UINT32_C(0xc0a801ff), 0},
    {UINT32_C(0xc0a8010a), 24, UINT32_C(0xc0a8010a), 0},
    {UINT32_C(0xc0a80110), 31, UINT32_C(0xc0a80111), 1},
    {UINT32_C(0xc0a80110), 32, UINT32_C(0xc0a80111), 1},
    {UINT32_C(0x0a000001), 8, UINT32_C(0x00000001), 0},
    {UINT32_C(0x0a000001), 8, UINT32_C(0x7f000001), 0},
    {UINT32_C(0x0a000001), 8, UINT32_C(0xe0000001), 0},
    {UINT32_C(0x0a000001), 8, UINT32_C(0x0a000002), 1},
    {UINT32_C(0x0a000001), 33, UINT32_C(0x0a000002), 0}
};

int main(void) {
    const uint32_t left = UINT32_C(0xc0a8010a);
    const uint32_t same_24 = UINT32_C(0xc0a801fe);
    const uint32_t other_24 = UINT32_C(0xc0a80201);

    for (size_t i = 0; i < sizeof(prefix_cases) / sizeof(prefix_cases[0]); ++i) {
        assert(srs_prefix_to_mask(prefix_cases[i].prefix) == prefix_cases[i].expected_mask);
        if (prefix_cases[i].valid_subnet_prefix) {
            assert(srs_same_subnet(left, left, prefix_cases[i].prefix));
        } else {
            assert(!srs_same_subnet(left, same_24, prefix_cases[i].prefix));
        }
    }
    assert(srs_same_subnet(left, same_24, 24));
    assert(!srs_same_subnet(left, other_24, 24));
    assert(srs_same_subnet(left, other_24, 16));

    for (size_t i = 0; i < sizeof(gateway_cases) / sizeof(gateway_cases[0]); ++i) {
        assert(srs_is_usable_gateway(gateway_cases[i].adapter_ip, gateway_cases[i].prefix,
                                     gateway_cases[i].source_ip) == gateway_cases[i].expected);
    }

    assert(srs_is_canonical_network(UINT32_C(0x0a000000), UINT32_C(0xff000000)));
    assert(!srs_is_canonical_network(UINT32_C(0x0a000001), UINT32_C(0xff000000)));
    assert(!srs_is_canonical_network(UINT32_C(0x0a000000), UINT32_C(0xff00ff00)));
    assert(!srs_is_canonical_network(UINT32_C(0), UINT32_C(0)));
    return 0;
}
