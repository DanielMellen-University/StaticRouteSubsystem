#ifndef SRS_HELPERS_H
#define SRS_HELPERS_H

#include <stdint.h>

static uint32_t srs_prefix_to_mask(unsigned prefix_length) {
    if (prefix_length > 32 || prefix_length == 0) {
        return 0;
    }
    if (prefix_length == 32) {
        return UINT32_C(0xffffffff);
    }
    return UINT32_C(0xffffffff) << (32 - prefix_length);
}

static int srs_same_subnet(uint32_t left_ip, uint32_t right_ip, unsigned prefix_length) {
    if (prefix_length > 32) {
        return 0;
    }
    uint32_t mask = srs_prefix_to_mask(prefix_length);
    return (left_ip & mask) == (right_ip & mask);
}

static int srs_is_usable_gateway(uint32_t adapter_ip, unsigned prefix_length, uint32_t source_ip) {
    uint32_t first_octet = source_ip >> 24;

    if (prefix_length == 0 || prefix_length > 32 || source_ip == 0 || source_ip == adapter_ip ||
        first_octet == 0 || first_octet == 127 || first_octet >= 224) {
        return 0;
    }

    if (prefix_length <= 30) {
        uint32_t host_mask = ~srs_prefix_to_mask(prefix_length);
        uint32_t host_part = source_ip & host_mask;
        if (host_part == 0 || host_part == host_mask) {
            return 0;
        }
    }
    return 1;
}

static int srs_prefix_length_from_mask(uint32_t mask, unsigned *prefix_length) {
    unsigned count = 0;
    int saw_zero = 0;

    if (prefix_length == 0) {
        return 0;
    }
    for (int bit = 31; bit >= 0; --bit) {
        if ((mask & (UINT32_C(1) << bit)) != 0) {
            if (saw_zero) {
                return 0;
            }
            ++count;
        } else {
            saw_zero = 1;
        }
    }
    if (count == 0) {
        return 0;
    }
    *prefix_length = count;
    return 1;
}

static int srs_is_canonical_network(uint32_t network, uint32_t mask) {
    unsigned prefix_length;
    return srs_prefix_length_from_mask(mask, &prefix_length) && (network & mask) == network;
}

#endif
