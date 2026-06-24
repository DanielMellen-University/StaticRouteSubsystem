#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

#ifndef IP_ADAPTER_DHCP_ENABLED
#define IP_ADAPTER_DHCP_ENABLED 0x00000004
#endif

#define MULTICAST_GROUP "239.255.0.1"
#define UDP_PORT 5000
#define DEST1_SUBNET "10.10.0.0"
#define DEST1_MASK "255.255.255.0"
#define DEST2_SUBNET "10.20.0.0"
#define DEST2_MASK "255.255.255.0"

#define POLL_INTERVAL_MS 2000

typedef struct AdapterInfo {
    ULONG if_index;
    ULONG prefix_length;
    int has_ipv4;
    uint32_t ipv4_host;
    char ipv4_text[INET_ADDRSTRLEN];
    WCHAR friendly_name[256];
} AdapterInfo;

static uint32_t prefix_to_mask(ULONG prefix_length) {
    if (prefix_length == 0) {
        return 0;
    }
    if (prefix_length >= 32) {
        return 0xffffffffu;
    }
    return 0xffffffffu << (32 - prefix_length);
}

static int same_subnet(uint32_t left_ip, uint32_t right_ip, ULONG prefix_length) {
    uint32_t mask = prefix_to_mask(prefix_length);
    return (left_ip & mask) == (right_ip & mask);
}

static int get_ipv4_from_unicast(IP_ADAPTER_UNICAST_ADDRESS *unicast, AdapterInfo *info) {
    while (unicast != NULL) {
        SOCKADDR *address = unicast->Address.lpSockaddr;
        if (address != NULL && address->sa_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
            if (ipv4->sin_addr.S_un.S_addr != 0) {
                info->has_ipv4 = 1;
                info->ipv4_host = ntohl(ipv4->sin_addr.S_un.S_addr);
                info->prefix_length = unicast->OnLinkPrefixLength;
                if (InetNtopA(AF_INET, &ipv4->sin_addr, info->ipv4_text, sizeof(info->ipv4_text)) == NULL) {
                    return 0;
                }
                return 1;
            }
        }
        unicast = unicast->Next;
    }

    info->has_ipv4 = 0;
    info->prefix_length = 0;
    info->ipv4_host = 0;
    info->ipv4_text[0] = '\0';
    return 1;
}

static int find_first_active_ethernet(AdapterInfo *info) {
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG family = AF_INET;
    ULONG buffer_size = 15000;
    IP_ADAPTER_ADDRESSES *addresses = NULL;
    ULONG result;

    ZeroMemory(info, sizeof(*info));

    for (;;) {
        addresses = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size);
        if (addresses == NULL) {
            fprintf(stderr, "Failed to allocate adapter buffer.\n");
            return -1;
        }

        result = GetAdaptersAddresses(family, flags, NULL, addresses, &buffer_size);
        if (result != ERROR_BUFFER_OVERFLOW) {
            break;
        }

        HeapFree(GetProcessHeap(), 0, addresses);
        addresses = NULL;
    }

    if (result != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses failed with error %lu.\n", result);
        HeapFree(GetProcessHeap(), 0, addresses);
        return -1;
    }

    for (IP_ADAPTER_ADDRESSES *adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        if (adapter->IfType != IF_TYPE_ETHERNET_CSMACD) {
            continue;
        }
        if (adapter->PhysicalAddressLength == 0) {
            continue;
        }
        if ((adapter->Flags & IP_ADAPTER_DHCP_ENABLED) == 0) {
            continue;
        }

        info->if_index = adapter->IfIndex;
        if (adapter->FriendlyName != NULL) {
            wcsncpy_s(info->friendly_name, sizeof(info->friendly_name) / sizeof(info->friendly_name[0]), adapter->FriendlyName, _TRUNCATE);
        }

        if (!get_ipv4_from_unicast(adapter->FirstUnicastAddress, info)) {
            fprintf(stderr, "Failed to read adapter IPv4 address.\n");
            HeapFree(GetProcessHeap(), 0, addresses);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, addresses);
        return 1;
    }

    HeapFree(GetProcessHeap(), 0, addresses);
    return 0;
}

static int wait_for_initial_dhcp_ipv4(AdapterInfo *current) {
    int status = find_first_active_ethernet(current);

    if (status <= 0) {
        if (status == 0) {
            fprintf(stderr, "No active DHCP-enabled Ethernet adapter was found.\n");
        }
        return 0;
    }

    if (current->has_ipv4) {
        printf("DHCP IPv4 address detected: %s.\n", current->ipv4_text);
        return 1;
    }

    printf("Monitoring adapter IPv4 address. No IPv4 address is currently assigned.\n");

    for (;;) {
        Sleep(POLL_INTERVAL_MS);

        status = find_first_active_ethernet(current);
        if (status < 0) {
            return 0;
        }
        if (status == 0) {
            continue;
        }
        if (!current->has_ipv4) {
            continue;
        }

        printf("DHCP IPv4 address detected: %s.\n", current->ipv4_text);
        return 1;
    }
}

static int wait_for_dhcp_ipv4_change(const AdapterInfo *previous, AdapterInfo *current) {
    int status;

    printf("Waiting for DHCP IPv4 address change.\n");

    for (;;) {
        Sleep(POLL_INTERVAL_MS);

        status = find_first_active_ethernet(current);
        if (status < 0) {
            return 0;
        }
        if (status == 0) {
            continue;
        }
        if (!current->has_ipv4) {
            continue;
        }
        if (current->ipv4_host != previous->ipv4_host) {
            printf("New DHCP IPv4 address detected: %s.\n", current->ipv4_text);
            return 1;
        }
    }
}

static int receive_multicast_source(const AdapterInfo *adapter, uint32_t *source_ip_host, char *source_ip_text, size_t source_ip_text_size) {
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in bind_address;
    struct ip_mreq membership;
    struct sockaddr_in sender;
    int sender_len = sizeof(sender);
    char buffer[2048];
    int received;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "socket failed with error %d.\n", WSAGetLastError());
        return 0;
    }

    {
        BOOL reuse = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
    }

    ZeroMemory(&bind_address, sizeof(bind_address));
    bind_address.sin_family = AF_INET;
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_address.sin_port = htons(UDP_PORT);

    if (bind(sock, (struct sockaddr *)&bind_address, sizeof(bind_address)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed with error %d.\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    if (InetPtonA(AF_INET, MULTICAST_GROUP, &membership.imr_multiaddr) != 1) {
        fprintf(stderr, "Invalid multicast group constant.\n");
        closesocket(sock);
        return 0;
    }
    if (InetPtonA(AF_INET, adapter->ipv4_text, &membership.imr_interface) != 1) {
        fprintf(stderr, "Invalid adapter IPv4 address.\n");
        closesocket(sock);
        return 0;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&membership, sizeof(membership)) == SOCKET_ERROR) {
        fprintf(stderr, "IP_ADD_MEMBERSHIP failed with error %d.\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    printf("Listening on multicast group %s UDP port %d.\n", MULTICAST_GROUP, UDP_PORT);

    received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
    if (received == SOCKET_ERROR) {
        fprintf(stderr, "recvfrom failed with error %d.\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    *source_ip_host = ntohl(sender.sin_addr.S_un.S_addr);
    if (InetNtopA(AF_INET, &sender.sin_addr, source_ip_text, (DWORD)source_ip_text_size) == NULL) {
        fprintf(stderr, "Failed to format packet source IP address.\n");
        closesocket(sock);
        return 0;
    }

    closesocket(sock);
    return 1;
}

static int to_wide(const char *input, WCHAR *output, int output_count) {
    return MultiByteToWideChar(CP_ACP, 0, input, -1, output, output_count) > 0;
}

static int run_route_add(const char *destination, const char *mask, const char *gateway, ULONG if_index) {
    WCHAR destination_w[64];
    WCHAR mask_w[64];
    WCHAR gateway_w[64];
    WCHAR command[512];
    STARTUPINFOW startup_info;
    PROCESS_INFORMATION process_info;
    DWORD exit_code = 1;

    if (!to_wide(destination, destination_w, (int)(sizeof(destination_w) / sizeof(destination_w[0]))) ||
        !to_wide(mask, mask_w, (int)(sizeof(mask_w) / sizeof(mask_w[0]))) ||
        !to_wide(gateway, gateway_w, (int)(sizeof(gateway_w) / sizeof(gateway_w[0])))) {
        fprintf(stderr, "Failed to convert route command arguments.\n");
        return 0;
    }

    if (swprintf_s(command, sizeof(command) / sizeof(command[0]),
                   L"route.exe -p add %ls mask %ls %ls if %lu",
                   destination_w, mask_w, gateway_w, if_index) < 0) {
        fprintf(stderr, "Failed to build route command.\n");
        return 0;
    }

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info)) {
        fprintf(stderr, "Failed to start route.exe with error %lu.\n", GetLastError());
        return 0;
    }

    WaitForSingleObject(process_info.hProcess, INFINITE);
    if (!GetExitCodeProcess(process_info.hProcess, &exit_code)) {
        fprintf(stderr, "Failed to read route.exe exit code with error %lu.\n", GetLastError());
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
        return 0;
    }

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);

    if (exit_code != 0) {
        fprintf(stderr, "route.exe failed for destination %s with exit code %lu.\n", destination, exit_code);
        return 0;
    }

    return 1;
}

int main(void) {
    WSADATA wsa_data;
    AdapterInfo adapter;
    int have_adapter = 0;
    uint32_t source_ip_host;
    char source_ip_text[INET_ADDRSTRLEN];

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    for (;;) {
        AdapterInfo active_adapter;

        if (!have_adapter) {
            if (!wait_for_initial_dhcp_ipv4(&active_adapter)) {
                WSACleanup();
                return 1;
            }
        } else {
            if (!wait_for_dhcp_ipv4_change(&adapter, &active_adapter)) {
                WSACleanup();
                return 1;
            }
        }

        adapter = active_adapter;
        have_adapter = 1;

        if (!receive_multicast_source(&adapter, &source_ip_host, source_ip_text, sizeof(source_ip_text))) {
            WSACleanup();
            return 1;
        }

        if (!same_subnet(adapter.ipv4_host, source_ip_host, adapter.prefix_length)) {
            printf("The source IP is not on the same subnet as the incoming interface.\n");
            WSACleanup();
            return 1;
        }

        if (!run_route_add(DEST1_SUBNET, DEST1_MASK, source_ip_text, adapter.if_index)) {
            WSACleanup();
            return 1;
        }
        if (!run_route_add(DEST2_SUBNET, DEST2_MASK, source_ip_text, adapter.if_index)) {
            WSACleanup();
            return 1;
        }

        printf("Persistent routes were added successfully.\n");
    }
}
