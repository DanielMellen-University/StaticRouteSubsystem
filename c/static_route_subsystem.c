#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Crypt32.lib")

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
    char adapter_name[256];
    ULONG if_index;
    ULONG prefix_length;
    int has_ipv4;
    uint32_t ipv4_host;
    char ipv4_text[INET_ADDRSTRLEN];
    WCHAR friendly_name[256];
} AdapterInfo;

static uint32_t prefix_to_mask(ULONG prefix_length) {
    if (prefix_length > 32) {
        return 0;
    }
    if (prefix_length == 0) {
        return 0;
    }
    if (prefix_length == 32) {
        return 0xffffffffu;
    }
    return 0xffffffffu << (32 - prefix_length);
}

static int same_subnet(uint32_t left_ip, uint32_t right_ip, ULONG prefix_length) {
    if (prefix_length > 32) {
        return 0;
    }
    uint32_t mask = prefix_to_mask(prefix_length);
    return (left_ip & mask) == (right_ip & mask);
}

static int get_ipv4_from_unicast(IP_ADAPTER_UNICAST_ADDRESS *unicast, AdapterInfo *info) {
    info->has_ipv4 = 0;
    info->prefix_length = 0;
    info->ipv4_host = 0;
    info->ipv4_text[0] = '\0';

    while (unicast != NULL) {
        SOCKADDR *address = unicast->Address.lpSockaddr;
        if (address != NULL && address->sa_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
            if (ipv4->sin_addr.S_un.S_addr != 0 &&
                unicast->PrefixOrigin == IpPrefixOriginDhcp &&
                unicast->DadState == IpDadStatePreferred &&
                unicast->OnLinkPrefixLength > 0 &&
                unicast->OnLinkPrefixLength <= 32) {
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

    return 1;
}

static int find_first_active_ethernet(AdapterInfo *info);

static int same_adapter_state(const AdapterInfo *left, const AdapterInfo *right) {
    return left->adapter_name[0] != '\0' &&
           right->adapter_name[0] != '\0' &&
           strcmp(left->adapter_name, right->adapter_name) == 0 &&
           left->if_index == right->if_index &&
           left->has_ipv4 == right->has_ipv4 &&
           left->ipv4_host == right->ipv4_host &&
           left->prefix_length == right->prefix_length;
}

static int refresh_selected_adapter(const AdapterInfo *selected, AdapterInfo *current) {
    int status = find_first_active_ethernet(current);
    if (status < 0) {
        return -1;
    }
    if (status == 0) {
        ZeroMemory(current, sizeof(*current));
        return 0;
    }
    return same_adapter_state(selected, current);
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
        if (adapter->AdapterName != NULL) {
            strncpy_s(info->adapter_name, sizeof(info->adapter_name), adapter->AdapterName, _TRUNCATE);
        }
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
    int status;

    printf("Monitoring for an active DHCP-enabled Ethernet adapter with a DHCP IPv4 address.\n");

    for (;;) {
        Sleep(POLL_INTERVAL_MS);

        status = find_first_active_ethernet(current);
        if (status < 0) {
            return 0;
        }
        if (status == 0 || !current->has_ipv4) {
            continue;
        }

        printf("DHCP IPv4 address detected: %s.\n", current->ipv4_text);
        return 1;
    }
}

static int wait_for_dhcp_ipv4_change(const AdapterInfo *previous, AdapterInfo *current) {
    int status;
    int address_was_unavailable = 0;

    printf("Waiting for DHCP IPv4 address or adapter change.\n");

    for (;;) {
        Sleep(POLL_INTERVAL_MS);

        status = find_first_active_ethernet(current);
        if (status < 0) {
            return 0;
        }
        if (status == 0 || !current->has_ipv4) {
            address_was_unavailable = 1;
            continue;
        }
        if (address_was_unavailable || !same_adapter_state(previous, current)) {
            printf("New DHCP IPv4 address detected: %s.\n", current->ipv4_text);
            return 1;
        }
    }
}

static int receive_multicast_source(const AdapterInfo *adapter, AdapterInfo *changed_adapter,
                                   uint32_t *source_ip_host, char *source_ip_text, size_t source_ip_text_size) {
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in bind_address;
    struct ip_mreq membership;
    struct sockaddr_in sender;
    DWORD packet_info_option = 1;
    u_long nonblocking = 1;
    GUID recv_msg_guid = {0xf689d7c8, 0x6f1f, 0x436b, {0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22}};
    LPFN_WSARECVMSG recv_msg = NULL;
    DWORD bytes_returned = 0;
    DWORD received_bytes = 0;
    char buffer[2048];
    int result;
    ULONGLONG last_adapter_check = GetTickCount64();

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "socket failed with error %d.\n", WSAGetLastError());
        return 0;
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

    if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, (const char *)&packet_info_option,
                   sizeof(packet_info_option)) == SOCKET_ERROR) {
        fprintf(stderr, "IP_PKTINFO failed with error %d.\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }
    if (ioctlsocket(sock, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        fprintf(stderr, "ioctlsocket failed with error %d.\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    if (WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &recv_msg_guid, sizeof(recv_msg_guid),
                 &recv_msg, sizeof(recv_msg), &bytes_returned, NULL, NULL) == SOCKET_ERROR) {
        fprintf(stderr, "WSAIoctl for WSARecvMsg failed with error %d.\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    printf("Listening on multicast group %s UDP port %d.\n", MULTICAST_GROUP, UDP_PORT);

    for (;;) {
        fd_set read_set;
        struct timeval timeout;
        int sender_len = sizeof(sender);
        WSABUF data_buffer;
        WSAMSG message;
        IN_PKTINFO *packet_info = NULL;
        WSACMSGHDR *control_header;
        union {
            WSACMSGHDR alignment;
            char data[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))];
        } control_buffer;

        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);
        timeout.tv_sec = POLL_INTERVAL_MS / 1000;
        timeout.tv_usec = (POLL_INTERVAL_MS % 1000) * 1000;
        result = select(0, &read_set, NULL, NULL, &timeout);
        if (result == SOCKET_ERROR) {
            fprintf(stderr, "select failed with error %d.\n", WSAGetLastError());
            closesocket(sock);
            return 0;
        }
        if (result == 0) {
            int adapter_status = refresh_selected_adapter(adapter, changed_adapter);
            last_adapter_check = GetTickCount64();
            if (adapter_status < 0) {
                closesocket(sock);
                return 0;
            }
            if (adapter_status == 0) {
                closesocket(sock);
                return 2;
            }
            continue;
        }

        ZeroMemory(&sender, sizeof(sender));
        ZeroMemory(&message, sizeof(message));
        ZeroMemory(&control_buffer, sizeof(control_buffer));
        data_buffer.buf = buffer;
        data_buffer.len = sizeof(buffer);
        message.name = (LPSOCKADDR)&sender;
        message.namelen = sender_len;
        message.lpBuffers = &data_buffer;
        message.dwBufferCount = 1;
        message.Control.buf = control_buffer.data;
        message.Control.len = sizeof(control_buffer.data);

        if (recv_msg(sock, &message, &received_bytes, NULL, NULL) == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                continue;
            }
            fprintf(stderr, "WSARecvMsg failed with error %d.\n", error);
            closesocket(sock);
            return 0;
        }

        if (GetTickCount64() - last_adapter_check >= POLL_INTERVAL_MS) {
            int adapter_status = refresh_selected_adapter(adapter, changed_adapter);
            last_adapter_check = GetTickCount64();
            if (adapter_status < 0) {
                closesocket(sock);
                return 0;
            }
            if (adapter_status == 0) {
                closesocket(sock);
                return 2;
            }
        }

        for (control_header = WSA_CMSG_FIRSTHDR(&message); control_header != NULL;
             control_header = WSA_CMSG_NXTHDR(&message, control_header)) {
            if (control_header->cmsg_level == IPPROTO_IP && control_header->cmsg_type == IP_PKTINFO &&
                control_header->cmsg_len >= WSA_CMSG_LEN(sizeof(IN_PKTINFO))) {
                packet_info = (IN_PKTINFO *)WSA_CMSG_DATA(control_header);
                break;
            }
        }
        if (packet_info == NULL || packet_info->ipi_ifindex != adapter->if_index ||
            packet_info->ipi_addr.S_un.S_addr != membership.imr_multiaddr.S_un.S_addr) {
            continue;
        }

        {
            int adapter_status = refresh_selected_adapter(adapter, changed_adapter);
            last_adapter_check = GetTickCount64();
            if (adapter_status < 0) {
                closesocket(sock);
                return 0;
            }
            if (adapter_status == 0) {
                closesocket(sock);
                return 2;
            }
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
}

static int destination_prefix(const char *destination, const char *mask, char *prefix, size_t prefix_size) {
    IN_ADDR destination_address;
    IN_ADDR mask_address;
    uint32_t mask_host;
    uint32_t destination_host;
    ULONG prefix_length = 0;
    int saw_zero = 0;

    if (InetPtonA(AF_INET, destination, &destination_address) != 1 ||
        InetPtonA(AF_INET, mask, &mask_address) != 1) {
        return 0;
    }

    mask_host = ntohl(mask_address.S_un.S_addr);
    destination_host = ntohl(destination_address.S_un.S_addr);
    for (int bit = 31; bit >= 0; --bit) {
        if ((mask_host & (1u << bit)) != 0) {
            if (saw_zero) {
                return 0;
            }
            ++prefix_length;
        } else {
            saw_zero = 1;
        }
    }
    if (prefix_length == 0 || (destination_host & mask_host) != destination_host) {
        return 0;
    }

    return snprintf(prefix, prefix_size, "%s/%lu", destination, prefix_length) > 0;
}

static int is_usable_gateway(const AdapterInfo *adapter, uint32_t source_ip_host) {
    uint32_t first_octet = source_ip_host >> 24;
    uint32_t host_mask;
    uint32_t host_part;

    if (source_ip_host == 0 || source_ip_host == adapter->ipv4_host ||
        first_octet == 0 || first_octet == 127 || first_octet >= 224) {
        return 0;
    }

    if (adapter->prefix_length <= 30) {
        host_mask = ~prefix_to_mask(adapter->prefix_length);
        host_part = source_ip_host & host_mask;
        if (host_part == 0 || host_part == host_mask) {
            return 0;
        }
    }
    return 1;
}

static int run_route_reconcile(const char *gateway, ULONG if_index) {
    char prefix1[INET_ADDRSTRLEN + 4];
    char prefix2[INET_ADDRSTRLEN + 4];
    WCHAR script[4096];
    WCHAR prefix1_w[INET_ADDRSTRLEN + 4];
    WCHAR prefix2_w[INET_ADDRSTRLEN + 4];
    WCHAR destination1_w[INET_ADDRSTRLEN];
    WCHAR mask1_w[INET_ADDRSTRLEN];
    WCHAR destination2_w[INET_ADDRSTRLEN];
    WCHAR mask2_w[INET_ADDRSTRLEN];
    WCHAR gateway_w[INET_ADDRSTRLEN];
    WCHAR windows_directory[32768];
    WCHAR powershell_path[32768];
    WCHAR command[32768];
    WCHAR *encoded_script = NULL;
    DWORD encoded_chars = 0;
    DWORD script_bytes;
    DWORD wait_result;
    DWORD exit_code = 1;
    UINT windows_directory_length;
    STARTUPINFOW startup_info;
    PROCESS_INFORMATION process_info;
    IN_ADDR gateway_address;
    int result;

    if (InetPtonA(AF_INET, gateway, &gateway_address) != 1 ||
        !destination_prefix(DEST1_SUBNET, DEST1_MASK, prefix1, sizeof(prefix1)) ||
        !destination_prefix(DEST2_SUBNET, DEST2_MASK, prefix2, sizeof(prefix2))) {
        fprintf(stderr, "Invalid route destination, mask, or gateway.\n");
        return 0;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, prefix1, -1, prefix1_w,
                            (int)(sizeof(prefix1_w) / sizeof(prefix1_w[0]))) == 0 ||
        MultiByteToWideChar(CP_UTF8, 0, prefix2, -1, prefix2_w,
                            (int)(sizeof(prefix2_w) / sizeof(prefix2_w[0]))) == 0 ||
        MultiByteToWideChar(CP_UTF8, 0, DEST1_SUBNET, -1, destination1_w,
                            (int)(sizeof(destination1_w) / sizeof(destination1_w[0]))) == 0 ||
        MultiByteToWideChar(CP_UTF8, 0, DEST1_MASK, -1, mask1_w,
                            (int)(sizeof(mask1_w) / sizeof(mask1_w[0]))) == 0 ||
        MultiByteToWideChar(CP_UTF8, 0, DEST2_SUBNET, -1, destination2_w,
                            (int)(sizeof(destination2_w) / sizeof(destination2_w[0]))) == 0 ||
        MultiByteToWideChar(CP_UTF8, 0, DEST2_MASK, -1, mask2_w,
                            (int)(sizeof(mask2_w) / sizeof(mask2_w[0]))) == 0 ||
        MultiByteToWideChar(CP_UTF8, 0, gateway, -1, gateway_w,
                            (int)(sizeof(gateway_w) / sizeof(gateway_w[0]))) == 0) {
        fprintf(stderr, "Failed to convert route parameters.\n");
        return 0;
    }

    result = swprintf_s(script, sizeof(script) / sizeof(script[0]),
        L"$ErrorActionPreference = 'Stop'\r\n"
        L"$managedPrefixes = @('%ls','%ls')\r\n"
        L"$routeExe = Join-Path ([Environment]::SystemDirectory) 'route.exe'\r\n"
        L"function Remove-ManagedRoutes([string]$store) {\r\n"
        L"  foreach ($prefix in $managedPrefixes) {\r\n"
        L"    $routes = @(Get-NetRoute -DestinationPrefix $prefix -PolicyStore $store -ErrorAction Stop | Where-Object { [string]$_.Protocol -eq 'NetMgmt' })\r\n"
        L"    foreach ($route in $routes) { $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop }\r\n"
        L"  }\r\n"
        L"}\r\n"
        L"try { Remove-ManagedRoutes 'ActiveStore'; Remove-ManagedRoutes 'PersistentStore' } catch {\r\n"
        L"  [Console]::Error.WriteLine($_.Exception.Message); exit 1\r\n"
        L"}\r\n"
        L"try {\r\n"
        L"  & $routeExe -p add '%ls' mask '%ls' '%ls' if %lu\r\n"
        L"  if ($LASTEXITCODE -ne 0) { throw 'route.exe failed for %ls' }\r\n"
        L"  & $routeExe -p add '%ls' mask '%ls' '%ls' if %lu\r\n"
        L"  if ($LASTEXITCODE -ne 0) { throw 'route.exe failed for %ls' }\r\n"
        L"} catch {\r\n"
        L"  $failure = $_.Exception.Message\r\n"
        L"  foreach ($store in @('ActiveStore','PersistentStore')) { try { Remove-ManagedRoutes $store } catch { } }\r\n"
        L"  [Console]::Error.WriteLine($failure); exit 1\r\n"
        L"}\r\n",
        prefix1_w, prefix2_w,
        destination1_w, mask1_w, gateway_w, if_index, prefix1_w,
        destination2_w, mask2_w, gateway_w, if_index, prefix2_w);
    if (result < 0) {
        fprintf(stderr, "Failed to build route reconciliation script.\n");
        return 0;
    }

    script_bytes = (DWORD)(wcslen(script) * sizeof(WCHAR));
    if (!CryptBinaryToStringW((const BYTE *)script, script_bytes,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encoded_chars)) {
        fprintf(stderr, "Failed to encode route reconciliation script with error %lu.\n", GetLastError());
        return 0;
    }
    encoded_script = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, encoded_chars * sizeof(WCHAR));
    if (encoded_script == NULL ||
        !CryptBinaryToStringW((const BYTE *)script, script_bytes,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded_script, &encoded_chars)) {
        fprintf(stderr, "Failed to encode route reconciliation script.\n");
        if (encoded_script != NULL) {
            HeapFree(GetProcessHeap(), 0, encoded_script);
        }
        return 0;
    }

    windows_directory_length = GetWindowsDirectoryW(windows_directory,
                                                      (UINT)(sizeof(windows_directory) / sizeof(windows_directory[0])));
    if (windows_directory_length == 0 ||
        windows_directory_length >= sizeof(windows_directory) / sizeof(windows_directory[0]) ||
        swprintf_s(powershell_path, sizeof(powershell_path) / sizeof(powershell_path[0]),
                   L"%ls\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", windows_directory) < 0 ||
        swprintf_s(command, sizeof(command) / sizeof(command[0]),
                   L"\"%ls\" -NoLogo -NoProfile -NonInteractive -EncodedCommand %ls",
                   powershell_path, encoded_script) < 0) {
        fprintf(stderr, "Failed to locate or start PowerShell.\n");
        HeapFree(GetProcessHeap(), 0, encoded_script);
        return 0;
    }

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = SW_HIDE;

    if (!CreateProcessW(powershell_path, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup_info, &process_info)) {
        fprintf(stderr, "Failed to start system PowerShell with error %lu.\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, encoded_script);
        return 0;
    }
    HeapFree(GetProcessHeap(), 0, encoded_script);

    wait_result = WaitForSingleObject(process_info.hProcess, INFINITE);
    if (wait_result != WAIT_OBJECT_0 || !GetExitCodeProcess(process_info.hProcess, &exit_code)) {
        fprintf(stderr, "Failed waiting for route reconciliation with error %lu.\n", GetLastError());
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
        return 0;
    }

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    if (exit_code != 0) {
        fprintf(stderr, "Persistent route reconciliation failed with exit code %lu.\n", exit_code);
        return 0;
    }
    return 1;
}

int main(void) {
    WSADATA wsa_data;
    AdapterInfo adapter;
    uint32_t source_ip_host;
    char source_ip_text[INET_ADDRSTRLEN];

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    if (!wait_for_initial_dhcp_ipv4(&adapter)) {
        WSACleanup();
        return 1;
    }

    for (;;) {
        AdapterInfo changed_adapter;
        int receive_status = receive_multicast_source(&adapter, &changed_adapter, &source_ip_host,
                                                      source_ip_text, sizeof(source_ip_text));
        if (receive_status == 0) {
            WSACleanup();
            return 1;
        }
        if (receive_status == 2) {
            adapter = changed_adapter;
            if (!adapter.has_ipv4 && !wait_for_initial_dhcp_ipv4(&adapter)) {
                WSACleanup();
                return 1;
            }
            continue;
        }

        if (!same_subnet(adapter.ipv4_host, source_ip_host, adapter.prefix_length)) {
            printf("The source IP is not on the same subnet as the incoming interface.\n");
            WSACleanup();
            return 1;
        }
        if (!is_usable_gateway(&adapter, source_ip_host)) {
            printf("The source IP is not a usable gateway address.\n");
            WSACleanup();
            return 1;
        }

        if (!run_route_reconcile(source_ip_text, adapter.if_index)) {
            WSACleanup();
            return 1;
        }

        printf("Persistent routes were reconciled successfully.\n");
        if (!wait_for_dhcp_ipv4_change(&adapter, &changed_adapter)) {
            WSACleanup();
            return 1;
        }
        adapter = changed_adapter;
    }
}
