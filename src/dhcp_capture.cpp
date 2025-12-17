// dhcp_capture.cpp

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <vector>
#include <map>
#include <string>

using namespace std;

static const int ETHERNET_HEADER_LEN = 14;
static const int DHCP_SERVER_PORT = 67;
static const int DHCP_CLIENT_PORT = 68;

// DHCP option numbers
enum {
    DHO_PAD = 0,
    DHO_SUBNET_MASK = 1,
    DHO_ROUTER = 3,
    DHO_DNS = 6,
    DHO_REQUESTED_IP = 50,
    DHO_LEASE_TIME = 51,
    DHO_MSG_TYPE = 53,
    DHO_SERVER_ID = 54,
    DHO_PARAM_REQ = 55,
    DHO_END = 255
};

string mac_to_str(const u_char *mac) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << setw(2) << (int)mac[i];
        if (i != 5) ss << ":";
    }
    return ss.str();
}

string now_iso() {
    time_t t = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", localtime(&t));
    return string(buf);
}

int get_dhcp_message_type(const u_char* options, int len) {
    int i = 0;
    while (i < len) {
        uint8_t opt = options[i];
        if (opt == DHO_END) break;
        if (opt == DHO_PAD) { i += 1; continue; }
        if (i + 1 >= len) break;
        uint8_t optlen = options[i+1];
        if (opt == DHO_MSG_TYPE && optlen >= 1) {
            if (i+2 < len) return options[i+2];
            else return -1;
        }
        i += 2 + optlen;
    }
    return -1;
}

string ip_to_str(const uint8_t *addr) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, buf, INET_ADDRSTRLEN);
    return string(buf);
}

void write_json_event(const string& outfile, const map<string,string>& m) {
    ofstream ofs(outfile, ios::app);
    if (!ofs) {
        cerr << "Cannot open " << outfile << " for append\n";
        return;
    }
    ofs << "{";
    bool first = true;
    for (auto &kv : m) {
        if (!first) ofs << ",";
        first = false;
        ofs << "\"" << kv.first << "\":";
        string v = kv.second;
        string esc;
        for (char c : v) {
            if (c == '"' ) esc += "\\\"";
            else if (c == '\\') esc += "\\\\";
            else esc += c;
        }
        ofs << "\"" << esc << "\"";
    }
    ofs << "}\n";
    ofs.close();
}

// Parse DHCP options and extract hostname (option 12 / 81)
string get_dhcp_hostname(const u_char* options, int len) {
    int i = 0;

    while (i < len) {
        uint8_t opt = options[i];

        // End option: stop parsing
        if (opt == 255) {
            break;
        }

        // Pad option: just skip 1 byte
        if (opt == 0) {
            i += 1;
            continue;
        }

        // Safety: ensure length byte exists
        if (i + 1 >= len) break;

        uint8_t opt_len = options[i + 1];

        // Safety: ensure value fits inside buffer
        if (i + 2 + opt_len > len) break;

        // Option 12 = Host Name
        // Option 81 = FQDN (we treat it as hostname for UI)
        if (opt == 12 || opt == 81) {
            return string((const char*)(options + i + 2), opt_len);
        }

        // Move to next option
        i += 2 + opt_len;
    }

    return "";
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    const string outfile = *((string*)user);

    if (h->caplen < ETHERNET_HEADER_LEN + sizeof(struct ip) + sizeof(struct udphdr)) return;

    const u_char *ip_packet = bytes + ETHERNET_HEADER_LEN;
    struct ip *ip = (struct ip*)ip_packet;
    if (ip->ip_p != IPPROTO_UDP) return;

    int ip_header_len = ip->ip_hl * 4;
    const u_char *udp_packet = ip_packet + ip_header_len;
    struct udphdr *udp = (struct udphdr*)udp_packet;
    uint16_t sport = ntohs(udp->uh_sport);
    uint16_t dport = ntohs(udp->uh_dport);

    if (!((sport == DHCP_SERVER_PORT || sport == DHCP_CLIENT_PORT) ||
          (dport == DHCP_SERVER_PORT || dport == DHCP_CLIENT_PORT))) return;

    const u_char *dhcp = udp_packet + sizeof(struct udphdr);
    if ((size_t)(h->caplen - (dhcp - bytes)) < 240) return;

    uint32_t xid = ntohl(*(uint32_t*)(dhcp + 4));
    const u_char *ciaddr = dhcp + 12;
    const u_char *yiaddr = dhcp + 16;
    const u_char *siaddr = dhcp + 20;
    const u_char *giaddr = dhcp + 24;
    const u_char *chaddr = dhcp + 28;
    string client_mac = mac_to_str(chaddr);

    const u_char *options = dhcp + 236;
    if (options[0] == 99 && options[1] == 130 && options[2] == 83 && options[3] == 99) {
        options += 4;
    }

    int options_len = h->caplen - (options - bytes);
    int msgtype = get_dhcp_message_type(options, options_len);
    string hostname = get_dhcp_hostname(options, options_len);

    map<string,string> out;
    out["ts"] = now_iso();
    out["xid"] = to_string(xid);
    out["mac"] = client_mac;
    out["ciaddr"] = ip_to_str(ciaddr);
    out["yiaddr"] = ip_to_str(yiaddr);
    out["siaddr"] = ip_to_str(siaddr);
    out["giaddr"] = ip_to_str(giaddr);
    out["sport"] = to_string(sport);
    out["dport"] = to_string(dport);
    if (!hostname.empty()) {
        out["hostname"] = hostname;
    }


    string type_str = "UNKNOWN";
    switch (msgtype) {
        case 1: type_str = "DISCOVER"; break;
        case 2: type_str = "OFFER"; break;
        case 3: type_str = "REQUEST"; break;
        case 4: type_str = "DECLINE"; break;
        case 5: type_str = "ACK"; break;
        case 6: type_str = "NAK"; break;
        case 7: type_str = "RELEASE"; break;
        case 8: type_str = "INFORM"; break;
        default: break;
    }
    out["dhcp_type"] = type_str;

    write_json_event(outfile, out);

    cout << out["ts"] << " | " << client_mac << " | host=" << hostname << " | " << type_str << " | xid=" << xid << " | yi=" << out["yiaddr"] << "\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: sudo " << argv[0] << " <interface> <output-json-lines-file>\n";
        return 1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = argv[1];
    string outfile = argv[2];

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp and (port 67 or port 68)", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "pcap_compile failed\n";
    } else {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    ofstream ofs(outfile, ios::trunc);
    ofs.close();

    string *user = new string(outfile);
    pcap_loop(handle, 0, packet_handler, (u_char*)user);

    pcap_close(handle);
    delete user;
    return 0;
}
