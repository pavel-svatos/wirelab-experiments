#include "magicbox/appliance.hpp"
#include <libmnl/libmnl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/fib_rules.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>

namespace magicbox {
namespace {
constexpr unsigned table_id = 4242;
constexpr unsigned rule_priority = 10424;
std::string read_file(const std::string& path) {
    std::ifstream in(path);
    std::string value;
    if (!(in >> value)) throw std::runtime_error("Cannot read " + path);
    return value;
}
void write_file(const std::string& path, const std::string& value) {
    std::ofstream out(path);
    out << value;
    out.flush();
    if (!out) throw std::runtime_error("Cannot write " + path);
}
unsigned index_of(const std::string& name) {
    const auto index = if_nametoindex(name.c_str());
    if (!index) throw std::runtime_error("Missing interface " + name);
    return index;
}
std::uint32_t ipv4(const std::string& value) {
    in_addr address{};
    if (inet_pton(AF_INET, value.c_str(), &address) != 1) throw std::invalid_argument("Invalid IPv4");
    return address.s_addr;
}
template<class Header, class Fill>
void netlink(unsigned short type, unsigned short flags, Fill fill, bool missing_ok = false, int protocol = NETLINK_ROUTE) {
    struct Close { void operator()(mnl_socket* socket) const { mnl_socket_close(socket); } };
    std::unique_ptr<mnl_socket, Close> socket(mnl_socket_open(protocol));
    if (!socket || mnl_socket_bind(socket.get(), 0, MNL_SOCKET_AUTOPID) < 0) throw std::runtime_error("Cannot open Netlink socket");
    timeval timeout{3, 0};
    setsockopt(mnl_socket_get_fd(socket.get()), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    alignas(nlmsghdr) std::array<char, 8192> buffer{};
    auto* message = mnl_nlmsg_put_header(buffer.data());
    message->nlmsg_type = type;
    message->nlmsg_flags = static_cast<unsigned short>(NLM_F_REQUEST | NLM_F_ACK | flags);
    message->nlmsg_seq = 1;
    auto* header = static_cast<Header*>(mnl_nlmsg_put_extra_header(message, sizeof(Header)));
    fill(message, header);
    if (mnl_socket_sendto(socket.get(), message, message->nlmsg_len) < 0) throw std::runtime_error("Netlink send failed");
    const int bytes = static_cast<int>(mnl_socket_recvfrom(socket.get(), buffer.data(), buffer.size()));
    if (bytes < 0) throw std::runtime_error("Netlink acknowledgement timed out");
    if (mnl_cb_run(buffer.data(), static_cast<std::size_t>(bytes), 1, mnl_socket_get_portid(socket.get()), nullptr, nullptr) < 0) {
        if (missing_ok && (errno == ENOENT || errno == ESRCH || errno == ENODEV || errno == EADDRNOTAVAIL)) return;
        throw std::runtime_error(std::string("Netlink: ") + strerror(errno));
    }
}
void link_state(const std::string& name, bool up, const std::string& mac = {}) {
    netlink<ifinfomsg>(RTM_NEWLINK, 0, [&](auto* msg, auto* h) {
        h->ifi_family = AF_UNSPEC; h->ifi_index = static_cast<int>(index_of(name));
        h->ifi_change = IFF_UP; h->ifi_flags = up ? IFF_UP : 0;
        if (!mac.empty()) {
            std::array<unsigned char, 6> bytes{};
            for (std::size_t i = 0; i < 6; ++i) bytes[i] = static_cast<unsigned char>(std::stoul(mac.substr(i * 3, 2), nullptr, 16));
            mnl_attr_put(msg, IFLA_ADDRESS, bytes.size(), bytes.data());
        }
    });
}
void vlan(const NetworkConfig& c, bool add) {
    const std::string name = "mbx-outer";
    if (!add && !if_nametoindex(name.c_str())) return;
    netlink<ifinfomsg>(add ? RTM_NEWLINK : RTM_DELLINK, add ? NLM_F_CREATE | NLM_F_EXCL : 0, [&](auto* msg, auto* h) {
        h->ifi_family = AF_UNSPEC;
        if (!add) { h->ifi_index = static_cast<int>(index_of(name)); return; }
        mnl_attr_put_u32(msg, IFLA_LINK, index_of(c.outer_interface));
        mnl_attr_put_strz(msg, IFLA_IFNAME, name.c_str());
        auto* info = mnl_attr_nest_start(msg, IFLA_LINKINFO);
        mnl_attr_put_strz(msg, IFLA_INFO_KIND, "vlan");
        auto* data = mnl_attr_nest_start(msg, IFLA_INFO_DATA);
        mnl_attr_put_u16(msg, IFLA_VLAN_ID, *c.vlan_id);
        mnl_attr_nest_end(msg, data); mnl_attr_nest_end(msg, info);
    }, !add);
}
void address(const std::string& iface, const std::string& ip, unsigned prefix, bool add) {
    netlink<ifaddrmsg>(add ? RTM_NEWADDR : RTM_DELADDR, add ? NLM_F_CREATE | NLM_F_EXCL : 0, [&](auto* msg, auto* h) {
        h->ifa_family = AF_INET; h->ifa_prefixlen = static_cast<unsigned char>(prefix); h->ifa_index = index_of(iface);
        mnl_attr_put_u32(msg, IFA_LOCAL, ipv4(ip)); mnl_attr_put_u32(msg, IFA_ADDRESS, ipv4(ip));
    }, !add);
}
void route(const NetworkConfig& c, bool gateway, bool add) {
    const auto iface = c.vlan_id ? "mbx-outer" : c.outer_interface;
    netlink<rtmsg>(add ? RTM_NEWROUTE : RTM_DELROUTE, add ? NLM_F_CREATE | NLM_F_EXCL : 0, [&](auto* msg, auto* h) {
        h->rtm_family = AF_INET; h->rtm_table = RT_TABLE_UNSPEC; h->rtm_protocol = RTPROT_STATIC;
        h->rtm_scope = gateway ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK; h->rtm_type = RTN_UNICAST;
        mnl_attr_put_u32(msg, RTA_TABLE, table_id); mnl_attr_put_u32(msg, RTA_OIF, index_of(iface));
        if (gateway) mnl_attr_put_u32(msg, RTA_GATEWAY, ipv4(c.outer_gateway_ipv4));
        else {
            h->rtm_dst_len = static_cast<unsigned char>(c.outer_prefix);
            const auto mask = 0xffffffffU << (32 - c.outer_prefix);
            mnl_attr_put_u32(msg, RTA_DST, htonl(ntohl(ipv4(c.outer_ipv4)) & mask));
        }
    }, !add);
}
void rule(const NetworkConfig& c, bool add) {
    netlink<fib_rule_hdr>(add ? RTM_NEWRULE : RTM_DELRULE, add ? NLM_F_CREATE | NLM_F_EXCL : 0, [&](auto* msg, auto* h) {
        h->family = AF_INET; h->src_len = 32; h->action = FR_ACT_TO_TBL;
        mnl_attr_put_u32(msg, FRA_TABLE, table_id); mnl_attr_put_u32(msg, FRA_PRIORITY, rule_priority);
        mnl_attr_put_u32(msg, FRA_SRC, ipv4(c.device_ipv4));
        mnl_attr_put_strz(msg, FRA_IIFNAME, c.inner_interface.c_str());
    }, !add);
}
void clear_connections() {
    // Delete only connections explicitly marked by our two forwarding rules.
    netlink<nfgenmsg>((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE, 0, [](auto* msg, auto* h) {
        h->nfgen_family = AF_INET; h->version = NFNETLINK_V0;
        mnl_attr_put_u32(msg, CTA_MARK, htonl(0x4d425800));
        mnl_attr_put_u32(msg, CTA_MARK_MASK, htonl(0xffffffff));
    }, false, NETLINK_NETFILTER);
}
std::string guard(const NetworkConfig& c) {
    const auto outer = c.vlan_id ? "mbx-outer" : c.outer_interface;
    return "table inet magicbox { chain forward { type filter hook forward priority -10; policy accept; iifname { \"" +
        c.inner_interface + "\", \"" + outer + "\" } drop; oifname { \"" + c.inner_interface + "\", \"" + outer + "\" } drop; }\n}\n";
}
std::string ruleset(const NetworkConfig& c) {
    const std::string outer = c.vlan_id ? "mbx-outer" : c.outer_interface;
    const auto i = "\"" + c.inner_interface + "\"";
    const auto o = "\"" + outer + "\"";
    return "table ip magicbox {\n"
        "chain prerouting { type nat hook prerouting priority dstnat; policy accept; iifname " + o + " ip daddr " + c.outer_ipv4 + " dnat to " + c.device_ipv4 + "; }\n"
        "chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname " + o + " ip saddr " + c.device_ipv4 + " snat to " + c.outer_ipv4 + "; }\n"
        "}\n"
        "table inet magicbox { chain forward { type filter hook forward priority -10; policy accept;\n"
        "iifname " + i + " oifname " + o + " ip saddr " + c.device_ipv4 + " ct mark set 0x4d425800 accept\n"
        "iifname " + o + " oifname " + i + " ip daddr " + c.device_ipv4 + " ct mark set 0x4d425800 accept\n"
        "iifname { " + i + ", " + o + " } drop\n"
        "oifname { " + i + ", " + o + " } drop\n"
        "}\n}\n";
}
bool table_exists(const std::string& family) {
    const auto tables = parse_json(command({"nft", "-j", "list", "tables"}));
    for (const auto& item : tables["nftables"])
        if (item["table"]["name"] == "magicbox" && item["table"]["family"] == family) return true;
    return false;
}
}

struct NetworkController::Lock {
    int fd{-1};
    ~Lock() { if (fd >= 0) close(fd); }
};
NetworkController::~NetworkController() = default;
NetworkController::NetworkController(Store& store, bool enabled) : store_(store), enabled_(enabled), state_(store.get("network")) {
    if (enabled_) {
        std::filesystem::create_directories("/run/magicbox");
        struct stat ns{};
        if (stat("/proc/self/ns/net", &ns) != 0) throw std::runtime_error("Cannot identify network namespace");
        const auto path = "/run/magicbox/network-" + std::to_string(ns.st_ino) + ".lock";
        lock_ = std::make_unique<Lock>();
        lock_->fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lock_->fd < 0 || flock(lock_->fd, LOCK_EX | LOCK_NB) != 0)
            throw std::runtime_error("Another controller owns this network namespace");
    }
    if (state_.isNull()) state_["status"] = "inactive";
    if (state_["status"] != "inactive" && enabled_) {
        const auto confirmed = state_["status"] == "confirmed";
        const auto desired = state_["config"];
        restore();
        if (confirmed) { apply(config_from_json(desired)); confirm(); }
    }
}
Json::Value NetworkController::interfaces() { return parse_json(command({"ip", "-j", "address", "show"})); }
Json::Value NetworkController::state() const {
    auto state = state_;
    state["enabled"] = enabled_;
    if (state["status"] == "awaiting_confirmation") {
        state["remaining_seconds"] = Json::Int64(std::max<std::int64_t>(0, std::chrono::duration_cast<std::chrono::seconds>(deadline_ - std::chrono::steady_clock::now()).count()));
    }
    return state;
}
void NetworkController::apply(const NetworkConfig& c) {
    if (!enabled_) throw std::runtime_error("Network changes disabled; restart with --allow-network after assigning dedicated unmanaged ports");
    if (state_["status"] != "inactive") throw std::runtime_error("Rollback the current network configuration before applying another");
    const auto validated = config_from_json(config_json(c));
    (void)validated;
    if (table_exists("ip") || table_exists("inet") || if_nametoindex("mbx-outer"))
        throw std::runtime_error("Reserved WireLab Experiments network resources already exist");
    const auto routes = parse_json(command({"ip", "-j", "route", "show", "table", "all"}));
    for (const auto& r : routes) if (r["table"].isUInt() && r["table"].asUInt() == table_id)
        throw std::runtime_error("Routing table 4242 is occupied");
    for (const auto& r : parse_json(command({"ip", "-j", "rule", "show"})))
        if (r["priority"].asUInt() == rule_priority) throw std::runtime_error("Rule priority 10424 is occupied");
    Json::Value baseline(Json::arrayValue);
    for (const auto& name : {c.outer_interface, c.inner_interface}) {
        index_of(name);
        auto info = parse_json(command({"ip", "-j", "address", "show", "dev", name}))[0];
        if (name == "lo" || info.isMember("master") || !info["addr_info"].empty())
            throw std::runtime_error(name + " has addresses or is a bridge/bond member; dedicate unused unmanaged ports first");
        info["disable_ipv6"] = read_file("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6");
        info["rp_filter"] = read_file("/proc/sys/net/ipv4/conf/" + name + "/rp_filter");
        baseline.append(info);
    }
    // Validate nft syntax before mutating links. The complete batch is committed atomically later.
    command({"nft", "-c", "-f", "-"}, ruleset(c));
    state_["config"] = config_json(c); state_["baseline"] = baseline;
    state_["ip_forward"] = read_file("/proc/sys/net/ipv4/ip_forward");
    state_["rp_filter_all"] = read_file("/proc/sys/net/ipv4/conf/all/rp_filter");
    state_["status"] = "applying";
    store_.put("network", state_); // Write-ahead journal, before the first mutation.
    try {
        install(c);
        state_["status"] = "awaiting_confirmation";
        deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        store_.put("network", state_);
    } catch (const std::exception& error) {
        const auto message = std::string(error.what());
        try { restore(); } catch (const std::exception& rollback_error) {
            throw std::runtime_error(message + "; rollback failed: " + rollback_error.what());
        }
        throw std::runtime_error(message);
    }
}
void NetworkController::install(const NetworkConfig& c) {
    for (const auto& name : {c.outer_interface, c.inner_interface}) {
        write_file("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", "1");
        write_file("/proc/sys/net/ipv4/conf/" + name + "/rp_filter", "0");
    }
    link_state(c.outer_interface, false);
    link_state(c.outer_interface, false, c.outer_mac);
    link_state(c.outer_interface, true);
    const std::string outer = c.vlan_id ? "mbx-outer" : c.outer_interface;
    if (c.vlan_id) {
        vlan(c, true);
        write_file("/proc/sys/net/ipv6/conf/mbx-outer/disable_ipv6", "1");
        write_file("/proc/sys/net/ipv4/conf/mbx-outer/rp_filter", "0");
        link_state(outer, true);
    }
    // Forwarding guard is installed before assigning addresses or routes.
    command({"nft", "-f", "-"}, guard(c));
    link_state(c.inner_interface, true);
    address(c.inner_interface, c.inner_gateway_ipv4, c.inner_prefix, true);
    address(outer, c.outer_ipv4, c.outer_prefix, true);
    route(c, false, true); route(c, true, true); rule(c, true);
    write_file("/proc/sys/net/ipv4/ip_forward", "1");
    write_file("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    command({"nft", "-f", "-"}, "delete table inet magicbox\n" + ruleset(c));
}
void NetworkController::restore() {
    const auto c = config_from_json(state_["config"]);
    state_["status"] = "rolling_back"; store_.put("network", state_);
    std::string errors;
    auto attempt = [&](auto action) { try { action(); } catch (const std::exception& e) { errors += std::string(e.what()) + "; "; } };
    attempt([&] {
        command({"nft", "-f", "-"}, (table_exists("inet") ? "delete table inet magicbox\n" : "") + guard(c));
        clear_connections();
    });
    attempt([&] { rule(c, false); });
    const std::string outer = c.vlan_id ? "mbx-outer" : c.outer_interface;
    if (if_nametoindex(outer.c_str())) {
        attempt([&] { route(c, true, false); }); attempt([&] { route(c, false, false); });
        attempt([&] { address(outer, c.outer_ipv4, c.outer_prefix, false); });
    }
    attempt([&] { address(c.inner_interface, c.inner_gateway_ipv4, c.inner_prefix, false); });
    if (c.vlan_id) attempt([&] { vlan(c, false); });
    attempt([&] { if (table_exists("ip")) command({"nft", "delete", "table", "ip", "magicbox"}); });
    attempt([&] { write_file("/proc/sys/net/ipv4/ip_forward", state_["ip_forward"].asString()); });
    attempt([&] { write_file("/proc/sys/net/ipv4/conf/all/rp_filter", state_["rp_filter_all"].asString()); });
    for (const auto& info : state_["baseline"]) attempt([&] {
        const auto name = info["ifname"].asString();
        bool up = false; for (const auto& flag : info["flags"]) if (flag == "UP") up = true;
        link_state(name, false); link_state(name, false, info["address"].asString());
        write_file("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", info["disable_ipv6"].asString());
        write_file("/proc/sys/net/ipv4/conf/" + name + "/rp_filter", info["rp_filter"].asString());
        link_state(name, up);
    });
    // Retain the forwarding guard if any restoration failed. A partial rollback
    // must not accidentally expose a partly configured device to the upstream.
    if (errors.empty()) attempt([&] {
        if (table_exists("inet")) command({"nft", "delete", "table", "inet", "magicbox"});
    });
    state_["status"] = errors.empty() ? "inactive" : "rollback_failed";
    state_["error"] = errors;
    store_.put("network", state_);
    if (!errors.empty()) throw std::runtime_error(errors);
}
void NetworkController::confirm() {
    if (!enabled_) throw std::runtime_error("Network changes disabled");
    tick();
    if (state_["status"] != "awaiting_confirmation") throw std::runtime_error("No pending configuration");
    state_["status"] = "confirmed"; store_.put("network", state_);
}
void NetworkController::rollback() {
    if (!enabled_) throw std::runtime_error("Network changes disabled");
    if (state_["status"] != "inactive") restore();
}
void NetworkController::tick() {
    if (enabled_ && state_["status"] == "awaiting_confirmation" && std::chrono::steady_clock::now() >= deadline_) restore();
}
} // namespace magicbox
