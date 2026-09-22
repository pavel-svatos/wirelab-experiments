#include "magicbox/config.hpp"

#include <arpa/inet.h>
#include <array>
#include <charconv>
#include <string_view>

namespace magicbox {
namespace {
bool valid_interface(std::string_view name) {
    if (name.empty() || name.size() > 15 || name == "." || name == "..") return false;
    for (const unsigned char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return false;
    }
    return true;
}
bool unicast_ipv4(const std::string& value) {
    in_addr address{};
    if (inet_pton(AF_INET, value.c_str(), &address) != 1 || value.find('\0') != std::string::npos) return false;
    const auto host = ntohl(address.s_addr);
    const auto first = host >> 24;
    return first != 0 && first != 127 && first < 224;
}
bool unicast_mac(std::string_view value) {
    if (value.size() != 17) return false;
    std::array<unsigned, 6> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto* start = value.data() + i * 3;
        const auto [end, error] = std::from_chars(start, start + 2, bytes[i], 16);
        if (error != std::errc{} || end != start + 2 || (i < 5 && start[2] != ':')) return false;
    }
    bool nonzero = false;
    for (auto byte : bytes) nonzero = nonzero || byte != 0;
    return nonzero && (bytes.front() & 1U) == 0;
}
} // namespace

std::vector<std::string> validate(const NetworkConfig& c) {
    std::vector<std::string> errors;
    if (!valid_interface(c.outer_interface)) errors.emplace_back("Invalid outer interface name");
    if (!valid_interface(c.inner_interface)) errors.emplace_back("Invalid inner interface name");
    if (c.outer_interface == c.inner_interface) errors.emplace_back("Interfaces must be distinct");
    for (const auto* value : {&c.device_ipv4, &c.inner_gateway_ipv4, &c.outer_ipv4, &c.outer_gateway_ipv4}) {
        if (!unicast_ipv4(*value)) errors.emplace_back("Expected a unicast IPv4 address: " + *value);
    }
    if (c.inner_prefix < 1 || c.inner_prefix > 30 || c.outer_prefix < 1 || c.outer_prefix > 30)
        errors.emplace_back("This initial routed topology supports prefixes 1 through 30");
    if (c.device_ipv4 == c.inner_gateway_ipv4) errors.emplace_back("Device and inner gateway addresses must differ");
    if (c.outer_ipv4 == c.outer_gateway_ipv4) errors.emplace_back("Outer address and gateway must differ");
    if (!unicast_mac(c.outer_mac)) errors.emplace_back("Expected a nonzero unicast MAC address");
    if (c.vlan_id && (*c.vlan_id < 1 || *c.vlan_id > 4094)) errors.emplace_back("VLAN ID must be 1 through 4094, or absent");
    if (errors.empty()) {
        auto host = [](const std::string& text) {
            in_addr address{};
            inet_pton(AF_INET, text.c_str(), &address);
            return ntohl(address.s_addr);
        };
        const auto inner_mask = 0xffffffffU << (32 - c.inner_prefix);
        const auto outer_mask = 0xffffffffU << (32 - c.outer_prefix);
        const auto inner = host(c.inner_gateway_ipv4), device = host(c.device_ipv4);
        const auto outer = host(c.outer_ipv4), gateway = host(c.outer_gateway_ipv4);
        auto usable = [](auto address, auto mask) { return (address & ~mask) != 0 && (address & ~mask) != ~mask; };
        if (!usable(inner, inner_mask) || !usable(device, inner_mask) ||
            !usable(outer, outer_mask) || !usable(gateway, outer_mask)) errors.emplace_back("Network and broadcast addresses are not usable hosts");
        if ((inner & inner_mask) != (device & inner_mask)) errors.emplace_back("Device must be on the inner gateway subnet");
        if ((outer & outer_mask) != (gateway & outer_mask)) errors.emplace_back("Outer gateway must be on the outer subnet");
        const auto common_mask = c.inner_prefix < c.outer_prefix ? inner_mask : outer_mask;
        if ((inner & common_mask) == (outer & common_mask)) errors.emplace_back("Inner and outer subnets must not overlap");
    }
    return errors;
}
} // namespace magicbox
