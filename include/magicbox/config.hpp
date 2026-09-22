#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace magicbox {
struct NetworkConfig {
    std::string outer_interface;
    std::string inner_interface;
    std::string device_ipv4;
    std::string inner_gateway_ipv4;
    unsigned inner_prefix{24};
    std::string outer_ipv4;
    unsigned outer_prefix{24};
    std::string outer_gateway_ipv4;
    std::string outer_mac;
    std::optional<std::uint16_t> vlan_id;
};

// Pure syntax validation; link existence, route conflicts, and address ownership
// must also be checked by the privileged controller before applying a plan.
[[nodiscard]] std::vector<std::string> validate(const NetworkConfig& config);
} // namespace magicbox
