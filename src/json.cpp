#include "magicbox/appliance.hpp"
#include <stdexcept>

namespace magicbox {
Json::Value parse_json(std::string_view input) {
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true;
    builder["failIfExtra"] = true;
    builder["allowComments"] = false;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value result;
    std::string errors;
    if (!reader->parse(input.data(), input.data() + input.size(), &result, &errors))
        throw std::invalid_argument("Invalid JSON: " + errors);
    return result;
}
std::string json_text(const Json::Value& value) {
    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";
    return Json::writeString(writer, value);
}
Json::Value config_json(const NetworkConfig& c) {
    Json::Value v;
    v["outer_interface"] = c.outer_interface; v["inner_interface"] = c.inner_interface;
    v["device_ipv4"] = c.device_ipv4; v["inner_gateway_ipv4"] = c.inner_gateway_ipv4;
    v["inner_prefix"] = c.inner_prefix; v["outer_ipv4"] = c.outer_ipv4;
    v["outer_prefix"] = c.outer_prefix; v["outer_gateway_ipv4"] = c.outer_gateway_ipv4;
    v["outer_mac"] = c.outer_mac;
    v["vlan_id"] = c.vlan_id ? Json::Value(*c.vlan_id) : Json::Value();
    return v;
}
NetworkConfig config_from_json(const Json::Value& v) {
    if (!v.isObject()) throw std::invalid_argument("Configuration must be an object");
    NetworkConfig c;
    const auto shape = config_json(c);
    for (const auto& name : v.getMemberNames())
        if (!shape.isMember(name)) throw std::invalid_argument("Unknown field: " + name);
    auto string = [&](const char* name) {
        if (!v[name].isString()) throw std::invalid_argument(std::string("Expected string: ") + name);
        return v[name].asString();
    };
    c.outer_interface = string("outer_interface"); c.inner_interface = string("inner_interface");
    c.device_ipv4 = string("device_ipv4"); c.inner_gateway_ipv4 = string("inner_gateway_ipv4");
    c.outer_ipv4 = string("outer_ipv4"); c.outer_gateway_ipv4 = string("outer_gateway_ipv4");
    c.outer_mac = string("outer_mac");
    if (!v["inner_prefix"].isUInt() || !v["outer_prefix"].isUInt())
        throw std::invalid_argument("Prefixes must be unsigned integers");
    c.inner_prefix = v["inner_prefix"].asUInt(); c.outer_prefix = v["outer_prefix"].asUInt();
    if (!v.isMember("vlan_id")) throw std::invalid_argument("vlan_id is required (null for untagged)");
    if (!v["vlan_id"].isNull()) {
        if (!v["vlan_id"].isUInt() || v["vlan_id"].asUInt() > 4094)
            throw std::invalid_argument("Invalid VLAN ID");
        c.vlan_id = static_cast<std::uint16_t>(v["vlan_id"].asUInt());
    }
    const auto errors = validate(c);
    if (!errors.empty()) {
        std::string message;
        for (const auto& error : errors) message += error + "; ";
        throw std::invalid_argument(message);
    }
    return c;
}
Json::Value packet_json(const PacketMetadata& p) {
    Json::Value v;
    v["timestamp_ms"] = Json::Int64(std::chrono::duration_cast<std::chrono::milliseconds>(p.timestamp.time_since_epoch()).count());
    v["source_ip"] = p.source_ip; v["destination_ip"] = p.destination_ip;
    v["source_port"] = p.source_port ? Json::Value(*p.source_port) : Json::Value();
    v["destination_port"] = p.destination_port ? Json::Value(*p.destination_port) : Json::Value();
    v["wire_bytes"] = p.wire_bytes;
    const char* protocols[]{"other", "tcp", "udp", "icmp"};
    const char* applications[]{"unknown", "http", "dns", "tls"};
    v["protocol"] = protocols[static_cast<unsigned>(p.protocol)];
    v["application"] = applications[static_cast<unsigned>(p.application)];
    return v;
}
} // namespace magicbox
