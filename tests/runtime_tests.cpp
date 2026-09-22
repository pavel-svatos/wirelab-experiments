#include "magicbox/appliance.hpp"
#include <iostream>
#include <stdexcept>

namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void rejects(F function) {
    bool rejected = false;
    try { function(); } catch (const std::exception&) { rejected = true; }
    require(rejected, "Expected rejection");
}
}
int main() {
    try {
        magicbox::NetworkConfig config{"outer", "inner", "10.0.0.5", "10.0.0.1", 24,
            "192.168.50.99", 24, "192.168.50.1", "02:11:22:33:44:55", 100};
        auto json = magicbox::config_json(config);
        require(magicbox::config_from_json(json).vlan_id == 100, "JSON round trip");
        json["extra"] = true; rejects([&] { magicbox::config_from_json(json); });
        rejects([] { magicbox::parse_json("{\"x\":1,\"x\":2}"); });
        config.outer_gateway_ipv4 = "192.168.51.1";
        require(!magicbox::validate(config).empty(), "Off-link gateway accepted");
        config.outer_gateway_ipv4 = "192.168.50.1";
        config.device_ipv4 = "10.0.0.255";
        require(!magicbox::validate(config).empty(), "Broadcast host accepted");

        std::vector<unsigned char> frame(14 + 20 + 8 + 12, 0);
        frame[12] = 8; frame[14] = 0x45; frame[16] = 0; frame[17] = 40;
        frame[23] = 17; frame[26] = 10; frame[29] = 5; frame[30] = 8; frame[33] = 8;
        frame[34] = 0x30; frame[35] = 0x39; frame[37] = 53; frame[39] = 20; frame[47] = 1;
        const auto packet = magicbox::dissect(frame, static_cast<std::uint32_t>(frame.size()), {});
        require(packet.source_ip == "10.0.0.5" && packet.destination_port == 53, "IPv4/UDP parsing");
        require(packet.application == magicbox::Application::dns, "DNS classification");
        auto first_fragment = frame;
        first_fragment[20] = 0x20;
        const auto fragmented = magicbox::dissect(first_fragment, 54, {});
        require(fragmented.source_ip == "10.0.0.5" && !fragmented.source_port &&
                fragmented.application == magicbox::Application::unknown,
                "First IPv4 fragment interpreted as complete transport");
        auto truncated = frame;
        truncated[17] = 48;
        require(magicbox::dissect(truncated, 62, {}).application == magicbox::Application::unknown,
                "Truncated IPv4 datagram classified as DNS");
        auto invalid_udp = frame;
        invalid_udp[39] = 28;
        require(magicbox::dissect(invalid_udp, 54, {}).application == magicbox::Application::unknown,
                "UDP length beyond IP payload classified as DNS");
        std::vector<unsigned char> ipv6(14 + 40, 0);
        ipv6[12] = 0x86; ipv6[13] = 0xdd; ipv6[14] = 0x60;
        ipv6[19] = 20; ipv6[20] = 17;
        ipv6[37] = 1; ipv6[53] = 2;
        ipv6.insert(ipv6.end(), frame.begin() + 34, frame.end());
        const auto packet6 = magicbox::dissect(ipv6, 74, {});
        require(packet6.source_ip == "::1" && packet6.destination_ip == "::2" &&
                packet6.destination_port == 53 && packet6.application == magicbox::Application::dns,
                "IPv6/UDP parsing");
        ipv6[19] = 28;
        const auto truncated6 = magicbox::dissect(ipv6, 82, {});
        require(truncated6.destination_port == 53 && truncated6.application == magicbox::Application::unknown,
                "Truncated IPv6 datagram classified as DNS");
        for (std::size_t size = 0; size < frame.size(); ++size)
            magicbox::dissect(std::span(frame).first(size), static_cast<std::uint32_t>(frame.size()), {});
        frame[20] = 0; frame[21] = 1;
        require(!magicbox::dissect(frame, 54, {}).source_port, "Fragment interpreted as transport");
        frame[21] = 0;
        frame.insert(frame.begin() + 12, {0x81, 0, 0, 100});
        require(magicbox::dissect(frame, 58, {}).destination_port == 53, "VLAN dissection");
        frame.insert(frame.begin() + 12, {0x88, 0xa8, 0, 200});
        require(magicbox::dissect(frame, 62, {}).destination_port == 53, "Double VLAN dissection");
        frame.insert(frame.begin() + 12, {0x81, 0, 0, 50});
        require(!magicbox::dissect(frame, 66, {}).destination_port, "Excess VLAN tags interpreted as IP");

        magicbox::Store store(":memory:");
        store.put("config", json); require(magicbox::json_text(store.get("config")) == magicbox::json_text(json), "SQLite settings round trip");
        store.sample(120, 2, 100, {}); store.sample(121, 3, 200, {});
        const auto rows = store.history(120, 180, 60);
        require(rows.size() == 1 && rows[0]["packets"] == "5" && rows[0]["wire_bytes"] == "300", "SQLite aggregation");
        rejects([&] { store.history(0, 100, 7); });
        Json::Value flow;
        const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        flow["key"] = "test-flow"; flow["first_seen"] = Json::Int64(timestamp);
        flow["timestamp_ms"] = Json::Int64(timestamp); flow["packets"] = Json::Int64(2); flow["bytes"] = Json::Int64(100);
        Json::Value flows(Json::arrayValue); flows.append(flow);
        store.record_flows(flows); store.record_flows(flows);
        const auto connections = store.connections();
        require(connections.size() == 1 && connections[0]["packets"] == "4" && connections[0]["bytes"] == "200", "Persistent flow accumulation");
        require(magicbox::command({"/usr/bin/printf", "%s", "$(literal); no shell"}) == "$(literal); no shell", "Command argument isolation");
        rejects([] { magicbox::command({"/usr/bin/false"}); });
        std::cout << "Runtime tests passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
