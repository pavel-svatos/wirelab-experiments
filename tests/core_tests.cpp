#include "magicbox/config.hpp"
#include "magicbox/engine.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace std::chrono_literals;
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
class BurstSource final : public magicbox::CaptureSource {
public:
    std::optional<magicbox::PacketMetadata> next(std::stop_token stop) override {
        if (remaining_-- > 0) {
            magicbox::PacketMetadata packet{};
            packet.wire_bytes = 100;
            return packet;
        }
        while (!stop.stop_requested()) std::this_thread::sleep_for(1ms);
        return std::nullopt;
    }
private:
    int remaining_{10};
};
class FailedSource final : public magicbox::CaptureSource {
public:
    std::optional<magicbox::PacketMetadata> next(std::stop_token) override {
        throw std::runtime_error("capture device disconnected");
    }
};
template<class Predicate> void eventually(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!predicate()) {
        require(std::chrono::steady_clock::now() < deadline, "Worker did not make progress");
        std::this_thread::sleep_for(1ms);
    }
}
}

int main() {
    try {
        magicbox::NetworkConfig config{"outer0", "inner0", "10.0.0.5", "10.0.0.1", 24,
                                       "192.168.50.99", 24, "192.168.50.1", "02:11:22:33:44:55", 100};
        require(magicbox::validate(config).empty(), "Valid configuration rejected");
        const auto valid_config = config;
        for (const auto vlan : {1, 4094}) {
            config.vlan_id = static_cast<std::uint16_t>(vlan);
            require(magicbox::validate(config).empty(), "Valid boundary VLAN rejected");
        }
        config.vlan_id = 0;
        require(!magicbox::validate(config).empty(), "VLAN zero accepted");
        config.vlan_id = 4095;
        require(!magicbox::validate(config).empty(), "Reserved VLAN accepted");
        config.vlan_id.reset();
        require(magicbox::validate(config).empty(), "Untagged configuration rejected");
        config.outer_mac = "01:11:22:33:44:55";
        require(!magicbox::validate(config).empty(), "Multicast MAC accepted");
        config.outer_mac = "02:11:22:33:44:55";
        config.outer_ipv4 = "192.168.50.999";
        require(!magicbox::validate(config).empty(), "Malformed address accepted");
        config = valid_config;
        config.inner_interface = config.outer_interface;
        require(!magicbox::validate(config).empty(), "Identical interfaces accepted");
        config = valid_config;
        config.inner_prefix = 33;
        require(!magicbox::validate(config).empty(), "Invalid prefix accepted");

        bool null_source_rejected = false;
        try { magicbox::CaptureEngine invalid(nullptr); }
        catch (const std::invalid_argument&) { null_source_rejected = true; }
        require(null_source_rejected, "Null capture source accepted");
        bool zero_capacity_rejected = false;
        try { magicbox::CaptureEngine invalid(std::make_unique<BurstSource>(), 0); }
        catch (const std::invalid_argument&) { zero_capacity_rejected = true; }
        require(zero_capacity_rejected, "Zero queue capacity accepted");

        magicbox::CaptureEngine engine(std::make_unique<BurstSource>(), 3);
        engine.start();
        eventually([&] { return engine.snapshot().packets == 10; });
        engine.stop();
        engine.stop();
        const auto snapshot = engine.snapshot();
        require(snapshot.wire_bytes == 1000 && snapshot.metadata_dropped == 7 && snapshot.queued == 3,
                "Queue overflow must preserve total traffic counters");
        require(!snapshot.running, "Stopped worker is still running");
        require(engine.drain(2).size() == 2 && engine.drain(9).size() == 1, "Bounded draining failed");
        require(engine.snapshot().queued == 0, "Drain did not empty queue");
        bool restart_rejected = false;
        try { engine.start(); } catch (const std::logic_error&) { restart_rejected = true; }
        require(restart_rejected, "Invalid restart accepted");

        magicbox::CaptureEngine failing(std::make_unique<FailedSource>());
        failing.start();
        eventually([&] { return !failing.snapshot().running; });
        require(failing.snapshot().error == "capture device disconnected", "Capture failure was lost");
        failing.stop();
        std::cout << "All core checks passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
