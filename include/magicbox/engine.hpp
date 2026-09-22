#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace magicbox {
enum class Protocol { other, tcp, udp, icmp };
enum class Application { unknown, http, dns, tls };

// Owns metadata only. Never retain pointers into a capture library's packet buffer.
struct PacketMetadata {
    std::chrono::system_clock::time_point timestamp;
    std::uint32_t wire_bytes{};
    std::string source_ip;
    std::string destination_ip;
    std::optional<std::uint16_t> source_port;
    std::optional<std::uint16_t> destination_port;
    Protocol protocol{Protocol::other};
    Application application{Application::unknown};
};

class CaptureSource {
public:
    virtual ~CaptureSource() = default;
    // Called only by the capture worker. Must observe stop within a bounded time
    // (e.g. poll a selectable pcap fd with a <=100ms timeout). nullopt = idle.
    // Parse borrowed packet bytes synchronously, then return owned metadata.
    virtual std::optional<PacketMetadata> next(std::stop_token stop) = 0;
    virtual std::optional<std::uint64_t> kernel_drops() const { return {}; }
};

struct CaptureSnapshot {
    std::uint64_t packets{};
    std::uint64_t wire_bytes{};
    std::uint64_t metadata_dropped{};
    std::optional<std::uint64_t> kernel_dropped;
    std::size_t queued{};
    bool running{};
    std::string error;
};

class CaptureEngine final {
public:
    explicit CaptureEngine(std::unique_ptr<CaptureSource> source, std::size_t capacity = 4096);
    ~CaptureEngine();
    CaptureEngine(const CaptureEngine&) = delete;
    CaptureEngine& operator=(const CaptureEngine&) = delete;
    // Lifecycle calls are serialized by the daemon control thread. One start only.
    void start();
    void stop() noexcept;
    [[nodiscard]] CaptureSnapshot snapshot() const;
    [[nodiscard]] std::vector<PacketMetadata> drain(std::size_t limit);

private:
    void run(std::stop_token stop) noexcept;
    std::unique_ptr<CaptureSource> source_;
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::deque<PacketMetadata> queue_;
    CaptureSnapshot counters_;
    bool started_{false};
    // Last member: joined before source, queue, or synchronization primitives die.
    std::jthread worker_;
};
} // namespace magicbox
