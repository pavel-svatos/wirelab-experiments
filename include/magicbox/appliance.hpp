#pragma once
#include "magicbox/config.hpp"
#include "magicbox/engine.hpp"
#include <json/json.h>
#include <filesystem>
#include <functional>
#include <span>

namespace magicbox {
Json::Value parse_json(std::string_view input);
std::string json_text(const Json::Value& value);
Json::Value config_json(const NetworkConfig& config);
NetworkConfig config_from_json(const Json::Value& value);
Json::Value packet_json(const PacketMetadata& packet);
PacketMetadata dissect(std::span<const unsigned char> bytes, std::uint32_t wire_bytes,
                       std::chrono::system_clock::time_point timestamp);
std::unique_ptr<CaptureSource> live_capture(const std::string& interface);
// argv is passed directly to execvp; no shell evaluation.
std::string command(const std::vector<std::string>& argv, const std::string& input = {});

class Store {
public:
    explicit Store(const std::filesystem::path& path);
    ~Store();
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
    void put(const std::string& key, const Json::Value& value);
    Json::Value get(const std::string& key);
    void sample(std::int64_t timestamp, std::uint64_t packets, std::uint64_t bytes,
                const Json::Value& details);
    Json::Value history(std::int64_t from, std::int64_t to, int interval);
    void record_flows(const Json::Value& flows);
    Json::Value connections();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// All control methods run on one serialized application worker.
class NetworkController {
public:
    NetworkController(Store& store, bool enabled);
    ~NetworkController();
    Json::Value interfaces();
    Json::Value state() const;
    void apply(const NetworkConfig& config);
    void confirm();
    void rollback();
    void tick();
private:
    struct Lock;
    std::unique_ptr<Lock> lock_;
    void install(const NetworkConfig& config);
    void restore();
    Store& store_;
    bool enabled_;
    Json::Value state_;
    std::chrono::steady_clock::time_point deadline_{};
};

struct Options {
    std::string listen{"127.0.0.1"};
    unsigned short port{8080};
    std::filesystem::path database{"magicbox.sqlite"};
    std::filesystem::path token_file;
    std::filesystem::path web_root{"web"};
    std::string capture_interface;
    bool allow_network{false};
};
int run_appliance(const Options& options);
} // namespace magicbox
