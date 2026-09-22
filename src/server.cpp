#include "magicbox/appliance.hpp"
#include <drogon/drogon.h>
#include <drogon/WebSocketController.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <map>
#include <queue>

namespace magicbox {
namespace {
using Reply = std::function<void(Json::Value, int)>;
bool token_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i) difference |= static_cast<unsigned char>(a[i] ^ b[i]);
    return difference == 0;
}
std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
Json::Value error_json(const std::string& message) { Json::Value j; j["error"] = message; return j; }
class ApplianceRuntime : public std::enable_shared_from_this<ApplianceRuntime> {
public:
    ApplianceRuntime(const Options& options, std::string token)
        : options_(options), token_(std::move(token)), store_(options.database), network_(store_, options.allow_network) {
        auto saved = store_.get("capture_interface");
        if (!options.capture_interface.empty()) start_capture(options.capture_interface);
        else if (saved.isString() && !saved.asString().empty()) {
            try { start_capture(saved.asString()); } catch (const std::exception& e) { capture_error_ = e.what(); }
        }
        worker_ = std::jthread([this](std::stop_token stop) { work(stop); });
    }
    ~ApplianceRuntime() { shutdown(); }
    void shutdown() {
        worker_.request_stop(); wake_.notify_all();
        if (worker_.joinable()) worker_.join();
    }
    bool authorized(std::string_view token) const { return token_equal(token_, token); }
    void submit(std::function<Json::Value()> task, Reply reply) {
        std::lock_guard lock(mutex_);
        if (tasks_.size() >= 64) { reply(error_json("Control queue full"), 429); return; }
        tasks_.push([task = std::move(task), reply = std::move(reply)] {
            try { reply(task(), 200); }
            catch (const std::invalid_argument& e) { reply(error_json(e.what()), 422); }
            catch (const std::exception& e) { reply(error_json(e.what()), 409); }
        });
        wake_.notify_one();
    }
    Json::Value request(const drogon::HttpRequestPtr& request) {
        const auto path = request->path();
        const auto method = request->method();
        if (path == "/api/v1/status" && method == drogon::Get) {
            Json::Value state;
            state["version"] = "0.2.0"; state["network"] = network_.state();
            state["capture_interface"] = capture_interface_; state["capture_error"] = capture_error_;
            state["storage_error"] = storage_error_; state["metrics"] = snapshot();
            return state;
        }
        if (path == "/api/v1/interfaces" && method == drogon::Get) return network_.interfaces();
        if (path == "/api/v1/config" && method == drogon::Get) return network_.state();
        if (path == "/api/v1/config/validate" && method == drogon::Post) {
            auto config = config_from_json(parse_json(request->body()));
            Json::Value result; result["valid"] = true; result["config"] = config_json(config); return result;
        }
        if (path == "/api/v1/config" && method == drogon::Put) {
            network_.apply(config_from_json(parse_json(request->body()))); return network_.state();
        }
        if (path == "/api/v1/config/confirm" && method == drogon::Post) { network_.confirm(); return network_.state(); }
        if (path == "/api/v1/config/rollback" && method == drogon::Post) { network_.rollback(); return network_.state(); }
        if (path == "/api/v1/capture" && method == drogon::Put) {
            const auto body = parse_json(request->body());
            if (!body["interface"].isString()) throw std::invalid_argument("interface must be a string");
            start_capture(body["interface"].asString()); return snapshot();
        }
        if (path == "/api/v1/capture" && method == drogon::Delete) {
            if (engine_) { engine_->stop(); sample(true); }
            engine_.reset(); capture_interface_.clear(); store_.put("capture_interface", ""); return snapshot();
        }
        if (path == "/api/v1/metrics" && method == drogon::Get) return snapshot();
        if (path == "/api/v1/packets" && method == drogon::Get) return recent_;
        if (path == "/api/v1/flows" && method == drogon::Get) return store_.connections();
        if (path == "/api/v1/history" && method == drogon::Get) {
            auto number = [&](const char* key, std::int64_t fallback) {
                const auto value = request->getParameter(key);
                if (value.empty()) return fallback;
                std::size_t consumed{}; const auto n = std::stoll(value, &consumed);
                if (consumed != value.size()) throw std::invalid_argument("Invalid query integer");
                return static_cast<std::int64_t>(n);
            };
            const auto interval = number("interval", 60);
            if (interval != 60 && interval != 300 && interval != 3600) throw std::invalid_argument("Invalid interval");
            return store_.history(number("from", now_seconds() - 3600), number("to", now_seconds() + 1), static_cast<int>(interval));
        }
        throw std::invalid_argument("Unknown endpoint or unsupported method");
    }
    Json::Value snapshot() {
        auto value = metrics_;
        value["type"] = "metrics"; value["schema_version"] = 1;
        value["capture_interface"] = capture_interface_;
        value["network"] = network_.state();
        if (engine_) {
            const auto counters = engine_->snapshot();
            value["packets"] = std::to_string(counters.packets); value["wire_bytes"] = std::to_string(counters.wire_bytes);
            value["metadata_dropped"] = std::to_string(counters.metadata_dropped);
            value["kernel_dropped"] = counters.kernel_dropped ? Json::Value(std::to_string(*counters.kernel_dropped)) : Json::Value();
            value["running"] = counters.running; value["capture_error"] = counters.error;
        } else value["running"] = false;
        return value;
    }
private:
    void start_capture(const std::string& name) {
        if (name.empty() || name.size() > 15 || name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != std::string::npos)
            throw std::invalid_argument("Invalid capture interface");
        auto next = std::make_unique<CaptureEngine>(live_capture(name), 8192);
        if (engine_) { engine_->stop(); sample(true); }
        next->start();
        store_.put("capture_interface", name);
        engine_ = std::move(next); capture_interface_ = name; capture_error_.clear();
        previous_packets_ = 0; previous_bytes_ = 0;
        protocols_.clear(); talkers_.clear(); flows_.clear(); recent_ = Json::Value(Json::arrayValue);
        metrics_ = Json::Value(Json::objectValue); talkers_omitted_ = 0; flows_omitted_ = 0;
        last_sample_ = std::chrono::steady_clock::now();
    }
    void sample(bool force = false) {
        if (!engine_) return;
        const auto packets = engine_->drain(8192);
        for (const auto& packet : packets) {
            const auto json = packet_json(packet);
            if (!packet.source_ip.empty()) {
                const auto key = capture_interface_ + "|" + packet.source_ip + "|" + packet.destination_ip + "|" +
                    json["protocol"].asString() + "|" + json["source_port"].asString() + "|" + json["destination_port"].asString();
                if (flows_.contains(key) || flows_.size() < 4096) {
                    auto& flow = flows_[key];
                    const auto count = flow.get("packets", Json::Int64(0)).asInt64();
                    const auto bytes = flow.get("bytes", Json::Int64(0)).asInt64();
                    const auto first = flow.get("first_seen", json["timestamp_ms"]).asInt64();
                    flow = json; flow["key"] = key; flow["capture_interface"] = capture_interface_;
                    flow["first_seen"] = Json::Int64(first);
                    flow["packets"] = Json::Int64(count + 1); flow["bytes"] = Json::Int64(bytes + packet.wire_bytes);
                } else ++flows_omitted_;
            }
            ++protocols_[json["protocol"].asString()];
            if (!packet.source_ip.empty()) {
                if (talkers_.contains(packet.source_ip) || talkers_.size() < 1024) talkers_[packet.source_ip] += packet.wire_bytes;
                else ++talkers_omitted_;
            }
            recent_.append(json);
        }
        if (recent_.size() > 200) {
            Json::Value tail(Json::arrayValue);
            for (Json::ArrayIndex i = recent_.size() - 200; i < recent_.size(); ++i) tail.append(recent_[i]);
            recent_ = std::move(tail);
        }
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::max(0.000001, std::chrono::duration<double>(now - last_sample_).count());
        if (elapsed < 1 && !force) return;
        const auto counters = engine_->snapshot();
        const auto delta_packets = counters.packets - previous_packets_, delta_bytes = counters.wire_bytes - previous_bytes_;
        metrics_["timestamp"] = Json::Int64(now_seconds());
        metrics_["bits_per_second"] = static_cast<double>(delta_bytes) * 8.0 / elapsed;
        metrics_["packets_per_second"] = static_cast<double>(delta_packets) / elapsed;
        metrics_["elapsed_seconds"] = elapsed;
        metrics_["protocols"] = Json::Value(Json::objectValue);
        for (const auto& [name, count] : protocols_) metrics_["protocols"][name] = std::to_string(count);
        std::vector<std::pair<std::string, std::uint64_t>> sorted(talkers_.begin(), talkers_.end());
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        metrics_["top_talkers"] = Json::Value(Json::arrayValue);
        for (std::size_t i = 0; i < std::min<std::size_t>(10, sorted.size()); ++i) {
            Json::Value talker; talker["ip"] = sorted[i].first; talker["wire_bytes"] = std::to_string(sorted[i].second);
            metrics_["top_talkers"].append(talker);
        }
        metrics_["talkers_omitted"] = std::to_string(talkers_omitted_);
        metrics_["flows_omitted"] = std::to_string(flows_omitted_);
        metrics_["breakdown_complete"] = counters.metadata_dropped == 0 && talkers_omitted_ == 0;
        try {
            store_.sample(now_seconds(), delta_packets, delta_bytes, metrics_);
            Json::Value flows(Json::arrayValue);
            for (const auto& [key, flow] : flows_) { (void)key; flows.append(flow); }
            store_.record_flows(flows);
            storage_error_.clear();
        }
        catch (const std::exception& e) { storage_error_ = e.what(); }
        previous_packets_ = counters.packets; previous_bytes_ = counters.wire_bytes; last_sample_ = now;
        protocols_.clear(); talkers_.clear(); flows_.clear(); talkers_omitted_ = 0; flows_omitted_ = 0;
    }
    void work(std::stop_token stop) {
        while (!stop.stop_requested()) {
            std::function<void()> task;
            {
                std::unique_lock lock(mutex_);
                wake_.wait_for(lock, std::chrono::milliseconds(50), [&] { return !tasks_.empty() || stop.stop_requested(); });
                if (!tasks_.empty()) { task = std::move(tasks_.front()); tasks_.pop(); }
            }
            try { network_.tick(); } catch (const std::exception& e) { std::cerr << "Network recovery: " << e.what() << '\n'; }
            if (task) task();
            try { sample(); } catch (const std::exception& e) { capture_error_ = e.what(); }
        }
        if (engine_) engine_->stop();
        try { sample(true); } catch (...) {}
        try { if (network_.state()["status"] == "awaiting_confirmation") network_.rollback(); }
        catch (const std::exception& e) { std::cerr << "Shutdown rollback: " << e.what() << '\n'; }
        std::queue<std::function<void()>> pending;
        { std::lock_guard lock(mutex_); std::swap(pending, tasks_); }
    }
    Options options_;
    const std::string token_;
    Store store_;
    NetworkController network_;
    std::unique_ptr<CaptureEngine> engine_;
    std::string capture_interface_, capture_error_, storage_error_;
    Json::Value metrics_{Json::objectValue}, recent_{Json::arrayValue};
    std::map<std::string, std::uint64_t> protocols_, talkers_;
    std::map<std::string, Json::Value> flows_;
    std::uint64_t flows_omitted_{};
    std::uint64_t previous_packets_{}, previous_bytes_{}, talkers_omitted_{};
    std::chrono::steady_clock::time_point last_sample_{std::chrono::steady_clock::now()};
    std::mutex mutex_;
    std::condition_variable wake_;
    std::queue<std::function<void()>> tasks_;
    std::jthread worker_;
};
std::weak_ptr<ApplianceRuntime> active;
struct SocketState { std::atomic<bool> busy{false}; std::atomic<std::uint64_t> sequence{0}; };
bool valid_origin(const drogon::HttpRequestPtr& request) {
    const auto origin = request->getHeader("origin");
    return origin.empty() || origin == "http://" + request->getHeader("host") || origin == "https://" + request->getHeader("host");
}
}

class LiveSocket : public drogon::WebSocketController<LiveSocket> {
public:
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/api/v1/live");
    WS_PATH_LIST_END
    void handleNewConnection(const drogon::HttpRequestPtr& request, const drogon::WebSocketConnectionPtr& connection) override {
        if (!valid_origin(request)) { connection->shutdown(drogon::CloseCode::kViolation); return; }
        connection->setContext(std::make_shared<SocketState>());
    }
    void handleNewMessage(const drogon::WebSocketConnectionPtr& connection, std::string&& message,
                          const drogon::WebSocketMessageType& type) override {
        if (type != drogon::WebSocketMessageType::Text) return;
        const auto app = active.lock();
        const auto state = connection->getContext<SocketState>();
        if (!app || !state) return;
        try {
            const auto body = parse_json(message);
            if (!body["token"].isString() || !app->authorized(body["token"].asString())) {
                connection->shutdown(drogon::CloseCode::kViolation, "Unauthorized"); return;
            }
            if (body.get("ack", "0").asString() != std::to_string(state->sequence.load()) || state->busy.exchange(true)) return;
            app->submit([app] { return app->snapshot(); }, [connection, state](Json::Value value, int) {
                value["sequence"] = std::to_string(++state->sequence);
                if (connection->connected()) connection->send(json_text(value));
                state->busy = false;
            });
        } catch (...) { connection->shutdown(drogon::CloseCode::kInvalidMessage); }
    }
    void handleConnectionClosed(const drogon::WebSocketConnectionPtr&) override {}
};

int run_appliance(const Options& options) {
    struct stat info{};
    if (stat(options.token_file.c_str(), &info) != 0 || !S_ISREG(info.st_mode) || (info.st_mode & 0077) != 0)
        throw std::runtime_error("Token file must exist and have mode 0600 (or 0400)");
    std::ifstream input(options.token_file);
    std::string token; std::getline(input, token);
    if (token.size() < 32 || token.size() > 256) throw std::runtime_error("Token must be 32–256 characters");
    const auto lock_path = options.database.string() + ".lock";
    const int fd = open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("Cannot open database lock");
    struct Lock { int fd; ~Lock() { close(fd); } } lock{fd};
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) throw std::runtime_error("Another appliance instance owns this database");
    if (!std::filesystem::is_regular_file(options.web_root / "index.html")) throw std::runtime_error("Missing dashboard; set --web-root");
    auto application = std::make_shared<ApplianceRuntime>(options, token);
    active = application;
    drogon::app().setLogLevel(trantor::Logger::kWarn)
        .setThreadNum(2).setClientMaxBodySize(16384).setClientMaxWebSocketMessageSize(1024)
        .setIdleConnectionTimeout(45).setMaxConnectionNum(64)
        .setDocumentRoot(std::filesystem::absolute(options.web_root).string())
        .addListener(options.listen, options.port);
    drogon::app().registerHandlerViaRegex("/api/v1/.*", [application](const drogon::HttpRequestPtr& req,
                                         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        auto reply = [callback = std::move(callback)](Json::Value value, int status) {
            auto response = drogon::HttpResponse::newHttpJsonResponse(value);
            response->setStatusCode(static_cast<drogon::HttpStatusCode>(status));
            response->addHeader("Cache-Control", "no-store");
            response->addHeader("X-Content-Type-Options", "nosniff");
            callback(response);
        };
        const auto auth = req->getHeader("authorization");
        if (!valid_origin(req) || !auth.starts_with("Bearer ") || !application->authorized(std::string_view(auth).substr(7))) {
            reply(error_json("Unauthorized"), 401); return;
        }
        application->submit([application, req] { return application->request(req); }, std::move(reply));
    }, {drogon::Get, drogon::Post, drogon::Put, drogon::Delete});
    std::cout << "WireLab Experiments listening on " << options.listen << ':' << options.port << '\n';
    drogon::app().run();
    active.reset();
    application->shutdown();
    return 0;
}
} // namespace magicbox
