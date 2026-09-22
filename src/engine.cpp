#include "magicbox/engine.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace magicbox {
CaptureEngine::CaptureEngine(std::unique_ptr<CaptureSource> source, std::size_t capacity)
    : source_(std::move(source)), capacity_(capacity) {
    if (!source_ || capacity_ == 0) throw std::invalid_argument("Capture requires a source and positive queue capacity");
}
CaptureEngine::~CaptureEngine() { stop(); }

void CaptureEngine::start() {
    if (started_) throw std::logic_error("Capture engine can only be started once");
    std::lock_guard lock(mutex_);
    counters_.running = true;
    try {
        worker_ = std::jthread([this](std::stop_token stop) { run(stop); });
        started_ = true;
    } catch (...) {
        counters_.running = false;
        throw;
    }
}

void CaptureEngine::stop() noexcept {
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
}

void CaptureEngine::run(std::stop_token stop) noexcept {
    try {
        while (!stop.stop_requested()) {
            auto packet = source_->next(stop);
            std::lock_guard lock(mutex_);
            counters_.kernel_dropped = source_->kernel_drops();
            if (!packet) continue;
            ++counters_.packets;
            counters_.wire_bytes += packet->wire_bytes;
            if (queue_.size() == capacity_) ++counters_.metadata_dropped;
            else queue_.push_back(std::move(*packet));
        }
    } catch (const std::exception& error) {
        std::lock_guard lock(mutex_);
        counters_.error = error.what();
    } catch (...) {
        std::lock_guard lock(mutex_);
        counters_.error = "Unknown capture failure";
    }
    std::lock_guard lock(mutex_);
    counters_.running = false;
}

CaptureSnapshot CaptureEngine::snapshot() const {
    std::lock_guard lock(mutex_);
    auto result = counters_;
    result.queued = queue_.size();
    return result;
}

std::vector<PacketMetadata> CaptureEngine::drain(std::size_t limit) {
    std::lock_guard lock(mutex_);
    const auto count = std::min(limit, queue_.size());
    std::vector<PacketMetadata> result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        result.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    return result;
}
} // namespace magicbox
