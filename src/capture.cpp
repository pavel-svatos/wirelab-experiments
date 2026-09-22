#include "magicbox/appliance.hpp"
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <poll.h>
#include <cstring>
#include <stdexcept>

namespace magicbox {
PacketMetadata dissect(std::span<const unsigned char> b, std::uint32_t size,
                       std::chrono::system_clock::time_point timestamp) {
    PacketMetadata p{};
    p.timestamp = timestamp; p.wire_bytes = size;
    auto u16 = [&](std::size_t i) { return static_cast<std::uint16_t>((b[i] << 8) | b[i + 1]); };
    if (b.size() < 14) return p;
    std::size_t offset = 14;
    auto type = u16(12);
    for (int depth = 0; (type == 0x8100 || type == 0x88a8) && depth < 2; ++depth) {
        if (b.size() < offset + 4) return p;
        type = u16(offset + 2); offset += 4;
    }
    unsigned protocol = 0;
    std::size_t end = b.size();
    bool complete = true;
    char source[INET6_ADDRSTRLEN]{}, destination[INET6_ADDRSTRLEN]{};
    if (type == 0x0800) {
        if (b.size() < offset + 20 || (b[offset] >> 4) != 4) return p;
        const auto header = static_cast<std::size_t>((b[offset] & 15) * 4);
        const auto total = u16(offset + 2);
        if (header < 20 || total < header || b.size() < offset + header) return p;
        end = std::min(b.size(), offset + total);
        complete = b.size() >= offset + total;
        inet_ntop(AF_INET, b.data() + offset + 12, source, sizeof(source));
        inet_ntop(AF_INET, b.data() + offset + 16, destination, sizeof(destination));
        p.source_ip = source; p.destination_ip = destination;
        protocol = b[offset + 9];
        // Neither initial nor later fragments are dissected without reassembly.
        if ((u16(offset + 6) & 0x3fff) != 0) return p;
        offset += header;
    } else if (type == 0x86dd) {
        if (b.size() < offset + 40 || (b[offset] >> 4) != 6) return p;
        end = std::min(b.size(), offset + 40 + u16(offset + 4));
        complete = b.size() >= offset + 40 + u16(offset + 4);
        inet_ntop(AF_INET6, b.data() + offset + 8, source, sizeof(source));
        inet_ntop(AF_INET6, b.data() + offset + 24, destination, sizeof(destination));
        p.source_ip = source; p.destination_ip = destination;
        protocol = b[offset + 6]; offset += 40;
        // IPv6 extension chains are deliberately unclassified, never guessed.
    } else return p;
    std::size_t payload = end;
    if (protocol == 6) {
        p.protocol = Protocol::tcp;
        if (end < offset + 20) return p;
        const auto header = static_cast<std::size_t>((b[offset + 12] >> 4) * 4);
        if (header < 20 || end < offset + header) return p;
        payload = offset + header;
    } else if (protocol == 17) {
        p.protocol = Protocol::udp;
        if (end < offset + 8 || u16(offset + 4) < 8) return p;
        complete = complete && offset + u16(offset + 4) <= end;
        end = std::min(end, offset + u16(offset + 4)); payload = offset + 8;
    } else {
        if (protocol == 1 || protocol == 58) p.protocol = Protocol::icmp;
        return p;
    }
    p.source_port = u16(offset); p.destination_port = u16(offset + 2);
    if (!complete) return p;
    const std::string_view content(reinterpret_cast<const char*>(b.data() + payload), end - payload);
    if (p.protocol == Protocol::tcp) {
        for (auto prefix : {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "HTTP/1."})
            if (content.starts_with(prefix)) p.application = Application::http;
        if (content.size() >= 6 && b[payload] == 22 && b[payload + 1] == 3 &&
            b[payload + 2] <= 4 && (b[payload + 5] == 1 || b[payload + 5] == 2))
            p.application = Application::tls;
    } else if ((*p.source_port == 53 || *p.destination_port == 53) && content.size() >= 12 &&
               (b[payload + 2] & 0x78) == 0 && u16(payload + 4) > 0) {
        p.application = Application::dns;
    }
    return p;
}
namespace {
class PcapSource final : public CaptureSource {
public:
    explicit PcapSource(const std::string& name) {
        char error[PCAP_ERRBUF_SIZE]{};
        handle_.reset(pcap_create(name.c_str(), error));
        if (!handle_) throw std::runtime_error(error);
        if (pcap_set_snaplen(handle_.get(), 65535) != 0 || pcap_set_promisc(handle_.get(), 1) != 0 ||
            pcap_set_timeout(handle_.get(), 50) != 0 || pcap_set_buffer_size(handle_.get(), 4 * 1024 * 1024) != 0)
            throw std::runtime_error("Cannot configure capture");
        if (pcap_activate(handle_.get()) < 0) throw std::runtime_error(pcap_geterr(handle_.get()));
        if (pcap_datalink(handle_.get()) != DLT_EN10MB) throw std::runtime_error("Capture requires an Ethernet interface");
        if (pcap_setnonblock(handle_.get(), 1, error) != 0) throw std::runtime_error(error);
    }
    std::optional<PacketMetadata> next(std::stop_token stop) override {
        if (stop.stop_requested()) return {};
        const auto now = std::chrono::steady_clock::now();
        if (now - last_stats_ >= std::chrono::seconds(1)) {
            pcap_stat stats{};
            if (pcap_stats(handle_.get(), &stats) == 0) dropped_ = stats.ps_drop;
            last_stats_ = now;
        }
        pcap_pkthdr* header = nullptr;
        const unsigned char* data = nullptr;
        const int result = pcap_next_ex(handle_.get(), &header, &data);
        if (result == 1) {
            auto timestamp = std::chrono::system_clock::time_point(std::chrono::seconds(header->ts.tv_sec) +
                                                                      std::chrono::microseconds(header->ts.tv_usec));
            return dissect({data, header->caplen}, header->len, timestamp);
        }
        if (result < 0) throw std::runtime_error(pcap_geterr(handle_.get()));
        pollfd fd{pcap_get_selectable_fd(handle_.get()), POLLIN, 0};
        poll(&fd, 1, 50);
        return {};
    }
    std::optional<std::uint64_t> kernel_drops() const override { return dropped_; }
private:
    struct Close { void operator()(pcap_t* p) const { pcap_close(p); } };
    std::unique_ptr<pcap_t, Close> handle_;
    std::optional<std::uint64_t> dropped_;
    std::chrono::steady_clock::time_point last_stats_{};
};
}
std::unique_ptr<CaptureSource> live_capture(const std::string& name) {
    return std::make_unique<PcapSource>(name);
}
} // namespace magicbox
