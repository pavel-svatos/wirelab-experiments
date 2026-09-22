#include "magicbox/appliance.hpp"
#include <charconv>
#include <iostream>

int main(int argc, char** argv) {
    try {
        magicbox::Options options;
        for (int i = 1; i < argc; ++i) {
            const std::string_view arg(argv[i]);
            if (arg == "--version") { std::cout << "magicboxd 0.2.0\n"; return 0; }
            if (arg == "--help" || arg == "-h") {
                std::cout << "Usage: magicboxd --token-file PATH [options]\n"
                    "  --listen ADDRESS       HTTP bind address (default 127.0.0.1)\n"
                    "  --port PORT            HTTP port (default 8080)\n"
                    "  --database PATH        SQLite database (default magicbox.sqlite)\n"
                    "  --web-root PATH        Dashboard directory (default web)\n"
                    "  --capture INTERFACE    Start passive Ethernet capture\n"
                    "  --allow-network        Enable confirmed network configuration transactions\n"
                    "  --token-file PATH      Required bearer token file, mode 0600, 32–256 characters\n"
                    "  --version              Print version\n"
                    "Use an SSH tunnel for remote management. Network changes require dedicated unmanaged ports.\n";
                return 0;
            }
            if (arg == "--allow-network") { options.allow_network = true; continue; }
            if (i + 1 >= argc) throw std::invalid_argument("Missing value for " + std::string(arg));
            const std::string value(argv[++i]);
            if (arg == "--listen") options.listen = value;
            else if (arg == "--database") options.database = value;
            else if (arg == "--web-root") options.web_root = value;
            else if (arg == "--capture") options.capture_interface = value;
            else if (arg == "--token-file") options.token_file = value;
            else if (arg == "--port") {
                unsigned port{};
                const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
                if (error != std::errc{} || end != value.data() + value.size() || port < 1 || port > 65535)
                    throw std::invalid_argument("Invalid port");
                options.port = static_cast<unsigned short>(port);
            } else throw std::invalid_argument("Unknown option: " + std::string(arg));
        }
        if (options.token_file.empty()) throw std::invalid_argument("--token-file is required; use --help for usage");
        return magicbox::run_appliance(options);
    } catch (const std::exception& e) {
        std::cerr << "magicboxd: " << e.what() << '\n';
        return 1;
    }
}
