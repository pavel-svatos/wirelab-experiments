#include "magicbox/appliance.hpp"
#include <spawn.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>

extern char** environ;
namespace magicbox {
std::string command(const std::vector<std::string>& args, const std::string& input) {
    if (args.empty()) throw std::invalid_argument("Empty command");
    struct CloseFile { void operator()(FILE* f) const { fclose(f); } };
    std::unique_ptr<FILE, CloseFile> in(tmpfile());
    if (!in) throw std::runtime_error("Cannot create command input");
    if (fwrite(input.data(), 1, input.size(), in.get()) != input.size()) throw std::runtime_error("Cannot write command input");
    rewind(in.get());
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) != 0) throw std::runtime_error("Cannot create command pipe");
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fileno(in.get()), STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipes[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipes[0]);
    std::vector<char*> argv;
    for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    pid_t pid{};
    const int error = posix_spawnp(&pid, argv[0], &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipes[1]);
    if (error != 0) { close(pipes[0]); throw std::runtime_error(args[0] + ": " + strerror(error)); }
    std::string output;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    bool failed = false;
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline || output.size() > 262144) { failed = true; break; }
        pollfd fd{pipes[0], POLLIN, 0};
        const int ready = poll(&fd, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { failed = true; break; }
        if (ready == 0) continue;
        char buffer[4096];
        const auto bytes = read(pipes[0], buffer, sizeof(buffer));
        if (bytes == 0) break;
        if (bytes < 0) { if (errno == EINTR) continue; failed = true; break; }
        output.append(buffer, static_cast<std::size_t>(bytes));
    }
    close(pipes[0]);
    if (failed) kill(pid, SIGKILL);
    int status{};
    for (;;) {
        const auto result = waitpid(pid, &status, WNOHANG);
        if (result == pid) break;
        if (result < 0 && errno != EINTR) throw std::runtime_error("Cannot reap command process");
        if (std::chrono::steady_clock::now() >= deadline) { failed = true; kill(pid, SIGKILL); }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (failed || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error(args[0] + " failed: " + (failed ? "timeout or output limit" : output));
    return output;
}
} // namespace magicbox
