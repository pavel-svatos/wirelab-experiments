#include "magicbox/appliance.hpp"
#include <sqlite3.h>
#include <stdexcept>

namespace magicbox {
namespace {
void check(int code, sqlite3* db) {
    if (code != SQLITE_OK && code != SQLITE_DONE && code != SQLITE_ROW)
        throw std::runtime_error(sqlite3_errmsg(db));
}
struct Statement {
    sqlite3_stmt* p{};
    sqlite3* db;
    Statement(sqlite3* database, const char* sql) : db(database) { check(sqlite3_prepare_v2(db, sql, -1, &p, nullptr), db); }
    ~Statement() { sqlite3_finalize(p); }
    void text(int i, const std::string& s) { check(sqlite3_bind_text(p, i, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT), db); }
    void number(int i, std::int64_t n) { check(sqlite3_bind_int64(p, i, n), db); }
    int step() { const auto result = sqlite3_step(p); check(result, db); return result; }
};
}
struct Store::Impl {
    sqlite3* db{};
    ~Impl() { sqlite3_close(db); }
};
Store::Store(const std::filesystem::path& path) : impl_(std::make_unique<Impl>()) {
    check(sqlite3_open_v2(path.c_str(), &impl_->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr), impl_->db);
    sqlite3_busy_timeout(impl_->db, 3000);
    const char* sql = "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;"
                      "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
                      "CREATE TABLE IF NOT EXISTS samples(ts INTEGER PRIMARY KEY, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,details TEXT NOT NULL);"
                      "CREATE TABLE IF NOT EXISTS flows(key TEXT PRIMARY KEY,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,packets INTEGER NOT NULL,bytes INTEGER NOT NULL,metadata TEXT NOT NULL);"
                      "CREATE INDEX IF NOT EXISTS flows_last_seen ON flows(last_seen);"
                      "PRAGMA user_version=1;";
    check(sqlite3_exec(impl_->db, sql, nullptr, nullptr, nullptr), impl_->db);
}
Store::~Store() = default;
void Store::put(const std::string& key, const Json::Value& value) {
    Statement s(impl_->db, "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
    s.text(1, key); s.text(2, json_text(value)); s.step();
}
Json::Value Store::get(const std::string& key) {
    Statement s(impl_->db, "SELECT value FROM settings WHERE key=?"); s.text(1, key);
    if (s.step() != SQLITE_ROW) return {};
    return parse_json(reinterpret_cast<const char*>(sqlite3_column_text(s.p, 0)));
}
void Store::sample(std::int64_t ts, std::uint64_t packets, std::uint64_t bytes, const Json::Value& details) {
    Statement s(impl_->db, "INSERT INTO samples VALUES(?,?,?,?) ON CONFLICT(ts) DO UPDATE SET packets=packets+excluded.packets,bytes=bytes+excluded.bytes,details=excluded.details");
    s.number(1, ts); s.number(2, static_cast<std::int64_t>(packets)); s.number(3, static_cast<std::int64_t>(bytes)); s.text(4, json_text(details)); s.step();
    Statement cleanup(impl_->db, "DELETE FROM samples WHERE ts < ?"); cleanup.number(1, ts - 7 * 86400); cleanup.step();
}
Json::Value Store::history(std::int64_t from, std::int64_t to, int interval) {
    if ((interval != 60 && interval != 300 && interval != 3600) || to <= from || to - from > 7 * 86400)
        throw std::invalid_argument("History requires interval 60/300/3600 and a range up to seven days");
    Statement s(impl_->db, "SELECT (ts / ?) * ?,SUM(packets),SUM(bytes),COUNT(*),"
        "SUM(COALESCE(json_extract(details,'$.protocols.tcp'),0)),"
        "SUM(COALESCE(json_extract(details,'$.protocols.udp'),0)),"
        "SUM(COALESCE(json_extract(details,'$.protocols.icmp'),0)),"
        "SUM(COALESCE(json_extract(details,'$.protocols.other'),0)) "
        "FROM samples WHERE ts>=? AND ts<? GROUP BY 1 ORDER BY 1 LIMIT 1000");
    s.number(1, interval); s.number(2, interval); s.number(3, from); s.number(4, to);
    Json::Value rows(Json::arrayValue);
    while (s.step() == SQLITE_ROW) {
        Json::Value row;
        row["timestamp"] = Json::Int64(sqlite3_column_int64(s.p, 0));
        row["packets"] = std::to_string(sqlite3_column_int64(s.p, 1));
        row["wire_bytes"] = std::to_string(sqlite3_column_int64(s.p, 2));
        row["samples"] = Json::Int64(sqlite3_column_int64(s.p, 3));
        int column = 4;
        for (const auto* protocol : {"tcp", "udp", "icmp", "other"})
            row["protocols"][protocol] = std::to_string(sqlite3_column_int64(s.p, column++));
        rows.append(row);
    }
    return rows;
}
void Store::record_flows(const Json::Value& flows) {
    check(sqlite3_exec(impl_->db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr), impl_->db);
    try {
        for (const auto& flow : flows) {
            Statement s(impl_->db, "INSERT INTO flows VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen,packets=packets+excluded.packets,bytes=bytes+excluded.bytes,metadata=excluded.metadata");
            s.text(1, flow["key"].asString()); s.number(2, flow["first_seen"].asInt64()); s.number(3, flow["timestamp_ms"].asInt64());
            s.number(4, flow["packets"].asInt64()); s.number(5, flow["bytes"].asInt64()); s.text(6, json_text(flow)); s.step();
        }
        check(sqlite3_exec(impl_->db, "DELETE FROM flows WHERE last_seen < (strftime('%s','now')-604800)*1000;"
            "DELETE FROM flows WHERE key IN (SELECT key FROM flows ORDER BY last_seen DESC LIMIT -1 OFFSET 10000); COMMIT;", nullptr, nullptr, nullptr), impl_->db);
    } catch (...) {
        sqlite3_exec(impl_->db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}
Json::Value Store::connections() {
    Statement s(impl_->db, "SELECT first_seen,last_seen,packets,bytes,metadata FROM flows ORDER BY last_seen DESC LIMIT 200");
    Json::Value rows(Json::arrayValue);
    while (s.step() == SQLITE_ROW) {
        auto row = parse_json(reinterpret_cast<const char*>(sqlite3_column_text(s.p, 4)));
        row["first_seen"] = Json::Int64(sqlite3_column_int64(s.p, 0));
        row["last_seen"] = Json::Int64(sqlite3_column_int64(s.p, 1));
        row["packets"] = std::to_string(sqlite3_column_int64(s.p, 2));
        row["bytes"] = std::to_string(sqlite3_column_int64(s.p, 3));
        rows.append(row);
    }
    return rows;
}
} // namespace magicbox
