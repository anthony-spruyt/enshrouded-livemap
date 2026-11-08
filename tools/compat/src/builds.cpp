#include "builds.h"

#include <algorithm>
#include <charconv>
#include <format>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "sites.h"

namespace livemap::compat {

namespace {

constexpr size_t kSteamIdMaxLength = 20;
constexpr size_t kSha256HexLength = 64;
constexpr int kHexBase = 16;

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

bool is_lower_hex(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f');
}

// The form data/builds.schema.json allows: 0x, lower-case digits, no leading zero, 32 bits.
std::optional<uint32_t> parse_hex(std::string_view text) {
    if (!text.starts_with("0x")) {
        return std::nullopt;
    }
    const std::string_view digits = text.substr(2);
    if (const bool leading_zero = digits.size() > 1 && digits.front() == '0'; leading_zero || !std::ranges::all_of(digits, is_lower_hex)) {
        return std::nullopt;
    }
    uint32_t value = 0;
    const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), value, kHexBase);
    return result.ec == std::errc() ? std::optional(value) : std::nullopt;
}

std::string hex_text(uint32_t value) {
    return std::format("0x{:x}", value);
}

bool is_sha256(std::string_view text) {
    return text.size() == kSha256HexLength && std::ranges::all_of(text, is_lower_hex);
}

// Reads the members of one object and keeps the first problem, so a reader of many members checks once at the end.
class Reader {
public:
    Reader(const Json& object, std::string where) : object_(object), where_(std::move(where)) {
        if (object.kind() != Json::Kind::Object) {
            error_ = std::format("{}: not an object", where_);
        }
    }

    bool ok() const { return error_.empty(); }
    const std::string& error() const { return error_; }

    std::string text(std::string_view key) {
        const Json* value = member(key, Json::Kind::String, "a string");
        return value == nullptr ? std::string() : value->text();
    }

    bool flag(std::string_view key) {
        const Json* value = member(key, Json::Kind::Bool, "true or false");
        return value != nullptr && value->as_bool();
    }

    uint32_t decimal(std::string_view key) {
        const Json* value = member(key, Json::Kind::Number, "a number");
        if (value == nullptr) {
            return 0;
        }
        const std::optional<uint64_t> number = value->as_uint();
        if (!number || *number > std::numeric_limits<uint32_t>::max()) {
            fail(key, "is not an unsigned number within 32 bits");
            return 0;
        }
        return static_cast<uint32_t>(*number);
    }

    uint32_t hex(std::string_view key) {
        const Json* value = member(key, Json::Kind::String, "a hex string");
        return value == nullptr ? 0 : hex_value(*value, key);
    }

    std::optional<std::string> text_or_null(std::string_view key) {
        const Json* value = lookup(key);
        if (value == nullptr || value->kind() == Json::Kind::Null) {
            return std::nullopt;
        }
        if (value->kind() != Json::Kind::String) {
            fail(key, "is neither a string nor null");
            return std::nullopt;
        }
        return value->text();
    }

    std::vector<std::string> steam_ids(std::string_view key) {
        std::vector<std::string> ids;
        const Json* ids_json = list(key);
        if (ids_json == nullptr) {
            return ids;
        }
        for (const Json& item : ids_json->items()) {
            if (item.kind() != Json::Kind::String || !is_steam_id(item.text())) {
                fail(key, "holds something that is no Steam id");
                return {};
            }
            ids.push_back(item.text());
        }
        if (ids.empty()) {
            fail(key, "is empty");
        }
        return ids;
    }

    // An object of hex numbers; `required` says whether a missing key is a problem.
    std::vector<NamedValue> hex_members(std::string_view key, bool required) {
        std::vector<NamedValue> values;
        if (!required && object_.find(key) == nullptr) {
            return values;
        }
        const Json* group = member(key, Json::Kind::Object, "an object");
        if (group == nullptr) {
            return values;
        }
        for (size_t i = 0; i < group->keys().size(); ++i) {
            values.emplace_back(group->keys()[i], hex_value(group->items()[i], std::format("{}.{}", key, group->keys()[i])));
        }
        return values;
    }

    const Json* object(std::string_view key) { return member(key, Json::Kind::Object, "an object"); }

    const Json* list(std::string_view key) { return member(key, Json::Kind::Array, "a list"); }

    std::string path(std::string_view key) const { return std::format("{}.{}", where_, key); }

private:
    void fail(std::string_view key, std::string_view what) {
        if (ok()) {
            error_ = std::format("{}: {}", path(key), what);
        }
    }

    uint32_t hex_value(const Json& value, std::string_view key) {
        const std::optional<uint32_t> parsed = value.kind() == Json::Kind::String ? parse_hex(value.text()) : std::nullopt;
        if (!parsed.has_value()) {
            fail(key, "is not a hex number like 0x1f within 32 bits");
            return 0;
        }
        return *parsed;
    }

    const Json* lookup(std::string_view key) {
        if (!ok()) {
            return nullptr;
        }
        const Json* value = object_.find(key);
        if (value == nullptr) {
            fail(key, "is missing");
        }
        return value;
    }

    const Json* member(std::string_view key, Json::Kind kind, std::string_view what) {
        const Json* value = lookup(key);
        if (value != nullptr && value->kind() != kind) {
            fail(key, std::format("is not {}", what));
            return nullptr;
        }
        return value;
    }

    const Json& object_;
    std::string where_;
    std::string error_;
};

std::expected<PatternDef, std::string> read_pattern(const Json& json, std::string_view where) {
    Reader reader(json, std::string(where));
    PatternDef pattern;
    pattern.site = reader.text("site");
    pattern.bytes = reader.text("bytes");
    pattern.offset = reader.hex("offset");
    pattern.mandatory = reader.flag("mandatory");
    pattern.operands = reader.hex_members("operands", false);
    if (!reader.ok()) {
        return std::unexpected(reader.error());
    }
    auto signature = parse_signature(pattern.bytes);
    if (!signature) {
        return std::unexpected(std::format("{}: bytes are no signature ({})", where, signature.error()));
    }
    pattern.signature = std::move(*signature);
    const size_t size = pattern.signature.size();
    if (pattern.offset > size) {
        return std::unexpected(std::format("{}: offset lies past the end of the pattern", where));
    }
    for (const NamedValue& operand : pattern.operands) {
        if (operand.value > size || size - operand.value < kOperandWidth) {
            return std::unexpected(std::format("{}: operand {} lies outside the pattern", where, operand.name));
        }
    }
    return pattern;
}

std::expected<std::vector<SigsetDef>, std::string> read_sigsets(const Json& document) {
    Reader reader(document, "document");
    const Json* sets = reader.object("sigsets");
    if (sets == nullptr) {
        return std::unexpected(reader.error());
    }
    std::vector<SigsetDef> out;
    for (size_t i = 0; i < sets->keys().size(); ++i) {
        const Json& list = sets->items()[i];
        SigsetDef set{sets->keys()[i], {}};
        if (list.kind() != Json::Kind::Array || list.items().empty()) {
            return std::unexpected(std::format("sigsets.{}: not a list of patterns", set.name));
        }
        for (size_t k = 0; k < list.items().size(); ++k) {
            auto pattern = read_pattern(list.items()[k], std::format("sigsets.{}[{}]", set.name, k));
            if (!pattern) {
                return std::unexpected(pattern.error());
            }
            set.patterns.push_back(std::move(*pattern));
        }
        out.push_back(std::move(set));
    }
    return out;
}

std::expected<BuildRow, std::string> read_row(const Json& json, std::string_view where, const std::vector<SigsetDef>& sigsets) {
    Reader reader(json, std::string(where));
    BuildRow row;
    row.label = reader.text("label");
    row.build_ids = reader.steam_ids("buildids");
    row.time_date_stamp = reader.decimal("time_date_stamp");
    row.size_of_image = reader.hex("size_of_image");
    row.sigset = reader.text("sigset");
    row.mining_layout = reader.text("mining_layout");
    row.expected = reader.hex_members("expected", true);
    row.expected_operands = reader.hex_members("expected_operands", false);
    if (const Json* steam = reader.object("steam")) {
        Reader inner(*steam, reader.path("steam"));
        row.depot = inner.text_or_null("depot");
        row.manifest = inner.text_or_null("manifest");
        row.exe_sha256 = inner.text_or_null("exe_sha256");
        if (!inner.ok()) {
            return std::unexpected(inner.error());
        }
    }
    if (!reader.ok()) {
        return std::unexpected(reader.error());
    }
    if (std::ranges::find(sigsets, row.sigset, &SigsetDef::name) == sigsets.end()) {
        return std::unexpected(std::format("{}: the sigset '{}' does not exist", where, row.sigset));
    }
    return row;
}

std::expected<std::vector<BuildRow>, std::string> read_rows(const Json& document, const std::vector<SigsetDef>& sigsets) {
    Reader reader(document, "document");
    const Json* builds = reader.list("builds");
    if (builds == nullptr) {
        return std::unexpected(reader.error());
    }
    if (builds->items().empty()) {
        return std::unexpected("document.builds: is empty");
    }
    std::vector<BuildRow> rows;
    for (size_t i = 0; i < builds->items().size(); ++i) {
        auto row = read_row(builds->items()[i], std::format("builds[{}]", i), sigsets);
        if (!row) {
            return std::unexpected(row.error());
        }
        rows.push_back(std::move(*row));
    }
    return rows;
}

std::expected<void, std::string> check_new_row(const BuildRow& base, const NewRow& added) {
    if (!is_steam_id(added.build_id) || !is_steam_id(added.manifest) || (added.depot && !is_steam_id(*added.depot))) {
        return std::unexpected("the build id, manifest and depot of a new row have to be Steam ids");
    }
    if (!is_sha256(added.exe_sha256)) {
        return std::unexpected("the checksum of a new row has to be 64 lower-case hex digits");
    }
    if (added.expected.size() != base.expected.size() || added.expected_operands.size() != base.expected_operands.size()) {
        return std::unexpected("a new row needs one RVA and one operand for each the row it follows has");
    }
    return {};
}

void set_values(Json& group, const std::vector<uint32_t>& values) {
    for (size_t i = 0; i < values.size(); ++i) {
        *group.at(i) = Json::string(hex_text(values[i]));
    }
}

// Overwrites the members in place, so the copy keeps the key order of the row it was made from.
void fill_row(Json& row, const NewRow& added) {
    Json ids = Json::array();
    ids.push(Json::string(added.build_id));
    row.set("label", Json::string(added.build_id));
    row.set("buildids", std::move(ids));
    row.set("time_date_stamp", Json::number(added.time_date_stamp));
    row.set("size_of_image", Json::string(hex_text(added.size_of_image)));
    Json& steam = *row.find("steam");
    if (added.depot) {
        steam.set("depot", Json::string(*added.depot));
    }
    steam.set("manifest", Json::string(added.manifest));
    steam.set("exe_sha256", Json::string(added.exe_sha256));
    set_values(*row.find("expected"), added.expected);
    if (Json* operands = row.find("expected_operands")) {
        set_values(*operands, added.expected_operands);
    }
}

}  // namespace

bool is_steam_id(std::string_view text) {
    return !text.empty() && text.size() <= kSteamIdMaxLength && text.front() != '0' && std::ranges::all_of(text, is_digit);
}

std::expected<Catalog, std::string> Catalog::from_json(Json document) {
    Catalog catalog(std::move(document));
    if (auto loaded = catalog.reload(); !loaded.has_value()) {
        return std::unexpected(loaded.error());
    }
    return catalog;
}

std::expected<void, std::string> Catalog::reload() {
    auto sigsets = read_sigsets(document_);
    if (!sigsets) {
        return std::unexpected(sigsets.error());
    }
    auto rows = read_rows(document_, *sigsets);
    if (!rows) {
        return std::unexpected(rows.error());
    }
    sigsets_ = std::move(*sigsets);
    rows_ = std::move(*rows);
    return {};
}

const SigsetDef* Catalog::sigset(std::string_view name) const {
    const auto found = std::ranges::find(sigsets_, name, &SigsetDef::name);
    return found == sigsets_.end() ? nullptr : std::to_address(found);
}

std::optional<size_t> Catalog::row_with_build_id(std::string_view id) const {
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (std::ranges::find(rows_[i].build_ids, id) != rows_[i].build_ids.end()) {
            return i;
        }
    }
    return std::nullopt;
}

std::optional<size_t> Catalog::row_with_label(std::string_view label) const {
    const auto found = std::ranges::find(rows_, label, &BuildRow::label);
    return found == rows_.end() ? std::nullopt : std::optional<size_t>(static_cast<size_t>(found - rows_.begin()));
}

std::vector<size_t> Catalog::rows_with_fingerprint(uint32_t time_date_stamp, uint32_t size_of_image) const {
    std::vector<size_t> found;
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (rows_[i].time_date_stamp == time_date_stamp && rows_[i].size_of_image == size_of_image) {
            found.push_back(i);
        }
    }
    return found;
}

std::expected<void, std::string> Catalog::add_alias(size_t row, std::string id) {
    if (row >= rows_.size()) {
        return std::unexpected("there is no such row");
    }
    if (!is_steam_id(id)) {
        return std::unexpected("a build id has to be a Steam id");
    }
    if (row_with_build_id(id).has_value()) {
        return std::unexpected("the build id is listed already");
    }
    document_.find("builds")->at(row)->find("buildids")->push(Json::string(std::move(id)));
    return reload();
}

std::expected<void, std::string> Catalog::append_row_like(size_t like, const NewRow& added) {
    if (like >= rows_.size()) {
        return std::unexpected("there is no such row");
    }
    if (auto fits = check_new_row(rows_[like], added); !fits.has_value()) {
        return fits;
    }
    if (row_with_build_id(added.build_id).has_value() || row_with_label(added.build_id).has_value()) {
        return std::unexpected("the build id is in the file already, as a build id or a label");
    }
    Json* builds = document_.find("builds");
    Json row = *builds->at(like);
    fill_row(row, added);
    builds->push(std::move(row));
    return reload();
}

}  // namespace livemap::compat
