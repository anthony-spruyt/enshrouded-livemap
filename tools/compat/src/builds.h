#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "json.h"
#include "signature.h"

namespace livemap::compat {

struct NamedValue {
    std::string name;
    uint32_t value = 0;
};

struct PatternDef {
    std::string site;
    std::string bytes;
    Signature signature;
    uint32_t offset = 0;
    bool mandatory = false;
    std::vector<NamedValue> operands;  // offsets from the start of the match of 4-byte values the code reads
};

struct SigsetDef {
    std::string name;
    std::vector<PatternDef> patterns;
};

struct BuildRow {
    std::string label;
    std::vector<std::string> build_ids;
    uint32_t time_date_stamp = 0;
    uint32_t size_of_image = 0;
    std::string sigset;
    std::string mining_layout;
    std::optional<std::string> depot;
    std::optional<std::string> manifest;
    std::optional<std::string> exe_sha256;
    std::vector<NamedValue> expected;
    std::vector<NamedValue> expected_operands;
};

// What a new row holds that is not copied from the row it follows. `expected` and `expected_operands` come in the order
// of the copied row's entries.
struct NewRow {
    std::string build_id;
    uint32_t time_date_stamp = 0;
    uint32_t size_of_image = 0;
    std::optional<std::string> depot;
    std::string manifest;
    std::string exe_sha256;
    std::vector<uint32_t> expected;
    std::vector<uint32_t> expected_operands;
};

// A Steam id as data/builds.schema.json has it: decimal digits, no leading zero, at most 20 of them.
bool is_steam_id(std::string_view text);

// data/builds.json: the typed rows and sigsets, and the document they were read from. Edits change the document by the
// smallest step and read the rows from it again, so the two cannot differ.
class Catalog {
public:
    static std::expected<Catalog, std::string> from_json(Json document);

    const Json& document() const { return document_; }
    const std::vector<SigsetDef>& sigsets() const { return sigsets_; }
    const std::vector<BuildRow>& rows() const { return rows_; }

    const SigsetDef* sigset(std::string_view name) const;
    std::optional<size_t> row_with_build_id(std::string_view id) const;
    std::optional<size_t> row_with_label(std::string_view label) const;
    std::vector<size_t> rows_with_fingerprint(uint32_t time_date_stamp, uint32_t size_of_image) const;

    // Lists one more build id for the row, and the manifest of that build as the row's: Steam serves only the newest build.
    std::expected<void, std::string> add_alias(size_t row, std::string id, std::string manifest);
    // Appends a row that is the row `like` with the new fingerprint, build id, manifest, checksum and found values.
    std::expected<void, std::string> append_row_like(size_t like, const NewRow& added);

private:
    explicit Catalog(Json document) : document_(std::move(document)) {}

    std::expected<void, std::string> reload();

    Json document_;
    std::vector<SigsetDef> sigsets_;
    std::vector<BuildRow> rows_;
};

}  // namespace livemap::compat
