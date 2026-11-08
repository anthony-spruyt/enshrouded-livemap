#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace livemap::compat {

// A JSON value that keeps object members in file order, so a document read and written again stays byte for byte the same.
// Numbers keep their literal text.
class Json {
public:
    enum class Kind { Null,
                      Bool,
                      Number,
                      String,
                      Array,
                      Object };

    static Json null();
    static Json boolean(bool value);
    static Json number(uint64_t value);
    // A number with this literal text, which the caller has checked against the JSON grammar.
    static Json number_literal(std::string text);
    static Json string(std::string value);
    static Json array();
    static Json object();

    Kind kind() const { return kind_; }
    bool as_bool() const { return flag_; }
    // The characters of a string, or the literal of a number.
    const std::string& text() const { return text_; }
    // The number as unsigned, or nothing for any other value, a negative number, a fraction or an overflow.
    std::optional<uint64_t> as_uint() const;

    // Array elements, or object values in the order of keys().
    const std::vector<Json>& items() const { return items_; }
    const std::vector<std::string>& keys() const { return keys_; }
    const Json* find(std::string_view key) const;
    Json* find(std::string_view key);
    // The array element or object value at this position, or null past the end and for any other kind.
    Json* at(size_t index);

    void push(Json value);
    // Replaces the member in place, or appends it.
    void set(std::string key, Json value);

    // Adds an element or member while parsing, without the lookup set() does.
    void append(std::string key, Json value);

private:
    explicit Json(Kind kind) : kind_(kind) {}

    size_t index_of(std::string_view key) const;

    Kind kind_ = Kind::Null;
    bool flag_ = false;
    std::string text_;
    std::vector<Json> items_;
    std::vector<std::string> keys_;
};

// An error names the byte offset it was found at.
std::expected<Json, std::string> parse_json(std::string_view text);

// Two-space indentation, one member or element per line, a newline at the end.
std::string write_json(const Json& value);

}  // namespace livemap::compat
