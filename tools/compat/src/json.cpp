#include "json.h"

#include <algorithm>
#include <charconv>
#include <format>
#include <stdexcept>
#include <string>
#include <utility>

namespace livemap::compat {

namespace {

constexpr int kMaxDepth = 64;
constexpr size_t kIndent = 2;
constexpr uint32_t kHighSurrogate = 0xd800;
constexpr uint32_t kLowSurrogate = 0xdc00;
constexpr uint32_t kSurrogateEnd = 0xe000;

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

class Reader {
public:
    explicit Reader(std::string_view text) : text_(text) {}

    Json document() {
        Json result = value(0);
        skip_space();
        if (pos_ != text_.size()) {
            fail("unexpected data after the document");
        }
        return result;
    }

private:
    [[noreturn]] void fail(std::string_view what) const { throw std::runtime_error(std::format("offset {}: {}", pos_, what)); }

    bool at_end() const { return pos_ >= text_.size(); }
    char peek() const { return at_end() ? '\0' : text_[pos_]; }

    void skip_space() {
        while (!at_end() && (peek() == ' ' || peek() == '\t' || peek() == '\n' || peek() == '\r')) {
            ++pos_;
        }
    }

    void expect(char c) {
        if (peek() != c) {
            fail(std::format("expected '{}'", c));
        }
        ++pos_;
    }

    Json value(int depth) {
        skip_space();
        if (depth > kMaxDepth) {
            fail("nesting too deep");
        }
        const char c = peek();
        if (c == '{') {
            return object(depth);
        }
        if (c == '[') {
            return array(depth);
        }
        if (c == '"') {
            return Json::string(string());
        }
        if (c == '-' || is_digit(c)) {
            return number();
        }
        return literal();
    }

    bool take(std::string_view word) {
        if (text_.substr(pos_, word.size()) != word) {
            return false;
        }
        pos_ += word.size();
        return true;
    }

    Json literal() {
        if (take("true")) {
            return Json::boolean(true);
        }
        if (take("false")) {
            return Json::boolean(false);
        }
        if (take("null")) {
            return Json::null();
        }
        fail("expected a value");
    }

    size_t digits() {
        const size_t start = pos_;
        while (is_digit(peek())) {
            ++pos_;
        }
        return pos_ - start;
    }

    Json number() {
        const size_t start = pos_;
        if (peek() == '-') {
            ++pos_;
        }
        if (peek() == '0') {
            ++pos_;
        } else if (digits() == 0) {
            fail("expected a digit");
        }
        if (peek() == '.') {
            ++pos_;
            if (digits() == 0) {
                fail("expected a digit after '.'");
            }
        }
        if (peek() == 'e' || peek() == 'E') {
            ++pos_;
            if (peek() == '+' || peek() == '-') {
                ++pos_;
            }
            if (digits() == 0) {
                fail("expected a digit in the exponent");
            }
        }
        return Json::number_literal(std::string(text_.substr(start, pos_ - start)));
    }

    uint32_t hex4() {
        constexpr std::string_view kDigits = "0123456789abcdefABCDEF";
        uint32_t code = 0;
        for (int i = 0; i < 4; ++i) {
            const size_t digit = kDigits.find(peek());
            if (digit == std::string_view::npos) {
                fail("expected four hex digits");
            }
            code = (code << 4) | static_cast<uint32_t>(digit < 16 ? digit : digit - 6);
            ++pos_;
        }
        return code;
    }

    static void append_utf8(std::string& out, uint32_t code) {
        if (code < 0x80) {
            out += static_cast<char>(code);
        } else if (code < 0x800) {
            out += static_cast<char>(0xc0 | (code >> 6));
            out += static_cast<char>(0x80 | (code & 0x3f));
        } else if (code < 0x10000) {
            out += static_cast<char>(0xe0 | (code >> 12));
            out += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (code & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (code >> 18));
            out += static_cast<char>(0x80 | ((code >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (code & 0x3f));
        }
    }

    uint32_t code_point() {
        const uint32_t first = hex4();
        if (first >= kLowSurrogate && first < kSurrogateEnd) {
            fail("a low surrogate without a high one");
        }
        if (first < kHighSurrogate || first >= kLowSurrogate) {
            return first;
        }
        if (text_.substr(pos_, 2) != "\\u") {
            fail("a high surrogate without a low one");
        }
        pos_ += 2;
        const uint32_t second = hex4();
        if (second < kLowSurrogate || second >= kSurrogateEnd) {
            fail("a high surrogate without a low one");
        }
        return 0x10000 + ((first - kHighSurrogate) << 10) + (second - kLowSurrogate);
    }

    void escape(std::string& out) {
        const char c = peek();
        ++pos_;
        switch (c) {
            case '"':
            case '\\':
            case '/':
                out += c;
                return;
            case 'b':
                out += '\b';
                return;
            case 'f':
                out += '\f';
                return;
            case 'n':
                out += '\n';
                return;
            case 'r':
                out += '\r';
                return;
            case 't':
                out += '\t';
                return;
            case 'u':
                append_utf8(out, code_point());
                return;
            default:
                --pos_;
                fail("unknown escape");
        }
    }

    std::string string() {
        expect('"');
        std::string out;
        while (peek() != '"') {
            if (at_end()) {
                fail("unterminated string");
            }
            const char c = text_[pos_++];
            if (static_cast<unsigned char>(c) < 0x20) {
                --pos_;
                fail("control character in a string");
            }
            if (c == '\\') {
                escape(out);
            } else {
                out += c;
            }
        }
        ++pos_;
        return out;
    }

    Json array(int depth) {
        expect('[');
        Json result = Json::array();
        skip_space();
        if (peek() == ']') {
            ++pos_;
            return result;
        }
        while (true) {
            result.push(value(depth + 1));
            skip_space();
            if (peek() == ']') {
                ++pos_;
                return result;
            }
            expect(',');
        }
    }

    Json object(int depth) {
        expect('{');
        Json result = Json::object();
        skip_space();
        if (peek() == '}') {
            ++pos_;
            return result;
        }
        while (true) {
            skip_space();
            const size_t key_at = pos_;
            std::string key = string();
            if (result.find(key) != nullptr) {
                pos_ = key_at;
                fail("duplicate key");
            }
            skip_space();
            expect(':');
            result.append(std::move(key), value(depth + 1));
            skip_space();
            if (peek() == '}') {
                ++pos_;
                return result;
            }
            expect(',');
        }
    }

    std::string_view text_;
    size_t pos_ = 0;
};

void write_string(std::string_view text, std::string& out) {
    out += '"';
    for (const char c : text) {
        switch (c) {
            case '"':
                out += R"(\")";
                break;
            case '\\':
                out += R"(\\)";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out += std::format("\\u{:04x}", static_cast<unsigned>(c));
                } else {
                    out += c;
                }
        }
    }
    out += '"';
}

void write_value(const Json& value, size_t indent, std::string& out);

void write_container(const Json& value, size_t indent, std::string& out) {
    const bool is_object = value.kind() == Json::Kind::Object;
    out += is_object ? '{' : '[';
    if (value.items().empty()) {
        out += is_object ? '}' : ']';
        return;
    }
    out += '\n';
    for (size_t i = 0; i < value.items().size(); ++i) {
        out.append(indent + kIndent, ' ');
        if (is_object) {
            write_string(value.keys()[i], out);
            out += ": ";
        }
        write_value(value.items()[i], indent + kIndent, out);
        out += i + 1 < value.items().size() ? ",\n" : "\n";
    }
    out.append(indent, ' ');
    out += is_object ? '}' : ']';
}

void write_value(const Json& value, size_t indent, std::string& out) {
    switch (value.kind()) {
        case Json::Kind::Null:
            out += "null";
            break;
        case Json::Kind::Bool:
            out += value.as_bool() ? "true" : "false";
            break;
        case Json::Kind::Number:
            out += value.text();
            break;
        case Json::Kind::String:
            write_string(value.text(), out);
            break;
        case Json::Kind::Array:
        case Json::Kind::Object:
            write_container(value, indent, out);
            break;
    }
}

}  // namespace

Json Json::null() {
    return Json(Kind::Null);
}

Json Json::boolean(bool value) {
    Json result(Kind::Bool);
    result.flag_ = value;
    return result;
}

Json Json::number(uint64_t value) {
    Json result(Kind::Number);
    result.text_ = std::to_string(value);
    return result;
}

Json Json::number_literal(std::string text) {
    Json result(Kind::Number);
    result.text_ = std::move(text);
    return result;
}

Json Json::string(std::string value) {
    Json result(Kind::String);
    result.text_ = std::move(value);
    return result;
}

Json Json::array() {
    return Json(Kind::Array);
}

Json Json::object() {
    return Json(Kind::Object);
}

std::optional<uint64_t> Json::as_uint() const {
    uint64_t value = 0;
    const char* const end = text_.data() + text_.size();
    if (kind_ != Kind::Number) {
        return std::nullopt;
    }
    const auto [stop, error] = std::from_chars(text_.data(), end, value);
    if (error != std::errc() || stop != end) {
        return std::nullopt;
    }
    return value;
}

size_t Json::index_of(std::string_view key) const {
    return static_cast<size_t>(std::ranges::find(keys_, key) - keys_.begin());
}

const Json* Json::find(std::string_view key) const {
    const size_t at = index_of(key);
    return at == keys_.size() ? nullptr : &items_[at];
}

Json* Json::find(std::string_view key) {
    const size_t at = index_of(key);
    return at == keys_.size() ? nullptr : &items_[at];
}

Json* Json::at(size_t index) {
    return index < items_.size() ? &items_[index] : nullptr;
}

void Json::push(Json value) {
    items_.push_back(std::move(value));
}

void Json::append(std::string key, Json value) {
    keys_.push_back(std::move(key));
    items_.push_back(std::move(value));
}

void Json::set(std::string key, Json value) {
    if (Json* existing = find(key)) {
        *existing = std::move(value);
        return;
    }
    append(std::move(key), std::move(value));
}

std::expected<Json, std::string> parse_json(std::string_view text) {
    try {
        return Reader(text).document();
    } catch (const std::runtime_error& error) {
        return std::unexpected(std::string(error.what()));
    }
}

std::string write_json(const Json& value) {
    std::string out;
    write_value(value, 0, out);
    out += '\n';
    return out;
}

}  // namespace livemap::compat
