#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace livemap::compat {

// One RUNTIME_FUNCTION of the exception table: the bytes [begin, end) of a function, as RVAs.
struct Function {
    uint32_t begin = 0;
    uint32_t end = 0;
};

// A PE32+ file laid out the way the loader maps it, so every address is an RVA into one buffer.
class Image {
public:
    uint32_t time_date_stamp() const { return time_date_stamp_; }
    uint32_t size_of_image() const { return static_cast<uint32_t>(mapped_.size()); }
    // The last section whose name starts with ".text" is the code, as in the DLL's scan.
    uint32_t text_rva() const { return text_rva_; }
    std::span<const std::byte> text() const { return at(text_rva_, text_size_); }
    std::span<const std::byte> mapped() const { return mapped_; }

    // The `length` bytes at `rva`, or nothing when they are not all inside the image.
    std::span<const std::byte> at(uint64_t rva, size_t length) const;
    // Whether `length` bytes from `rva` all lie inside .text.
    bool in_text(uint64_t rva, uint64_t length) const;

    // Sorted by begin.
    const std::vector<Function>& functions() const { return functions_; }
    const Function* function_at(uint32_t rva) const;
    // The first function of the chain of unwind info that the function holding `rva` belongs to: the cold chunks of a
    // function share its root. Nothing when no function holds `rva`.
    std::optional<uint32_t> chain_root(uint32_t rva) const;

private:
    friend std::expected<Image, std::string> load_image(std::span<const std::byte> file);

    uint32_t time_date_stamp_ = 0;
    uint32_t text_rva_ = 0;
    uint32_t text_size_ = 0;
    std::vector<std::byte> mapped_;
    std::vector<Function> functions_;
    std::vector<uint32_t> roots_;
};

// Parses the file as the loader would map it; the error says what is wrong with the file.
std::expected<Image, std::string> load_image(std::span<const std::byte> file);

}  // namespace livemap::compat
