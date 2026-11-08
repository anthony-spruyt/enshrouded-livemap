#include "pe.h"

#include <algorithm>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace livemap::compat {

namespace {

constexpr uint32_t kMaxImageSize = 1U << 30;
constexpr size_t kDosHeaderSize = 0x40;
constexpr size_t kLfanewOffset = 0x3c;
constexpr size_t kCoffSize = 20;
constexpr size_t kSectionEntrySize = 40;
constexpr size_t kFunctionEntrySize = 12;
constexpr size_t kUnwindHeaderSize = 4;
constexpr size_t kUnwindCountOffset = 2;
constexpr size_t kUnwindCodeSize = 2;
constexpr uint64_t kUnwindVersionMask = 7;
constexpr unsigned kUnwindFlagsShift = 3;
constexpr uint64_t kChainFlag = 4;
constexpr size_t kMaxChainLength = 64;
constexpr size_t kSizeOfImageOffset = 56;
constexpr size_t kDirectoryCountOffset = 108;
constexpr size_t kDirectoriesOffset = 112;
constexpr size_t kExceptionDirectory = 3;
constexpr uint16_t kMachineX64 = 0x8664;
constexpr uint16_t kMagicPe32Plus = 0x20b;
constexpr std::string_view kTextPrefix = ".text";

class PeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Section {
    std::string name;
    uint32_t virtual_size = 0;
    uint32_t rva = 0;
    uint32_t raw_size = 0;
    uint32_t raw_offset = 0;
};

class File {
public:
    explicit File(std::span<const std::byte> bytes) : bytes_(bytes) {}

    size_t size() const { return bytes_.size(); }

    uint64_t read(uint64_t at, size_t width, std::string_view what) const {
        if (at > bytes_.size() || width > bytes_.size() - at) {
            throw PeError(std::format("the file ends inside {}", what));
        }
        uint64_t value = 0;
        for (size_t i = 0; i < width; ++i) {
            value |= std::to_integer<uint64_t>(bytes_[at + i]) << (8 * i);
        }
        return value;
    }

    std::span<const std::byte> slice(uint64_t at, uint64_t length, std::string_view what) const {
        if (at > bytes_.size() || length > bytes_.size() - at) {
            throw PeError(std::format("the file ends inside {}", what));
        }
        return bytes_.subspan(at, length);
    }

private:
    std::span<const std::byte> bytes_;
};

Section read_section(const File& file, uint64_t at) {
    Section s;
    for (const std::byte b : file.slice(at, 8, "a section name")) {
        if (b == std::byte{0}) {
            break;
        }
        s.name += static_cast<char>(std::to_underlying(b));
    }
    s.virtual_size = static_cast<uint32_t>(file.read(at + 8, 4, "a section header"));
    s.rva = static_cast<uint32_t>(file.read(at + 12, 4, "a section header"));
    s.raw_size = static_cast<uint32_t>(file.read(at + 16, 4, "a section header"));
    s.raw_offset = static_cast<uint32_t>(file.read(at + 20, 4, "a section header"));
    return s;
}

void map_section(const File& file, const Section& s, std::vector<std::byte>& mapped) {
    const uint64_t copied = s.virtual_size == 0 ? s.raw_size : std::min(s.raw_size, s.virtual_size);
    if (const uint64_t extent = std::max<uint64_t>(copied, s.virtual_size); s.rva + extent > mapped.size()) {
        throw PeError(std::format("section '{}' lies outside the image", s.name));
    }
    const auto raw = file.slice(s.raw_offset, copied, "section data");
    std::ranges::copy(raw, mapped.begin() + s.rva);
}

struct Entry {
    Function range;
    uint32_t unwind = 0;
};

std::vector<Entry> read_entries(const std::vector<std::byte>& mapped, uint64_t rva, uint64_t size) {
    if (rva > mapped.size() || size > mapped.size() - rva || size % kFunctionEntrySize != 0) {
        throw PeError("the exception table is malformed");
    }
    const File table(std::span<const std::byte>(mapped).subspan(rva, size));
    std::vector<Entry> entries;
    for (uint64_t at = 0; at < size; at += kFunctionEntrySize) {
        Entry e{{static_cast<uint32_t>(table.read(at, 4, "the exception table")), static_cast<uint32_t>(table.read(at + 4, 4, "the exception table"))},
                static_cast<uint32_t>(table.read(at + 8, 4, "the exception table"))};
        if (e.range.begin >= e.range.end || e.range.end > mapped.size()) {
            throw PeError(std::format("exception table entry at 0x{:x} is not a range inside the image", e.range.begin));
        }
        entries.push_back(e);
    }
    std::ranges::sort(entries, {}, [](const Entry& e) { return e.range.begin; });
    return entries;
}

// The begin of the function a chunk continues, read from its unwind info; nothing when the info does not chain.
std::optional<uint32_t> chained_parent(const std::vector<std::byte>& mapped, const Entry& entry) {
    constexpr std::string_view kWhat = "the unwind info";
    const File image(mapped);
    const uint64_t header = image.read(entry.unwind, 1, kWhat);
    if (const uint64_t version = header & kUnwindVersionMask; (version != 1 && version != 2) || ((header >> kUnwindFlagsShift) & kChainFlag) == 0) {
        return std::nullopt;
    }
    const uint64_t codes = image.read(uint64_t{entry.unwind} + kUnwindCountOffset, 1, kWhat);
    const uint64_t parent = uint64_t{entry.unwind} + kUnwindHeaderSize + (codes + 1) / 2 * 2 * kUnwindCodeSize;
    return static_cast<uint32_t>(image.read(parent, 4, kWhat));
}

// The entry holding the function that `current` chains to; nothing when it does not chain or the parent is not another entry.
const Entry* chain_parent_entry(const std::vector<std::byte>& mapped, const std::vector<Entry>& entries, const Entry& current) {
    const auto parent = chained_parent(mapped, current);
    if (!parent.has_value()) {
        return nullptr;
    }
    const auto next = std::ranges::upper_bound(entries, *parent, {}, [](const Entry& e) { return e.range.begin; });
    if (next == entries.begin() || *parent >= (next - 1)->range.end) {
        return nullptr;
    }
    const Entry* owner = std::to_address(next - 1);
    return owner == &current ? nullptr : owner;
}

// The begin of the first function of the chain each entry belongs to.
std::vector<uint32_t> chain_roots(const std::vector<std::byte>& mapped, const std::vector<Entry>& entries) {
    std::vector<uint32_t> roots;
    for (const Entry& start : entries) {
        const Entry* current = &start;
        size_t steps = 0;
        while (const Entry* owner = chain_parent_entry(mapped, entries, *current)) {
            if (steps++ == kMaxChainLength) {
                throw PeError(std::format("the unwind info of the function at 0x{:x} chains in a circle", start.range.begin));
            }
            current = owner;
        }
        roots.push_back(current->range.begin);
    }
    return roots;
}

}  // namespace

std::span<const std::byte> Image::at(uint64_t rva, size_t length) const {
    if (rva > mapped_.size() || length > mapped_.size() - rva) {
        return {};
    }
    return std::span<const std::byte>(mapped_).subspan(rva, length);
}

bool Image::in_text(uint64_t rva, uint64_t length) const {
    return rva >= text_rva_ && rva - text_rva_ < text_size_ && length <= text_size_ - (rva - text_rva_);
}

std::optional<uint32_t> Image::chain_root(uint32_t rva) const {
    const Function* function = function_at(rva);
    if (function == nullptr) {
        return std::nullopt;
    }
    return roots_[function - functions_.data()];
}

const Function* Image::function_at(uint32_t rva) const {
    const auto next = std::ranges::upper_bound(functions_, rva, {}, &Function::begin);
    if (next == functions_.begin()) {
        return nullptr;
    }
    const Function& candidate = *(next - 1);
    return rva < candidate.end ? &candidate : nullptr;
}

std::expected<Image, std::string> load_image(std::span<const std::byte> bytes) {
    try {
        const File file(bytes);
        Image image;
        if (file.read(0, 2, "the DOS header") != 0x5a4d || file.size() < kDosHeaderSize) {
            throw PeError("not a PE file (no MZ header)");
        }
        const uint64_t pe = file.read(kLfanewOffset, 4, "the DOS header");
        if (file.read(pe, 4, "the PE header") != 0x4550) {
            throw PeError("not a PE file (no PE signature)");
        }
        const uint64_t coff = pe + 4;
        const uint64_t optional = coff + kCoffSize;
        if (file.read(coff, 2, "the COFF header") != kMachineX64) {
            throw PeError("not an x64 file");
        }
        if (file.read(optional, 2, "the optional header") != kMagicPe32Plus) {
            throw PeError("not a PE32+ file");
        }
        const uint64_t section_count = file.read(coff + 2, 2, "the COFF header");
        image.time_date_stamp_ = static_cast<uint32_t>(file.read(coff + 4, 4, "the COFF header"));
        const uint64_t optional_size = file.read(coff + 16, 2, "the COFF header");
        const uint64_t image_size = file.read(optional + kSizeOfImageOffset, 4, "the optional header");
        if (image_size == 0 || image_size > kMaxImageSize) {
            throw PeError("the image size is not plausible");
        }
        image.mapped_.assign(image_size, std::byte{0});

        bool has_text = false;
        for (uint64_t i = 0; i < section_count; ++i) {
            const Section s = read_section(file, optional + optional_size + i * kSectionEntrySize);
            map_section(file, s, image.mapped_);
            if (s.name.starts_with(kTextPrefix)) {
                has_text = true;
                image.text_rva_ = s.rva;
                image.text_size_ = s.virtual_size;
            }
        }
        if (!has_text) {
            throw PeError("no .text section");
        }

        if (const uint64_t directories = file.read(optional + kDirectoryCountOffset, 4, "the optional header"); directories > kExceptionDirectory) {
            const uint64_t entry = optional + kDirectoriesOffset + kExceptionDirectory * 8;
            const auto entries = read_entries(image.mapped_, file.read(entry, 4, "the data directories"), file.read(entry + 4, 4, "the data directories"));
            image.roots_ = chain_roots(image.mapped_, entries);
            std::ranges::transform(entries, std::back_inserter(image.functions_), &Entry::range);
        }
        return image;
    } catch (const PeError& error) {
        return std::unexpected(std::string(error.what()));
    }
}

}  // namespace livemap::compat
