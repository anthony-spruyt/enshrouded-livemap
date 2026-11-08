#pragma once

// Synthetic PE32+ files for the tests: a few sections and an exception table, with no game bytes.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "test_support.h"

namespace compat_test {

struct SectionSpec {
    std::string name;
    uint32_t rva = 0;
    std::vector<std::byte> data;
    uint32_t virtual_size = 0;  // 0: the size of data
};

struct FunctionSpec {
    uint32_t begin = 0;
    uint32_t end = 0;
    uint32_t chained_to = 0;  // begin of the function whose unwind info this one continues; 0: not a chunk
    uint32_t unwind = 0;      // the raw unwind RVA when it is not a chunk
    uint32_t unwind_codes = 0;  // unwind codes between the header of a chunk and the function it continues
    unsigned unwind_version = 1;
};

struct PeSpec {
    uint32_t time_date_stamp = 1;
    uint32_t size_of_image = 0x10000;
    std::vector<SectionSpec> sections;
    std::vector<FunctionSpec> functions;
    uint32_t pdata_rva = 0x8000;
    uint32_t xdata_rva = 0x9000;
};

constexpr uint32_t kPeHeaderOffset = 0x80;
constexpr uint32_t kCoffOffset = kPeHeaderOffset + 4;
constexpr uint32_t kOptionalOffset = kCoffOffset + 20;
constexpr uint32_t kOptionalSize = 240;
constexpr uint32_t kSectionTableOffset = kOptionalOffset + kOptionalSize;
constexpr uint32_t kSectionEntrySize = 40;
constexpr uint32_t kFirstRawOffset = 0x400;
constexpr uint32_t kFileAlignment = 0x200;
constexpr uint32_t kExceptionDirectoryOffset = kOptionalOffset + 112 + 3 * 8;
constexpr uint32_t kUnwindInfoSize = 64;
constexpr unsigned kChainFlag = 4;

constexpr unsigned kExceptionHandlerFlag = 1;
constexpr unsigned kTerminationHandlerFlag = 2;

// One record of the scope table that follows a structured exception handler in the unwind info.
struct ScopeRecord {
    uint32_t begin = 0;
    uint32_t end = 0;
    uint32_t handler = 1;
    uint32_t jump = 0;
};

inline void push_dword(std::vector<std::byte>& bytes, uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<std::byte>(value >> shift));
    }
}

// Unwind info with `flags`, `codes` unwind codes, a handler address, then a scope table that claims `count` records.
inline std::vector<std::byte> scope_info(unsigned flags, unsigned codes, const std::vector<ScopeRecord>& records, uint32_t count, unsigned version = 1) {
    std::vector<std::byte> info{static_cast<std::byte>(version | (flags << 3)), std::byte{0}, static_cast<std::byte>(codes), std::byte{0}};
    info.resize(info.size() + (codes + 1) / 2 * 4);
    push_dword(info, 0x1f00);
    push_dword(info, count);
    for (const ScopeRecord& r : records) {
        for (const uint32_t field : {r.begin, r.end, r.handler, r.jump}) {
            push_dword(info, field);
        }
    }
    return info;
}

inline void put(std::vector<std::byte>& file, size_t at, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; ++i) {
        file.at(at + i) = static_cast<std::byte>(value >> (8 * i));
    }
}

inline uint32_t end_of(const PeSpec& spec, uint32_t begin) {
    const auto found = std::ranges::find(spec.functions, begin, &FunctionSpec::begin);
    return found == spec.functions.end() ? begin + 1 : found->end;
}

// Unwind info with the chained flag, its codes, then the RUNTIME_FUNCTION of the function it continues.
inline std::vector<std::byte> chain_info(const PeSpec& spec) {
    std::vector<std::byte> info(spec.functions.size() * kUnwindInfoSize);
    for (size_t i = 0; i < spec.functions.size(); ++i) {
        const FunctionSpec& f = spec.functions[i];
        if (f.chained_to != 0) {
            const size_t at = i * kUnwindInfoSize;
            put(info, at, f.unwind_version | (kChainFlag << 3), 1);
            put(info, at + 2, f.unwind_codes, 1);
            const size_t parent = at + 4 + (f.unwind_codes + 1) / 2 * 4;
            put(info, parent, f.chained_to, 4);
            put(info, parent + 4, end_of(spec, f.chained_to), 4);
        }
    }
    return info;
}

inline std::vector<std::byte> build_pe(PeSpec spec) {
    if (!spec.functions.empty()) {
        SectionSpec pdata{".pdata", spec.pdata_rva, {}, 0};
        pdata.data.resize(spec.functions.size() * 12);
        for (size_t i = 0; i < spec.functions.size(); ++i) {
            const FunctionSpec& f = spec.functions[i];
            put(pdata.data, i * 12, f.begin, 4);
            put(pdata.data, i * 12 + 4, f.end, 4);
            put(pdata.data, i * 12 + 8, f.chained_to != 0 ? spec.xdata_rva + i * kUnwindInfoSize : f.unwind, 4);
        }
        spec.sections.push_back(std::move(pdata));
        const auto is_chained = [](const FunctionSpec& f) { return f.chained_to != 0; };
        if (std::ranges::any_of(spec.functions, is_chained)) {
            spec.sections.emplace_back(".xdata", spec.xdata_rva, chain_info(spec), 0);
        }
    }
    uint32_t raw_end = kFirstRawOffset;
    for (const SectionSpec& s : spec.sections) {
        raw_end += (static_cast<uint32_t>(s.data.size()) + kFileAlignment - 1) / kFileAlignment * kFileAlignment;
    }
    std::vector<std::byte> file(raw_end);
    put(file, 0, 0x5a4d, 2);
    put(file, 0x3c, kPeHeaderOffset, 4);
    put(file, kPeHeaderOffset, 0x4550, 4);
    put(file, kCoffOffset, 0x8664, 2);
    put(file, kCoffOffset + 2, spec.sections.size(), 2);
    put(file, kCoffOffset + 4, spec.time_date_stamp, 4);
    put(file, kCoffOffset + 16, kOptionalSize, 2);
    put(file, kOptionalOffset, 0x20b, 2);
    put(file, kOptionalOffset + 56, spec.size_of_image, 4);
    put(file, kOptionalOffset + 60, kFirstRawOffset, 4);
    put(file, kOptionalOffset + 108, 16, 4);
    if (!spec.functions.empty()) {
        put(file, kExceptionDirectoryOffset, spec.pdata_rva, 4);
        put(file, kExceptionDirectoryOffset + 4, spec.functions.size() * 12, 4);
    }
    uint32_t raw = kFirstRawOffset;
    for (size_t i = 0; i < spec.sections.size(); ++i) {
        const SectionSpec& s = spec.sections[i];
        const size_t entry = kSectionTableOffset + i * kSectionEntrySize;
        for (size_t k = 0; k < s.name.size(); ++k) {
            file[entry + k] = static_cast<std::byte>(s.name[k]);
        }
        put(file, entry + 8, s.virtual_size != 0 ? s.virtual_size : s.data.size(), 4);
        put(file, entry + 12, s.rva, 4);
        put(file, entry + 16, s.data.size(), 4);
        put(file, entry + 20, raw, 4);
        std::ranges::copy(s.data, file.begin() + raw);
        raw += (static_cast<uint32_t>(s.data.size()) + kFileAlignment - 1) / kFileAlignment * kFileAlignment;
    }
    return file;
}

}  // namespace compat_test
