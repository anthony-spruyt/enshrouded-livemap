#include "sites.h"

#include <span>
#include <vector>

#include "disasm.h"
#include "signature.h"

namespace livemap::compat {

namespace {

constexpr unsigned kBitsPerByte = 8;

uint32_t read_u32(std::span<const std::byte> bytes) {
    uint32_t value = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        value |= static_cast<uint32_t>(bytes[i]) << (kBitsPerByte * i);
    }
    return value;
}

SiteHit scan_pattern(const Image& image, const PatternDef& pattern) {
    SiteHit hit;
    hit.pattern = &pattern;
    const std::vector<size_t> found = find_all(pattern.signature, image.text());
    hit.matches = found.size();
    if (found.size() != 1) {
        return hit;
    }
    hit.match_rva = image.text_rva() + static_cast<uint32_t>(found[0]);
    hit.rva = hit.match_rva + pattern.offset;
    hit.fits_in_text = image.in_text(hit.rva, kHookLength);
    for (const NamedValue& operand : pattern.operands) {
        const uint64_t at = uint64_t{hit.match_rva} + operand.value;
        const bool inside = image.in_text(at, kOperandWidth);
        hit.fits_in_text = hit.fits_in_text && inside;
        hit.operands.emplace_back(operand.name, inside ? read_u32(image.at(at, kOperandWidth)) : 0);
    }
    return hit;
}

}  // namespace

std::vector<SiteHit> scan_sigset(const Image& image, const SigsetDef& sigset) {
    std::vector<SiteHit> hits;
    for (const PatternDef& pattern : sigset.patterns) {
        hits.push_back(scan_pattern(image, pattern));
    }
    return hits;
}

}  // namespace livemap::compat
