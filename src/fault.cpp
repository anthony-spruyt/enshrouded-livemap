#include "fault.h"

namespace livemap::fault {

namespace {

constexpr uint32_t kSeverityMask = 0xE0000000;
constexpr uint32_t kErrorSeverity = 0xC0000000;
constexpr uint32_t kDatatypeMisalignment = 0x80000002;
constexpr uint32_t kAccessViolation = 0xC0000005;
constexpr uint32_t kInPageError = 0xC0000006;
constexpr size_t kMaxSite = 32;

bool contains(const Range& range, uintptr_t address) {
    return address >= range.begin && address < range.end;
}

// What the probes in memory.cpp guard against with their own __except.
bool is_bad_read(uint32_t code) {
    return code == kAccessViolation || code == kInPageError;
}

class Writer {
public:
    Writer(char* out, size_t capacity) : out_(out), capacity_(capacity) {}

    void text(const char* s) {
        for (; *s != '\0'; ++s) {
            put(*s);
        }
    }

    void site(const char* name) {
        size_t n = 0;
        for (; name != nullptr && name[n] != '\0' && n < kMaxSite; ++n) {
            put(name[n]);
        }
        if (n == 0) {
            text("none");
        }
    }

    void decimal(unsigned value, int digits) {
        unsigned scale = 1;
        for (int i = 1; i < digits; ++i) {
            scale *= 10;
        }
        for (; scale > 0; scale /= 10) {
            put(static_cast<char>('0' + (value / scale) % 10));
        }
    }

    void hex8(uint32_t value) {
        text("0x");
        for (int shift = 28; shift >= 0; shift -= 4) {
            put("0123456789ABCDEF"[(value >> shift) & 0xF]);
        }
    }

    size_t finish() const { return ok_ ? length_ : 0; }

private:
    void put(char c) {
        if (length_ < capacity_) {
            out_[length_] = c;
        } else {
            ok_ = false;
        }
        ++length_;
    }

    char* out_;
    size_t capacity_;
    size_t length_ = 0;
    bool ok_ = true;
};

}  // namespace

bool is_fault_code(uint32_t code) {
    return (code & kSeverityMask) == kErrorSeverity || code == kDatatypeMisalignment;
}

Verdict classify(const Layout& layout, size_t regions, uintptr_t address, uint32_t code) {
    if (!is_fault_code(code)) {
        return {};
    }
    if (contains(layout.probes, address) && is_bad_read(code)) {
        return {};
    }
    if (contains(layout.module, address)) {
        return {Where::Module, static_cast<uint32_t>(address - layout.module.begin), nullptr};
    }
    for (size_t i = 0; i < regions && i < kMaxRegions; ++i) {
        const Region& region = layout.regions[i];
        if (contains(region.range, address)) {
            return {Where::Trampoline, static_cast<uint32_t>(address - region.range.begin), region.site};
        }
    }
    return {};
}

size_t format_line(char* out, size_t capacity, const Stamp& at, uint32_t code, Where where, uint32_t offset,
                   const char* site) {
    Writer w(out, capacity);
    w.decimal(at.year, 4);
    w.text("-");
    w.decimal(at.month, 2);
    w.text("-");
    w.decimal(at.day, 2);
    w.text(" ");
    w.decimal(at.hour, 2);
    w.text(":");
    w.decimal(at.minute, 2);
    w.text(":");
    w.decimal(at.second, 2);
    w.text(".");
    w.decimal(at.millisecond, 3);
    w.text(" [livemap] FAULT code=");
    w.hex8(code);
    w.text(where == Where::Trampoline ? " at=trampoline+" : " at=livemap+");
    w.hex8(offset);
    w.text(" site=");
    w.site(site);
    w.text("\r\n");
    return w.finish();
}

}  // namespace livemap::fault
