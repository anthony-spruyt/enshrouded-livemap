#include "fault.h"

namespace livemap::fault {

namespace {

constexpr uint32_t kSeverityMask = 0xE0000000;
constexpr uint32_t kErrorSeverity = 0xC0000000;
constexpr uint32_t kDatatypeMisalignment = 0x80000002;

bool contains(const Range& range, uintptr_t address) {
    return address >= range.begin && address < range.end;
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
        for (; name != nullptr && n < kMaxSite && name[n] != '\0'; ++n) {
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

const char* place_of(Where where) {
    using enum Where;
    switch (where) {
        case Trampoline:
            return "trampoline";
        case Game:
            return "game";
        default:
            return "livemap";
    }
}

}  // namespace

bool is_fault_code(uint32_t code) {
    return (code & kSeverityMask) == kErrorSeverity || code == kDatatypeMisalignment;
}

size_t RegionTable::publish(const Range& range, const char* site) {
    if (range.begin >= range.end) {
        return kNoSlot;
    }
    const size_t slot = used_.fetch_add(1);
    if (slot >= kMaxRegions) {
        return kNoSlot;
    }
    entries_[slot] = {range, site};
    live_[slot].store(&entries_[slot]);
    return slot;
}

void RegionTable::retire(size_t slot) {
    if (slot < kMaxRegions) {
        live_[slot].store(nullptr);
    }
}

const Region* RegionTable::find(uintptr_t address) const {
    for (const auto& slot : live_) {
        if (const Region* region = slot.load(); region != nullptr && contains(region->range, address)) {
            return region;
        }
    }
    return nullptr;
}

Verdict classify(const Layout& layout, uintptr_t address, uint32_t code, const char* active_site) {
    using enum Where;
    if (!is_fault_code(code)) {
        return {};
    }
    if (contains(layout.probes, address) && is_bad_read(code)) {
        return {};
    }
    if (contains(layout.dll, address)) {
        return {Module, static_cast<uint32_t>(address - layout.dll.begin), active_site};
    }
    if (const Region* region = layout.regions.find(address)) {
        return {Trampoline, static_cast<uint32_t>(address - region->range.begin), region->site};
    }
    if (active_site != nullptr && contains(layout.game, address)) {
        return {Game, static_cast<uint32_t>(address - layout.game.begin), active_site};
    }
    return {};
}

size_t format_line(char* out, size_t capacity, const Stamp& at, uint32_t code, const Verdict& verdict) {
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
    w.text(" at=");
    w.text(place_of(verdict.where));
    w.text("+");
    w.hex8(verdict.offset);
    w.text(" site=");
    w.site(verdict.site);
    w.text("\r\n");
    return w.finish();
}

}  // namespace livemap::fault
