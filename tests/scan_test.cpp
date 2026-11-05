// find_targets and find_chat_sites on synthetic PE images (no game bytes): each supported build's
// fingerprint with its signatures planted at the RVAs the selftest expects of that build.
#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "builds_generated.h"
#include "builds_snapshot.h"
#include "scan.h"

namespace {

int failures = 0;

#define EXPECT(cond, ...)                                                           \
    do {                                                                            \
        if (!(cond)) {                                                              \
            std::printf("FAIL %s:%d  %s  ", __FILE__, __LINE__, #cond);             \
            std::printf(__VA_ARGS__);                                               \
            std::printf("\n");                                                      \
            ++failures;                                                             \
        }                                                                           \
    } while (0)

constexpr size_t kTextRva = 0x1000;
constexpr size_t kImageSize = 0xa00000;  // past the highest expected RVA
constexpr size_t kPadding = 0x1000;      // mapped bytes after the .text section
constexpr size_t kAccessorRva = 0x300000;
constexpr size_t kJoinLineRva = 0x400000;
constexpr size_t kDuplicateRva = 0x500000;
constexpr uint32_t kPlantedTable = 0x830;
constexpr uint32_t kPlantedTag = 0x2fec0cdf;
constexpr size_t kHookBytes = 5;     // a hook overwrites a jmp rel32
constexpr size_t kTextEnd = 0x3000;  // a .text this short lets a pattern end on its last byte

class Image {
public:
    explicit Image(const snapshot::Row& row, size_t text_end = kImageSize) : bytes_(kImageSize + kPadding) {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes_.data());
        dos->e_lfanew = 0x80;
        nt_ = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes_.data() + 0x80);
        nt_->FileHeader.NumberOfSections = 1;
        nt_->FileHeader.SizeOfOptionalHeader = static_cast<WORD>(sizeof nt_->OptionalHeader);
        nt_->FileHeader.TimeDateStamp = row.time_date_stamp;
        nt_->OptionalHeader.SizeOfImage = row.size_of_image;
        IMAGE_SECTION_HEADER* text = IMAGE_FIRST_SECTION(nt_);
        std::memcpy(text->Name, ".text", 5);
        text->VirtualAddress = kTextRva;
        text->Misc.VirtualSize = static_cast<DWORD>(text_end - kTextRva);
    }

    const uint8_t* base() const { return bytes_.data(); }
    uintptr_t at(size_t rva) const { return reinterpret_cast<uintptr_t>(bytes_.data()) + rva; }
    void fingerprint(uint32_t time_date_stamp) { nt_->FileHeader.TimeDateStamp = time_date_stamp; }

    // ?? bytes stay zero.
    void plant(size_t rva, const std::string& hex) {
        for (size_t i = 0; i < hex.size(); i += 3) {
            if (hex[i] != '?') bytes_[rva + i / 3] = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        }
    }
    void write32(size_t rva, uint32_t value) { std::memcpy(&bytes_[rva], &value, sizeof value); }
    void clear(size_t rva) { bytes_[rva] = 0; }
    void drop_sections() { nt_->FileHeader.NumberOfSections = 0; }

private:
    std::vector<uint8_t> bytes_;
    IMAGE_NT_HEADERS64* nt_ = nullptr;
};

// A copy of one build's sigset that a test edits before scanning with it.
class Table {
public:
    explicit Table(const snapshot::Row& row)
        : row_(row), sites_(row.patch1 ? snapshot::patch1_sites() : snapshot::launch_sites()) {}
    Table(const Table&) = delete;
    Table& operator=(const Table&) = delete;

    snapshot::Site& site(const std::string& name) {
        return *std::find_if(sites_.begin(), sites_.end(), [&](const snapshot::Site& s) { return name == s.name; });
    }
    void remove(const std::string& name) {
        sites_.erase(std::remove_if(sites_.begin(), sites_.end(), [&](const snapshot::Site& s) { return name == s.name; }),
                     sites_.end());
    }
    void fingerprint(uint32_t time_date_stamp) { stamp_ = time_date_stamp; }

    const livemap::Build& build() {
        named_.clear();
        patterns_.clear();
        for (const snapshot::Site& s : sites_) {
            std::vector<livemap::Named>& list = named_.emplace_back();
            for (const snapshot::Operand& op : s.operands) list.push_back({op.name, static_cast<uint32_t>(op.offset)});
        }
        for (size_t i = 0; i < sites_.size(); ++i) {
            const snapshot::Site& s = sites_[i];
            patterns_.push_back({s.name, s.hex.c_str(), static_cast<uint32_t>(s.offset), s.mandatory, named_[i]});
        }
        sigset_ = {"synthetic", patterns_};
        build_ = {row_.label, stamp_.value_or(row_.time_date_stamp), row_.size_of_image, &sigset_,
                  row_.patch1 ? livemap::MiningLayout::StackRecord : livemap::MiningLayout::InlineArray, {}, {}};
        return build_;
    }

private:
    const snapshot::Row& row_;
    std::vector<snapshot::Site> sites_;
    std::optional<uint32_t> stamp_;
    std::vector<std::vector<livemap::Named>> named_;
    std::vector<livemap::Pattern> patterns_;
    livemap::Sigset sigset_{};
    livemap::Build build_{};
};

size_t byte_count(const std::string& hex) {
    return (hex.size() + 1) / 3;
}

const livemap::Build& shipped(const snapshot::Row& row) {
    for (const livemap::Build& b : livemap::kBuilds) {
        if (std::strcmp(b.label, row.label) == 0) return b;
    }
    std::printf("FAIL %s is not in builds.json\n", row.label);
    std::exit(1);
}

uint32_t expected_rva(const snapshot::Row& row, const std::string& site) {
    if (site == "player_table") return row.player_table;
    if (site == "movement") return row.movement;
    if (site == "daytime") return row.daytime;
    if (site == "registry") return row.registry;
    if (site == "mining") return row.mining;
    if (site == "chest") return row.chest;
    if (site == "bases") return row.bases;
    if (site == "chat_post") return row.chat_post;
    return 0;
}

// The hook of every site sits where the selftest expects it; the match starts `offset` bytes before.
void plant_build(Image& image, const snapshot::Row& row, bool accessor, bool join_line) {
    for (const snapshot::Site& site : row.patch1 ? snapshot::patch1_sites() : snapshot::launch_sites()) {
        if (site.name == std::string("param_entity")) {
            if (!accessor) continue;
            image.plant(kAccessorRva, site.hex);
            image.write32(kAccessorRva + site.operands[0].offset, kPlantedTable);
        } else if (site.name == std::string("join_line")) {
            if (!join_line) continue;
            image.plant(kJoinLineRva, site.hex);
            image.write32(kJoinLineRva + site.operands[0].offset, kPlantedTag);
            const size_t call = kJoinLineRva + snapshot::kJoinCallOffset;
            image.plant(call, "e8");
            image.write32(call + 1, static_cast<uint32_t>(row.chat_post - (call + 5)));
            image.plant(kJoinLineRva + snapshot::kJoinAfterOffset, "44");
        } else {
            image.plant(expected_rva(row, site.name) - site.offset, site.hex);
        }
    }
}

void check_build(const snapshot::Row& row) {
    Image image(row);
    plant_build(image, row, row.patch1, true);
    livemap::Targets t;
    std::string error;
    EXPECT(livemap::find_targets(image.base(), t, error), "%s: %s", row.label, error.c_str());
    EXPECT(t.build != nullptr && std::strcmp(t.build, row.label) == 0, "%s recognised as %s", row.label, t.build ? t.build : "nothing");
    EXPECT(t.mining_layout == (row.patch1 ? livemap::MiningLayout::StackRecord : livemap::MiningLayout::InlineArray),
           "%s mining layout", row.label);
    EXPECT(t.player_table == image.at(row.player_table), "%s player_table", row.label);
    EXPECT(t.movement == image.at(row.movement), "%s movement", row.label);
    EXPECT(t.daytime == image.at(row.daytime), "%s daytime", row.label);
    EXPECT(t.registry == image.at(row.registry), "%s registry", row.label);
    EXPECT(t.mining == image.at(row.mining), "%s mining", row.label);
    EXPECT(t.chest == image.at(row.chest), "%s chest", row.label);
    EXPECT(t.bases == image.at(row.bases), "%s bases", row.label);
    EXPECT(t.chat_post == image.at(row.chat_post), "%s chat_post", row.label);
    EXPECT(t.param_entity == (row.patch1 ? image.at(kAccessorRva) : 0), "%s param_entity", row.label);
    EXPECT(t.entity_table == (row.patch1 ? kPlantedTable : 0x828), "%s entity_table 0x%x", row.label, t.entity_table);

    livemap::ChatSites chat;
    EXPECT(livemap::find_chat_sites(image.base(), shipped(row), chat), "%s: join line", row.label);
    EXPECT(chat.join_call == image.at(kJoinLineRva + snapshot::kJoinCallOffset), "%s join_call", row.label);
    EXPECT(chat.join_after == image.at(kJoinLineRva + snapshot::kJoinAfterOffset), "%s join_after", row.label);
    EXPECT(chat.chat_post == image.at(row.chat_post), "%s chat queue function", row.label);
    EXPECT(chat.join_tag == kPlantedTag, "%s join_tag 0x%x", row.label, chat.join_tag);
    EXPECT(!chat.shared, "%s join line already hooked", row.label);
}

void check_rejections(const snapshot::Row& row) {
    livemap::Targets t;
    std::string error;
    {
        Image image(row);
        plant_build(image, row, true, false);
        image.fingerprint(0);
        EXPECT(!livemap::find_targets(image.base(), t, error), "%s: unknown fingerprint accepted", row.label);
        EXPECT(error.find("unknown server build") != std::string::npos, "%s: %s", row.label, error.c_str());
    }
    {
        Image image(row);
        plant_build(image, row, true, false);
        image.clear(expected_rva(row, "registry"));
        EXPECT(!livemap::find_targets(image.base(), t, error), "%s: broken registry signature accepted", row.label);
        EXPECT(error.find("registry") != std::string::npos, "%s: %s", row.label, error.c_str());
    }
    for (const snapshot::Site& site : row.patch1 ? snapshot::patch1_sites() : snapshot::launch_sites()) {
        if (site.name != std::string("player_table") && site.name != std::string("chest")) continue;
        Image image(row);
        plant_build(image, row, true, false);
        image.plant(kDuplicateRva, site.hex);
        const bool required = site.name == std::string("player_table");
        EXPECT(livemap::find_targets(image.base(), t, error) != required, "%s: %s planted twice", row.label, site.name);
        if (required) {
            EXPECT(error.find("matched 2 times") != std::string::npos, "%s: %s", row.label, error.c_str());
        } else {
            EXPECT(t.chest == 0 && t.player_table != 0, "%s: a duplicated optional site was hooked", row.label);
        }
    }
    {
        Image image(row);
        plant_build(image, row, row.patch1, false);
        image.clear(expected_rva(row, "mining") - (row.patch1 ? 2 : 0x16));
        EXPECT(livemap::find_targets(image.base(), t, error), "%s: %s", row.label, error.c_str());
        EXPECT(t.mining == 0 && t.player_table != 0, "%s: a missing optional site stops the rest", row.label);
        livemap::ChatSites chat;
        EXPECT(!livemap::find_chat_sites(image.base(), shipped(row), chat), "%s: join line found without it", row.label);
    }
    {
        Image image(row);
        plant_build(image, row, row.patch1, true);
        for (const snapshot::Site& site : row.patch1 ? snapshot::patch1_sites() : snapshot::launch_sites()) {
            if (site.name == std::string("join_line")) image.plant(kJoinLineRva + 0x1000, site.hex);
        }
        livemap::ChatSites chat;
        EXPECT(!livemap::find_chat_sites(image.base(), shipped(row), chat), "%s: two join lines accepted", row.label);
    }
    {
        Image image(row);
        image.drop_sections();
        livemap::ChatSites chat;
        EXPECT(!livemap::find_targets(image.base(), t, error), "%s: image without .text accepted", row.label);
        EXPECT(error.find("no .text section") != std::string::npos, "%s: %s", row.label, error.c_str());
        EXPECT(!livemap::find_chat_sites(image.base(), shipped(row), chat), "%s: join line found without .text", row.label);
    }
}

std::span<const livemap::Build> only(const livemap::Build& build) {
    return {&build, 1};
}

// install() hooks these four unconditionally; a build that leaves one unfound is not hooked at all.
void check_installed_sites_are_required(const snapshot::Row& row) {
    Table control(row);
    Image intact(row);
    plant_build(intact, row, true, false);
    livemap::Targets t;
    std::string error;
    EXPECT(livemap::find_targets(intact.base(), only(control.build()), t, error), "%s: %s", row.label, error.c_str());
    for (const char* name : {"player_table", "movement", "daytime", "registry"}) {
        {
            Table table(row);
            table.remove(name);
            Image image(row);
            plant_build(image, row, true, false);
            EXPECT(!livemap::find_targets(image.base(), only(table.build()), t, error), "%s: sigset without %s accepted", row.label, name);
            EXPECT(error.find(name) != std::string::npos, "%s: %s", row.label, error.c_str());
        }
        {
            Table table(row);
            table.site(name).mandatory = false;
            Image image(row);
            plant_build(image, row, true, false);
            image.clear(expected_rva(row, name) - table.site(name).offset);
            EXPECT(!livemap::find_targets(image.base(), only(table.build()), t, error), "%s: optional %s accepted", row.label, name);
            EXPECT(error.find(name) != std::string::npos, "%s: %s", row.label, error.c_str());
        }
    }
}

// Two rows with one fingerprint: which one is the server is not decided, so nothing is hooked.
void check_ambiguous_fingerprint(const snapshot::Row& row) {
    Table first(row), second(row);
    const livemap::Build both[] = {first.build(), second.build()};
    Image image(row);
    plant_build(image, row, true, false);
    livemap::Targets t;
    std::string error;
    EXPECT(!livemap::find_targets(image.base(), both, t, error), "%s: two rows with one fingerprint accepted", row.label);
    EXPECT(error.find("more than one") != std::string::npos, "%s: %s", row.label, error.c_str());
}

// The join line is searched with the sigset of the build that was recognised, not with every sigset.
void check_chat_sites_use_the_given_build(const snapshot::Row& row) {
    Image image(row);
    plant_build(image, row, row.patch1, true);
    livemap::ChatSites chat;
    Table with(row);
    EXPECT(livemap::find_chat_sites(image.base(), with.build(), chat), "%s: join line not found", row.label);
    Table without(row);
    without.remove("join_line");
    EXPECT(!livemap::find_chat_sites(image.base(), without.build(), chat), "%s: join line found through another sigset", row.label);
    Table other(row);
    other.fingerprint(row.time_date_stamp + 1);
    EXPECT(!livemap::find_chat_sites(image.base(), other.build(), chat), "%s: join line found for another build", row.label);
}

// Every address the scan derives has to lie inside .text, to its last byte: the 5 bytes a hook overwrites
// at each hook site and the 4 bytes it reads for the entity table.
void check_derived_addresses_stay_in_text(const snapshot::Row& row) {
    livemap::Targets t;
    std::string error;
    for (const char* name : {"registry", "chest"}) {
        for (const bool inside : {true, false}) {
            Table table(row);
            snapshot::Site& site = table.site(name);
            const size_t was = site.offset;
            site.offset = byte_count(site.hex) - (inside ? kHookBytes : kHookBytes - 1);
            Image image(row);
            plant_build(image, row, true, false);
            image.clear(expected_rva(row, name) - was);
            image.plant(kImageSize - byte_count(site.hex), site.hex);
            const bool ok = livemap::find_targets(image.base(), only(table.build()), t, error);
            EXPECT(ok == inside, "%s: %s hook site %s .text: %s", row.label, name, inside ? "inside" : "past the end of", error.c_str());
            if (!inside) EXPECT(error.find(name) != std::string::npos, "%s: %s", row.label, error.c_str());
        }
    }
    for (const bool inside : {true, false}) {
        constexpr size_t kTableBytes = sizeof t.entity_table;
        Table table(row);
        table.site("param_entity").operands[0].offset = byte_count(table.site("param_entity").hex) - (inside ? kTableBytes : kTableBytes - 1);
        Image image(row);
        plant_build(image, row, true, false);
        image.clear(kAccessorRva);
        image.plant(kImageSize - byte_count(table.site("param_entity").hex), table.site("param_entity").hex);
        const bool ok = livemap::find_targets(image.base(), only(table.build()), t, error);
        EXPECT(ok == inside, "%s: operand %s .text: %s", row.label, inside ? "ending on the last byte of" : "read past", error.c_str());
        if (!inside) EXPECT(error.find("param_entity") != std::string::npos, "%s: %s", row.label, error.c_str());
    }
}

// A .text that holds only chat_post and join_line. The join call, the instruction after it and chat_post are
// hooked with kHookBytes each, and the join tag is copied out as 4 bytes.
struct JoinLayout {
    const char* call_op = "e8";
    size_t join_start = 0x1800;
    size_t chat_start = 0x1100;
    size_t chat_offset = 0;
    size_t tag_offset = snapshot::kJoinTagOffset;
};

bool find_join_sites(const snapshot::Row& row, const JoinLayout& at, livemap::ChatSites& chat) {
    Table table(row);
    for (const char* name : {"player_table", "movement", "daytime", "registry", "param_entity", "mining", "chest", "bases"}) {
        table.remove(name);
    }
    table.site("chat_post").offset = at.chat_offset;
    table.site("join_line").operands[0].offset = at.tag_offset;
    Image image(row, kTextEnd);
    image.plant(at.chat_start, table.site("chat_post").hex);
    image.plant(at.join_start, table.site("join_line").hex);
    image.write32(at.join_start + at.tag_offset, kPlantedTag);
    const size_t call = at.join_start + snapshot::kJoinCallOffset;
    image.plant(call, at.call_op);
    image.write32(call + 1, static_cast<uint32_t>(at.chat_start + at.chat_offset - (call + 5)));
    image.plant(call + 5, "44");
    return livemap::find_chat_sites(image.base(), table.build(), chat);
}

// Each address of the join scan is checked to its last byte: the call and the instruction after it (twice
// kHookBytes), the chat_post hook (kHookBytes) and the tag (4 bytes), one byte inside and one past .text.
void check_join_sites_stay_in_text(const snapshot::Row& row) {
    for (const char* call_op : {"e8", "e9"}) {
        for (const bool inside : {true, false}) {
            const size_t room = 2 * kHookBytes - (inside ? 0 : 1);
            JoinLayout at;
            at.call_op = call_op;
            at.join_start = kTextEnd - snapshot::kJoinCallOffset - room;
            livemap::ChatSites chat;
            EXPECT(find_join_sites(row, at, chat) == inside, "%s: %s join call with %zu bytes of .text left", row.label, call_op, room);
        }
    }
    Table probe(row);
    const size_t chat_bytes = byte_count(probe.site("chat_post").hex);
    for (const bool inside : {true, false}) {
        JoinLayout at;
        at.chat_start = kTextEnd - chat_bytes;
        at.chat_offset = chat_bytes - (inside ? kHookBytes : kHookBytes - 1);
        livemap::ChatSites chat;
        EXPECT(find_join_sites(row, at, chat) == inside, "%s: chat_post hook site %s .text", row.label, inside ? "inside" : "past the end of");
    }
    for (const bool inside : {true, false}) {
        JoinLayout at;
        at.join_start = kTextEnd - snapshot::kJoinCallOffset - 2 * kHookBytes;
        at.tag_offset = kTextEnd - at.join_start - sizeof(uint32_t) + (inside ? 0 : 1);
        livemap::ChatSites chat;
        EXPECT(find_join_sites(row, at, chat) == inside, "%s: join tag %s .text", row.label, inside ? "ending on the last byte of" : "read past");
        if (inside) EXPECT(chat.join_tag == kPlantedTag, "%s: join_tag 0x%x", row.label, chat.join_tag);
    }
}

// Another mod (Shared XP) may have hooked the join line already; anything else there is rejected.
void check_join_line_variants(const snapshot::Row& row) {
    const size_t call = kJoinLineRva + snapshot::kJoinCallOffset;
    const struct {
        const char* what;
        const char* call_op;
        const char* after_op;
        bool other_function;
        bool accepted;
        bool shared;
    } cases[] = {
        {"call hooked by another mod", "e9", "44", false, true, true},
        {"instruction after the call hooked", "e8", "e9", false, true, false},
        {"call to another function", "e8", "44", true, false, false},
        {"neither call nor jump", "90", "44", false, false, false},
        {"another instruction after the call", "e8", "00", false, false, false},
    };
    for (const auto& c : cases) {
        Image image(row);
        plant_build(image, row, row.patch1, true);
        image.plant(call, c.call_op);
        image.plant(kJoinLineRva + snapshot::kJoinAfterOffset, c.after_op);
        if (c.other_function) image.write32(call + 1, static_cast<uint32_t>(row.chat_post + 0x10 - (call + 5)));
        livemap::ChatSites chat;
        EXPECT(livemap::find_chat_sites(image.base(), shipped(row), chat) == c.accepted, "%s: %s", row.label, c.what);
        if (c.accepted) EXPECT(chat.shared == c.shared && chat.join_call == image.at(call), "%s: %s", row.label, c.what);
    }
}

}  // namespace

int main() {
    for (const snapshot::Row& row : snapshot::kRows) {
        check_build(row);
        check_rejections(row);
        check_join_line_variants(row);
        check_installed_sites_are_required(row);
        check_ambiguous_fingerprint(row);
        check_chat_sites_use_the_given_build(row);
        check_derived_addresses_stay_in_text(row);
        check_join_sites_stay_in_text(row);
        if (row.patch1) {
            Image image(row);
            plant_build(image, row, false, false);
            livemap::Targets t;
            std::string error;
            EXPECT(!livemap::find_targets(image.base(), t, error), "%s: patch1 build without the entity id accessor", row.label);
            EXPECT(error.find("param_entity") != std::string::npos, "%s: %s", row.label, error.c_str());
        }
    }
    if (failures == 0) std::puts("find_targets and find_chat_sites match the hard-coded builds");
    return failures == 0 ? 0 : 1;
}
