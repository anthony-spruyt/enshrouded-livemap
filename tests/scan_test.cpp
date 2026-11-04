// find_targets and find_chat_sites on synthetic PE images (no game bytes): each supported build's
// fingerprint with its signatures planted at the RVAs the selftest expects of that build.
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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
constexpr size_t kAccessorRva = 0x300000;
constexpr size_t kJoinLineRva = 0x400000;
constexpr size_t kDuplicateRva = 0x500000;
constexpr uint32_t kPlantedTable = 0x830;
constexpr uint32_t kPlantedTag = 0x2fec0cdf;

class Image {
public:
    explicit Image(const snapshot::Row& row) : bytes_(kImageSize) {
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
        text->Misc.VirtualSize = kImageSize - kTextRva;
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
    EXPECT(livemap::find_chat_sites(image.base(), chat), "%s: join line", row.label);
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
        EXPECT(!livemap::find_chat_sites(image.base(), chat), "%s: join line found without it", row.label);
    }
    {
        Image image(row);
        plant_build(image, row, row.patch1, true);
        for (const snapshot::Site& site : row.patch1 ? snapshot::patch1_sites() : snapshot::launch_sites()) {
            if (site.name == std::string("join_line")) image.plant(kJoinLineRva + 0x1000, site.hex);
        }
        livemap::ChatSites chat;
        EXPECT(!livemap::find_chat_sites(image.base(), chat), "%s: two join lines accepted", row.label);
    }
    {
        Image image(row);
        image.drop_sections();
        livemap::ChatSites chat;
        EXPECT(!livemap::find_targets(image.base(), t, error), "%s: image without .text accepted", row.label);
        EXPECT(error.find("no .text section") != std::string::npos, "%s: %s", row.label, error.c_str());
        EXPECT(!livemap::find_chat_sites(image.base(), chat), "%s: join line found without .text", row.label);
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
        EXPECT(livemap::find_chat_sites(image.base(), chat) == c.accepted, "%s: %s", row.label, c.what);
        if (c.accepted) EXPECT(chat.shared == c.shared && chat.join_call == image.at(call), "%s: %s", row.label, c.what);
    }
}

}  // namespace

int main() {
    for (const snapshot::Row& row : snapshot::kRows) {
        check_build(row);
        check_rejections(row);
        check_join_line_variants(row);
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
