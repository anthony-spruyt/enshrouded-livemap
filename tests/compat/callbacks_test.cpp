// The registers the hook callbacks read, as the compat tool knows them, against the callbacks in src/ and the sites in data/builds.json.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "builds.h"
#include "callbacks.h"
#include "json.h"
#include "registers.h"
#include "src/mining.h"
#include "test_support.h"

using livemap::MiningLayout;
using livemap::MiningSample;
using livemap::compat::Callback;
using livemap::compat::Registers;

namespace {

std::string read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cout << "cannot read " << path << "\n";
        std::exit(2);
    }
    std::ostringstream text;
    text << file.rdbuf();
    return text.str();
}

using RegistersByName = std::map<std::string, Registers, std::less<>>;
using Names = std::set<std::string, std::less<>>;

// The registers each callback of the source reads from its context, by function name.
RegistersByName registers_in_source() {
    RegistersByName found;
    const std::regex header(R"(void (on_\w+)\(SafetyHookContext&[^)]*\) \{\n)");
    const std::regex use(R"(ctx\.(r\w+))");
    for (const std::string_view file : {"world.cpp", "announce.cpp"}) {
        const std::string text = read_file(std::string(LIVEMAP_SOURCE_DIR) + "/" + std::string(file));
        for (std::sregex_iterator it(text.begin(), text.end(), header), end; it != end; ++it) {
            const auto body = static_cast<size_t>(it->position() + it->length());
            const std::string code = text.substr(body, text.find("\n}\n", body) - body);
            Registers reads = 0;
            for (std::sregex_iterator hit(code.begin(), code.end(), use); hit != std::sregex_iterator(); ++hit) {
                reads |= livemap::compat::register_named((*hit)[1].str()).value_or(0);
            }
            found[(*it)[1].str()] = reads;
        }
    }
    return found;
}

livemap::compat::Catalog catalog() {
    auto document = livemap::compat::parse_json(read_file(LIVEMAP_BUILDS_JSON));
    auto parsed = document ? livemap::compat::Catalog::from_json(std::move(*document)) : std::unexpected(document.error());
    if (!parsed) {
        std::cout << "data/builds.json does not load: " << parsed.error() << "\n";
        std::exit(2);
    }
    return std::move(*parsed);
}

// The registers that change what mining_sample returns for a layout.
Registers sample_registers(MiningLayout layout) {
    const MiningSample base = livemap::mining_sample(layout, 0, 0, 0);
    const std::array<std::pair<std::string_view, MiningSample>, 3> probes{{
        {"rax", livemap::mining_sample(layout, 1, 0, 0)},
        {"rbp", livemap::mining_sample(layout, 0, 1, 0)},
        {"r15", livemap::mining_sample(layout, 0, 0, 1)},
    }};
    Registers used = 0;
    for (const auto& [name, sample] : probes) {
        if (sample.item != base.item || sample.amount != base.amount) {
            used |= livemap::compat::register_named(name).value_or(0);
        }
    }
    return used;
}

// Each mining layout reads the registers src/mining.h takes for it, and the ones on_mining reads for every layout.
void check_mining_layouts(compat_test::Suite& t, Registers in_source) {
    const std::array<std::pair<std::string_view, MiningLayout>, 2> layouts{{
        {"inline_array", MiningLayout::InlineArray},
        {"stack_record", MiningLayout::StackRecord},
    }};
    Registers by_layout = 0;
    for (const auto& [name, layout] : layouts) {
        by_layout |= sample_registers(layout);
    }
    const auto common = static_cast<Registers>(in_source & ~by_layout);
    for (const Callback& callback : livemap::compat::callbacks()) {
        const bool known = callback.layout.empty() || std::ranges::any_of(layouts, [&](const auto& layout) { return layout.first == callback.layout; });
        t.check(callback.function != "on_mining" || known, std::string(callback.layout) + " is a layout of src/mining.h");
    }
    for (const auto& [name, layout] : layouts) {
        Registers table = 0;
        for (const Callback& callback : livemap::compat::callbacks()) {
            if (callback.function == "on_mining" && (callback.layout.empty() || callback.layout == name)) {
                table |= callback.reads;
            }
        }
        const auto expected = static_cast<Registers>(common | sample_registers(layout));
        t.check(table == expected, std::format("on_mining reads {} under {} in src/, the compat tool lists {}", livemap::compat::register_list(expected), name, livemap::compat::register_list(table)));
    }
}

void check_against_source(compat_test::Suite& t) {
    const auto source = registers_in_source();
    t.check(!source.empty(), "the source has callbacks");
    RegistersByName table;
    for (const Callback& callback : livemap::compat::callbacks()) {
        table[std::string(callback.function)] |= callback.reads;
    }
    for (const auto& [function, reads] : source) {
        t.check(table.contains(function), function + " has an entry in the callbacks of the compat tool");
        t.check(table[function] == reads, function + " reads " + livemap::compat::register_list(reads) + " in src/, the compat tool lists " + livemap::compat::register_list(table[function]));
    }
    for (const auto& [function, reads] : table) {
        t.check(source.contains(function), function + " is a callback in src/");
    }
    check_mining_layouts(t, source.at("on_mining"));
}

void check_against_data(compat_test::Suite& t) {
    const auto data = catalog();
    Names sites;
    Names layouts;
    for (const auto& sigset : data.sigsets()) {
        for (const auto& pattern : sigset.patterns) {
            sites.insert(pattern.site);
        }
    }
    for (const auto& row : data.rows()) {
        layouts.insert(row.mining_layout);
    }
    Names hooked;
    for (const Callback& callback : livemap::compat::callbacks()) {
        hooked.emplace(callback.site);
        t.check(sites.contains(callback.site), std::string(callback.site) + " is a site of a sigset");
        t.check(callback.layout.empty() || layouts.contains(callback.layout), std::string(callback.layout) + " is a mining layout of a build");
    }
    for (const std::string& site : sites) {
        t.check(hooked.contains(site) || site == "param_entity" || site == "chat_post", site + " is hooked or read by the DLL without a hook");
    }
}

}  // namespace

int main() {
    compat_test::Suite t;
    check_against_source(t);
    check_against_data(t);
    return t.result();
}
