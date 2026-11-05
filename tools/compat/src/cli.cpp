#include "cli.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "analyze.h"
#include "builds.h"
#include "json.h"
#include "pe.h"
#include "report.h"
#include "sha256.h"

namespace livemap::compat {

namespace {

constexpr std::string_view kUsage =
    "usage: livemap_compat --builds FILE --previous EXE --exe EXE --build-id ID --manifest ID --depot ID --report FILE [--builds-out FILE]\n";
constexpr std::array<std::string_view, 7> kRequired{"--builds", "--previous", "--exe", "--build-id", "--manifest", "--depot", "--report"};
constexpr std::array<std::string_view, 8> kFlags{"--builds", "--previous", "--exe", "--build-id", "--manifest", "--depot", "--report", "--builds-out"};

using Values = std::map<std::string, std::string, std::less<>>;

std::expected<Values, std::string> read_flags(std::span<const std::string_view> args) {
    Values values;
    for (size_t i = 0; i < args.size(); i += 2) {
        if (std::ranges::find(kFlags, args[i]) == kFlags.end()) {
            return std::unexpected(std::format("unknown argument {}", args[i]));
        }
        if (i + 1 == args.size()) {
            return std::unexpected(std::format("{} needs a value", args[i]));
        }
        if (!values.emplace(args[i], args[i + 1]).second) {
            return std::unexpected(std::format("{} is given twice", args[i]));
        }
    }
    return values;
}

std::optional<std::string> value_of(const Values& values, std::string_view flag) {
    const auto found = values.find(flag);
    return found == values.end() ? std::nullopt : std::optional(found->second);
}

std::expected<std::string, std::string> read_text(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(std::format("cannot read {}", path));
    }
    std::ostringstream text;
    text << file.rdbuf();
    return text.str();
}

std::expected<void, std::string> write_text(const std::string& path, std::string_view text) {
    std::ofstream file(path, std::ios::binary);
    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!file.flush()) {
        return std::unexpected(std::format("cannot write {}", path));
    }
    return {};
}

std::expected<void, std::string> clear_stale_output(const CliOptions& options) {
    if (!options.builds_out) {
        return {};
    }
    std::error_code error;
    for (const std::string& input : {options.builds, options.previous, options.exe}) {
        if (std::filesystem::equivalent(*options.builds_out, input, error)) {
            return std::unexpected(std::format("--builds-out {} is an input file", *options.builds_out));
        }
    }
    if (std::filesystem::is_regular_file(*options.builds_out, error) && !std::filesystem::remove(*options.builds_out, error)) {
        return std::unexpected(std::format("cannot remove {}", *options.builds_out));
    }
    return {};
}

struct LoadedExe {
    std::vector<std::byte> file;
    std::string sha256;
    Image image;
};

std::expected<LoadedExe, std::string> read_exe(const std::string& path) {
    const auto text = read_text(path);
    if (!text) {
        return std::unexpected(text.error());
    }
    const std::span<const std::byte> view = std::as_bytes(std::span(*text));
    std::vector file(view.begin(), view.end());
    auto image = load_image(file);
    if (!image) {
        return std::unexpected(std::format("{}: {}", path, image.error()));
    }
    std::string sha256 = sha256_hex(file);
    return LoadedExe{std::move(file), std::move(sha256), std::move(*image)};
}

std::expected<Catalog, std::string> read_catalog(const std::string& path) {
    const auto text = read_text(path);
    if (!text) {
        return std::unexpected(text.error());
    }
    auto document = parse_json(*text);
    if (!document) {
        return std::unexpected(std::format("{}: {}", path, document.error()));
    }
    return Catalog::from_json(std::move(*document));
}

void summarize(const Analysis& analysis, std::ostream& out) {
    out << std::format("{}: build {}\n", verdict_name(analysis.verdict), analysis.build_id);
    for (const std::string& reason : analysis.reasons) {
        out << std::format("  {}\n", reason);
    }
}

std::expected<void, std::string> execute(const CliOptions& options, std::ostream& out) {
    auto catalog = read_catalog(options.builds);
    if (!catalog) {
        return std::unexpected(catalog.error());
    }
    const auto previous = read_exe(options.previous);
    if (!previous) {
        return std::unexpected(previous.error());
    }
    const auto current = read_exe(options.exe);
    if (!current) {
        return std::unexpected(current.error());
    }
    if (auto cleared = clear_stale_output(options); !cleared) {
        return cleared;
    }
    Request request;
    request.previous = &previous->image;
    request.previous_sha256 = previous->sha256;
    request.current = &current->image;
    request.current_sha256 = current->sha256;
    request.build_id = options.build_id;
    request.manifest = options.manifest;
    request.depot = options.depot;
    const auto analysis = analyze(*catalog, request);
    if (!analysis) {
        return std::unexpected(analysis.error());
    }
    if (auto written = write_text(options.report, write_json(report_json(*analysis))); !written) {
        return written;
    }
    summarize(*analysis, out);
    if (!options.builds_out || analysis->verdict == Verdict::Hard) {
        return {};
    }
    return apply_edit(*catalog, analysis->edit).and_then([&catalog, &options] { return write_text(*options.builds_out, write_json(catalog->document())); });
}

}  // namespace

std::expected<CliOptions, std::string> parse_arguments(std::span<const std::string_view> args) {
    const auto values = read_flags(args);
    if (!values) {
        return std::unexpected(values.error());
    }
    for (const std::string_view flag : kRequired) {
        if (!values->contains(flag)) {
            return std::unexpected(std::format("{} is required", flag));
        }
    }
    CliOptions options;
    options.builds = values->at("--builds");
    options.previous = values->at("--previous");
    options.exe = values->at("--exe");
    options.build_id = values->at("--build-id");
    options.manifest = values->at("--manifest");
    options.depot = values->at("--depot");
    options.report = values->at("--report");
    options.builds_out = value_of(*values, "--builds-out");
    if (!is_steam_id(options.build_id) || !is_steam_id(options.manifest) || !is_steam_id(options.depot)) {
        return std::unexpected("--build-id, --manifest and --depot are Steam ids: decimal digits without a leading zero");
    }
    return options;
}

int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    const auto options = parse_arguments(args);
    if (!options) {
        err << std::format("error: {}\n{}", options.error(), kUsage);
        return kExitUsage;
    }
    if (const auto done = execute(*options, out); !done) {
        err << std::format("error: {}\n", done.error());
        return kExitInput;
    }
    return kExitJudged;
}

}  // namespace livemap::compat
