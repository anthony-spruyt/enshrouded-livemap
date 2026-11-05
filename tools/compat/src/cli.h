#pragma once

#include <expected>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>

namespace livemap::compat {

// 0 for any verdict, 1 when the inputs cannot be judged, 2 for a command line that is wrong.
constexpr int kExitJudged = 0;
constexpr int kExitInput = 1;
constexpr int kExitUsage = 2;

struct CliOptions {
    std::string builds;
    std::string previous;
    std::string exe;
    std::string build_id;
    std::string manifest;
    std::string depot;
    std::string report;
    std::optional<std::string> builds_out;
};

std::expected<CliOptions, std::string> parse_arguments(std::span<const std::string_view> args);

// Runs the tool for the arguments after the program name. The verdict and the reasons go to `out`, problems to `err`.
int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

}  // namespace livemap::compat
