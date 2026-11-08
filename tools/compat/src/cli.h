#pragma once

#include <expected>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>

namespace livemap::compat {

// 0 for any verdict or a check that passed, 1 when the inputs cannot be judged, 2 for a command line that is wrong, 3 for a
// check that found problems.
constexpr int kExitJudged = 0;
constexpr int kExitInput = 1;
constexpr int kExitUsage = 2;
constexpr int kExitFailed = 3;

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

// Runs the tool for the arguments after the program name: the analysis of a new build, or with `check` first, the checks of
// the sigset of the row that describes one exe. The verdict and the reasons go to `out`, problems to `err`.
int run_cli(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

}  // namespace livemap::compat
