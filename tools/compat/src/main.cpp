#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "cli.h"

int main(int argc, char** argv) {
    const std::span all(argv, static_cast<size_t>(argc));
    std::vector<std::string_view> args;
    for (const char* arg : all.subspan(1)) {
        args.emplace_back(arg);
    }
    return livemap::compat::run_cli(args, std::cout, std::cerr);
}
