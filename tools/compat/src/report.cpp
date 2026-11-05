#include "report.h"

#include <format>
#include <string>
#include <utility>
#include <vector>

namespace livemap::compat {

namespace {

Json hex(uint64_t value) {
    return Json::string(std::format("0x{:x}", value));
}

Json optional_hex(const std::optional<uint32_t>& value) {
    return value ? hex(*value) : Json::null();
}

Json region_json(const std::optional<Region>& region) {
    if (!region) {
        return Json::null();
    }
    Json out = Json::object();
    out.set("kind", Json::string(region->window ? "window" : "function"));
    out.set("begin", hex(region->begin));
    out.set("end", hex(region->end));
    return out;
}

Json branches_json(const std::vector<Branch>& branches) {
    Json out = Json::array();
    for (const Branch& branch : branches) {
        Json one = Json::object();
        one.set("from", hex(branch.from));
        one.set("to", hex(static_cast<uint64_t>(branch.target)));
        out.push(std::move(one));
    }
    return out;
}

Json difference_json(const std::optional<Difference>& difference) {
    if (!difference) {
        return Json::null();
    }
    Json out = Json::object();
    out.set("kind", Json::string(difference->kind));
    out.set("rva", hex(difference->rva));
    out.set("base_rva", hex(difference->base_rva));
    return out;
}

Json site_json(const SiteReport& site) {
    Json out = Json::object();
    out.set("site", Json::string(site.site));
    out.set("mandatory", Json::boolean(site.mandatory));
    out.set("matches", Json::number(site.matches));
    out.set("rva", optional_hex(site.rva));
    out.set("base_rva", optional_hex(site.base_rva));
    out.set("region", region_json(site.region));
    out.set("base_region", region_json(site.base_region));
    out.set("hook_aligned", site.hook_aligned ? Json::boolean(*site.hook_aligned) : Json::null());
    out.set("branches_into_hook", branches_json(site.into_hook));
    out.set("difference", difference_json(site.difference));
    return out;
}

Json exe_json(const ExeInfo& exe) {
    Json out = Json::object();
    out.set("time_date_stamp", Json::number(exe.time_date_stamp));
    out.set("size_of_image", hex(exe.size_of_image));
    out.set("sha256", Json::string(exe.sha256));
    return out;
}

Json base_json(const Analysis& analysis) {
    Json out = Json::object();
    out.set("label", Json::string(analysis.base_label));
    out.set("sigset", Json::string(analysis.base_sigset));
    return out;
}

Json operands_json(const std::vector<NamedValue>& operands) {
    Json out = Json::object();
    for (const NamedValue& operand : operands) {
        out.set(operand.name, hex(operand.value));
    }
    return out;
}

}  // namespace

Json report_json(const Analysis& analysis) {
    Json out = Json::object();
    out.set("result", Json::string(std::string(verdict_name(analysis.verdict))));
    out.set("build_id", Json::string(analysis.build_id));
    out.set("manifest", Json::string(analysis.manifest));
    out.set("exe", exe_json(analysis.exe));
    out.set("base", base_json(analysis));
    out.set("matched_row", analysis.matched_label ? Json::string(*analysis.matched_label) : Json::null());
    Json reasons = Json::array();
    for (const std::string& reason : analysis.reasons) {
        reasons.push(Json::string(reason));
    }
    out.set("reasons", std::move(reasons));
    out.set("undecodable_functions", analysis.undecodable_functions ? Json::number(*analysis.undecodable_functions) : Json::null());
    out.set("operands", operands_json(analysis.operands));
    Json sites = Json::array();
    for (const SiteReport& site : analysis.sites) {
        sites.push(site_json(site));
    }
    out.set("sites", std::move(sites));
    return out;
}

std::string_view verdict_name(Verdict verdict) {
    switch (verdict) {
        case Verdict::Known:
            return "known";
        case Verdict::Easy:
            return "easy";
        case Verdict::Hard:
            return "hard";
    }
    return "hard";
}

}  // namespace livemap::compat
