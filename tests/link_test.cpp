// Plain assert-based tests for the map link (no framework, runs on the build PC).
#include <cstdio>
#include <cstdlib>
#include <print>
#include <source_location>
#include <string>

#include "../src/link.h"

namespace link = livemap::link;

static int failures = 0;

static void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok) {
        std::print("FAIL {}:{}\n", where.file_name(), where.line());
        ++failures;
    }
}

int main() {
    check(link::query_port("{\n\t\"name\": \"x\",\n\t\"queryPort\": 15637,\n\t\"slotCount\": 2\n}") == 15637);
    check(link::query_port("{\"queryPort\":15699}") == 15699);
    check(link::query_port("{\"gamePort\": 15636}") == 0);
    check(link::query_port("{\"queryPort\": \"x\"}") == 0);
    check(link::query_port("{\"queryPort\": 70000}") == 0);

    check(link::valid_ip("203.0.113.5"));
    check(link::valid_ip("2001:db8::1"));
    check(!link::valid_ip("203.0.113"));
    check(!link::valid_ip("256.1.1.1"));
    check(!link::valid_ip("<html>"));
    check(!link::valid_ip(""));
    check(!link::valid_ip("1::2::3"));

    check(link::make("", "203.0.113.5", 15637, "abc") == "http://203.0.113.5:15637/?key=abc");
    check(link::make("", "2001:db8::1", 15637, "abc") == "http://[2001:db8::1]:15637/?key=abc");
    check(link::make("https://karte.example.ch/", "203.0.113.5", 15637, "abc") == "https://karte.example.ch/?key=abc");
    check(link::make("http://map.example.com:8080", "", 0, "k") == "http://map.example.com:8080/?key=k");
    check(link::make("", "", 15637, "abc").empty());
    check(link::make("map.example.com:8080", "203.0.113.5", 15637, "k") == "http://203.0.113.5:15637/?key=k");
    check(link::make("map.example.com", "", 0, "k").empty());
    check(link::make("ftp://map.example.com", "203.0.113.5", 15637, "k") == "http://203.0.113.5:15637/?key=k");

    check(link::has_scheme("http://map.example.com"));
    check(link::has_scheme("https://map.example.com"));
    check(!link::has_scheme("map.example.com"));
    check(!link::has_scheme("map.example.com:8080"));
    check(!link::has_scheme("ftp://map.example.com"));
    check(!link::has_scheme("//map.example.com"));
    check(!link::has_scheme(""));
    check(link::has_scheme("HTTPS://map.example.com"));
    check(link::has_scheme("Http://map.example.com"));
    check(!link::has_scheme("httpx://map.example.com"));
    check(!link::has_scheme("xhttp://map.example.com"));
    check(!link::has_scheme("://map.example.com"));
    check(!link::has_scheme("http:/map.example.com"));
    check(!link::has_scheme("map.example.com/?next=http://elsewhere"));
    check(link::has_scheme("https://map.example.com/?next=ftp://x"));
    check(link::make("HTTPS://karte.example.ch/", "203.0.113.5", 15637, "abc") == "HTTPS://karte.example.ch/?key=abc");

    check(link::chat_line("http://203.0.113.5:15637/?key=abc", 15637) == "Live map: 203.0.113.5:15637/abc");
    check(link::chat_line("http://map.example.com:8080/?key=k", 8080) == "Live map: map.example.com:8080/k");
    check(link::short_form("https://karte.example.ch/?key=ourmap") == "karte.example.ch/ourmap");
    check(link::short_form("http://[2001:db8::1]:15637/?key=x1y2") == "[2001:db8::1]:15637/x1y2");

    check(link::key_ok("ourmap"));
    check(link::key_ok("Embervale-33_map"));
    check(link::key_ok("map"));
    check(!link::key_ok("ab"));             // too short
    check(!link::key_ok("our map"));        // space
    check(!link::key_ok("map.json"));       // dot
    check(!link::key_ok("State"));          // a route of the server
    check(link::key_equal("OurMap", "ourmap"));
    check(!link::key_equal("ourmap", "ourmaps"));
    check(link::chat_line("", 15637).find("port 15637") != std::string::npos);

    if (failures == 0) {
        std::printf("link tests passed\n");
        return EXIT_SUCCESS;
    }
    std::printf("%d link test(s) failed\n", failures);
    return EXIT_FAILURE;
}
