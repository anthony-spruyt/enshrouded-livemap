#include "sha256.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <format>
#include <string>

namespace livemap::compat {

namespace {

constexpr size_t kBlockSize = 64;
constexpr size_t kLengthSize = 8;

constexpr std::array<uint32_t, 64> kRound = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

using State = std::array<uint32_t, 8>;

uint32_t load_be32(std::span<const std::byte, 4> bytes) {
    uint32_t value = 0;
    for (const std::byte b : bytes) {
        value = (value << 8) | std::to_integer<uint32_t>(b);
    }
    return value;
}

void compress(State& state, std::span<const std::byte, kBlockSize> block) {
    std::array<uint32_t, 64> w{};
    for (size_t i = 0; i < 16; ++i) {
        w[i] = load_be32(block.subspan(i * 4).first<4>());
    }
    for (size_t i = 16; i < w.size(); ++i) {
        const uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    State v = state;
    for (size_t i = 0; i < w.size(); ++i) {
        const uint32_t s1 = std::rotr(v[4], 6) ^ std::rotr(v[4], 11) ^ std::rotr(v[4], 25);
        const uint32_t choose = (v[4] & v[5]) ^ (~v[4] & v[6]);
        const uint32_t t1 = v[7] + s1 + choose + kRound[i] + w[i];
        const uint32_t s0 = std::rotr(v[0], 2) ^ std::rotr(v[0], 13) ^ std::rotr(v[0], 22);
        const uint32_t majority = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        const uint32_t t2 = s0 + majority;
        std::ranges::rotate(v, v.end() - 1);
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (size_t i = 0; i < state.size(); ++i) {
        state[i] += v[i];
    }
}

}  // namespace

std::string sha256_hex(std::span<const std::byte> data) {
    State state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t done = 0;
    while (data.size() - done >= kBlockSize) {
        compress(state, data.subspan(done).first<kBlockSize>());
        done += kBlockSize;
    }

    // The tail, a 0x80 marker and the bit length fill one or two final blocks.
    std::array<std::byte, 2 * kBlockSize> tail{};
    const size_t rest = data.size() - done;
    std::ranges::copy(data.subspan(done), tail.begin());
    tail[rest] = std::byte{0x80};
    const size_t tail_size = rest + 1 + kLengthSize <= kBlockSize ? kBlockSize : 2 * kBlockSize;
    const uint64_t bits = static_cast<uint64_t>(data.size()) * 8;
    for (size_t i = 0; i < kLengthSize; ++i) {
        tail[tail_size - 1 - i] = static_cast<std::byte>(bits >> (8 * i));
    }
    for (size_t at = 0; at < tail_size; at += kBlockSize) {
        compress(state, std::span<const std::byte>(tail).subspan(at).first<kBlockSize>());
    }

    std::string hex;
    for (const uint32_t word : state) {
        hex += std::format("{:08x}", word);
    }
    return hex;
}

}  // namespace livemap::compat
