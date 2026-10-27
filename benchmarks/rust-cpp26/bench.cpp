#include <algorithm>
#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
static inline std::uint64_t splitmix64(std::uint64_t x) {
    x += UINT64_C(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}
static std::uint64_t hash_mix(std::uint64_t seed) {
    std::uint64_t state = seed ^ UINT64_C(0xdedab00b15c0ffee);
    std::uint64_t acc = 0;
    for (std::uint64_t i = 0; i < 6'000'000; ++i) {
        state = splitmix64(state ^ i);
        acc ^= std::rotl(state, static_cast<int>(i & 63));
    }
    return acc;
}
static std::uint64_t scan(std::uint64_t seed) {
    constexpr std::size_t N = 4'194'304;
    std::vector<std::uint32_t> v(N);
    const auto offset = static_cast<std::uint32_t>(seed) * UINT32_C(1013904223);
    for (std::size_t i = 0; i < N; ++i) {
        v[i] = static_cast<std::uint32_t>(i) * UINT32_C(1664525) + offset;
    }
    std::uint64_t sum = 0;
    for (std::uint32_t round = 0; round < 6; ++round) {
        for (auto x : v) {
            if ((x & 7u) == round)
                sum += static_cast<std::uint64_t>(x) ^ static_cast<std::uint64_t>(round);
        }
    }
    return sum;
}
static std::uint64_t random_gather(std::uint64_t seed) {
    constexpr std::size_t N = 1'048'576;
    std::vector<std::uint32_t> v(N);
    const auto offset = static_cast<std::uint32_t>(seed) * UINT32_C(1013904223);
    for (std::size_t i = 0; i < N; ++i) {
        v[i] = static_cast<std::uint32_t>(i) * UINT32_C(1664525) + offset;
    }
    std::uint64_t state = (seed | UINT64_C(1)) ^ UINT64_C(0x9e3779b97f4a7c15);
    std::uint64_t sum = 0;
    for (std::uint32_t i = 0; i < 8'000'000; ++i) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        sum += v[static_cast<std::size_t>(state) & (N - 1)];
    }
    return sum;
}
static std::uint64_t integer_sort(std::uint64_t seed) {
    constexpr std::size_t N = 200'000;
    std::vector<std::uint32_t> v(N);
    std::uint64_t state = seed ^ UINT64_C(0xabcd1234beef9876);
    for (std::size_t i = 0; i < N; ++i) {
        state = splitmix64(state);
        v[i] = static_cast<std::uint32_t>(state >> 32);
    }
    std::sort(v.begin(), v.end());
    std::uint64_t sum = 0;
    for (std::size_t i = 0; i < N; i += 997)
        sum += static_cast<std::uint64_t>(v[i]) * (i + 1);
    return sum;
}
int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: bench <hash|scan|gather|sort> <seed>\n";
        return 2;
    }
    std::string task = argv[1];
    std::uint64_t seed = std::strtoull(argv[2], nullptr, 10);
    const auto start = std::chrono::steady_clock::now();
    std::uint64_t result = 0;
    if (task == "hash") result = hash_mix(seed);
    else if (task == "scan") result = scan(seed);
    else if (task == "gather") result = random_gather(seed);
    else if (task == "sort") result = integer_sort(seed);
    else { std::cerr << "invalid task\n"; return 2; }
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now() - start).count();
    std::cout << "checksum=" << std::hex << std::setw(16) << std::setfill('0') << result
              << "\nelapsed_ns=" << std::dec << elapsed << "\n";
}
