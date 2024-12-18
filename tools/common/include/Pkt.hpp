#ifndef PKT_HPP
#define PKT_HPP

#include <array>
#include <cstdint>

namespace Pkt {
namespace Defs {
constexpr const char fileInfoVersion[]{"PKTV001X"};
};

template<std::size_t N>
constexpr std::array<char, N - 1> to_array(const char (&str)[N]) {
    std::array<char, N - 1> arr{};
    for (std::size_t i = 0; i < N - 1; ++i) {
        arr[i] = str[i];
    }
    return arr;
}

// Structure representing the header of the PKT file
#pragma pack(push, 1)
struct Header {
  std::array<char, 8> fileInfoVersion;
  uint64_t numEntries;
  std::array<char, 48> reserved;
};
#pragma pack(pop)

// Structure representing an entry in the PKT file
#pragma pack(push, 1)
struct Entry {
  uint32_t srcIp;     // 4 bytes
  uint32_t dstIp;     // 4 bytes
  uint32_t rsvdExp; // 4 bytes
  uint32_t rsvdAnnotation; // 4 bytes

  bool is_original_malicious() const {
    return rsvdAnnotation & 0x1; // First bit indicates malicious status
  }

  bool is_classified_malicious() const {
    return rsvdExp & 0x1; // First bit indicates malicious status
  }
};
#pragma pack(pop)

} // namespace Pkt

#endif
