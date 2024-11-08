#include "PktWriter.hpp"
#include <cstdint>
#include <fstream>

namespace Pkt {
// Constructor that validates PKT file format
Writer::Writer(const std::string &filePath) :
  outputFile{filePath, std::ios::out | std::ios::binary} {
  if (!outputFile.is_open()) {
    std::runtime_error("Failed to open output file.");
  }
}

Writer::~Writer() {
  outputFile.close();
}

// Write entries to file
uint64_t Writer::write(const std::vector<const Pkt::Entry *> &packets) {
  // Write header
  const auto header{ generate_header(packets.size()) };
  outputFile.write(reinterpret_cast<const char *>(&header), sizeof(Pkt::Header));

  // Write contents
  for (auto &p : packets) {
    outputFile.write(reinterpret_cast<const char *>(&p), sizeof(Pkt::Entry));
  }

  return sizeof(Pkt::Header) + packets.size() * sizeof(Pkt::Entry);
}

// Generates the header for the file
Pkt::Header Writer::generate_header(uint64_t numEntries) const {
  constexpr auto magicString{ Pkt::to_array(Defs::fileInfoVersion) };
  return Header{ magicString, numEntries, {} };
}
} // namespace Pkt
