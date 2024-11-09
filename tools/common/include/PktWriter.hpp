#ifndef PKTWRITER_HPP
#define PKTWRITER_HPP

#include "Pkt.hpp"
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace Pkt {
class Writer {
public:
  // Constructor that validates PKT file format
  explicit Writer(const std::string &filePath);
  ~Writer();

  // Write entries to file
  uint64_t write(const std::vector<const Pkt::Entry *> &packets);

  // Write entries to file
  uint64_t write(const std::vector<Pkt::Entry> &packets);

private:
  std::ofstream outputFile;

  // Generates the header for the file
  Pkt::Header generate_header(uint64_t numEntries) const;
};
} // namespace Pkt
#endif // PKTWRITER_HPP
