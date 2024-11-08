// MappedPktFile.cpp

#include "MappedPktFile.hpp"
#include <algorithm>
#include <cstring>

MappedPktFile::MappedPktFile(const std::string &filePath)
    : MappedFile(filePath), entryCount(0), entryStartPosition(0) {
  validateAndInitialize();
}

void MappedPktFile::validateAndInitialize() {
  // Expected header size: 8 bytes for "PKTV001X" + 8 bytes for the entry count
  // + 48 bytes reserved
  const size_t headerSize = 8 + sizeof(uint64_t) + 48;
  if (size() < headerSize) {
    throw std::runtime_error(
        "Invalid PKT file: too small to contain a valid header.");
  }

  // Check the magic number "PKTV001X"
  if (std::memcmp(data(), Pkt::Defs::fileInfoVersion, 8) != 0) {
    throw std::runtime_error("Invalid PKT file: incorrect format identifier.");
  }

  // Read the entry count (next 8 bytes after the magic number)
  const Pkt::Header *headerPtr = reinterpret_cast<const Pkt::Header *>(data());
  entryCount = headerPtr->numEntries;

  // Set the position where entries start (8 bytes magic + 8 bytes entry count +
  // 48 bytes reserved)
  entryStartPosition = sizeof(Pkt::Header);

  // Move the current position to the start of entries
  resetEntries();
}

uint64_t MappedPktFile::getEntryCount() const { return entryCount; }

const Pkt::Entry *MappedPktFile::readNextEntry() {
  // Calculate the size of an entry
  constexpr size_t entrySize = sizeof(Pkt::Entry);

  // Check if there are entries left to read
  if (currentPosition + entrySize > size()) {
    return nullptr; // No more entries to read
  }

  // Cast the current position to a PktEntry pointer
  const Pkt::Entry *entry =
      reinterpret_cast<const Pkt::Entry *>(data() + currentPosition);

  // Advance the current position
  currentPosition += entrySize;

  return entry;
}

void MappedPktFile::resetEntries() {
  // Set currentPosition to the beginning of the entries
  currentPosition = entryStartPosition;
}
