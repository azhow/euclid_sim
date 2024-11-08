// MappedPktFile.hpp

#ifndef MAPPEDPKTFILE_HPP
#define MAPPEDPKTFILE_HPP

#include "MappedFile.hpp"
#include "Pkt.hpp"
#include <cstdint>
#include <string>

class MappedPktFile : public MappedFile {
public:
    // Constructor that validates PKT file format
    explicit MappedPktFile(const std::string &filePath);

    // Get the number of entries in the file
    uint64_t getEntryCount() const;

    // Read the next entry
    const Pkt::Entry* readNextEntry();

    // Reset the current position to the beginning of the entries
    void resetEntries();

private:
    uint64_t entryCount;
    size_t entryStartPosition; // Position where entries begin

    // Validates PKT file format and initializes entryCount and entryStartPosition
    void validateAndInitialize();
};

#endif // MAPPEDPKTFILE_HPP
