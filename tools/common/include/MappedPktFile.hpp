// MappedPktFile.hpp

#ifndef MAPPEDPKTFILE_HPP
#define MAPPEDPKTFILE_HPP

#include "MappedFile.hpp"
#include "IPktFile.hpp"
#include "Pkt.hpp"
#include <cstdint>
#include <string>

class MappedPktFile : public MappedFile, public IPktFile {
public:
    // Constructor that validates PKT file format
    explicit MappedPktFile(const std::string &filePath);

    // Get the number of entries in the file
    virtual uint64_t get_entry_count() const override;

    // Read the next entry
    virtual const Pkt::Entry* read_next_entry() override;

    // Reset the current position to the beginning of the entries
    virtual void reset() override;

private:
    uint64_t entryCount;
    size_t entryStartPosition; // Position where entries begin

    // Validates PKT file format and initializes entryCount and entryStartPosition
    void validate_and_initialize();
};

#endif // MAPPEDPKTFILE_HPP
