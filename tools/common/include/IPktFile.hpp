// MappedPktFile.hpp

#ifndef IPKTFILE_HPP
#define IPKTFILE_HPP

#include "Pkt.hpp"
#include <cstdint>
#include <string>

class IPktFile {
public:
    // Get the number of entries in the file
    virtual uint64_t get_entry_count() const = 0;

    // Read the next entry
    virtual const Pkt::Entry* read_next_entry() = 0;

    // Reset the current position to the beginning of the entries
    virtual void reset() = 0;
};

#endif // IPKTFILE_HPP
