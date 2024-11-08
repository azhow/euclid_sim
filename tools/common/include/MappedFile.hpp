// MappedFile.hpp (Modified Constructor)

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

class MappedFile {
public:
    // Constructor and Destructor
    explicit MappedFile(const std::string &filePath);
    ~MappedFile();

    // Deleted copy and move constructors/assignments
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&&) = delete;
    MappedFile& operator=(MappedFile&&) = delete;

    // Get the size of the file
    size_t size() const;

protected:
    const char* data() const;

    size_t currentPosition; // Track the current read position

private:
    int fileDescriptor;
    size_t fileSize;
    void *mappedData;
};
