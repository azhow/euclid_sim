// MappedFile.cpp

#include "MappedFile.hpp"

MappedFile::MappedFile(const std::string &filePath)
    : fileDescriptor(-1), fileSize(0), mappedData(nullptr), currentPosition(0) {

    // Open the file
    fileDescriptor = open(filePath.c_str(), O_RDONLY);
    if (fileDescriptor == -1) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    // Get the file size
    struct stat fileStat;
    if (fstat(fileDescriptor, &fileStat) == -1) {
        close(fileDescriptor);
        throw std::runtime_error("Failed to get file size for: " + filePath);
    }
    fileSize = fileStat.st_size;

    // Memory map the file with MAP_POPULATE to load all pages
    mappedData = mmap(nullptr, fileSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE, fileDescriptor, 0);
    if (mappedData == MAP_FAILED) {
        close(fileDescriptor);
        throw std::runtime_error("Failed to memory map file: " + filePath);
    }
}

MappedFile::~MappedFile() {
    if (mappedData != MAP_FAILED && mappedData != nullptr) {
        munmap(mappedData, fileSize);
    }
    if (fileDescriptor != -1) {
        close(fileDescriptor);
    }
}

size_t MappedFile::size() const {
    return fileSize;
}

const char* MappedFile::data() const {
    return static_cast<const char*>(mappedData);
}
