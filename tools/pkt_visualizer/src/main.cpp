#include "cxxopts.hpp"
#include "MappedPktFile.hpp"
#include "Pkt.hpp"
#include <iostream>

// Convert a 32-bit integer to dotted-decimal IP format
std::string format_ip(uint32_t ip) {
  return std::to_string((ip >> 24) & 0xFF) + "." +
         std::to_string((ip >> 16) & 0xFF) + "." +
         std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
}

int main(int argc, char *argv[]) {
  cxxopts::Options options("PKT Visualizer",
                           "This tool visualizes the contents of PKT files");

  options.add_options()("f,file", "The malicious PKT file path",
                        cxxopts::value<std::string>())("h,help", "Print help");

  try {
    auto result = options.parse(argc, argv);

    // Check if help was requested
    if (result.count("h")) {
      std::cout << options.help() << std::endl;
      return 0;
    }

    // Check all parameters provided
    if (!result.count("f")) {
      std::cerr << "Error: Missing parameters." << std::endl;
      std::cout << options.help() << std::endl;
      return 1;
    }

    // Open input files
    MappedPktFile inputFile(result["f"].as<std::string>());

    std::cout << "Entry count: " << inputFile.getEntryCount() << std::endl;

    // Insert the data for the training and pre-attack phases
    size_t count{ 0 };
    for (const Pkt::Entry *entry = inputFile.readNextEntry(); entry != nullptr; entry = inputFile.readNextEntry()) {
      if ((count <= 5) || (inputFile.getEntryCount() - count <= 5)) {
         std::cout << count + 1
              << ":\n\tSource IP: " << format_ip(entry->srcIp)
              << "\n\tDestination IP: " << format_ip(entry->dstIp)
              << "\n\tReserved Exp: " << entry->rsvdExp;
              << "\n\tReserved Annotation: " << entry->rsvdAnnotation;
              << "\n\tMalicious: " << (entry->is_malicious() ? "Yes" : "No") << "\n";
      }
      else if ((count > (inputFile.getEntryCount() / 2)) && (count <= (inputFile.getEntryCount() / 2) + 20)) {
         std::cout << count + 1
              << ":\n\tSource IP: " << format_ip(entry->srcIp)
              << "\n\tDestination IP: " << format_ip(entry->dstIp)
              << "\n\tReserved Exp: " << entry->rsvdExp;
              << "\n\tReserved Annotation: " << entry->rsvdAnnotation;
              << "\n\tMalicious: " << (entry->is_malicious() ? "Yes" : "No") << "\n";
      }

      count++;
    }
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
