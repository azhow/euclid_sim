#include "Pkt.hpp"
#include "PktWriter.hpp"
#include "MappedPktFile.hpp"
#include "cxxopts.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <ostream>
#include <string>
#include <random>

int main(int argc, char *argv[]) {
  cxxopts::Options options(
      "PKT Mixer",
      "This tool mixes legitimate and malicious PKT files "
      "into a new mixed file. The datasets are split into the following:\nn/2 "
      "-> Training phase\nn/4 -> Pre-Attack with legitimate traffic\npn/2 -> "
      "Attack phase\nn/4 -> Post-Attack");

  options.add_options()
    ("m,malicious", "The malicious PKT file path", cxxopts::value<std::string>())
    ("l,legitimate", "Legitimate PKT file path", cxxopts::value<std::string>())
    ("o,output", "Output directory for the new PKT file", cxxopts::value<std::string>())
    ("n,num", "Number of packets for the detection phase mixed PKT file", cxxopts::value<uint64_t>())
    ("p,percentage", "Percentage of malicious traffic to be added (0-1.0)", cxxopts::value<float>())
    ("h,help", "Print help");

  try {
    auto result = options.parse(argc, argv);

    // Check if help was requested
    if (result.count("help")) {
      std::cout << options.help() << std::endl;
      return 0;
    }

    // Check all parameters provided
    if (!result.count("m") || !result.count("l") || !result.count("o") ||
        !result.count("n") || !result.count("p")) {
      std::cerr << "Error: Missing parameters." << std::endl;
      std::cout << options.help() << std::endl;
      return 1;
    }

    // Check that the percentage value makes sense
    const auto percentage{result["p"].as<float>()};
    if (percentage > 1.0 || percentage < 0) {
      std::cerr << "Error: Percentage parameter out of range (0-1.0)."
                << std::endl;
      return 2;
    }

    std::cout << "Opening input files..." << std::endl;

    // Open input files
    MappedPktFile legitFile(result["l"].as<std::string>());
    MappedPktFile maliciousFile(result["m"].as<std::string>());

    std::cout << "Checking that there are enough entries in the input datasets..." << std::endl;

    // Check that the number that there are enough entries for the new dataset
    const auto detectionPhaseSize{result["n"].as<uint64_t>()};
    const auto totalNumMaliciousEntries{ detectionPhaseSize/2 * percentage };
    if ((detectionPhaseSize + detectionPhaseSize / 2) - totalNumMaliciousEntries > legitFile.get_entry_count()) {
      std::cerr << "Error: Not enough entries in the legitimate dataset for the chosen value of n."
                << std::endl;
      return 3;
    }

    if (totalNumMaliciousEntries > maliciousFile.get_entry_count()) {
      std::cerr << "Error: Not enough entries in the malicious dataset for the chosen value of n."
                << std::endl;
      return 3;
    }

    std::cout << "Creating new dataset..." << std::endl;

    // Create the mixed dataset with the full size already
    std::vector<const Pkt::Entry*> mixedData{};
    mixedData.reserve(detectionPhaseSize + (detectionPhaseSize/2));

    std::cout << "Adding training phase data..." << std::endl;
    std::cout << "Adding pre-attack phase data..." << std::endl;

    // Insert the data for the training and pre-attack phases
    for (size_t i = 0; i <= (detectionPhaseSize / 2) + (detectionPhaseSize / 4); ++i) {
      const auto entry = legitFile.read_next_entry();
      mixedData.emplace_back(entry);
    }

    std::cout << "Adding attack phase data..." << std::endl;
    // Insert the data for the attack phase
    std::random_device rd;  // Seed the random engine
    std::default_random_engine engine{rd()};  // Mersenne Twister engine
    std::bernoulli_distribution distribution{percentage};

    for (size_t i = 0; i <= (detectionPhaseSize / 2); ++i) {
      const Pkt::Entry* entry = nullptr;
      if(distribution(engine)) {
        entry = maliciousFile.read_next_entry();
        const_cast<Pkt::Entry*>(entry)->rsvdAnnotation = 1;
      } else {
        entry = legitFile.read_next_entry();
      }

      mixedData.emplace_back(entry);
    }

    std::cout << "Adding post-attack phase data..." << std::endl;

    // Insert the data for the post-attack phase
    for (size_t i = 0; i <= (detectionPhaseSize / 4); ++i) {
      const auto entry = legitFile.read_next_entry();
      mixedData.emplace_back(entry);
    }

    std::cout << "Gathered " << mixedData.size() << " entries for the output dataset..." << std::endl;

    // Generate output file name
    const std::filesystem::path outputDirectory{result["o"].as<std::string>()};
    const std::string outputFilename{"mixed_n" + std::to_string(detectionPhaseSize) + "_p"
        + std::to_string(static_cast<uint32_t>(percentage * 10000)) + ".pkt"};

    std::string outputFilePath{outputDirectory / outputFilename};
    std::cout << "Creating the output file: " << outputFilePath << "..." << std::endl;

    // Save mixed data to file
    Pkt::Writer outputFile{ outputFilePath };

    std::cout << "Writing mixed dataset..." << std::endl;
    outputFile.write(mixedData);

    std::cout << "Saved output file!" << std::endl;

    std::cout << "Done!" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
