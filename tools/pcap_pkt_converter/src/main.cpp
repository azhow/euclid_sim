#include "cxxopts.hpp"
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iostream>
#include <ostream>
#include <stdexcept>
#include <string>

std::vector<std::array<uint32_t, 4>>
read_ip_pairs_from_pcap(const std::string &pcapFilePath) {
  std::vector<std::array<uint32_t, 4>> ipPairs{};

  // open a pcap file for reading
  pcpp::PcapFileReaderDevice reader(pcapFilePath);

  if (!reader.open()) {
    throw std::runtime_error("Error opening the pcap file");
  }

  std::cout << "Reading packets..." << std::endl;

  // read the first (and only) packet from the file
  pcpp::RawPacket rawPacket;
  while (reader.getNextPacket(rawPacket)) {

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
      // extract source and dest IPs
      pcpp::IPv4Address srcIP =
          parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
      pcpp::IPv4Address destIP =
          parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

      ipPairs.emplace_back(
          std::array<uint32_t, 4>{srcIP.toInt(), destIP.toInt(), 0, 0});
    }
  }

  // close the input file
  reader.close();

  return ipPairs;
}

size_t save_ip_pairs_to_pkt_format(
    const std::string &pktFilePath,
    const std::vector<std::array<uint32_t, 4>> &ipPairs) {
  // Put the pairs into a new file
  std::ofstream outputFile{pktFilePath, std::ios::out | std::ios::binary};

  if (!outputFile.is_open()) {
    std::runtime_error("Failed to open output file.");
  }

  // Write metadata to file header
  const char *fileVersion{"PKTV001X"};
  outputFile.write(fileVersion, sizeof(fileVersion));

  // Write the number of ip pair entries into the file
  const uint64_t pairCount{ipPairs.size()};
  const auto sizeOfCount{sizeof(pairCount)};
  outputFile.write(reinterpret_cast<const char *>(&pairCount), sizeOfCount);

  // Write reserved metadata section
  const size_t sizeOfReservedMetadata{64 - sizeof(fileVersion) - sizeOfCount};
  outputFile.write("0", sizeOfReservedMetadata);

  // Calculate file contents size
  const auto fileSize{sizeof(fileVersion) + sizeOfCount + sizeOfReservedMetadata + pairCount * 16};

  // Write each entry in to the file
  for (auto &p : ipPairs) {
    const auto ipSrc{p[0]};
    const auto ipDst{p[1]};
    const auto rsvd1{p[2]};
    const auto rsvd2{p[3]};
    outputFile.write(reinterpret_cast<const char *>(&ipSrc), sizeof(ipSrc));
    outputFile.write(reinterpret_cast<const char *>(&ipDst), sizeof(ipDst));
    outputFile.write(reinterpret_cast<const char *>(&rsvd1), sizeof(rsvd1));
    outputFile.write(reinterpret_cast<const char *>(&rsvd2), sizeof(rsvd2));
  }

  outputFile.close();

  return fileSize;
}

int main(int argc, char *argv[]) {
  cxxopts::Options options(
      "Pcap2PKT Converter",
      "This tool converts pcap files into simpler PKT files");

  options.add_options()("i,input", "Input pcap file",
                        cxxopts::value<std::string>())(
      "o,output", "Output PKT file path",
      cxxopts::value<std::string>())("h,help", "Print help");

  auto result = options.parse(argc, argv);

  if (result.count("help")) {
    std::cout << options.help() << std::endl;
    return 0;
  }

  if (!result.count("input") || !result.count("output")) {
    std::cerr << "Missing parameters!" << std::endl;
    std::cout << options.help() << std::endl;
    return 1;
  }

  std::cout << "Opening input pcap file..." << std::endl;

  try {
    const auto ipPairs{
        read_ip_pairs_from_pcap(result["input"].as<std::string>())};

    std::cout << "Read " << ipPairs.size() << " packets..." << std::endl;

    std::cout << "Saving to new PKT file..." << std::endl;

    const auto fileSize{save_ip_pairs_to_pkt_format(
        result["output"].as<std::string>(), ipPairs)};

    std::cout << "PKT file size is " << fileSize << " bytes." << std::endl;

    std::cout << "Done!" << std::endl;

  } catch (std::runtime_error &e) {
    std::cerr << "Error happened in converting between pcap and PKT: "
              << e.what() << std::endl;
    return 2;
  } catch (std::exception &e) {
    std::cerr << "Unexpected error occurred: " << e.what() << std::endl;
    return 3;
  }

  return 0;
}
