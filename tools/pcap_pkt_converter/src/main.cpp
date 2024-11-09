#include "cxxopts.hpp"
#include "Pkt.hpp"
#include "PktWriter.hpp"
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

size_t save_ip_pairs_to_pkt_format(const std::string &pktFilePath, const std::vector<std::array<uint32_t, 4>> &ipPairs) {
  Pkt::Writer writer{ pktFilePath };

  std::vector<Pkt::Entry> entries{};
  entries.reserve(ipPairs.size());
  for (auto &p : ipPairs) {
    entries.emplace_back(Pkt::Entry{p[0], p[1], 0, 0});
  }

  return writer.write(entries);
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
