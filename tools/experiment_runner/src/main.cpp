#include "cxxopts.hpp"
#include "json.hpp"

#include <iostream>
#include <fstream>
#include <string>

#include "experiment/Runner.hpp"

int main(int argc, char *argv[]) {
  cxxopts::Options options(
      "Experiment executer",
      "This tool executes the experiments defined in a configuration JSON file.");

  options.add_options()
    ("f,file", "Input JSON configuration file with the experiments description", cxxopts::value<std::string>())
    ("h,help", "Print help");

  options.parse_positional({"file"});

  try {
    auto result = options.parse(argc, argv);

    // Check if help was requested
    if (result.count("help")) {
      std::cout << options.help() << std::endl;
      return 0;
    }

    // Check all parameters provided
    if (!result.count("f")) {
      std::cerr << "Error: Missing experiment configuration file." << std::endl;
      std::cout << options.help() << std::endl;
      return 1;
    }

    // Load JSON from a file
    std::ifstream json_file(result["f"].as<std::string>());
    nlohmann::json parsed_json;
    json_file >> parsed_json;

    for (const auto& experimentConfig : parsed_json["experiments"]) {
      std::cout << "Starting experiment..." << std::endl;

      // Create experiment
      Experiment::Runner experiment{ experimentConfig };

      experiment.print();
      experiment.run_experiment();

      std::cout << "Experiment finished!" << std::endl;
      std::cout << "=====================================================================================" << std::endl;
    }

    std::cout << "All finished!" << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
