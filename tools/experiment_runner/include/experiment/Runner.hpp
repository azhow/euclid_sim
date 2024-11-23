#ifndef EXPERIMENT_RUNNER_HPP
#define EXPERIMENT_RUNNER_HPP

#include "MappedPktFile.hpp"
#include "json.hpp"

#include <filesystem>
#include <iostream>
#include <memory>

#include "Diagnoser.hpp"
#include "IClassifier.hpp"

// TODO: this include is temporary -- remove in the future in favor of Factory
#include "../euclid/Classifier.hpp"

namespace Experiment {
class Runner {
public:
  Runner(nlohmann::json experimentConfig)
      : name{experimentConfig["name"]}, input{experimentConfig["input"]},
        output{experimentConfig["output"]},
        classifier{create_classifier(experimentConfig["classifier"])} {}

  void run_experiment() {
    run_training(classifier.get());
    run_classification(classifier.get());
    diagnoser.print();
  }

  void print() const {
    std::cout << "Experiment: " << name << "\n";
    std::cout << "\tInput Size: " << input.get_entry_count() << "\n";
    std::cout << "\tOutput: " << output << std::endl;
    classifier->print();
  }

private:
  const std::string name;
  MappedPktFile input;
  const std::filesystem::path output;
  const std::unique_ptr<IClassifier> classifier;
  // Diagnoser is only used during classification
  Diagnoser diagnoser;

  std::unique_ptr<IClassifier>
  create_classifier(const nlohmann::json &classifierConfig) {
    std::unique_ptr<IClassifier> classifier{nullptr};

    // Use the classifier name to instanstantiate the classifier
    const std::string classifierName{classifierConfig["name"]};

    if (classifierName == "EUCLID") {
      // Create euclid classifier
      classifier =
          std::make_unique<Euclid::Classifier>(classifierConfig["parameters"]);
    }

    return classifier;
  }

  void run_training(IClassifier *classifier) {
    classifier->train(input);
  }

  void run_classification(IClassifier *classifier) {
    classifier->classify(input, diagnoser);
  }
};

} // namespace Experiment

#endif // !EXPERIMENT_RUNNER_HPP
