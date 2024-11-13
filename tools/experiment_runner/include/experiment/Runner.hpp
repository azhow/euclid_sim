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
  }

  void print() const {
    std::cout << "Experiment: " << name << std::endl;
    std::cout << "Input Size: " << input.getEntryCount() << std::endl;
    std::cout << "Output: " << output << std::endl;
    classifier->print();
  }

private:
  const std::string name;
  MappedPktFile input;
  const std::filesystem::path output;
  const std::unique_ptr<IClassifier> classifier;
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
    // TODO -- Is the training entries part of the dataset or the classifier?
    // Eitherway, it should not be read until the end
    const auto training_size{ classifier->get_training_size(input.getEntryCount()) };
    for (size_t count = 0; count < training_size; ++count) {
      const Pkt::Entry *entry = input.readNextEntry();
      classifier->train(const_cast<Pkt::Entry *>(entry));
    }
  }

  void run_classification(IClassifier *classifier) {
    // Reads from the end of the training until the end
    for (const Pkt::Entry *entry = input.readNextEntry(); entry != nullptr; entry = input.readNextEntry()) {
      classifier->classify(const_cast<Pkt::Entry *>(entry));
      diagnoser.collect_stats(entry);
    }
  }
};

} // namespace Experiment

#endif // !EXPERIMENT_RUNNER_HPP
