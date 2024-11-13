#ifndef EUCLID_CLASSIFIER_HPP
#define EUCLID_CLASSIFIER_HPP

#include "Pkt.hpp"

#include <iostream>

#include "../experiment/IClassifier.hpp"

namespace Euclid {
class Classifier : public Experiment::IClassifier {
public:
  Classifier(nlohmann::json classifier_params)
      : IClassifier(classifier_params),
        sensitivity_(classifier_params["sensitivity"]),
        csDepth_(classifier_params["count_sketch_depth"]),
        csWidth_(classifier_params["count_sketch_width"]),
        observationWindow_(classifier_params["observation_window"]) {}

  virtual void train(Pkt::Entry *entry) override {
    // TODO
  }

  virtual void classify(Pkt::Entry *entry) override {
    // TODO
  }

  virtual uint64_t get_training_size(uint64_t dataset_size) const override {
    return dataset_size / 2;
  }

  virtual void print() const override {
    std::cout << "\tClassifier: EUCLID" << std::endl;
    std::cout << "\tParams:" << std::endl;
    std::cout << "\t\tSensitivity: " << sensitivity_ << std::endl;
    std::cout << "\t\tCount Sketch Depth: " << csDepth_ << std::endl;
    std::cout << "\t\tCount Sketch Width: " << csWidth_ << std::endl;
    std::cout << "\t\tObservation Window Size: " << observationWindow_ << std::endl;
  }

private:
  const float sensitivity_;
  const uint64_t csDepth_;
  const uint64_t csWidth_;
  const uint64_t observationWindow_;
};

} // namespace Euclid

#endif // !EUCLID_CLASSIFIER_HPP
