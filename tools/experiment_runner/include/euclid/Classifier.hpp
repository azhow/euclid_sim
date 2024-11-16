#ifndef EUCLID_CLASSIFIER_HPP
#define EUCLID_CLASSIFIER_HPP

#include <iostream>

#include "../experiment/IClassifier.hpp"
#include "ExtendedCountSketch.hpp"

namespace Euclid {
class Classifier : public Experiment::IClassifier {
public:
  Classifier(nlohmann::json classifier_params)
      : IClassifier(classifier_params),
        sensitivity_(classifier_params["sensitivity"]),
        count_sketch_(classifier_params["count_sketch_depth"], classifier_params["count_sketch_width"]),
        observation_window_(classifier_params["observation_window"]) {}

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
    std::cout << "\t\tCount Sketch Depth: " << count_sketch_.get_depth() << std::endl;
    std::cout << "\t\tCount Sketch Width: " << count_sketch_.get_width() << std::endl;
    std::cout << "\t\tObservation Window Size: " << observation_window_ << std::endl;
  }

private:
  const float sensitivity_;
  ExtendedCountSketch count_sketch_;
  const uint64_t observation_window_;
};

} // namespace Euclid

#endif // !EUCLID_CLASSIFIER_HPP
