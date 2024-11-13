#ifndef EXPERIMENT_ICLASSIFIER_HPP
#define EXPERIMENT_ICLASSIFIER_HPP

#include "Pkt.hpp"
#include "json.hpp"
#include <cstdint>

namespace Experiment {
class IClassifier {
public:
  IClassifier(nlohmann::json classifier_params) {};
  virtual void train(Pkt::Entry *entry) = 0;
  virtual void classify(Pkt::Entry *entry) = 0;
  virtual uint64_t get_training_size(uint64_t dataset_size) const = 0;
  virtual void print() const = 0;
};
} // namespace Experiment

#endif // !EXPERIMENT_ICLASSIFIER_HPP
