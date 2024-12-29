#ifndef EXPERIMENT_ICLASSIFIER_HPP
#define EXPERIMENT_ICLASSIFIER_HPP

#include "IPktFile.hpp"
#include "experiment/Diagnoser.hpp"
#include "json.hpp"
#include <cstdint>

namespace Experiment {
class IClassifier {
public:
  IClassifier(nlohmann::json classifier_params) {};
  virtual void run(IPktFile& input, Diagnoser& diagnoser) = 0;
  virtual void print() const = 0;
};
} // namespace Experiment

#endif // !EXPERIMENT_ICLASSIFIER_HPP
