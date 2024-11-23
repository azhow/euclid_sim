#ifndef EUCLID_CLASSIFIER_HPP
#define EUCLID_CLASSIFIER_HPP

#include <cmath>
#include <cstdlib>
#include <iostream>

#include "../experiment/IClassifier.hpp"
#include "ExtendedCountSketch.hpp"
#include "IPktFile.hpp"
#include "experiment/Diagnoser.hpp"

namespace Euclid {
class Classifier : public Experiment::IClassifier {
public:
  Classifier(nlohmann::json classifier_params)
      : IClassifier(classifier_params),
        sensitivity_(classifier_params["sensitivity"]),
        src_count_sketch_(classifier_params["count_sketch_depth"],
                          classifier_params["count_sketch_width"]),
        dst_count_sketch_(classifier_params["count_sketch_depth"],
                          classifier_params["count_sketch_width"]),
        observation_window_(classifier_params["observation_window"]),
        ewma_src_baseline(0), ewma_dst_baseline(0), ewmmd_src_baseline(0),
        ewmmd_dst_baseline(0), threshold_src(0), threshold_dst(0) {}

  virtual void train(IPktFile &input) override {
    const auto training_size{get_training_size(input.get_entry_count())};
    for (size_t count = 1; count <= training_size; ++count) {
      const Pkt::Entry *entry{input.read_next_entry()};

      src_count_sketch_.update(entry->srcIp);
      dst_count_sketch_.update(entry->dstIp);

      // When the first OW is done we set the base values for the moving
      // averages
      if (count == observation_window_) {
        ewma_src_baseline = src_count_sketch_.get_entropy();
        ewma_dst_baseline = dst_count_sketch_.get_entropy();
      }

      if (count % observation_window_ == 0) {
        // Reset ECS
        src_count_sketch_.reset();
        dst_count_sketch_.reset();

        update_training_parameters();
      }
    }

    // Update parameters one last time if needed - OW size is not divisor of training size
    if (training_size % observation_window_ != 0) {
        update_training_parameters();
    }

    std::cout << "============================================================="
                 "=========\n";
    std::cout << "Training done!\n";
    std::cout << "Baseline parameters:\n";
    std::cout << "\tSrc EWMA: " << ewma_src_baseline << "\n";
    std::cout << "\tDst EWMA: " << ewma_dst_baseline << "\n";
    std::cout << "\tSrc EWMMD: " << ewmmd_src_baseline << "\n";
    std::cout << "\tDst EWMMD: " << ewmmd_dst_baseline << "\n";
    std::cout << "\tSrc threshold: " << threshold_src << "\n";
    std::cout << "\tDst threshold: " << threshold_dst << "\n";
    std::cout << "============================================================="
                 "========="
              << std::endl;
  }

  virtual void classify(IPktFile &input,
                        Experiment::Diagnoser &diagnoser) override {
    // Reads from the end of the training until the end
    for (const Pkt::Entry *entry = input.read_next_entry(); entry != nullptr;
         entry = input.read_next_entry()) {
      // classifier->classify(const_cast<Pkt::Entry *>(entry));
      diagnoser.collect_stats(entry);
    }
  }

  virtual uint64_t get_training_size(uint64_t dataset_size) const override {
    return dataset_size / 2;
  }

  virtual void print() const override {
    std::cout << "\tClassifier: EUCLID" << std::endl;
    std::cout << "\tParams:" << std::endl;
    std::cout << "\t\tSensitivity: " << sensitivity_ << std::endl;
    std::cout << "\t\tCount Sketch Depth: "
              << src_count_sketch_.get_depth() << std::endl;
    std::cout << "\t\tCount Sketch Width: "
              << src_count_sketch_.get_width() << std::endl;
    std::cout << "\t\tObservation Window Size: " << observation_window_
              << std::endl;
  }

private:
  const double sensitivity_;
  ExtendedCountSketch src_count_sketch_;
  ExtendedCountSketch dst_count_sketch_;
  const uint64_t observation_window_;

  // Training calculated values
  const double smoothing_{20 * 2e-8};
  double ewma_src_baseline;
  double ewma_dst_baseline;
  double ewmmd_src_baseline;
  double ewmmd_dst_baseline;
  double threshold_src;
  double threshold_dst;

  double ewma_;
  double ewmmd_;

  void update_training_parameters() {
      const auto src_entropy{src_count_sketch_.get_entropy()};
      const auto dst_entropy{dst_count_sketch_.get_entropy()};

      ewma_src_baseline =
          smoothing_ * src_entropy + (1 - smoothing_) * ewma_src_baseline;
      ewma_dst_baseline =
          smoothing_ * dst_entropy + (1 - smoothing_) * ewma_dst_baseline;

      ewmmd_src_baseline =
          smoothing_ * std::fabs(src_entropy - ewma_src_baseline) +
          (1 - smoothing_) * ewmmd_src_baseline;
      ewmmd_dst_baseline =
          smoothing_ * std::fabs(dst_entropy - ewma_dst_baseline) +
          (1 - smoothing_) * ewmmd_dst_baseline;

      threshold_src = ewma_src_baseline + sensitivity_ * ewmmd_src_baseline;
      threshold_dst = ewma_dst_baseline - sensitivity_ * ewmmd_dst_baseline;
  }
};

} // namespace Euclid

#endif // !EUCLID_CLASSIFIER_HPP
