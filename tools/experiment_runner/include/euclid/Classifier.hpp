#ifndef EUCLID_CLASSIFIER_HPP
#define EUCLID_CLASSIFIER_HPP

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>

#include "experiment/IClassifier.hpp"
#include "ExtendedCountSketch.hpp"
#include "IPktFile.hpp"
#include "Status.hpp"
#include "Pkt.hpp"
#include "experiment/Diagnoser.hpp"

namespace Euclid {

class Classifier : public Experiment::IClassifier {
public:
  Classifier(nlohmann::json classifier_params)
      : IClassifier(classifier_params),
        smoothing_(classifier_params["smoothing"]),
        sensitivity_(classifier_params["sensitivity"]),
        observation_window_size_(classifier_params["observation_window"]),
        defense_threshold_(classifier_params["defense_threshold"]),
        system_status_(Status::SAFE),
        src_cs_(classifier_params["count_sketch_depth"], classifier_params["count_sketch_width"], classifier_params.value("seed", std::random_device{}())),
        dst_cs_(classifier_params["count_sketch_depth"], classifier_params["count_sketch_width"], classifier_params.value("seed", std::random_device{}())),
        ewma_src_(0), ewma_dst_(0), ewmmd_src_(0), ewmmd_dst_(0) {}

  virtual void run(IPktFile &input, Experiment::Diagnoser &diagnoser) override {
    size_t count{1};
    size_t curr_wid{0};
    const auto total_wids { input.get_entry_count() / observation_window_size_ + 1 };

    bool anomaly_in_last_window{ false };
    for (const Pkt::Entry *entry = input.read_next_entry(); entry != nullptr; entry = input.read_next_entry()) {
      // A. Traffic statistics
      // A.1 Frequency approximation
      // Here we access the count sketches to get the approx. frequencies
      // A.2 Entropy estimation
      // Also retrieved from the count sketches
      // A.3 Traffic characterization
      // Calculate ewma and ewmmd
      // A.4 Anomaly detection
      // Check entropy measurements vs threshold (eq. 6a and 6b)
      // Update the model if measurements params within thresholds
      // else mark packet metadata
      //
      // B. Attack mitigation
      // B.1 Defence readiness
      // Execute once per OW
      // Transition between different states
      // Next stages are only executed in DEFENSE_* states
      // B.2 Frequency variation
      // Call the functions that do the freq. variation calculation on the current CS
      // B.3 Packet Classification
      // Compare freq. variation against operator set threshold
      // B.4 Enforcement
      // Drop/Ignore/Whatever - this is irrelevant for this work
      //
      // A. Impl
      // A.1 - Update count sketches
      src_cs_.update(entry->srcIp, curr_wid, system_status_);
      dst_cs_.update(entry->dstIp, curr_wid, system_status_);

      auto under_attack = false;

      if (count % observation_window_size_ == 0) {
        curr_wid++;

        std::cout << "WID: " << curr_wid << "/" << total_wids << "\n";
        diagnoser.print();
        std::cout << "========================================================================" << "\n";

        // A.2 - Retrieve updated entropy
        // Equation 11
        const auto ow_log{ log2(observation_window_size_) };
        const auto src_entropy{ ow_log - (src_cs_.get_entropy_norm() / observation_window_size_) };
        const auto dst_entropy{ ow_log - (dst_cs_.get_entropy_norm() / observation_window_size_) };

        // A.3 & 4 - Update EWMA and EWMMD
        if (curr_wid == 1) {
          ewma_src_ = src_entropy;
          ewma_dst_ = dst_entropy;
          ewmmd_src_ = 1;
          ewmmd_dst_ = 1;
        }
        else {
          // Equation 6a/b
          const auto src_threshold = ewma_src_ + sensitivity_ * ewmmd_src_;
          const auto dst_threshold = ewma_dst_ - sensitivity_ * ewmmd_dst_;
          under_attack = (src_entropy > src_threshold) || (dst_entropy < dst_threshold);

            std::cout << "under_attack: " << under_attack  << "\n";
            std::cout << "src_entropy: " << src_entropy << "\n";
            std::cout << "threshold_src: " << src_threshold << "\n";
            std::cout << "ewma_src: " << ewma_src_ << "\n";
            std::cout << "ewmmd_src: " << ewmmd_src_ << "\n";
            std::cout << "dst_entropy: " << dst_entropy << "\n";
            std::cout << "threshold_dst: " << dst_threshold << "\n";
            std::cout << "ewma_dst: " << ewma_dst_ << "\n";
            std::cout << "ewmmd_dst: " << ewmmd_dst_ << "\n";
//
//          if (under_attack) {
//            throw;
//          }
//
          if (!under_attack) {
            update_ewms(src_entropy, dst_entropy, curr_wid);
          }
        }

        src_cs_.reset_entropy_norm();
        dst_cs_.reset_entropy_norm();

        // B. Impl
        // B.1 - Transition state
        transition_state(under_attack);
      }

      // B.2 - Check freq. variation if state is not safe
      if (system_status_ != Status::SAFE) {
        // Equation 7
        const auto frequency_variation = dst_cs_.get_variation(entry->dstIp) -
          src_cs_.get_variation(entry->srcIp);

        // B.3 - Mark the packet as malicious
        // Equation 9b
        if (frequency_variation > defense_threshold_) {
          mark_packet_malicious(entry);
        }
      }

      // B.4 - Out of scope for this work - NOP

      // Collect stats
      diagnoser.collect_stats(entry);

      count++;
    }
  }

  virtual void print() const override {
    std::cout << "\tClassifier: EUCLID" << std::endl;
    std::cout << "\tParams:" << std::endl;
    std::cout << "\t\tSensitivity: " << sensitivity_ << std::endl;
    std::cout << "\t\tObservation Window Size: " << observation_window_size_
              << std::endl;
  }

private:
  // Parameters
  const double sensitivity_;
  const uint64_t observation_window_size_;
  const double defense_threshold_;
  const double smoothing_;

  // Count Sketches
  CountSketchManager src_cs_;
  CountSketchManager dst_cs_;

  // Runtime values
  Status system_status_;
  double ewma_src_;
  double ewma_dst_;
  double ewmmd_src_;
  double ewmmd_dst_;

  void update_ewms(double src_entropy, double dst_entropy, size_t wid) {
    // Equation 4a/b
    ewma_src_ = smoothing_ * src_entropy + (1 - smoothing_) * ewma_src_;
    ewma_dst_ = smoothing_ * dst_entropy + (1 - smoothing_) * ewma_dst_;

    // Equation 5a/b
    ewmmd_src_ = smoothing_ * std::fabs(src_entropy - ewma_src_) + (1 - smoothing_) * ewmmd_src_;
    ewmmd_dst_ = smoothing_ * std::fabs(dst_entropy - ewma_dst_) + (1 - smoothing_) * ewmmd_dst_;
  }

  void transition_state(bool attack_last_window) {
    switch (system_status_) {
    case Status::SAFE:
      if (attack_last_window)
        system_status_ = Status::DEFENSE_ACTIVE;
      break;
    case Status::DEFENSE_ACTIVE:
      if (!attack_last_window)
        system_status_ = Status::DEFENSE_COOLDOWN;
      break;
    case Status::DEFENSE_COOLDOWN:
      if (attack_last_window)
        system_status_ = Status::DEFENSE_ACTIVE;
      else
        system_status_ = Status::SAFE;
      break;
    }
  }

  void mark_packet_malicious(const Pkt::Entry *entry) const {
    const_cast<Pkt::Entry *>(entry)->rsvdExp = 1;
  }

  void update_state(bool was_anomaly_detected) {
    if (system_status_ == Status::SAFE) {
      if (was_anomaly_detected) {
        system_status_ = Status::DEFENSE_ACTIVE;
      }
    }
    else if (system_status_ == Status::DEFENSE_ACTIVE) {
      if (!was_anomaly_detected) {
        system_status_ = Status::DEFENSE_COOLDOWN;
      }
    }
    else {
      if (was_anomaly_detected) {
        system_status_ = Status::DEFENSE_ACTIVE;
      }
      else {
        system_status_ = Status::SAFE;
      }
    }
  }
};
} // namespace Euclid

#endif // !EUCLID_CLASSIFIER_HPP
