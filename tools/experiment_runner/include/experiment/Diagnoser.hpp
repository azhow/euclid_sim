#ifndef EXPERIMENT_DIAGNOSER_HPP
#define EXPERIMENT_DIAGNOSER_HPP

#include "Pkt.hpp"

#include <cstdint>

namespace Experiment {
class Diagnoser {
public:
  void collect_stats(const Pkt::Entry *entry) {
    bool originally_malicious{entry->is_original_malicious()};
    bool classified_malicious{entry->is_classified_malicious()};

    total_true_malicious_ += 1 && originally_malicious;
    total_classified_malicious_ += 1 && classified_malicious;
    true_positives_count_ += 1 && originally_malicious && classified_malicious;
    false_positives_count_ += 1 && !originally_malicious && classified_malicious;

    total_entries_++;
  }

private:
  uint64_t total_true_malicious_;
  uint64_t total_classified_malicious_;
  uint64_t true_positives_count_;
  uint64_t false_positives_count_;
  uint64_t total_entries_;
};
} // namespace Experiment

#endif // !EXPERIMENT_DIAGNOSER_HPP
