#ifndef EXPERIMENT_DIAGNOSER_HPP
#define EXPERIMENT_DIAGNOSER_HPP

#include "Pkt.hpp"

#include <cstdint>
#include <iostream>

namespace Experiment {
class Diagnoser {
public:
  Diagnoser()
      : total_true_malicious_{0}, total_classified_malicious_{0},
        true_positives_count_{0}, false_positives_count_{0},
        total_entries_{0} {};

  void collect_stats(const Pkt::Entry *entry) {
    bool originally_malicious{entry->is_original_malicious()};
    bool classified_malicious{entry->is_classified_malicious()};

    total_true_malicious_ += 1 && originally_malicious;
    total_classified_malicious_ += 1 && classified_malicious;
    true_positives_count_ += 1 && originally_malicious && classified_malicious;
    false_positives_count_ +=
        1 && !originally_malicious && classified_malicious;

    total_entries_++;
  }

  void print() {
    std::cout << "Diagnoser stats:\n";
    std::cout << "\tTotal entries classified: " << total_entries_ << "\n";
    std::cout << "\tTotal true malicious entries: " << total_true_malicious_
              << "\n";
    std::cout << "\tTotal classified malicious entries: "
              << total_classified_malicious_ << "\n";
    std::cout << "\tTrue positives: " << true_positives_count_ << "\n";
    std::cout << "\tFalse positives: " << false_positives_count_ << "\n";
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
