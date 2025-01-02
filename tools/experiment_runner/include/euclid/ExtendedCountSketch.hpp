#ifndef EUCLID_EXTENDEDCOUNTSKETCH_HPP
#define EUCLID_EXTENDEDCOUNTSKETCH_HPP

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <random>
#include <vector>

#include "Status.hpp"

namespace Euclid {
using THashFunction = std::function<int64_t(uint32_t)>;

class ExtendedCountSketch {
public:
  // This is (count, window_id)
  struct CountSketchEntry {
    int64_t count;
    uint32_t wid;

    CountSketchEntry() : count(0), wid(0) {}
  };

  ExtendedCountSketch(uint64_t depth, uint64_t width)
      : depth_(depth), width_(width), table_(depth, width), estimates_(depth, 0) {
  }

  uint64_t get_depth() const { return depth_; }

  uint64_t get_width() const { return width_; }

  inline CountSketchEntry& operator()(size_t row, size_t col) { return table_(row, col); }

  int64_t estimate(uint32_t address,
                   const std::vector<THashFunction>& hash_functions,
                   const std::vector<THashFunction>& sign_functions) {
    for (size_t i = 0; i < depth_; ++i) {
      const int64_t col = hash_functions[i](address); // Find the column index for this row
      const int64_t sign = 2 * sign_functions[i](address) - 1; // Determine the sign (+1 or -1)
      estimates_[i] = table_(i, col).count * sign; // Get signed count
    }

    // Use std::nth_element to find the median
    size_t mid = depth_ / 2; // Index of the median
    std::nth_element(estimates_.begin(), estimates_.begin() + mid, estimates_.end());

    return estimates_[mid]; // Return the median
  }

private:
  class Matrix {
  public:
    Matrix(size_t rows, size_t cols)
        : rows_(rows), cols_(cols), data_(std::vector<CountSketchEntry>(rows * cols, CountSketchEntry())) {}

    inline CountSketchEntry &operator()(size_t row, size_t col) { return data_[row * cols_ + col]; }
    inline const CountSketchEntry &operator()(size_t row, size_t col) const { return data_[row * cols_ + col]; }

  private:
    std::vector<CountSketchEntry> data_;
    size_t rows_, cols_;
  };

  const uint64_t depth_;
  const uint64_t width_;
  double entropy_;
  Matrix table_;
  std::vector<int64_t> estimates_;
};

class CountSketchManager {
public:
  enum CountSketchSelection {
    SAFE = 0,
    RUNNING,
    LAST
  };

  CountSketchManager(uint64_t depth, uint64_t width, uint32_t seed) :
    hash_functions_(), sign_functions_(), count_sketches_(), entropy_norm_(0) {

    hash_functions_.reserve(depth);
    sign_functions_.reserve(depth);

    // Initialize hash functions
    std::mt19937 rng{seed};

    for (auto i = 0; i < depth; ++i) {
      hash_functions_.push_back(create_hash_function(rng(), width));
      sign_functions_.push_back(create_hash_function(rng(), 2));
    }

    // Initialize count sketches
    for (auto el : {CountSketchSelection::SAFE, CountSketchSelection::RUNNING, CountSketchSelection::LAST}) {
      count_sketches_.push_back(ExtendedCountSketch(depth, width));
    }
  }

  double get_variation(int32_t address) {
    // Equation 8a/b
    return estimate(address, CountSketchSelection::LAST) - estimate(address, CountSketchSelection::SAFE);
  }

  void update(uint32_t address, uint32_t curr_wid, Status curr_system_status) {
    for (auto i = 0; i < hash_functions_.size(); ++i) {
      const auto col{ hash_functions_[i](address) };
      const auto sign{ sign_functions_[i](address) };

      auto& running_cs { count_sketches_[CountSketchSelection::RUNNING] };
      if (running_cs(i, col).wid != curr_wid) {
        auto& last_cs { count_sketches_[CountSketchSelection::LAST] };

        if (curr_wid > 1 && curr_system_status == Status::SAFE) {
          // Copy from the last running window
          auto& safe_cs { count_sketches_[CountSketchSelection::SAFE] };
          safe_cs(i, col).count = last_cs(i, col).count;
          safe_cs(i, col).wid = last_cs(i, col).wid;
        }
        last_cs(i, col).count = running_cs(i, col).count;
        last_cs(i, col).wid = running_cs(i, col).wid;
        running_cs(i, col).count = 0;
        running_cs(i, col).wid = curr_wid;
      }

      running_cs(i, col).count += sign;
    }

    const auto estimated_freq{ estimate(address, CountSketchSelection::RUNNING) };

    // Equation 10
    if (estimated_freq > 1) {
      entropy_norm_ += estimated_freq * log2(estimated_freq) - (estimated_freq - 1) * log2(estimated_freq - 1);
    }
  }

  int64_t estimate(uint32_t address, CountSketchSelection which) {
    auto& count_sketch { count_sketches_[which] };
    return count_sketch.estimate(address, hash_functions_, sign_functions_);
  }

  double get_entropy_norm() const { return entropy_norm_; }

  void reset_entropy_norm() { entropy_norm_ = 0; }

private:
  std::vector<THashFunction> hash_functions_;
  std::vector<THashFunction> sign_functions_;
  std::vector<ExtendedCountSketch> count_sketches_;
  double entropy_norm_;

  // Helper function to create hash functions with different seeds
  std::function<int32_t(int32_t)> create_hash_function(int32_t seed, int32_t mod) const {
    return [seed, mod](int32_t key) {
      std::hash<int32_t> hash_fn;
      return (hash_fn(key ^ seed) % mod); // Map hash to table width
    };
  };
};
} // namespace Euclid

#endif // !EUCLID_EXTENDEDCOUNTSKETCH_HPP
