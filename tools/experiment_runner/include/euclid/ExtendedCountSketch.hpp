#ifndef EUCLID_EXTENDEDCOUNTSKETCH_HPP
#define EUCLID_EXTENDEDCOUNTSKETCH_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <random>
#include <vector>

namespace Euclid {
class ExtendedCountSketch {
public:
  ExtendedCountSketch(uint64_t depth, uint64_t width)
      : depth_(depth), width_(width), entropy_(0), hash_functions_(), table_(depth, width) {
    hash_functions_.reserve(depth_);
    sign_functions_.reserve(depth_);

    // Create the hash functions
    std::mt19937 rng{std::random_device{}()};

    for (auto i = 0; i < depth_; ++i) {
      hash_functions_.push_back(create_hash_function(rng(), width_));
      sign_functions_.push_back(create_hash_function(rng(), 2));
    }
  }

  uint64_t get_depth() const { return depth_; }

  uint64_t get_width() const { return width_; }

  uint64_t get_entropy() const { return entropy_; }

  void update(uint32_t address) {
    const auto old_frequency{estimate(address)};

    for (size_t i = 0; i < depth_; ++i) {
      const auto col{hash_functions_[i](address)};
      const auto sign{sign_functions_[i](address)};
      table_(i, col) += sign;
    }

    const auto new_frequency{estimate(address)};

    const auto log_new_f{
        (new_frequency > 0) ? new_frequency * std::log2(new_frequency) : 0};
    const auto log_old_f{
        (old_frequency > 0) ? old_frequency * std::log2(old_frequency) : 0};

    entropy_ += log_new_f - log_old_f;
  }

  int64_t estimate(uint32_t address) {
    std::vector<int64_t> estimates{};
    estimates.reserve(depth_);

    for (size_t i = 0; i < depth_; ++i) {
      const int64_t col =
          hash_functions_[i](address); // Find the column index for this row
      const int64_t sign =
          2 * sign_functions_[i](address) - 1; // Determine the sign (+1 or -1)
      estimates.push_back(table_(i, col) * sign); // Get signed count
    }

    // Use std::nth_element to find the median
    size_t mid = depth_ / 2; // Index of the median
    std::nth_element(estimates.begin(), estimates.begin() + mid,
                     estimates.end());

    return estimates[mid]; // Return the median
  }

  void reset() {
    table_.reset();
  }

private:
  class Matrix {
  public:
    Matrix(size_t rows, size_t cols)
        : rows_(rows), cols_(cols), data_(std::vector<int64_t>(rows * cols, 0)) {}

    inline int64_t &operator()(size_t row, size_t col) { return data_[row * cols_ + col]; }

    inline const int64_t &operator()(size_t row, size_t col) const {
      return data_[row * cols_ + col];
    }

    void reset() {
      std::fill(data_.begin(), data_.end(), 0);
    }

  private:
    std::vector<int64_t> data_;
    size_t rows_, cols_;
  };

  const uint64_t depth_;
  const uint64_t width_;
  double entropy_;
  std::vector<std::function<int64_t(uint32_t)>> hash_functions_;
  std::vector<std::function<int64_t(uint32_t)>> sign_functions_;
  Matrix table_;

  // Helper function to create hash functions with different seeds
  std::function<int32_t(int32_t)> create_hash_function(int32_t seed,
                                                       int32_t mod) const {
    return [seed, mod](int32_t key) {
      std::hash<int32_t> hash_fn;
      return (hash_fn(key ^ seed) % mod); // Map hash to table width
    };
  }
};
} // namespace Euclid

#endif // !EUCLID_EXTENDEDCOUNTSKETCH_HPP
