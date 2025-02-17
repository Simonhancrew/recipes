#pragma once

#include <cassert>
#include <string>

namespace recipes::utils {

class BufferView {
public:
  // Create an empty BufferView.
  BufferView() : data_(""), length_(0) {}

  // Create a BufferView that refers to data[0,length-1].
  BufferView(const char *data, std::size_t length)
      : data_(data), length_(length) {}

  BufferView(const void *data, std::size_t length)
      : data_(static_cast<const char *>(data)), length_(length) {}

  // Create a BufferView that refers to the contents of "s"
  explicit BufferView(const std::string &str)
      : data_(str.data()), length_(str.size()) {}

  // Create a BufferView that refers to data[0,strlen(data)-1]
  explicit BufferView(const char *data) : data_(data), length_(strlen(data)) {}

  ~BufferView() = default;

  BufferView(const BufferView &buf) = default;
  BufferView &operator=(const BufferView &buf) = default;

  // Return a pointer to the beginning of the referenced data
  const char *Data() const { return data_; }

  // Return the length (in bytes) of the referenced data
  std::size_t Length() const { return length_; }

  // Return true if the length of the referenced data is zero
  bool Empty() const { return length_ == 0; }

  void Clear() {
    data_ = "";
    length_ = 0;
  }

  const char *begin() const { return Data(); }
  const char *end() const { return Data() + Length(); }

  // Return the ith byte in the referenced data.
  // REQUIRES: n < Length()
  char operator[](std::size_t index) const {
    assert(index < length_);
    return data_[index];
  }

  std::string ToString() const {
    if (Empty()) {
      return {};
    }
    return {data_, length_};
  }

  // Return true if "x" is a prefix of "*this"
  bool StartsWith(const BufferView &x) const {
    return ((length_ >= x.length_) && (memcmp(data_, x.data_, x.length_) == 0));
  }

  // Drop the first "n" bytes from this bufferview.
  // REQUIRES: n <= Length()
  void RemovePrefix(size_t n) {
    assert(n <= Length());
    data_ += n;
    length_ -= n;
  }

  // Three-way comparison.  Returns value:
  //   <  0 if "*this" <  "b",
  //   == 0 if "*this" == "b",
  //   >  0 if "*this" >  "b"
  int Compare(const BufferView &b) const;

private:
  const char *data_;
  std::size_t length_;
};

inline int BufferView::Compare(const BufferView &b) const {
  const size_t min_len = (length_ < b.length_) ? length_ : b.length_;
  int res = 0;
  if (min_len > 0) {
    res = memcmp(data_, b.data_, min_len);
  }
  if (res == 0) {
    if (length_ < b.length_) {
      res = -1;
    } else if (length_ > b.length_) {
      res = +1;
    }
  }
  return res;
}

inline bool operator==(const BufferView &x, const BufferView &y) {
  return ((x.Length() == y.Length()) &&
          (memcmp(x.Data(), y.Data(), x.Length()) == 0));
}

inline bool operator!=(const BufferView &x, const BufferView &y) {
  return !(x == y);
}

} // namespace recipes::utils
