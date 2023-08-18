#pragma once

#include <algorithm>
#include <iterator>

namespace base {
namespace utils {

// Test to see if a set or map contains a particular key.
// Returns true if the key is in the collection.
template <typename Collection, typename Key>
bool ContainsKey(const Collection& collection, const Key& key) {
  return collection.find(key) != collection.end();
}

template <typename Collection>
class HasKeyType {
  template <typename C>
  static std::true_type test(typename C::key_type*);
  template <typename C>
  static std::false_type test(...);

 public:
  static constexpr bool value = decltype(test<Collection>(nullptr))::value;
};

// Test to see if a collection like a vector contains a particular value.
// Returns true if the value is in the collection.
// Don't use this on collections such as sets or maps. This is enforced by
// disabling this method if the collection defines a key_type.
template <
    typename Collection, typename Value,
    typename std::enable_if<!HasKeyType<Collection>::value, int>::type = 0>
bool ContainsValue(const Collection& collection, const Value& value) {
  return std::find(std::begin(collection), std::end(collection), value) !=
         std::end(collection);
}

// Returns true if the container is sorted.
template <typename Container>
bool STLIsSorted(const Container& cont) {
  // Note: Use reverse iterator on container to ensure we only require
  // value_type to implement operator<.
  return std::adjacent_find(cont.rbegin(), cont.rend(),
                            std::less<typename Container::value_type>()) ==
         cont.rend();
}

// Calls erase on iterators of matching elements.
template <typename Container, typename Predicate>
void IterateAndEraseIf(Container& container, Predicate pred) {
  for (auto it = container.begin(); it != container.end();) {
    if (pred(*it)) {
      it = container.erase(it);
    } else {
      ++it;
    }
  }
}

template <typename CharT, typename Traits, typename Allocator, typename Value>
void Erase(std::basic_string<CharT, Traits, Allocator>& container,
           const Value& value) {
  container.erase(std::remove(container.begin(), container.end(), value),
                  container.end());
}

}  // namespace utils
}  // namespace base
