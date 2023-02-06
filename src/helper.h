#pragma once

#include <boost/algorithm/string/predicate.hpp>
#include <string>
#include <vector>
namespace Helper {

struct case_insensitive_comp {
  // bool operator()(std::string& lhs, std::string& rhs) {
  //   // return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
  //   // return boost::algorithm::iequals(lhs, rhs, std::locale::classic()) <
  //   0;
  // }

  // case-independent (ci) compare_less binary function
  struct nocase_compare {
    bool operator()(const unsigned char& c1, const unsigned char& c2) const {
      return tolower(c1) < tolower(c2);
    }
  };
  bool operator()(const std::string& s1, const std::string& s2) const {
    return std::lexicographical_compare(s1.begin(), s1.end(),  // source range
                                        s2.begin(), s2.end(),  // dest range
                                        nocase_compare());     // comparison
  }
};

template <typename T, typename TT>
inline void vector_insert(std::vector<T>* v, TT* a) {
  // std::copy(a->begin(), a->end(), std::back_inserter(v));
  v->insert(v->end(), a->begin(), a->end());
};

}  // namespace Helper
