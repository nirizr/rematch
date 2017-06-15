from . import fuzzy_matcher


class FnvHashMatcher(fuzzy_matcher.FuzzyHashMatcher):
  vector_type = 'fnv_hash'
  match_type = 'fnv_hash'
  matcher_name = 'FNV Hash'
