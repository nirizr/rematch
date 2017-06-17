from . import fuzzy_matcher


class ApiDominatorMatcher(fuzzy_matcher.FuzzyHashMatcher):
  vector_type = 'apidom_hash'
  match_type = 'apidom_hash'
  matcher_name = 'API Call Dominator Hash'
