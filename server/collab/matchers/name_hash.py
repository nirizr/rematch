from . import hash_matcher


class NameHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'name_hash'
  match_type = 'name_hash'
  matcher_name = "Name Hash"
