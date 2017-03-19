from . import hash_matcher


class AssemblyHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'assembly_hash'
  match_type = 'assembly_hash'
