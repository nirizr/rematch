from . import hash_matcher


class InstructionHashMatcher(hash_matcher.HashMatcher):
  vector_type = 'instruction_hash'
  match_type = 'instruction_hash'
  matcher_name = "Instruction Hash"
  matcher_description = ("Exact matches for functions with identical binary "
                         "listings.")
