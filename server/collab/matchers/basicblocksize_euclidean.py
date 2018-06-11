from .euclidean_matcher import EuclideanDictionaryMatcher


class BasicBlockSizeEuclideanMatcher(EuclideanDictionaryMatcher):
  vector_type = 'basicblocksize_hist'
  match_type = 'basicblocksize_euclidean'
  matcher_name = "Basic Block size Distance"
  matcher_description = ("Matches functions according to their basic block "
                         "size listing using histogram and an euclidean "
                         "distance metric.")
