from . import hist_matcher


class MnemonicHistogramMatcher(hist_matcher.HistogramMatcher):
  vector_type = 'mnemonic_hist'
  match_type = 'mnemonic_hist'
