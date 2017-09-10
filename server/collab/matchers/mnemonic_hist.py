from . import hist_matcher


class MnemonicHistogramMatcher(hist_matcher.HistogramMatcher):
  vector_type = 'mnemonic_hist'
  match_type = 'mnemonic_hist'
  matcher_name = "Mnemonic Histogram"
  matcher_description = ("Matches functions according to thier mnemonic "
                         "listing using histogram and a distance metric.")
