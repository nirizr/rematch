from .strategy import Strategy
from .strategy_step import BinningStrategyStep

from django.db.models import Max, Min

from math import ceil, log


class BinningStrategy(Strategy):
  strategy_name = 'Binning'
  strategy_type = 'binning_strategy'
  strategy_description = ("divide functions to bins by function size, and "
                          "only attempt to match functions in the same bin.")

  # Prevent splitting matched objects to bins which are too small
  MINIMAL_BIN_SIZE = 16
  BIN_BASE = 2

  def get_bins(self, matcher):
    del matcher

    source_sizes = (self.vector_cls.objects.filter(self.get_source_filter())
                                           .aggregate(Min('instance__size'),
                                                      Max('instance__size')))
    target_sizes = (self.vector_cls.objects.filter(self.get_target_filter())
                                           .aggregate(Min('instance__size'),
                                                      Max('instance__size')))

    # find the common denomenator of sizes
    # or 0 parts are a trick to replce Nones with 0
    min_size = max(source_sizes['instance__size__min'] or 0,
                   target_sizes['instance__size__min'] or 0)
    max_size = min(source_sizes['instance__size__max'] or 0,
                   target_sizes['instance__size__max'] or 0)

    # Get the highest exponent of BASE that is below the minimal actual matched
    # object's size. This is esentially the upper bound bin size. Make sure
    # that size is at least MINIMAL_BIN_SIZE, because we want all really small
    # matched objects to be binned together (sizes 4 & 6 should still be
    # matched to eachother, difference is too small to men anything)
    min_size = max(min_size, self.MINIMAL_BIN_SIZE)
    min_bin_base_power = int(ceil(log(min_size, self.BIN_BASE)))

    # Get the lowest exponenet of BASE that is above the minimat actual matched
    # object's size. This is esentially the upper bound bin size.
    max_size = max(max_size, 1)
    max_bin_base_power = 1 + int(ceil(log(max_size, self.BIN_BASE)))
    print(max_bin_base_power)

    # build binning boundaries based
    boundaries = [self.BIN_BASE ** i for i in range(min_bin_base_power,
                                                    max_bin_base_power)]

    # if min size is below the first boundary, which will happen if
    # min_bin_base_power got bumped up thanks for MINIMAL_BIN_EXPONENT
    if len(boundaries) > 0 and min_size < boundaries[0]:
      boundaries = [0] + boundaries

    bins = [(boundaries[i - 1], boundaries[i])
              for i in range(1, len(boundaries))]

    return bins

  def get_ordered_steps(self):
    ordered_steps = list()

    for matcher in self.get_ordered_matchers():
      for bin_min, bin_max in self.get_bins(matcher):
        step = BinningStrategyStep(self, matcher, bin_min, bin_max)
        ordered_steps.append(step)

    return ordered_steps
