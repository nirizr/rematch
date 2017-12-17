from .strategy import Strategy
from .strategy_step import StrategyStep


class AllStrategy(Strategy):
  strategy_name = 'All'
  strategy_type = 'all_strategy'
  strategy_description = ("The most brute strategy, runs all matchers on all "
                          "pairs, regardless of size, previous matching "
                          "results or any other potential optimization. This "
                          "makes this strategy the slowest possible, but it "
                          "provides as many results as possible (which can be "
                          "an advantage or a disadvantage at the same time).")

  def get_ordered_steps(self, source_vectors, target_vectors):
    del source_vectors
    del target_vectors

    return [StrategyStep(matcher) for matcher in self.get_ordered_matchers()]
