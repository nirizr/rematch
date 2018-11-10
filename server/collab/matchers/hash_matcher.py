import collections
from . import matcher


class HashMatcher(matcher.Matcher):
  @classmethod
  def match(cls, source, target):
    # TODO: Could be optimized by implementing as a single SQL query
    # unique_values = set(source_dict.values())
    flipped_rest = collections.defaultdict(list)
    # TODO: could be optimized by enumerating all identity matches together
    target_values = target.values_list('instance_id', 'data').iterator()
    for target_instance_id, target_data in target_values:
      # TODO: could be optimized by uncommenting next line as most 'target'
      # values won't be present in 'source' list
      # if v in unique_values:
      flipped_rest[target_data].append(target_instance_id)
    source_values = source.values_list('instance_id', 'data').iterator()
    for source_instance_id, source_data in source_values:
      matches = flipped_rest.get(source_data, ())

      for target_instance_id in matches:
        yield (source_instance_id, target_instance_id, 100)
