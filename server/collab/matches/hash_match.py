import collections
import match


class HashMatch(match.Match):
  @classmethod
  def match(cls, source, target):
    # unique_values = set(source_dict.values())
    flipped_rest = collections.defaultdict(list)
    # TODO: could be optimized by enumerating all identity matchs together
    target_values = target.values_list('id', 'instance_id', 'data').iterator()
    for target_id, target_instance_id, target_data in target_values:
      # TODO: could be optimized by uncommenting next line as most 'target'
      # values won't be present in 'source' list
      # if v in unique_values:
      flipped_rest[target_data].append((target_id, target_instance_id))
    source_values = source.values_list('id', 'instance_id', 'data').iterator()
    for source_id, source_instance_id, source_data in source_values:
      for target_id, target_instance_id in flipped_rest.get(source_data, ()):
        yield source_id, source_instance_id, target_id, target_instance_id, 100
