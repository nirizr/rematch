import collections
from . import matcher


class HashMatcher(matcher.Matcher):
  @classmethod
  def match(cls, source, target):
    # TODO: Could be optimized by implementing as a single SQL query where
    # hash_func is not implemented

    flipped_rest = collections.defaultdict(list)
    target_values = target.values_list('instance_id', 'data').iterator()
    for target_instance_id, target_data in cls.apply_hash_func(target_values):
      flipped_rest[target_data].append(target_instance_id)

    source_values = source.values_list('instance_id', 'data').iterator()
    for source_instance_id, source_data in cls.apply_hash_func(source_values):
      matches = flipped_rest.get(source_data, ())

      for target_instance_id in matches:
        yield (source_instance_id, target_instance_id, 100)

  @classmethod
  def apply_hash_func(self, values):
    """allow easy hash generation from more structured data by applying a
    hash function on provided data."""

    if not hasattr(self, 'hash_func'):
      return values

    return ((i_id, self.hash_func(data)) for i_id, data in values)
