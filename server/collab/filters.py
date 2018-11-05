from django_filters import FilterSet, ModelChoiceFilter
from django_filters.filterset import FILTER_FOR_DBFIELD_DEFAULTS

from django.db import models

from collab.models import (Instance)


def foreignkey_distinct_extra(f):
  d = FILTER_FOR_DBFIELD_DEFAULTS[models.ForeignKey]['extra'](f)
  d['distinct'] = True
  return d


class InstanceFilter(FilterSet):
  class Meta:
    model = Instance
    fields = ('owner', 'file_version', 'type', 'from_matches__task',
              'to_matches__task')
    filter_overrides = {
        models.ForeignKey: {
            'filter_class': ModelChoiceFilter,
            'extra': foreignkey_distinct_extra}}
