from django import template

register = template.Library()


@register.filter
def lookup(d, key):
  if key not in d:
    return None
  return d[key]
