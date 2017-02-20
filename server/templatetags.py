from django import template

register = template.Library()


@register.filter
def lookup(d, key):
  if key not in d:
    return None
  return d[key]


@register.inclusion_tag('components/list.html')
def component_list(view):
  return {'headers': view.get_template_fields(),
          'items': view.Meta.Model.objects.all()}
