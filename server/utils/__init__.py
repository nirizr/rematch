import os


class ViewSetTemplateMixin(object):
  def get_template_names(self):
    name_parts = [self.__class__.__name__.lower(),
                  "{}.html".format(self.action)]
    template_name = os.path.join(*name_parts)
    return [template_name]
