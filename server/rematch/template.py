import os


class ViewSetTemplateMixin(object):
  def get_app_name(self):
    return self.__class__.__module__.lower().replace('.views', '')

  def get_model_name(self):
    return self.__class__.__name__.lower().replace('viewset', '')

  def get_template_names(self):
    page = "{}.html".format(self.action)
    model_template_name = os.path.join(self.get_model_name(), page)
    app_template_name = os.path.join(self.get_app_name(), page)
    return [model_template_name, app_template_name, page]

  def get_template_fields(self):
    return self.template_fields

  def list(self, request):
    response = super(ViewSetTemplateMixin, self).list(request)

    if request.accepted_renderer.format == 'html':
      response.data = {'data': response.data,
                       'headers': self.get_template_fields()}
    return response
