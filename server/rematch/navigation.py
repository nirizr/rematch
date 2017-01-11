class Menu:
  def __init__(self, name, url=None, icon=None, *submenu, **kwargs):
    self.name = name
    self.icon = icon if icon else ''
    self.url = url if url else 'javascript:;'
    self.submenu = submenu
    self.active = False or any(sm.active for sm in self.submenu)

  @property
  def menu_class(self):
    return 'sub-menu' if self.submenu else 'mf'


def navigation(request):
  menu = [Menu("Dashboard", icon='fa-dashboard'),
          Menu("UI Elements", None, 'fa-desktop',
               Menu("General", url='general.html'),
               Menu("Buttons", url='buttons.html'),
               Menu("Panels", url='panels.html')),

          Menu("Components", None, 'fa-cogs',
               Menu("Calendar", url='calendar.html'),
               Menu("Gallery", url='gallery.html'),
               Menu("Todo List", url='todo_list.html')),

          Menu("Extra Pages", None, 'fa-book',
               Menu("Blank Page", url='blank.html'),
               Menu("Login", url='login.html'),
               Menu("Lock Screen", url='lock_screen.html')),

          Menu("Forms", None, 'fa-tasks',
               Menu("Form Components", url='form_component.html')),

          Menu("Data Tables", None, 'fa-th',
               Menu("Basic Table", url='basic_table.html'),
               Menu("Responsive Table", url='responsive_table.html')),

          Menu("Charts", None, 'fa-bar-chart-o',
               Menu("Morris", url='morris.html'),
               Menu("Chartjs", url='chartjs.html'))]

  return {'navigation': menu}
