class Menu:
  active_url = None

  def __init__(self, name, url=None, icon=None, *submenu, **kwargs):
    self.name = name
    self.icon = icon if icon else ''
    self.url = url if url else ''
    self.submenu = submenu
    self.active = (url == self.active_url or
                   any(sm.active for sm in self.submenu))

  @property
  def menu_class(self):
    return 'sub-menu' if self.submenu else 'mf'


def navigation(request):
  Menu.active_url = request.resolver_match.url_name
  print(Menu.active_url)
  menu = [Menu("Dashboard", icon='fa-dashboard'),
          Menu("Collaboration", None, 'fa-cogs',
               Menu("Projects", url='project-list'),
               Menu("Files", url='file-list'),
               Menu("Tasks", url='task-list'),
               Menu("Instances", url='instance-list')),

          Menu("Account", None, 'fa-desktop',
               Menu("Your profile", url='profile'),
               # Menu("Settings", url='settings'),
               Menu("Logout", url='auth_logout'))]

  return {'navigation': menu}
