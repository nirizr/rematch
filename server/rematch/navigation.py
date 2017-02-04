class Menu:
  active_url = None

  def __init__(self, name, url=None, icon=None, *submenu):
    if self.active_url is None:
      raise RuntimeError("Active url is not set when menu item is created")

    self.name = name
    self.icon = icon if icon else ''
    self.url = url
    self.submenu = submenu
    self.active = (url == self.active_url or
                   any(sm.active for sm in self.submenu))
    print(self.name, self.url)

  @classmethod
  def set_url(cls, url):
    cls.active_url = '' if url is None else url

  @property
  def menu_class(self):
    return 'sub-menu' if self.submenu else 'mf'


def navigation(request):
  Menu.set_url(request.resolver_match.url_name)

  menu = [Menu("Dashboard", 'index', icon='fa-dashboard'),

          Menu("Collaboration", None, 'fa-cogs',
               Menu("Projects", url='project-list'),
               Menu("Files", url='file-list'),
               Menu("Tasks", url='task-list'),
               Menu("Instances", url='instance-list'))]

  if request.user.is_authenticated():
    account = Menu("Account", None, 'fa-desktop',
                   Menu("Your profile", url='profile'),
                   # Menu("Settings", url='settings'),
                   Menu("Logout", url='auth_logout'))
  else:
    account = Menu("Login", 'auth_login')
  menu.append(account)

  return {'navigation': menu}
