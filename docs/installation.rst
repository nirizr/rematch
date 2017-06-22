Installation
============

The rematch project is composed of two parts: a server and an IDA plugin client.

While installing the plugin is exteremly easy, installing the server tends to
be a little more difficult. Luckily, it's only done once per organisation.

Installing the Rematch Server
-----------------------------

Installing a rematch server is only required once for a group of rematch users.
Once an admin user is created, additional users can be managend through the
admin console.

.. warning:: Since permissions are not currently enforced, it is advised that
  confidential data will be kept on servers only accessible to those with
  permission to access said data. See Privacy section for more details.

.. tip:: Windows based server installtions are possible but not recommended.
  Some packages (scikit-learn, numpy, scipy) are required by the server but are
  more complicated to install on windows. Windows Subsystem for Linux may ease
  the installation process. Using Anaconda for python package management may
  also be helpful.

Installing Rematch server docker container
++++++++++++++++++++++++++++++++++++++++++

We provide a docker container with Rematch server installed and configured with
nginx, mysql, rabbitmq and celery micro components. This makes server
deployment a lot easier however a docker installation and roughly 1 GB of free
space is required.

The docker container is not in the docker hub, but the the following docker-compose
command can be used to build docker inside the rematch repository:

.. code-block:: console

   $ service docker start ;
   $ docker-compose -f ./server/docker-compose.yml build ;
   $ docker-compose -f ./server/docker-compose.yml up -d ;

Installing the Rematch IDA Plugin
---------------------------------

Installing IDA plugins is done by placing the plugin source inside IDA's
plugins directory (location is based on operating system). To make plugin
installation as simple as possibe, the rematch plugin has no dependecies.

Once installed the plugin automatically updates itself (as long as it's
configured to), so installing the plugin is a one-time process.

Installing the plugin using pip
+++++++++++++++++++++++++++++++

If pip is installed for IDA's version of python, using it is simplest
installation method.

.. note:: By default, pip is not installed for Windows installations of IDA,
   but is more commonly found in Mac and Linux installations.

To install using IDA's pip, simply run the following pip command:

.. code-block:: console

   $ pip install rematch-idaplugin

.. warning:: Make sure you're installing the plugin using a version of pip
   inside IDA's copy of python.

If pip is not installed for IDA's version of python, it is still possible to
install the plugin with another copy of pip using pip's `--target` flag. To do
this run the following pip command line with any instance of pip:

.. code-block:: console

   $ pip install rematch-idaplugin --target="<Path to IDA's plugins directory>"

.. warning:: Using the pip ``--target`` flag with a pip version installed by
   Homebrew does not work because of a `known issue
   <https://github.com/Homebrew/brew/issues/837>`_ with Homebrew. Homebrew OSX
   users will have to use a different installation method.

.. note:: IDA's plugins directory is located inside IDA's installation
   directory. For example if IDA is installed at:

   `C:\Program Files (x86)\IDA 6.9`

   Then the plugins directory will be:

   `C:\Program Files (x86)\IDA 6.9\plugins`

   and the executed command line should be:

   .. code-block:: console

      $ pip install rematch-idaplugin
          --target="C:\Program Files (x86)\IDA 6.9\plugins"

Installing the plugin manually
++++++++++++++++++++++++++++++

If you don't have pip, or prefer not to use it, you can still manually install
the plugin by simply extracting the contents of the `idaplugin directory
<https://github.com/nirizr/rematch/tree/master/idaplugin>`_ in the repository's
root, to IDA's plugins directory.

Simply download the package from `PyPI
<https://pypi.python.org/pypi/rematch-idaplugin>`_ or `Github
<https://github.com/nirizr/rematch>`_ and extract the idaplugin directory
contents into IDA's plugins directory, so that the file
idaplugin/rematch_plugin.py is located in the plugins sub-directory in IDA's
installation directory.
