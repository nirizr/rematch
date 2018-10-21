|Read The Docs| |Gitter Chat| |Build Status| |Codacy Badge| |idaplugin PyPI| |server PyPI|

rematch
=======

REmatch, yet another binary comparison tool.

Rematch is still a work in progress and is not as feature-rich as we'd like
it to be. Basic functionality is available at this point and more advanced
features are being worked on. Hopefully, since extendability and
maintainability were first priorities we'll get there relatively fast.

It is intended to be used by reverse engineers by revealing and identifying
previously reverse engineered similar functions and migrating documentation
and annotations to current IDB. It does that by locally collecting data about
functions in your IDB and uploading that information to a web service (which
you're supposed to set up as well). Upon request, the web service can match
your functions against all (or part) of previously uploaded functions and
provide matches.

A secondary goal of this (which is not currently pursued) is to allow
synchronization between multiple reverse engineers working on the same file.

Installation
============

Rematch is made of two components, both are quite simple to install. Additional
information can be found at https://rematch.readthedocs.io

**IDA plugin**: Installing the IDA plugin is a simple as dropping it in IDA's
plugins directory.

**Web service**: Installing the web service requires docker and building
the webservice's docker image by executing the following command:

.. code-block:: console

   $ vim ./server/.env # this file holds passwords, change them!
   $ docker-compose -f ./server/docker-compose.yml build ;
   $ docker-compose -f ./server/docker-compose.yml up -d ;

To create the rematch server administrator execute the following command:

.. code-block:: console

   $ docker-compose -f ./server/docker-compose.yml exec web ./server/manage.py createsuperuser

Finally, point your browser to http://SERVER_IP:8000/admin/ to manage the
service and add more users.

.. |Read The Docs| image:: https://readthedocs.org/projects/rematch/badge/?version=latest
   :alt: Read The Docs
   :target: http://rematch.readthedocs.io/en/latest/?badge=latest
.. |Gitter Chat| image:: https://img.shields.io/gitter/room/rematch/rematch.js.svg
   :alt: Gitter Chat
   :target: https://gitter.im/rematch/rematch
.. |Build Status| image:: https://travis-ci.org/nirizr/rematch.svg?branch=master
   :alt: Build Status
   :target: https://travis-ci.org/nirizr/rematch
.. |Codacy Badge| image:: https://api.codacy.com/project/badge/Grade/244945976779490d8f78706a9d4ab46b
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/rematch/rematch?utm_campaign=Badge_Grade
.. |idaplugin PyPI| image:: https://img.shields.io/pypi/v/rematch-idaplugin.svg
   :alt: rematch-idaplugin PyPI
   :target: https://pypi.python.org/pypi/rematch-idaplugin
.. |server PyPI| image:: https://img.shields.io/pypi/v/rematch-server.svg
   :alt: rematch-server PyPI
   :target: https://pypi.python.org/pypi/rematch-server
