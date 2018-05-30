Architecture
============

The rematch solution is divided into two main parts: a client and a server.
The server is in-charge of most of the heavy lifting, matching, and data
storage. The client is collecting :term:`Annotations <Annotation>` and
:term:`Vectors <Vector>`, applying annotations after matches are displayed to
the user and overall user interface.

Clients are designed to be replacable, however we only have an IDA client at
the moment.

Data Model
----------

Project Layout
++++++++++++++

A :term:`Files <File>` object is a database representation of a single binary
instance being reverse engineered. While working on two distinctive versions of
the same application, each of those versions should have a different File
object for it's executable binary. If the application also has a single DLL,
you should have 4 File objects. A good rule of thumb is that each File object
should have an IDA IDB file.

In rematch, files are grouped together into :term:`Projects <Project>`. The
purpose of projects is completely left to the user. For example a project could
be holding all versions of a single executable or all executables of a single
application.

The obvious purpose of dividing files to projects is logical seperation and
ease of use, but another notable advantage is matching granularity. When
starting a :term:`Match Task`, the user is able to choose to match the current
file against either a single oher file, all files in it's project, all files in
another project or against the entire database. This is so a user could create
a single project for all files of a specific application version and another
project for a different version. Then, to only get matches from the previous
version, a single remote project match is performed. Alternatively, a single
project can hold multiple versions of a single library (or all libraries with a
similar functionality) and then requesting matches between an malware
executable and all SSL libraries.

File Binding
++++++++++++
Binding a file means an IDB will be associated with a specific :term:`File`
object in the remote server. This lets rematch automatically identify the
database object describing the current IDB. This is how matches are made and
are linked to a specific IDB, this is how caching of uploaded :term:`Vectors
<Vector>` and :term:`Annotations <Annotation>` is done.

File bindings are embedded inside IDB files, which means multiple copies of the
same IDB file will share their File databsse objects.

File Version
++++++++++++

.. todo:: Document the file version concept

Matching Process
----------------

Matches are made using three entity types defined throughout the rematch
project:

* :term:`Vectors <Vector>`
* :term:`Matchers <Matcher>`
* :term:`Strategies <Strategy>`

Vectors
-------

.. todo:: explain what vectors are

.. todo:: document existing vectors

Matcher / Matching Engines
--------------------------

.. todo:: explain what matchers are

.. todo:: document existing engines

Strategies
----------
Strategies control the way multiple :term:`Matchers <Matcher>` are used
together, which :term:`Instances <Instance>` are matched against which and
other similar logical decisions that may have significant implications on the
overall outcome of the matching process.

For example, one could wish to match all instances against all other instances,
in an "All VS All" kind of way. This is the "All" Strategy. However when
comparing big databases, one may point out matching 5-byte and 1000-byte long
functions to each-other is redundant, as those are highly unlikely to match.
Therefore, "Binning" functions and only matching the bins might speed up the
matching process without causing a decrease in match accuracy, as it may reduce
a lot of unnecessary matches. This is called the "Binning  strategy".
