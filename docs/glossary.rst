Glossary
========

Sorted alphabetically

.. glossary::

   Annotation
     A piece of information describing an :term:`Instance` in more detail, often
     created by the user while reverse engineering as part of the reverse
     engineering process. Annotations help the reverse engineer and therefore
     there's an advantage in applying annotations to matched :term:`Instances
     <Instance>`.

   Engine
     .. todo:: TODO
 
   File
     .. todo:: TODO

   Instance
     When used throughtout these docs, an Instance generally means a matchable
     object inside a binary file, or it's representation in any rematch
     component.

     The following are currently entities:

     #. A function defined within a binary executable.
     #. A function imported into a binary file from another binary.
     #. A stream of initialised data or structure.
     #. A stream of uninitialised data or structure.
  
   Project
     .. todo:: TODO

   Vector
      Raw data used to describe an :term:`Instance` in a way that facilitates and
      enables matching. Those are also occasionally called features in data-
      science and machine learning circles.
 
   Matcher
      Matchers implement the logic of matching :term:`Instances <Instance>`
      together using thier :term:`Vectors <Vector>`.

   Match Task
      .. todo:: TODO
