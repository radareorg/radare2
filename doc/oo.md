Radare OO
=========

I do realize that Object Orientation sucks, so I tried to do libr API
following some sane and basic OO concepts.

  - No inheritance
  - Instances are used to keep states
  - Enforces instance recycling
  - Reduce creation/destruction of objects
  - Easily interfaced with Vala through the VAPIs

Global picture
--------------

```
[Class]
   |
   |-- [Plugins]  // shared among instances
   |        \
   |         \
   `------> [Instance] ----> [Liberation]
```

* We need a construction/destruction API for plugins among instances
  - simplify code

A library implements a set of functionalities, those ones are mainly
the lifecycle of the class containing the state of

Plugins are singletons. Or we will have to create factories for every class.

Lifecycle of the class
----------------------

Class
   - new
   - as_new
   - init
   - free

Library plugins
---------------
  They are stored in the p/ directory of each library under the libr directory.

