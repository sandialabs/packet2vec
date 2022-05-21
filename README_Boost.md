# Notes on building Boost from scratch

We use [Boost python](https://www.boost.org/doc/libs/1_79_0/libs/python/doc/html/index.html) to link the C++ ParallelPcap library to python, so that we can use it within python. This documents the process building the library from scratch.

* Install python3: Make sure you have python installed on your system, with a version greater than 3.5.
  * Numpy: Make sure that the python you intend to use has numpy installed.
* Boost: Get the source from [here](boost.org). The latest version should work. Follow the instructions for building with following modifications:
  * Bootstrap: for the boostrap.sh step, be sure to point to the python version with the _--with-python_ switch.
  * b2: After running _./b2 install_, you can check that it worked by looking at the library directory (by default on linux systems, that is /usr/local/lib). The two libraries you need are:
    * libboost_python3<minor>.<lib extension>, where <minor> is the minor version of python (e.g. if you have python 3.6.8, it would be 6), and <lib extension> is a _a_, _so_, and a _so.<boost_version>.
    * libboost_numpy3<minor>.<lib extension>
    
ParallelPcap uses other boost components, which you can find in packet2vec/ParallelPcap/CMakeLists.txt, but the python component is the one liable to have issues if the above is not followed.  
 
