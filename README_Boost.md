# Notes on building Boost from scratch

We use [Boost python](https://www.boost.org/doc/libs/1_79_0/libs/python/doc/html/index.html) to link the C++ ParallelPcap library to python, so that we can use it within python. This documents the process building the library from scratch.

* Install python3: Make sure you have python installed on your system, with a version greater than 3.5.
  * Numpy: Make sure that the python you intend to use has numpy installed.
* Boost: Get the source from [here](boost.org). The latest version should work. Follow the instructions for building with following modifications:
  * Bootstrap: for the boostrap.sh step, be sure to point to the python version with the _--with-python_ switch.
  * b2: After running _./b2 install_, you can check that it worked by looking at the library directory (by default on linux systems, that is /usr/local/lib). The two libraries you need are:
    * libboost_python3\<minor\>.\<lib extension\>, where \<minor\> is the minor version of python (e.g. if you have python 3.6.8, it would be 6), and \<lib extension\> is a _a_, _so_, and a _so.<boost_version>.
    * libboost_numpy3\<minor\>.\<lib extension\>
    
ParallelPcap uses other boost components, which you can find in packet2vec/ParallelPcap/CMakeLists.txt, but the python component is the one liable to have issues if the above is not followed.  

## Notes on Centos 7

Centos 7 comes with GCC 4.8.5 which has some support for c++11. A recent addition to the ParallelPcap code base added a component (get_time) that is not supported in GCC 4.8.5. As such, I added GCC 9.5.0, building it from source:

 * wget https://ftp.gnu.org/gnu/gcc/gcc-9.5.0/gcc-9.5.0.tar.gz 
 * tar xzvf gcc-9.5.0.tar.gz
 * mkdir obj.gcc-9.5.0
 * cd gcc-9.5.0/
 * ./contrib/download_prerequisites
 * cd ../obj.gcc-9.5.0/ 
 * ../gcc-9.5.0/configure --enable-languages=c,c++ --disable-multilib
 * make -j 10
 * make install

After that, getting boost to build was problematic. What eventually worked:

 * I created ~/user-config.jam with the following contents:
 {
    using gcc : : g++ ;
    using python : 3.6 : /usr/bin/python3 ;
 }
 * ./bootstrap.sh --with-libraries=python --with-python=python3
 * ./b2

For some reason, b2 would not install to /usr/local, even when explicitly stating the prefix (e.g. with --install --prefix=/usr/local).  I think it was because of an error in the generated project-config.xml.



