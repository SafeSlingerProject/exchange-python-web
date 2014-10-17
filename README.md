exchange-python-web
===================

Web based version of the SafeSlinger key exchange library in Python.


SafeSlinger Python Client
===================
The open source SafeSlinger Exchange library is a secure and easy to use method of exchanging public keys or other authentication data, with strong protection from Man-In-The-Middle (MITM) attacks. Our goal is to make exchanging public keys as simple as possible without sacrificing security. Our [research paper](http://sparrow.ece.cmu.edu/group/pub/farb_safeslinger_mobicom2013.pdf), presented at MobiCom '13, provides a technical analysis of SafeSlinger's key exchange properties.

Library Features:

- Open source makes security audits easy.
- The only secure simultaneous key exchange for up to 10 people.
- Easy to implement and use.
- Cross-platform between mobile devices (Android and iOS) and laptop machines (Python).
- Protection from Man-In-The-Middle attacks during key exchanges.
- Exchange keys either in person or remote.

The SafeSlinger secure key exchange is implemented cross-platform for [Android](http://github.com/SafeSlingerProject/SafeSlinger-Android) and [iOS](http://github.com/SafeSlingerProject/SafeSlinger-iOS) devices. Keys are exchanged using a simple server implementation on [App Engine](http://github.com/SafeSlingerProject/SafeSlinger-AppEngine).

Repository Python Projects
=======

- **/exchangelibrary** contains the library project you can add to your own python applications. 


Requirement:
========

The python exchange program currently runs for python 2.x now.
Since we leverage several cryptographic primitives, we require users to install pycrypto and pysha3.

## Install [pycrypto](https://pypi.python.org/pypi/pycrypto) for symmetric cryptography.
- Download source tarball from the website, the newest verison is 2.6.1 now.
- Untar the source and run **python setup.py build**.
- Then run **python setup.py install** to install the library.

## Install [pysha3](https://pypi.python.org/pypi/pysha3/) for SHA3 hash library.
- Download source tarball from the website, the newest verison is 3.0.3 now.
- Untar the source and run **python setup.py build**.
- Then run **python setup.py install** to install the library.

Run SafeSlinger Client:
========

Simply execute **python main.py** in **/exchangelibrary** folder. The program will run in terminal to allow user to exchange secrets other python clients.
Mobile devices can install SafeSlinger Exchange Developer's App on either [Android](http://play.google.com/store/apps/details?id=edu.cmu.cylab.starslinger.demo) or [iOS](https://itunes.apple.com/app/safeslinger-exchange-for-developers/id909442873) to perform secret exchange with python clients.


Todo:
========

1. Support python 3.x.
2. Design customized UI for laptop environment.
