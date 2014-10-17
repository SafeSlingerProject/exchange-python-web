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
We also use bitarray library to computate word phrases during verification.

## Install [pycrypto](https://pypi.python.org/pypi/pycrypto) for symmetric cryptography.
- Download source tarball from the website, the newest verison is 2.6.1 now.
- Untar the source and run **python setup.py build**.
- Then run **python setup.py install** to install the library.

## Install [pysha3](https://pypi.python.org/pypi/pysha3/) for SHA3 hash library.
- Download source tarball from the website, the newest verison is 3.0.3 now.
- Untar the source and run **python setup.py build**.
- Then run **python setup.py install** to install the library.

## Install [bitarray](https://pypi.python.org/pypi/bitarray/0.8.1) for BitArray library.
- Download source tarball from the website, the newest verison is 0.8.1 now.
- Untar the source and run **python setup.py install** to install the library.

Run SafeSlinger Client:
========

Simply execute **python main.py** in **/exchangelibrary** folder. The program will run in terminal to allow user to exchange secrets other python clients.
Mobile devices can install SafeSlinger Exchange Developer's App on either [Android](http://play.google.com/store/apps/details?id=edu.cmu.cylab.starslinger.demo) or [iOS](https://itunes.apple.com/app/safeslinger-exchange-for-developers/id909442873) to perform secret exchange with python clients.


Todo:
========

1. Support python 3.x.
2. Design customized UI for laptop environment.

Contact
=======

* SafeSlinger [Project Website](http://www.cylab.cmu.edu/safeslinger)
* Please submit [Bug Reports](http://github.com/SafeSlingerProject/exchange-python-web//issues)!
* Looking for answers, try our [FAQ](http://www.cylab.cmu.edu/safeslinger/faq.html)!
* Support: <safeslingerapp@gmail.com>

License
=======
	The MIT License (MIT)

	Copyright (c) 2010-2014 Carnegie Mellon University

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
