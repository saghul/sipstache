
======================================================
sipstache: The Ultimate Virtual Moustache Toolkit (TM)
======================================================

sipstache is a `SylkServer <http://sylkserver.com>`_ demo application I coded for my talk "SIP is had let's go shopping!" which
I gave at FOSDEM 2013 (Telephony Devroom).

It handles incoming MSRP chat requests and file transfers and after getting a picture it processes
it using OpenCV and adds a moustache to the detected faces. Then it sends back the modified picture.
It's optimized for headshot style pictures.

The slides from the talk can be found `here <http://www.slideshare.net/saghul/sip-is-hard-lets-go-shopping>`_.


Installation
============

OpenCV is required, so make sure you have that installed first. Then just download sipstache somewhere
in your server and configure SylkServer to use it:

::

    mkdir -p ~/sylk-apps
    cd sylk-apps
    git clone https://github.com/saghul/sipstache

Now edit /etc/sylkserver/config.ini:

::

    application_map = echo:echo, sipstache:sipstache
    extra_applications_dir = /home/saghul/sylk-apps


Example
=======

Here is an example on how sipstache works.

Original picture:

.. image:: https://raw.github.com/saghul/sipstache/master/samples/saghul_head.jpg

Moustache-ified picture:

.. image:: https://raw.github.com/saghul/sipstache/master/samples/saghul_head_0.jpg

Moustache-ified picture with face and eyes detection debug enabled:

.. image:: https://raw.github.com/saghul/sipstache/master/samples/saghul_head_1.jpg

