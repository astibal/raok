Raok
~~~~
is very simple RADIUS  **testing** server which accepts any authentication or accounting and
prints it out. Unless you specify otherwise.
It supports challenges, and PAP/CHAP/MS-CHAP/MS-CHAP2 and various other small things good for testing.

NOTE: before start, run **raok-init.sh** to create default config files.

You can configure it in:

.. code-block::

    /etc/raok/raok.cfg

or from current directory, if the above is not found.

.. code-block::

   ./etc/raok.cfg

Rasta
~~~~~
is very simple program sending RADIUS accounting  using the same config file.

Support
~~~~~~~

For comments, feedback or new feature discussion feel free to
drop a message to **pplay-users@googlegroups.com** mailing list.
