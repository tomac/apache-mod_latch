apache-mod_latch
================

mod_latch is an Apache 2.4 module that implements a latch-protected directory. Once configured, if Latch is 'on' everything behaves as expected, but if Latch is 'off', Apache returns a 404 Not Found error. This feature is really useful when you want to protect an Apache directory (for instance /admin) from sneaky visitors.

Installation
============

mod_latch only supports Apache 2.4 (2.2 is not supported) because it uses an Apache hook only available from version 2.4 (ap_hook_access_checker) that replaces many of the authentication hooks in earlier Apache versions. Apache 2.4.1 was released on February 2012 and any more updated version (2.4.10 at the time of this README file) is available in any popular linux distribution.

1) Install Apache 2.4.x and the Apache devel packages (we need apxs2 for compiling the module)
2) Install libcurl and openssl development libreries (used by the Latch SDK)
3) Download the Latch C SDK from https://github.com/ElevenPaths/latch-sdk-c
4) Compile the Latch C SDK with
   apxs2 -i -a -c mod_latch.c
5) Download de mod_latch Apache module from https://github.com/ElevenPaths/apache-mod_latch
6) Compile the module with root permissions
   apxs2 -i -a -c mod_latch.c latch.lo -lcurl

The apxs2 command (with root permissions) will compile and install the Apache module.

Now mod_latch is ready to be used. Just add a few lines in the directory you want to protect with Latch and replace MY_APP_ID, MY_SECRET_KEY and MY_ACCOUNT_ID with your corresponding values that you can get from the Latch developers website.

<Directory /var/www/admin/>
    LatchEnabled On
    LatchAppId MY_APP_ID
    LatchSecretKey MY_SECRET_KEY
    LatchAccountID MY_ACCOUNT_ID
</Directory>
