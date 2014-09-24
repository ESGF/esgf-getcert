esgf-getcert (MyProxyLogon jar)
============

This branch of esgf-getcert explores use MyProxyLogon of http://grid.ncsa.illinois.edu/myproxy/MyProxyLogon/ instead of MyProxy and implements a own implementation to convert private key PKCS#8 in PKCS#1.  So it can avoid the bug with openJDK versions (https://github.com/ESGF/esgf-getcert/issues/2).

Also, this new implementation allows generate a getcert.jar smaller than MyProxy version getcert.jar.

  new getcert.jar with MyProxyLogon -> 229,7 kB                                                                            
  old getcert.jar with MyProxy -> 2,5 MB

This new version has been run succesfully in openJDK 6/7 and JDK7.
