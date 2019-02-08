Golang experiments
==================

Here are some of my personal Go programs, I'm working on these as I learn Go. They are probably going to be rough and I'll look back on this and probably cringe in pain, but I this is a start. Have mercy everyone. :-)

Cert.go
-------
This is mostly an attempt to get into x509 certificates at a lower level than what a typical openssl/certool/keytool might allow. 
The overall goal will be:
 - take certificate print:
  * expire date
  * CN
  * SAN DNS fields
  * key capabilities
  * public key
  * most importantly, Issuer
 - key:
  * obtain public key
 - requests:
  * generate them
  * view them
 - CA:
  * check cert against the given CA

Overall much of this has been done elsewhere, and has been done much better. I figure this is a nice opportunity to learn a few things and have fun in the process. I would also like for some of my peers to have an easier interface to interact with.

Bash to sqlite
--------------
I would like for my bash history to be stored, sometimes I would like to favorite a for loop or something like that. Right now, it works, but it is slow since it scans the whole file and stores it without doig any kind of analyzation. If this were Python I would have this done already. But with this project I think I will investigate goroutines, for concurrency.
