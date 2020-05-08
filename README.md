## kitphishr

Hunts for Phishing Kit source code by traversing URL folders and searching in open directories for zip files. 

The code handles large lists of URLs which may be hosting malicious content. You can supply your own list of URLs or alternatively the code will parse the latest list from PhishTank so you can easily go hunting for badness.

Phishing kit source code is particularly valuable to blue-teamers as often it's easy to find the identity of the bad-guy in addition to log file locations where victim data is stored on the server.

## Recommended Usage

`$ cat urls | kitphishr -c 250 -v -d -o output`

or 

`$ kitphishr -c 250 -v -d -o output`

or simply

`$ kitphishr`

## Options

```
-c int
    set the concurrency level (default 50)

-d  option to download suspected phishing kits

-o string
    directory to save output files (default "kits")

-v  get more info on URL attempts
```

## Install

You need to have Go installed and configured (i.e. with $GOPATH/bin in your $PATH):

`go get -u github.com/cybercdh/kitphishr`



