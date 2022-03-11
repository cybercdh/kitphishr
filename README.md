## DEV VERSION - kitphishr
Hunts for Phishing Kit source code by traversing URL folders and searching in open directories for zip files. 

The code handles large lists of URLs which may be hosting malicious content. You can supply your own list of URLs or alternatively the code will parse the latest list from [PhishTank](https://www.phishtank.com/) so you can easily go hunting for badness.

Phishing kit source code is particularly valuable to blue-teamers as often it's easy to find the identity of the bad-guy in addition to log file locations where victim data is stored on the server.

## Recommended Usage

`$ cat urls | kitphishr -c 250 -v -d -o output`

or 

`$ kitphishr -c 250 -v -d -o output`

or simply

`$ kitphishr`

## Demo


![](https://github.com/cybercdh/kitphishr/blob/assets/demo.gif)

## Options

```
-c int
    set the concurrency level (default 50)

-d  option to download suspected phishing kits

-o string
    directory to save output files (default "kits")

-t int
    set the connection timeout in seconds (useful to ensure the download of large files)

-v  get more info on URL attempts
```

## Install

You need to have [Go installed](https://golang.org/doc/install) and configured (i.e. with $GOPATH/bin in your $PATH):

`go get -u github.com/cybercdh/kitphishr`

## Configuration

Kitphishr will work just fine right out of the box, but if you're going to be running this tool a lot then I suggest getting a [free API key from Phishtank](https://www.phishtank.com/api_register.php)

Then, you can save this as an environment variable which Kitphishr will find and use:

`$ export PT_API_KEY=<your_key>`

or, to make this persist, add the following to your `~/.bashrc` file:

`export PT_API_KEY=<your_key>`

## Thanks

A lot of Go concepts were taken from @tomnomnom's excellent repos, particularly [meg](https://github.com/tomnomnom/meg)

Additionally, I took inspiration from [ffuf](https://github.com/ffuf/ffuf)

Finally, the initial idea for writing this tool came from great research from [Duo Labs](https://github.com/duo-labs/phish-collect)

Thanks to each of these developers for their awesome open-source tools.
