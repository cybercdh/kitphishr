package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/gookit/color"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	userAgent        = "Mozilla/5.0 (compatible; kitphishr/0.1; +https://github.com/cybercdh/kitphishr)"
	defaultOutputDir = "./out"
)

// globals arg vars
var verbose bool
var concurrency int

var tr = &http.Transport{
	TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	DisableKeepAlives: true,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

var c = &http.Client{
	Transport: tr,
}

func main() {

	flag.IntVar(&concurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&verbose, "v", false, "Get more info on URL attempts")
	flag.Parse()

	// timeout := time.Duration(to * 1000000)
	timeout := time.Second * 5

	var tr = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}

	// client := MakeClient()
	jobs := make(chan string)

	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {

		wg.Add(1)

		go func() {

			defer wg.Done()

			for url := range jobs {

				zipurl := url + ".zip"

				// ignore http://example.com/.zip
				if strings.HasSuffix(zipurl, "/.zip") {
					continue
				}

				// ignore http://example.com.zip
				if strings.Count(zipurl, "/") < 3 {
					continue
				}

				if verbose {
					fmt.Printf("[+]	Attempting %s\n", zipurl)
				}

				if IsPathAZip(client, zipurl) {
					if verbose {
						color.Green.Printf("[+]	Found phishing kit from path at %s\n", zipurl)
					} else {
						fmt.Println(zipurl)
					}
				}
			}

		}()

	}

	// get input and send urls to jobs chan
	urls := GetUserInput()
	for url := range urls {
		jobs <- url
	}

	close(jobs)

	wg.Wait()
}
