package main

import (
	"flag"
	"fmt"
	"github.com/gookit/color"
	"strings"
	"sync"
)

const (
	defaultOutputDir = "./kits"
)

// globals arg vars
var verbose bool
var concurrency int

func main() {

	flag.IntVar(&concurrency, "c", 20, "set the concurrency level")
	flag.BoolVar(&verbose, "v", false, "Get more info on URL attempts")
	flag.Parse()

	client := MakeClient()

	zips := make(chan string)
	dirs := make(chan string)

	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {

		wg.Add(2)

		go func() {
			defer wg.Done()

			for url := range zips {

				if verbose {
					fmt.Printf("Attempting %s\n", url)
				}

				if IsPathAZip(client, url) {
					if verbose {
						color.Green.Printf("Found phishing kit from path at %s\n", url)
					} else {
						fmt.Println(url)
					}
				}
			}
		}()

		go func() {
			defer wg.Done()

			for url := range dirs {
				if verbose {
					fmt.Printf("Checking for open directory at %s\n", url)
				}

				zdurl := ZipFromDir(client, url)
				if zdurl == "" {
					continue
				}
				if verbose {
					color.Green.Printf("Found a zip from open directory at %s\n", zdurl)
				} else {
					fmt.Println(zdurl)
				}
			}
		}()

	} // concurrency

	// get input eithe from user or phishtank
	urls := GetUserInput()

	for url := range urls {

		// send to dirs channel
		dirs <- url

		// prep and send to zips channel
		zipurl := url + ".zip"

		// ignore http://example.com/.zip
		// ignore http://example.com.zip
		if strings.HasSuffix(zipurl, "/.zip") || strings.Count(zipurl, "/") < 3 {
			continue
		}

		zips <- zipurl
	}

	close(zips)
	close(dirs)
	wg.Wait()
}
