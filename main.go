package main

import (
	"flag"
	"fmt"
	"github.com/gookit/color"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const MAX_DOWNLOAD_SIZE = 104857600 // 100MB

var verbose bool
var downloadKits bool
var concurrency int
var to int
var defaultOutputDir string
var index *os.File

func main() {

	flag.IntVar(&concurrency, "c", 50, "set the concurrency level")
	flag.IntVar(&to, "t", 45, "set the connection timeout in seconds (useful to ensure the download of large files)")
	flag.BoolVar(&verbose, "v", false, "get more info on URL attempts")
	flag.BoolVar(&downloadKits, "d", false, "option to download suspected phishing kits")
	flag.StringVar(&defaultOutputDir, "o", "kits", "directory to save output files")

	flag.Parse()

	client := MakeClient()

	targets := make(chan string)
	responses := make(chan Response)
	tosave := make(chan Response)

	// create the output directory, ready to save files to
	if downloadKits {
		err := os.MkdirAll(defaultOutputDir, os.ModePerm)
		if err != nil {
			fmt.Printf("There was an error creating the output directory : %s\n", err)
			os.Exit(1)
		}
		// open the index file
		indexFile := filepath.Join(defaultOutputDir, "/index")
		index, err = os.OpenFile(indexFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open index file for writing: %s\n", err)
			os.Exit(1)
		}
	}

	// worker group to fetch the urls from targets channel
	// send the output to responses channel for further processing
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {

		wg.Add(1)

		go func() {

			defer wg.Done()

			for url := range targets {
				if verbose {
					fmt.Printf("Attempting %s\n", url)
				}
				res, err := AttemptTarget(client, url)
				if err != nil {
					continue
				}

				responses <- res
			}

		}()

	}

	// response group
	// determines if we've found a zip from a url folder
	// or if we've found an open directory and looks for a zip within
	var rg sync.WaitGroup

	for i := 0; i < concurrency/2; i++ {

		rg.Add(1)

		go func() {

			defer rg.Done()

			for resp := range responses {

				if resp.StatusCode != http.StatusOK {
					continue
				}

				requrl := resp.URL

				// if we found a zip from a URL path
				if strings.HasSuffix(requrl, ".zip") {

					// make sure it's a valid zip
					if resp.ContentLength > 0 && resp.ContentLength < MAX_DOWNLOAD_SIZE && strings.Contains(resp.ContentType, "zip") {

						if verbose {
							color.Green.Printf("Zip found from URL folder at %s\n", requrl)
						} else {
							fmt.Println(requrl)
						}

						// download the zip
						if downloadKits {
							tosave <- resp
							continue
						}
					}
				}

				// check if we've found an open dir containing a zip
				// todo - walk an open dir for zips in other folders
				href, err := ZipFromDir(resp)
				if err != nil {
					continue
				}
				if href != "" {
					hurl := ""
					if strings.HasSuffix(requrl, "/") {
						hurl = requrl + href
					} else {
						hurl = requrl + "/" + href
					}
					if verbose {
						color.Green.Printf("Zip found from Open Directory at %s\n", hurl)
					} else {
						fmt.Println(hurl)
					}
					if downloadKits {
						resp, err := AttemptTarget(client, hurl)
						if err != nil {
							if verbose {
								color.Red.Printf("There was an error downloading %s\n", hurl)
							}
							continue
						}
						tosave <- resp
						continue
					}
				}
			}
		}()
	}

	// save group
	var sg sync.WaitGroup

	// give this a few threads to play with
	for i := 0; i < 10; i++ {

		sg.Add(1)

		go func() {
			defer sg.Done()
			for resp := range tosave {
				filename, err := SaveResponse(resp)
				if err != nil {
					if verbose {
						color.Red.Printf("There was an error saving %s : %s\n", resp.URL, err)
					}
					continue
				} else if filename != "" {
					if verbose {
						color.Yellow.Printf("Successfully saved %s\n", filename)
					}
					// update the index file
					line := fmt.Sprintf("%s : %s\n", resp.URL, filename)
					fmt.Fprintf(index, "%s", line)
				}
			}
		}()
	}

	// get input either from user or phishtank
	input, err := GetUserInput()
	if err != nil {
		fmt.Printf("There was an error getting URLS from PhishTank.\n")
		os.Exit(3)
	}

	// generate targets based on user input
	urls := GenerateTargets(input)

	// send target urls to target channel
	for url := range urls {
		targets <- url
	}

	close(targets)
	wg.Wait()

	close(responses)
	rg.Wait()

	close(tosave)
	sg.Wait()

}
