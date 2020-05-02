package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	termutil "github.com/andrew-d/go-termutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// custom struct for parshing phishtank urls
type PhishUrls struct {
	URL string `json:"url"`
}

// read from the PhishTank URL and return just the urls
func GetPhishTankURLs() ([]PhishUrls, error) {
	pturl := "http://data.phishtank.com/data/0b393f31fd33920fb29454c5aa984e90e6e16a24be239f69c20f58986d454a7f/online-valid.json"
	resp, err := http.Get(pturl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var urls []PhishUrls
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	respByte := buf.Bytes()
	if err := json.Unmarshal(respByte, &urls); err != nil {
		return nil, err
	}
	return urls, nil
}

// process user input
func GetUserInput() chan string {
	var urls []PhishUrls

	_urls := make(chan string, 1)

	// if nothing on stdin, default getting input from phishtank
	if termutil.Isatty(os.Stdin.Fd()) {

		pturls, err := GetPhishTankURLs()
		if err != nil {
			panic(err)
		}
		urls = pturls

	} else {

		// if we do have stdin input, process that instead
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urls = append(urls, PhishUrls{URL: sc.Text()})
		}
	}

	/*
	   now we have our urls
	   iterate through the paths in each to generate
	   a target list...e.g.
	     http://example.com/foo/bar
	     http://example.com/foo/
	     http://example.com/
	   and feed them to the _urls channel to process
	*/
	go func() {
		seen := make(map[string]bool)

		for _, row := range urls {
			myurl := row.URL

			// parse the url
			u, err := url.Parse(myurl)
			if err != nil {
				fmt.Printf("[!] Error processing %s\n", myurl)
				continue
			}
			// split the paths from the parsed url
			paths := strings.Split(u.Path, "/")

			// iterate over the paths slice to traverse and send to urls channel
			for i := 0; i < len(paths); i++ {
				_path := paths[:len(paths)-i]
				tmp_url := fmt.Sprintf(u.Scheme + "://" + u.Host + strings.Join(_path, "/"))

				// if we've seen the url already, keep moving
				if _, ok := seen[tmp_url]; ok {
					// if verbose {
					//   fmt.Printf("[+] Already seen %s\n", tmp_url)
					// }
					continue
				}

				// add to seen
				seen[tmp_url] = true

				// feed the _urls channels
				_urls <- tmp_url
			}
		}
		close(_urls)
	}()
	return _urls
}

func IsPathAZip(client *http.Client, url string) bool {

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	contentlength := resp.ContentLength
	contentType := resp.Header.Get("Content-Type")

	if contentlength > 0 && strings.Contains(contentType, "zip") {
		return true
	}

	return false
}
