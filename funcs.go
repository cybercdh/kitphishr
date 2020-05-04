package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	termutil "github.com/andrew-d/go-termutil"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const MAX_DOWNLOAD_SIZE = 104857600 // 100MB

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
				if verbose {
					fmt.Printf("[!] Error processing %s\n", myurl)
				}
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

	if contentlength > 0 && contentlength < MAX_DOWNLOAD_SIZE && strings.Contains(contentType, "zip") {
		return true
	}

	return false
}

func ZipFromDir(client *http.Client, url string) string {

	// perform a GET
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}

	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	defer resp.Body.Close()

	zdurl := ""

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ""
		}
		bodyString := string(bodyBytes)
		if !strings.Contains(bodyString, "Index Of /") {
			return ""
		}
	}

	// read body for hrefs
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ""
	}

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if ok {
			if strings.Contains(href, ".zip") {
				if strings.HasSuffix(url, "/") {
					zdurl = url + href
				} else {
					zdurl = url + "/" + href	
				}
			}
		}
	})

	return zdurl
}

func MakeClient() *http.Client {

	proxyURL := http.ProxyFromEnvironment

	var tr = &http.Transport{
		Proxy:               proxyURL,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 500,
		MaxConnsPerHost:     500,
		IdleConnTimeout:     time.Second,
		DisableKeepAlives:   true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 5,
			KeepAlive: time.Second,
		}).DialContext,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       time.Second * 5,
	}

	return client

}
