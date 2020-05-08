package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	termutil "github.com/andrew-d/go-termutil"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// custom struct for parsing phishtank urls
type PhishUrls struct {
	URL string `json:"url"`
}

/*
	read from the PhishTank URL and return just the urls
*/
func GetPhishTankURLs() ([]PhishUrls, error) {

	pturl := "http://data.phishtank.com/data/online-valid.json"

	// if the user has their own phishtank api key, use it
	apiKey := os.Getenv("PT_API_KEY")
	if apiKey != "" {
		pturl = fmt.Sprintf("http://data.phishtank.com/data/%s/online-valid.json", apiKey)
	}

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

/*
	get a list of urls either from the user
	piping into this program, or fetch the latest
	phishing urls from phishtank
*/
func GetUserInput() ([]PhishUrls, error) {

	var urls []PhishUrls

	// if nothing on stdin, default getting input from phishtank
	if termutil.Isatty(os.Stdin.Fd()) {

		pturls, err := GetPhishTankURLs()
		if err != nil {
			return urls, err
		}
		urls = pturls

	} else {

		// if we do have stdin input, process that instead
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urls = append(urls, PhishUrls{URL: sc.Text()})
		}
	}

	return urls, nil

}

/*
   iterate through the paths of each url to generate
   a target list...e.g.
     http://example.com/foo/bar
     http://example.com/foo/bar.zip
     http://example.com/foo/
     http://example.com/foo.zip
     http://example.com/
*/
func GenerateTargets(urls []PhishUrls) chan string {

	_urls := make(chan string, 1)

	go func() {

		seen := make(map[string]bool)

		for _, row := range urls {
			myurl := row.URL

			// parse the url
			u, err := url.Parse(myurl)
			if err != nil {
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

				// guess zip path and send to targets
				zipurl := tmp_url + ".zip"

				// ignore http://example.com/.zip and http://example.com.zip
				if strings.HasSuffix(zipurl, "/.zip") || strings.Count(zipurl, "/") < 3 {
					continue
				}

				// add this one to seen too
				seen[zipurl] = true

				// feed the _urls channels
				_urls <- zipurl
			}
		}
		close(_urls)
	}()

	return _urls
}

func ZipFromDir(resp *http.Response) (string, error) {

	ziphref := ""

	// read body for hrefs
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ziphref, err
	}

	title := doc.Find("title").Text()

	if strings.Contains(title, "Index of /") {
		doc.Find("a").Each(func(i int, s *goquery.Selection) {
			if strings.Contains(s.Text(), ".zip") {
				ziphref = s.Text()
			}
		})
	}

	return ziphref, nil
}

/*
	make an http client
	allow redirects
	skip ssl warnings
	set some timeouts
*/
func MakeClient() *http.Client {

	proxyURL := http.ProxyFromEnvironment

	var tr = &http.Transport{
		Proxy: proxyURL,
		// MaxIdleConns:        1000,
		// MaxIdleConnsPerHost: 500,
		// MaxConnsPerHost:     500,
		// IdleConnTimeout:     time.Second * 1,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			// KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	// re := func(req *http.Request, via []*http.Request) error {
	// 	return http.ErrUseLastResponse
	// }

	client := &http.Client{
		Transport: tr,
		// CheckRedirect: re,
		Timeout: time.Second * 15,
	}

	return client

}

/*
	peform a GET against the target URL
	return the response
*/
func AttemptTarget(client *http.Client, url string) (*http.Response, error) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")
	req.Header.Add("Connection", "close")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil

}

/*
	saves the resp.body to a file
	calls it name.ext_sha1
	returns name of file, err
*/
func SaveResponse(resp *http.Response) (string, error) {

	filename := ""

	// convert the body to bytes to generate the sha1sum
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return filename, err
	}

	data := []byte(bodyBytes)
	checksum := sha1.Sum(data)
	filename = fmt.Sprintf("%s_%x", path.Base(resp.Request.URL.Path), checksum)

	// restore the ioreader to get back the content of resp.body
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// create the output file
	out, err := os.Create(defaultOutputDir + "/" + filename)
	if err != nil {
		return filename, err
	}
	defer out.Close()

	// write the body to file
	_, err = io.Copy(out, resp.Body)
	return filename, err
}
