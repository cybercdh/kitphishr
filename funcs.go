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

type Response struct {
	StatusCode    int64
	Body          []byte
	URL           string
	ContentLength int64
	ContentType   string
}

func NewResponse(httpresp *http.Response, url string) Response {
	var resp Response
	resp.StatusCode = int64(httpresp.StatusCode)

	if respbody, err := ioutil.ReadAll(httpresp.Body); err == nil {
		resp.Body = respbody
	}

	resp.URL = url
	return resp
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

/*
	parse the response to see if we've hit an open dir
	if we have, then look for hrefs that are zips
*/
func ZipFromDir(resp Response) (string, error) {

	ziphref := ""

	// read body for hrefs
	data := bytes.NewReader(resp.Body)
	doc, err := goquery.NewDocumentFromReader(data)
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
		MaxConnsPerHost:   50,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			DualStack: true,
		}).DialContext,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 15,
	}

	return client

}

/*
	peform a GET against the target URL
	return the response
*/
func AttemptTarget(client *http.Client, url string) (Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Response{}, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36")
	req.Header.Add("Connection", "close")
	req.Close = true

	httpresp, err := client.Do(req)
	if err != nil {
		return Response{}, err
	}

	defer httpresp.Body.Close()

	resp := NewResponse(httpresp, url)

	resp.ContentLength = httpresp.ContentLength
	resp.ContentType = httpresp.Header.Get("Content-Type")

	return resp, nil

}

/*
	saves the resp.body to a file
	calls it sha1_name.ext
	note uses first half of sha1 hash to keep filenames
	relatively short.
	returns name of file, err
*/
func SaveResponse(resp Response) (string, error) {

	checksum := sha1.Sum(resp.Body)
	filename := fmt.Sprintf("%x_%s",checksum[:len(checksum)/2], path.Base(resp.URL))

	// create the output file
	out, err := os.Create(defaultOutputDir + "/" + filename)
	if err != nil {
		return filename, err
	}
	defer out.Close()

	// write the body to file
	out.Write(resp.Body)

	return filename, err
}
