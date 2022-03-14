package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
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
	"sync"
	"time"
)

type PhishUrls struct {
	URL string `json:"url"`
}

type fetchFn func() ([]PhishUrls, error)

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
	iterate over a list of functions to pull the latest
	phishfeed urls from each source. this provides an easy
	template to add more sources when they're identified
*/
func GetPhishURLsFromManyFeeds() ([]PhishUrls, error) {

	fetchFns := []fetchFn{
		getPhishTankURLs,
		getOpenPhishURLs,
		getNewLinksToday,
		getPhishStatsInfo,
	}

	phishing_urls := make(chan PhishUrls)
	out := make([]PhishUrls, 0)

	var wg sync.WaitGroup
	for _, fn := range fetchFns {
		wg.Add(1)
		fetch := fn
		go func() {
			defer wg.Done()
			resp, err := fetch()
			if err != nil {
				return
			}
			for _, r := range resp {
				phishing_urls <- r
			}
		}()
	}

	go func() {
		wg.Wait()
		close(phishing_urls)
	}()

	for w := range phishing_urls {
		out = append(out, PhishUrls{URL: w.URL})
	}

	return out, nil

}

func getOpenPhishURLs() ([]PhishUrls, error) {

	phishfeed := "https://openphish.com/feed.txt"

	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}

	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	out := make([]PhishUrls, 0)

	for sc.Scan() {
		out = append(out, PhishUrls{URL: sc.Text()})
	}
	return out, nil
}

func getPhishTankURLs() ([]PhishUrls, error) {

	phishfeed := "http://data.phishtank.com/data/online-valid.json"

	apiKey := os.Getenv("PT_API_KEY")
	if apiKey != "" {
		phishfeed = fmt.Sprintf("http://data.phishtank.com/data/%s/online-valid.json", apiKey)
	}

	resp, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}

	defer resp.Body.Close()

	var urls []PhishUrls
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	respByte := buf.Bytes()
	if err := json.Unmarshal(respByte, &urls); err != nil {
		return []PhishUrls{}, err
	}
	return urls, nil
}

func getNewLinksToday() ([]PhishUrls, error) {

	phishfeed := "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt"

	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}

	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	out := make([]PhishUrls, 0)

	for sc.Scan() {
		out = append(out, PhishUrls{URL: sc.Text()})
	}
	return out, nil
}

func getPhishStatsInfo() ([]PhishUrls, error) {

	phishfeed := "https://phishstats.info/phish_score.csv"
	out := make([]PhishUrls, 0)

	res, err := http.Get(phishfeed)
	if err != nil {
		return []PhishUrls{}, err
	}

	defer res.Body.Close()
	reader := csv.NewReader(res.Body)
	reader.Comma = ','
	reader.Comment = '#'
	data, err := reader.ReadAll()
	if err != nil {
		return []PhishUrls{}, err
	}

	for _, row := range data {
		out = append(out, PhishUrls{URL: row[2]})
	}
	return out, nil
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

		phishfeeds, err := GetPhishURLsFromManyFeeds()
		if err != nil {
			return urls, err
		}
		urls = phishfeeds

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
func ZipFromDir(resp Response) ([]string, error) {

	var zip_href []string

	// read body for hrefs
	data := bytes.NewReader(resp.Body)
	doc, err := goquery.NewDocumentFromReader(data)
	if err != nil {
		return nil, err
	}

	title := doc.Find("title").Text()

	if strings.Contains(title, "Index of /") {

		// iterate over each href and look for all zips
		doc.Find("a").Each(func(i int, s *goquery.Selection) {
			if strings.Contains(s.Text(), ".zip") {
				zip_href = append(zip_href, s.Text())
			}
		})

	}

	// return slice of zip hrefs
	return zip_href, nil
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
		Proxy:           proxyURL,
		MaxConnsPerHost: 50,
		// DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * time.Duration(to),
			DualStack: true,
		}).DialContext,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * time.Duration(to),
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

	req.Header.Set("User-Agent", ua)
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
	uses the url as the basis for the filename
*/
func (r Response) SaveResponse() (string, error) {
	/*
		WIP
		use the hostname as the filename when saving

		TODO
		check if r.Body > 0
		have option to overwrite existing files?
	*/

	content := r.Body

	// generate and clean the filename based on the url
	replacer := strings.NewReplacer("//", "_", "/", "_", ":", "", "&", "", ">", "", "<", "", " ", "_", ")", "", "(", "")
	filename := replacer.Replace(r.URL)
	parts := []string{defaultOutputDir}
	parts = append(parts, filename)
	p := path.Join(parts...)

	// truncate filename if it's too long
	// usually MAX is 255 chars
	if len(p) >= 255 {
		diff := len(p) - 255
		p = p[:100] + p[100+diff:]
	}

	// if file exists, return with an error
	// else write it
	if fileExists(p) {
		return "", errors.New("File already exists")
	} else {
		err := ioutil.WriteFile(p, content, 0640)
		if err != nil {
			return "", err
		}
	}
	return filename, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
