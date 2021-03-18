package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
	caCertRaw, err := ioutil.ReadFile("pauling.crt")
	if err != nil {
		panic(err)
	}
	if ok := certPool.AppendCertsFromPEM(caCertRaw); !ok {
		panic("Could not add root ceritificate to pool.")
	}
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	//quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	interval := flag.Int("interval", 10, "interval between each request")
	numRequest := flag.Int("numRequest", 20, "number of requests send in one test")
	bodyContent := flag.String("body", "", "key log file")
	printResp := flag.Bool("p", false, "verbose")

	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		//logger.SetLogLevel(utils.LogLevelInfo)
		logger.SetLogLevel(utils.LogLevelNothing)
	}

	logger.SetLogTimeFormat("[kaiyhou_client_tls]")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool := x509.NewCertPool()
	AddRootCA(pool)


	log.Println("Start Test")
	for i := 0; i < *numRequest; i ++ {
		go func() {
			var wg sync.WaitGroup
			wg.Add(len(urls))
			startTime := time.Now()

			roundTripper := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            pool,
					InsecureSkipVerify: *insecure,
					KeyLogWriter:       keyLog,
				},
			}

			hclient := &http.Client{
				Transport: roundTripper,
			}
			defer hclient.CloseIdleConnections()

			for _, addr := range urls {
				logger.Infof("GET %s", addr)
				go func(addr string) {

					var req *http.Request
					if len(*bodyContent) > 0 {
						req, _ = http.NewRequest(http.MethodPost, addr, bytes.NewReader([]byte(*bodyContent)))
						if *printResp {
							fmt.Printf("[HTTP POST] Addr: %s, Body: %s\n", addr, *bodyContent)
						}
					} else {
						req, _ = http.NewRequest(http.MethodGet, addr, nil)
						if *printResp {
							fmt.Printf("[HTTP GET] Addr: %s, Body: %s\n", addr, *bodyContent)
						}
					}

					rsp, err := hclient.Do(req)

					log.Printf("%s", time.Since(startTime))

					if err != nil {
						log.Fatal(err)
					}

					body := &bytes.Buffer{}
					_, err = io.Copy(body, rsp.Body)
					if err != nil {
						log.Fatal(err)
					}

					logger.Infof("Got response for %s: %#v", addr, rsp)
					logger.Infof("Request Body: %d bytes", body.Len())

					if *printResp {
						fmt.Printf("[HTTP Resp] Body: %s\n", body.Bytes())
					}

					wg.Done()
				}(addr)
			}
			wg.Wait()
		}()
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}
