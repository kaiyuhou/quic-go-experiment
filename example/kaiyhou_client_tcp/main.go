package main

import (
	"bytes"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go"
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
// Keep this function for providing the same for CA loading time
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
	//qlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
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
		logger.SetLogLevel(utils.LogLevelNothing)
	}

	logger.SetLogTimeFormat("[tcp_client]")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	//pool, err := x509.SystemCertPool()
	//if err != nil {
	//	log.Fatal(err)
	//}
	pool := x509.NewCertPool()
	AddRootCA(pool)

	var qconf quic.Config

	log.Println(keyLog)
	log.Println(insecure)
	log.Println(qconf)


	log.Println("TCP Client Start Test")
	for i := 0; i < *numRequest; i ++ {

		go func() {
			var wg sync.WaitGroup
			wg.Add(len(urls))
			startTime := time.Now()

			hclient := &http.Client{}
			defer hclient.CloseIdleConnections()

			for _, addr := range urls {
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
							fmt.Printf("[HTTP POST] Addr: %s, Body: %s\n", addr, *bodyContent)
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

					logger.Infof("Request Body:")
					logger.Infof("%s", body.Bytes())

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
