package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Thic Client keep reuses a single H3 Client instances

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
	caCertRaw, err := ioutil.ReadFile("pauling.crt") // "ca.pem"
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
	qlogEnable := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	interval := flag.Int("interval", 5, "interval between each request")
	numRequest := flag.Int("numRequest", 1, "number of requests send in one test")
	bodyContent := flag.String("body", "", "key log file")
	printResp := flag.Bool("p", false, "print resp")

	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
		//logger.SetLogLevel(utils.LogLevelNothing)
	}

	timeFormat := "2006-01-02 15:04:05.000"
	logger.SetLogTimeFormat(timeFormat)
	//logger.SetLogTimeFormat("[quic_client]")

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

	tokenGets := make(chan string, 100)
	tokenPuts := make(chan string, 100)
	tokenStore := newTokenStore(tokenGets, tokenPuts)

	qconf := &quic.Config{
		TokenStore: tokenStore,
		Versions:           []protocol.VersionNumber{protocol.VersionDraft32},
		//, protocol.VersionDraft29, protocol.VersionTLS
		//Versions: [VersionDraft29, VersionDraft32],
	}

	if *qlogEnable {
		qconf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	log.Printf("Start Test\n")

	tlcConfig := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: *insecure,
		KeyLogWriter:       keyLog,
		//NextProtos: []string{nextProtoH3},
	}

	gets := make(chan string, 100)
	puts := make(chan string, 100)
	tlcConfig.ClientSessionCache = newClientSessionCache(gets, puts)

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlcConfig,
		QuicConfig:      qconf,
	}

	hclient := &http.Client{
		Transport: roundTripper,
	}

	for i := 0; i < *numRequest; i++ {

		go func() {
			var wg sync.WaitGroup
			wg.Add(len(urls))
			startTime := time.Now()

			if *printResp {
				//fmt.Printf("[Before Connection] qconf.TokenStore: %s\n", qconf.TokenStore)
				//fmt.Printf("[Before Connection] tlcConfig.ClientSessionCache: %s\n", tlcConfig.ClientSessionCache
			}

			for _, addr := range urls {
				go func(addr string) {

					var req *http.Request
					if len(*bodyContent) > 0 {
						req, _ = http.NewRequest(http.MethodPost, addr, bytes.NewReader([]byte(*bodyContent)))
						if *printResp {
							fmt.Printf("[HTTP POST] Addr: %s, Body: %s\n", addr, *bodyContent)
						}
					} else {
						if *printResp {
							fmt.Printf("[HTTP GET0RTT] Addr: %s, Body: %s\n", addr, *bodyContent)
						}
						req, _ = http.NewRequest(http3.MethodGet0RTT, addr, nil)
						//req, _ = http.NewRequest(http.MethodGet, addr, nil)
					}

					//log.Println("Before DO: ", time.Since(startTime)): 0 ms

					rsp, err := hclient.Do(req)

					log.Println(time.Since(startTime)) // This time is a litter longer than the wireshark record.
																							// Don't know the reason: because of DNS

					if err != nil {
						log.Fatal(err)
					}

					if rsp.Body != nil {
						defer rsp.Body.Close()
					}

					body := &bytes.Buffer{}
					_, err = io.Copy(body, rsp.Body)
					if err != nil {
						log.Fatal(err)
					}

					//	logger.Infof("Request Body: %d bytes", body.Len())
					logger.Infof("Request Body: %s", body.Bytes())

					if *printResp {
						fmt.Printf("[HTTP Resp] Status: %d, Body: %s\n", rsp.StatusCode, body.Bytes())
					}
					wg.Done()
				}(addr)
			}
			wg.Wait()
		}()

		//log.Printf("%s", time.Since(startTime))
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

// clientSessionCache

type clientSessionCache struct {
	mutex sync.Mutex
	cache map[string]*tls.ClientSessionState

	gets chan<- string
	puts chan<- string
}

var _ tls.ClientSessionCache = &clientSessionCache{}

func newClientSessionCache(gets, puts chan<- string) *clientSessionCache {
	return &clientSessionCache{
		cache: make(map[string]*tls.ClientSessionState),
		gets:  gets,
		puts:  puts,
	}
}

func (c *clientSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {

	c.gets <- sessionKey
	c.mutex.Lock()
	session, ok := c.cache[sessionKey]
	c.mutex.Unlock()

	return session, ok
}

func (c *clientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.puts <- sessionKey
	c.mutex.Lock()
	c.cache[sessionKey] = cs
	c.mutex.Unlock()
}

// TokenStore
type tokenStore struct {
	store quic.TokenStore
	gets  chan<- string
	puts  chan<- string
}

var _ quic.TokenStore = &tokenStore{}

func newTokenStore(gets, puts chan<- string) quic.TokenStore {
	return &tokenStore{
		store: quic.NewLRUTokenStore(10, 4),
		gets:  gets,
		puts:  puts,
	}
}

func (c *tokenStore) Put(key string, token *quic.ClientToken) {
	c.puts <- key
	c.store.Put(key, token)
}

func (c *tokenStore) Pop(key string) *quic.ClientToken {
	c.gets <- key
	return c.store.Pop(key)
}
