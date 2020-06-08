package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"image"
	"image/png"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/signalsciences/tlstext"
)

func asyncRequestProcessor(ctx context.Context, wg *sync.WaitGroup, queue <-chan *http.Request) {
	defer wg.Done()
	header := []string{"date_time", "request_ip", "method", "host", "uri", "referrer", "user_agent", "query_string", "cookie", "xforwarded_for", "tsl_protocol", "tsl_cipher", "tsl_version", "http_version"}
	tickerFileRotation := time.NewTicker(1 * time.Hour)
	tickerFileFlush := time.NewTicker(2 * time.Minute)
	fileName := time.Now().Format("20060102T150400Z0700") + ".csv"
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	writer := csv.NewWriter(bufio.NewWriter(file))
	writer.Write(header)
	defer writer.Flush()
	line := 0
	for {
		select {
		case <-tickerFileRotation.C:
			writer.Flush()
			file.Close()
			line = 0
			fileName = time.Now().Format("20060102T150400Z0700") + ".csv"
			file, err = os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
			writer = csv.NewWriter(bufio.NewWriter(file))
			writer.Write(header)
		case <-tickerFileFlush.C:
			writer.Flush()
		case r := <-queue:
			record := []string{}
			record = append(record, time.Now().Format(time.RFC3339Nano))
			record = append(record, r.RemoteAddr)
			record = append(record, r.Method)
			record = append(record, r.Host)
			record = append(record, r.URL.Path)
			record = append(record, r.Referer())
			record = append(record, r.UserAgent())
			record = append(record, r.URL.Query().Encode())
			record = append(record, r.Header.Get("Cookie"))
			record = append(record, r.Proto)
			record = append(record, r.Header.Get("X-Forwarded-For"))
			if r.TLS != nil {
				record = append(record, r.TLS.NegotiatedProtocol)
				record = append(record, tlstext.CipherSuite(r.TLS.CipherSuite))
				record = append(record, tlstext.Version(r.TLS.Version))
			}
			writer.Write(record)
			line++
		case <-ctx.Done():
			writer.Flush()
			return
		}
	}
}

func asyncRequestLogger(queue chan<- *http.Request) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			go func() {
				queue <- r
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func queue() (chan<- *http.Request, <-chan *http.Request) {
	in := make(chan *http.Request)
	out := make(chan *http.Request)
	go func() {
		queue := []*http.Request{}
		outCh := func() chan *http.Request {
			if len(queue) == 0 {
				return nil
			}
			return out
		}
		curVal := func() *http.Request {
			if len(queue) == 0 {
				return nil
			}
			return queue[0]
		}
		for len(queue) > 0 || in != nil {
			select {
			case v, err := <-in:
				if !err {
					in = nil
				} else {
					queue = append(queue, v)
				}
			case outCh() <- curVal():
				queue = queue[:]
			}
		}
		close(out)
	}()
	return in, out
}

func main() {
	numCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUs)
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, image.Transparent)
	buffer := new(bytes.Buffer)
	png.Encode(buffer, img)
	fileSize := strconv.Itoa(len(buffer.Bytes()))
	in, out := queue()

	r.Use(asyncRequestLogger(in))
	wg.Add(1)
	go asyncRequestProcessor(ctx, wg, out)

	r.Get("/t.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", "inline; filename=t.png")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", fileSize)
		buffer.WriteTo(w)
	})

	r.Get("/", http.RedirectHandler("/t.png", 301).ServeHTTP)

	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	server := &http.Server{
		Addr:         "0.0.0.0:8080",
		Handler:      r,
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}
	go gracefullShutdown(ctx, cancel, wg, server, logger, quit, done)
	logger.Println("Server is ready to handle requests at", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Could not listen on %s: %v\n", server.Addr, err)
	}
	<-done
	logger.Println("Server stopped")
}

func gracefullShutdown(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, server *http.Server, logger *log.Logger, quit <-chan os.Signal, done chan<- bool) {
	<-quit
	logger.Println("Server is shutting down...")

	server.SetKeepAlivesEnabled(false)
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Could not gracefully shutdown the server: %v\n", err)
	}
	close(done)
	cancel()
	wg.Wait()
}
