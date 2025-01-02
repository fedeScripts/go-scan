package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	host     = flag.String("ip", "127.0.0.1", "Host o dirección IP a escanear")
	hostFile = flag.String("iL", "", "Archivo con direcciones IP y/o redes en formato CIDR")
	ports    = flag.String("p", "1-65535", "Rango de puertos a comprobar: 80,443,1-65535,1000-2000, ...")
	threads  = flag.Int("T", 1000, "Número de hilos a usar")
	timeout  = flag.Duration("timeout", 1*time.Second, "Segundos por puerto")
	output   = flag.String("o", "", "Archivo para guardar el resultado del escaneo")

// verbose  = flag.Bool("v", false, "Mostrar el progreso del escaneo")
)

func readHostsFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			hosts = append(hosts, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

func parseHosts() ([]string, error) {
	var hosts []string

	if *hostFile != "" {
		fileHosts, err := readHostsFromFile(*hostFile)
		if err != nil {
			return nil, fmt.Errorf("error leyendo archivo de hosts: %v", err)
		}
		hosts = append(hosts, fileHosts...)
	}

	if *host != "" {
		hosts = append(hosts, strings.Split(*host, ",")...)
	}

	return hosts, nil
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func processRange(ctx context.Context, r string) chan int {
	c := make(chan int)
	done := ctx.Done()

	go func() {
		defer close(c)
		blocks := strings.Split(r, ",")

		for _, block := range blocks {
			rg := strings.Split(block, "-")
			var minPort, maxPort int
			var err error

			minPort, err = strconv.Atoi(rg[0])
			if err != nil {
				log.Print("No ha sido posible interpretar el rango: ", block)
				continue
			}

			if len(rg) == 1 {
				maxPort = minPort
			} else {
				maxPort, err = strconv.Atoi(rg[1])
				if err != nil {
					log.Print("No ha sido posible interpretar el rango: ", block)
					continue
				}
			}

			for port := minPort; port <= maxPort; port++ {
				select {
				case c <- port:
				case <-done:
					return
				}
			}
		}
	}()
	return c
}

func scanPorts(ctx context.Context, in <-chan int) chan string {
	out := make(chan string)
	done := ctx.Done()
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case port, ok := <-in:
					if !ok {
						return
					}
					s := scanPort(port)
					select {
					case out <- s:
					case <-done:
						return
					}
				case <-done:
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func scanPort(port int) string {
	addr := fmt.Sprintf("%s:%d", *host, port)
	conn, err := net.DialTimeout("tcp", addr, *timeout)

	if err != nil {
		return fmt.Sprintf("%d: %s", port, err.Error())
	}

	conn.Close()
	return fmt.Sprintf("%d open", port)
}

func writeOutput(results []string) error {
	if *output == "" {
		return nil
	}
	file, err := os.Create(*output)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range results {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startTime := time.Now()

	flag.Parse()
	fmt.Printf("\n[+] Escaneando IP: %s", *host)
	fmt.Printf("\n[i] Puertos: %s\n\n", *ports)

	pR := processRange(ctx, *ports)
	sP := scanPorts(ctx, pR)

	var openPorts int
	for port := range sP {
		if strings.HasSuffix(port, " open") {
			fmt.Printf("	tcp/%s\n", port)
			openPorts++
		}
	}

	var results []string
	for result := range sP {
		results = append(results, result)
		fmt.Println(result)
	}

	if err := writeOutput(results); err != nil {
		log.Printf("Error escribiendo archivo de salida: %v", err)
	}

	elapsedTime := time.Since(startTime)
	fmt.Printf("\n[i] Se encontraron %d puertos abiertos.\n", openPorts)
	fmt.Printf("\n[i] Tiempo transcurrido: %s\n", elapsedTime)
	fmt.Println("[+] Escaneo finalizado.\n")
}
