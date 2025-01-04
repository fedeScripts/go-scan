package main

/*
 Autor: Federico Galarza
 Descripción: Escaner rapido de puertos TCP, inspirado en el FastTcpScan de @s4vitar.
 Repo: https://github.com/fedeScripts/go-scan
 Version: 1.1
*/

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

// Flags
var (
	hostCli  = flag.String("ip", "127.0.0.1", "Dirección IP o segmento CDIR a escanear separados por coma, ej: 10.1.1.1/24,192.168.0.24")
	hostFile = flag.String("iL", "", "Archivo con direcciones IP y/o segmentos CDIR. (Uno por línea.)")
	ports    = flag.String("p", "1-65535", "Rango de puertos a comprobar: 80,443,1-65535,1000-2000, ...")
	threads  = flag.Int("T", 500, "Cantidad de hilos a usar")
	timeout  = flag.Duration("timeout", 1*time.Second, "Segundos de tiem por puerto")
	output   = flag.String("o", "", "Archivo para guardar el resultado del escaneo")
)

// Pocesar segmentos de red CDIR
func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("error al analizar el CIDR %s: %v", cidr, err)
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// Auxiliar para expandCIDR
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Parsear las IPs desde -iL
func parseHostsFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("error al abrir el archivo: %v", err)
	}
	defer file.Close()

	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			expandedIPs, err := expandCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("error al expandir CIDR %s: %v", line, err)
			}
			hosts = append(hosts, expandedIPs...)
		} else {
			hosts = append(hosts, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error al leer el archivo: %v", err)
	}
	return hosts, nil
}

// Parsear las IPs desde -ip
func parseHostsFromCli(input string) ([]string, error) {
	parts := strings.Split(input, ",")
	var hosts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			expandedIPs, err := expandCIDR(part)

			if err != nil {
				return nil, fmt.Errorf("error al expandir CIDR %s: %v", part, err)
			}
			hosts = append(hosts, expandedIPs...)

		} else {
			hosts = append(hosts, part)
		}
	}
	for _, host := range hosts {
		fmt.Println("parseHostsFromCli", host)
	}
	return hosts, nil
}

// Procesar los puertos
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

// Escanear los puertos del canal processRange
func scanPorts(ctx context.Context, host string, in <-chan int) chan string {
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
					s := scanPort(host, port)
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

// Escanear una IP y un puerto
func scanPort(host string, port int) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, *timeout)

	if err != nil {
		return fmt.Sprintf("%d: %s", port, err.Error())
	}

	conn.Close()
	return fmt.Sprintf("%d \ttcp\topen", port)
}

// Manejar el escaneo multihilo de cada IP
func scanHosts(ctx context.Context, hostCli string, hostFile string, portRange string) {
	var hosts []string
	var err error

	if hostFile != "" {
		hosts, err = parseHostsFromFile(hostFile)
		if err != nil {
			log.Fatalf("Error al leer hosts desde archivo: %v", err)
		}
	} else if hostCli != "" {
		hosts, err = parseHostsFromCli(hostCli)
		if err != nil {
			log.Fatalf("Error al leer hosts desde CLI: %v", err)
		}
	} else {
		log.Fatalf("Debe especificar un archivo de hosts o un input por CLI")
	}

	for _, host := range hosts {
		fmt.Printf("\n[+] Escaneando IP: %s \n", host)
		fmt.Printf("\n\tPuerto\tProto\tEstado\n")

		pR := processRange(ctx, *ports)
		sP := scanPorts(ctx, host, pR)

		var openPorts int
		for port := range sP {
			if strings.HasSuffix(port, "open") {
				fmt.Printf("\t%s\n", port)
				openPorts++
			}
		}
		fmt.Printf("\n[i] Se encontraron %d puertos abiertos.\n", openPorts)
	}
}

// Escribir la salida por consola en un archivo
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

// Main
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	//wg := &sync.WaitGroup{}
	startTime := time.Now()

	flag.Parse()
	fmt.Printf("\n[i] Iniciando escaneo a las %s\n", startTime.Format("15:04 del 02-01-2006"))
	fmt.Printf("[i] Puertos a escanear: %s\n", *ports)

	scanHosts(ctx, *hostCli, *hostFile, *ports)

	endTime := time.Now()
	elapsedTime := time.Since(startTime)
	fmt.Printf("\n[i] Escaneo finalizado a las %s\n", endTime.Format("15:04 del 02-01-2006"))
	fmt.Printf("[i] Tiempo transcurrido: %s\n", elapsedTime)
}
