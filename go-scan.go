package main

/*
 Autor: Federico Galarza
 Descripción: Escaner rapido de puertos TCP, inspirado en el FastTcpScan de @s4vitar.
 Repo: https://github.com/fedeScripts/go-scan
 Version: 1.2
*/

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
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
	hostCli    = flag.String("ip", "127.0.0.1", "Dirección IP o segmento CIDR a escanear, se admiten múltiples valores separados por coma, ej: 10.1.1.1/24,192.168.0.24")
	hostFile   = flag.String("iL", "", "Archivo con direcciones IP y/o segmentos de red en formato CIDR. Uno por línea.")
	ports      = flag.String("p", "1-65535", "Rango de puertos a comprobar, ej: 80,443,1-65535,1000-2000")
	threads    = flag.Int("T", 1000, "Cantidad de puertos escaneados en simultáneo. (default 1000)")
	timeout    = flag.Duration("timeout", 1*time.Second, "Limite de tiempo por puerto, en segundos.")
	output     = flag.String("o", "", "Archivo para guardar el resultado del escaneo.")
	csv_output = flag.String("csv", "", "Archivo para guardar el resultado del escaneo en formato CSV.")
)

// Pocesar segmentos de red CIDR
func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		logError("al analizar el segmento CIDR %s: %v", cidr, err)
		os.Exit(1)
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// Auxiliar
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
		return nil, logError("al abrir el archivo: %v", err)
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
				return nil, logError("al expandir CIDR %s: %v", line, err)
			}
			hosts = append(hosts, expandedIPs...)
		} else {
			hosts = append(hosts, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, logError("al leer el archivo: %v", err)
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
			expandedIPs, _ := expandCIDR(part)
			hosts = append(hosts, expandedIPs...)

		} else {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, logError("la dirección IP '%s' no es válida", part)
			}
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
				logError("no ha sido posible interpretar el rango: %v", block)
				continue
			}

			if len(rg) == 1 {
				maxPort = minPort
			} else {
				maxPort, err = strconv.Atoi(rg[1])
				if err != nil {
					logError("no ha sido posible interpretar el rango: %v", block)
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
	startTime := time.Now()

	if hostFile != "" {
		hosts, err = parseHostsFromFile(hostFile)
		if err != nil {
			os.Exit(1)
		}
	} else if hostCli != "" {
		hosts, err = parseHostsFromCli(hostCli)
		if err != nil {
			os.Exit(1)
		}
	} else {
		err = logError("debe especificar una IP o un archivo de IPs a escanear.")
		os.Exit(1)
	}

	writeOutput("\n[i] Iniciando escaneo a las %s\n", startTime.Format("15:04 del 02-01-2006"))
	writeOutput("[i] Puertos a escanear: %s\n", *ports)

	for _, host := range hosts {
		writeOutput("\n[+] Escaneando IP: %s \n", host)
		writeOutput("\n\tPuerto\tProto\tEstado\n")

		pR := processRange(ctx, *ports)
		sP := scanPorts(ctx, host, pR)

		var openPorts int
		for port := range sP {
			if strings.HasSuffix(port, "open") {
				writeOutput("\t%s\n", port)
				openPorts++
				if *csv_output != "" {
					writeCSV("%s %s\n", host, port)
				}
			}
		}
		writeOutput("\n[+] Se encontraron %d puertos abiertos.\n", openPorts)
	}

	endTime := time.Now()
	elapsedTime := time.Since(startTime)
	writeOutput("\n[i] Escaneo finalizado a las %s\n", endTime.Format("15:04 del 02-01-2006"))
	writeOutput("[i] Tiempo transcurrido: %s\n", elapsedTime)
}

// Escribir la salida en la consola y en un archivo
func writeOutput(format string, args ...interface{}) {
	var outputWriter io.Writer

	if *output != "" {
		file, err := os.OpenFile(*output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("[!] Error al abrir el archivo para escribir los resultados: %v", err)
		}
		defer file.Close()

		outputWriter = io.MultiWriter(os.Stdout, file)
	} else {
		outputWriter = os.Stdout
	}

	fmt.Fprintf(outputWriter, format, args...)
}

// Escribir el archivo csv
func writeCSV(format string, args ...interface{}) {
	if *csv_output == "" {
		return
	}

	file, err := os.OpenFile(*csv_output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("[!] Error al abrir el archivo CSV para escribir los resultados: %v", err)
	}
	defer file.Close()

	csvWriter := csv.NewWriter(file)

	fileInfo, err := file.Stat()
	if err == nil && fileInfo.Size() == 0 {
		_ = csvWriter.Write([]string{"IP", "Puerto", "Protocolo", "Estado"})
	}

	parts := strings.Fields(fmt.Sprintf(format, args...))
	if len(parts) == 4 {
		csvRow := []string{parts[0], parts[1], parts[2], parts[3]}
		_ = csvWriter.Write(csvRow)
	}

	csvWriter.Flush()
}

// Manejar los mensajes de error
func logError(format string, args ...interface{}) error {
	message := fmt.Sprintf("[!] Error "+format, args...)
	fmt.Fprintln(os.Stderr, message)
	return fmt.Errorf(message)
}

// Main
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flag.Parse()
	scanHosts(ctx, *hostCli, *hostFile, *ports)
}
