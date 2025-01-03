# go-scan
Escaner rapido de puertos TCP, inspirado en el [FastTcpScan](https://s4vitar.github.io/fasttcpscan-go/#) de [@s4vitar](https://github.com/s4vitar).

## Uso
```go
  go-scan -ip 127.0.0.1 
```

##### Opciones:
```
  -ip		Dirección IP a escanear (default "127.0.0.1")
  -T		Cantidad de hilos a usar (default 1000)
  -iL		Archivo con direcciones IP y/o segmentos de red en formato CIDR (uno por linea)
  -o		Guardar el resultado del escaneo
  -p		Rango de puertos a comprobar: 80,443,1-65535,1000-2000, ... (default "1-65535")
  -timeout	Timeout por puerto (default 1s)
```

## Instalación


```
  git pull https://github.com/fedeScripts/go-scan.git
  cd go-scan
  go build
```

## To Do
Implementar las siguientes funcionalidades
```
  -v	    Mostrar el progreso del escaneo.
  -udp		Escanear puertos UDP.
  -csv    Exportar a csv.
```

## Autor
- Federico Galarza  - [@fedeScripts](https://github.com/fedeScripts) 

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/federico-galarza)

