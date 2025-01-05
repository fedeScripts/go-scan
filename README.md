# go-scan
Escaner rapido de puertos TCP, inspirado en el [FastTcpScan](https://s4vitar.github.io/fasttcpscan-go/#) de [@s4vitar](https://github.com/s4vitar).

## Uso
```go
  go-scan -ip 127.0.0.1 
```

##### Opciones:
```
  -ip		Dirección IP o segmento CIDR a escanear, se admiten múltiples valores separados por coma, ej: 10.1.1.1/24,192.168.0.24
  -iL		Archivo con direcciones IP y/o segmentos de red en formato CIDR. (Uno por linea)
  -p		Rango de puertos a comprobar: 80,443,1-65535,1000-2000, ... (default "1-65535")
  -o		Archivo para guardar el resultado del escaneo.
  -csv      Archivo para guardar el resultado del escaneo en formato CSV.
  -T		Cantidad de puertos escaneados en simultáneo. (default 1000)
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
  Opciones nuevas:
    -v        Mostrar el progreso del escaneo.
    -udp      Escanear puertos UDP.

  Capacidades nuevas:
    - Utilizar ping para comprobar conectividad de manera rapida
    - Interpretear nombres de Host
    - Realizar consultas DNS
```

## Autor
- Federico Galarza  - [@fedeScripts](https://github.com/fedeScripts) 

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/federico-galarza)

