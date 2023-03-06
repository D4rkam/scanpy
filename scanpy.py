#!/usr/bin/python3
import signal, sys, nmap, subprocess, time, re, os

#=========== Manejo de Ctrl + C ===========#
def handler(signal, frame):
    print("\n[-] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, handler)
#==========================================#

listOfPorts = []

def getArgs():
    if len(sys.argv) != 3:
        print(f"[!] Uso: scanpy <ip_address> <filename>")
        sys.exit(1)
    host = getHost(sys.argv[1])
    filenameSave = f"{os.getcwd()}/{sys.argv[2]}"
    return (host, filenameSave)

def getHost(hostInput):
    cmd = f"/usr/bin/ping -c 1 {hostInput}"
    out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    (out, err) = out.communicate()
    out = str(out, encoding='utf-8')
    host = re.search(string=out,pattern=r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")[0]
    return host

def copyPorts():
    open_ports = ""
    count = 0
    for port in listOfPorts:
        if count == 0:
            open_ports = open_ports + "" + f"{port}"
            count = 1
        else:
            open_ports = open_ports + "," + f"{port}"
    return open_ports

def getPorts(nm: nmap.PortScanner, host: str):
    for proto in nm[host].all_protocols():
        print("----------------------")
        print(f"Protocolo : {proto}")
        lport = nm[host][proto].keys()

        for port in lport:
            serviceInfo =  nm[host][proto][port]['name']
            print(f"Puerto : {port}\tEstado : Abierto\tServicio : {serviceInfo}")
            listOfPorts.append(port)

def scanVersionAndServices(host, filenameSave):
    nm = nmap.PortScanner()
    nm.scan(host, arguments=f"-sC -sV -p{copyPorts()} {host} -oN {filenameSave}")
    print(f"[+] Reporte generado en la ruta: {filenameSave}\n")

def scanOpenPorts(host, filenameSave):
    print("""
        ░█▀▀▀█ ░█▀▀█ ─█▀▀█ ░█▄─░█ ░█▀▀█ ░█──░█ 
        ─▀▀▀▄▄ ░█─── ░█▄▄█ ░█░█░█ ░█▄▄█ ░█▄▄▄█ 
        ░█▄▄▄█ ░█▄▄█ ░█─░█ ░█──▀█ ░█─── ──░█──\n""")
    nm = nmap.PortScanner()
    nm.scan(host, arguments=f"-sS --open --min-rate 5000 -oG {filenameSave}")
    hostName = nm[host].hostnames()[0]["name"]
    hostState = nm[host].state()

    print(f"Host : {host}\nHostname : {hostName}")
    print("Estado : Abierto")
    getPorts(nm, host)
    print(f"[+] Reporte generado en la ruta: {filenameSave}")

if __name__ == "__main__":
    (host, filenameSave) = getArgs()
    scanOpenPorts(host, filenameSave)
    while True:
        option = input("\n[?] Generar reporte avanzado de versiones y servicios? (s/n): ")
        if option.lower() == "s":
            filenameSave = f"{os.getcwd()}/" + input("[+] Ingrese el nombre del archivo: ")
            scanVersionAndServices(host, filenameSave)
            break
        if option.lower() == "n":
            break


"""
░█▀▀▄ ─█▀█─ ░█▀▀█ ░█─▄▀ ─█▀▀█ ░█▀▄▀█ 
░█─░█ █▄▄█▄ ░█▄▄▀ ░█▀▄─ ░█▄▄█ ░█░█░█ 
░█▄▄▀ ───█─ ░█─░█ ░█─░█ ░█─░█ ░█──░█
"""