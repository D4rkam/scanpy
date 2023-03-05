#!/usr/bin/python3
import signal, sys, nmap, subprocess, time, re

#=========== Manejo de Ctrl + C ===========#
def handler(signal, frame):
    print("\n[-] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, handler)
#==========================================#

listOfPorts = []

def getArgs():
    if len(sys.argv) != 3:
        print(f"[!] Uso: scanpy <ip_address> <filenameSaveData>")
        sys.exit(1)
    return (host:=getHost(sys.argv[1]), filenameSave:=sys.argv[2])

def getHost(hostInput):
    cmd = f"/usr/bin/ping -c 1 {hostInput}"
    out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    (out, err) = out.communicate()
    out = str(out, encoding='utf-8')
    host = re.search(string=out,pattern=r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")[0]
    return host

#def showMessage(ports: list, host):
#    open_ports = "-p"
#    count = 0
#    for port in ports:
#        if count == 0:
#            open_ports = open_ports + "" + f"{port}"
#            count = 1
#        else:
#            open_ports = open_ports + "," + f"{port}"
#    print("----------------------")
#    print(f"Puertos Abiertos (copiar) : {open_ports} {host}")

def getPorts(nm: nmap.PortScanner, host: str):
    for proto in nm[host].all_protocols():
        print("----------------------")
        print(f"Protocolo : {proto}")
        lport = nm[host][proto].keys()

        for port in lport:
            serviceInfo =  nm[host][proto][port]['name']
            print(f"Puerto : {port}\tEstado : Abierto\tServicio : {serviceInfo}")
            listOfPorts.append(port)

def scanOpenPorts():
    (host, filenameSave) = getArgs()
    print("""
        ░█▀▀▀█ ░█▀▀█ ─█▀▀█ ░█▄─░█ ░█▀▀█ ░█──░█ 
        ─▀▀▀▄▄ ░█─── ░█▄▄█ ░█░█░█ ░█▄▄█ ░█▄▄▄█ 
        ░█▄▄▄█ ░█▄▄█ ░█─░█ ░█──▀█ ░█─── ──░█──\n""")
    nm = nmap.PortScanner()
    nm.scan(host, arguments=f"-sS --open --min-rate 5000 -oG {filenameSave}")
    hostName = nm[host].hostnames()[0]["name"]
    hostState = nm[host].state()

    print(f"Host : {host}\nHostname : {hostName}")
    print("Estado : " + ("Activo" if hostState == "up" else hostState)) #Si el estado del host es Up se intercambia por Activo
    getPorts(nm, host)

if __name__ == "__main__":
    t1 = time.time()
    scanOpenPorts()
    #Implementar el segundo escaneo (versiones y servicios; -sCV)
    #Utilizando los puertos abiertos y solicitando al usuario si quiere o no realizarlo
    print(f"\nEl escaneo tardo: {round(time.time() - t1)}s")



"""
░█▀▀▄ ─█▀█─ ░█▀▀█ ░█─▄▀ ─█▀▀█ ░█▀▄▀█ 
░█─░█ █▄▄█▄ ░█▄▄▀ ░█▀▄─ ░█▄▄█ ░█░█░█ 
░█▄▄▀ ───█─ ░█─░█ ░█─░█ ░█─░█ ░█──░█
"""