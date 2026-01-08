#!/usr/bin/env python3
import socket
import threading
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_port(target: str, port: int, timeout: float = 1.0) -> tuple:
    """Scan un port et récupère bannière"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            # Récup bannière
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(100).decode('utf-8', errors='ignore').strip()
            sock.close()
            return (port, True, banner[:50])
    except:
        pass
    finally:
        try: sock.close()
        except: pass
    return (port, False, "")

def scan_target(target: str, ports: range, threads: int):
    """Scan multi-thread cible"""
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        for future in futures:
            port_info = future.result()
            if port_info[1]:
                open_ports.append(port_info)
                logger.info(f"Port {port_info[0]} ouvert: {port_info[2]}")
    
    return sorted(open_ports)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("-p", "--ports", default="1-1000", help="Plage ports ex: 1-1000")
    parser.add_argument("-t", "--threads", type=int, default=100)
    args = parser.parse_args()
    
    start, end = map(int, args.ports.split('-'))
    ports = range(start, end + 1)
    
    logger.info(f"Scan {args.target} ports {start}-{end}")
    results = scan_target(args.target, ports, args.threads)
    
    print(f"\nPorts ouverts ({len(results)}):")
    for port, status, banner in results:
        print(f"{port}/tcp : {banner}")

if __name__ == "__main__":
    main()
