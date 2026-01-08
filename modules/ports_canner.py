#!/usr/bin/env python3
"""
Module de scan de ports avec banner grabbing
Pour API Flask
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def scan_port(target: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scan un port et récupère la bannière
    
    Args:
        target: IP ou domaine cible
        port: Numéro de port à scanner
        timeout: Timeout de connexion en secondes
    
    Returns:
        dict: Informations sur le port
    """
    result = {
        'port': port,
        'open': False,
        'banner': '',
        'service': get_service_name(port)
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection_result = sock.connect_ex((target, port))
        
        if connection_result == 0:
            result['open'] = True
            
            try:
                # Tentative de récupération de bannière
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                result['banner'] = banner[:200] if banner else 'No banner'
            except:
                result['banner'] = 'No banner retrieved'
            
            logger.info(f"Port {port} ouvert sur {target}")
    
    except socket.timeout:
        pass
    except socket.error as e:
        pass
    except Exception as e:
        logger.error(f"Erreur scan port {port}: {e}")
    finally:
        try:
            sock.close()
        except:
            pass
    
    return result


def scan_target_api(target: str, ports: range, threads: int = 100, timeout: float = 1.0) -> list:
    """
    Scan multi-thread d'une cible
    
    Args:
        target: IP ou domaine cible
        ports: Range de ports à scanner
        threads: Nombre de threads parallèles
        timeout: Timeout par connexion
    
    Returns:
        list: Liste des ports ouverts avec leurs infos
    """
    open_ports = []
    
    logger.info(f"Scan de {target} sur {len(list(ports))} ports avec {threads} threads")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Soumettre tous les scans
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port 
            for port in ports
        }
        
        # Récupérer les résultats au fur et à mesure
        for future in as_completed(future_to_port):
            try:
                port_info = future.result()
                if port_info['open']:
                    open_ports.append(port_info)
            except Exception as e:
                port = future_to_port[future]
                logger.error(f"Erreur pour port {port}: {e}")
    
    return sorted(open_ports, key=lambda x: x['port'])


def get_service_name(port: int) -> str:
    """
    Retourne le nom du service courant pour un port
    
    Args:
        port: Numéro de port
    
    Returns:
        str: Nom du service
    """
    common_ports = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    return common_ports.get(port, 'Unknown')


# Pour usage CLI (optionnel)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Port Scanner avec banner grabbing')
    parser.add_argument('target', help='Cible (IP ou domaine)')
    parser.add_argument('-p', '--ports', default='1-1000', help='Plage de ports (ex: 1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Nombre de threads')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout en secondes')
    
    args = parser.parse_args()
    
    try:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
        
        print(f"\n[*] Scan de {args.target} ports {start}-{end}")
        print(f"[*] Threads: {args.threads}, Timeout: {args.timeout}s\n")
        
        results = scan_target_api(args.target, ports, args.threads, args.timeout)
        
        print(f"\n[+] Ports ouverts trouvés: {len(results)}\n")
        print(f"{'PORT':<10} {'SERVICE':<15} {'BANNER'}")
        print("-" * 80)
        
        for port_info in results:
            print(f"{port_info['port']:<10} {port_info['service']:<15} {port_info['banner'][:50]}")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrompu par l'utilisateur")
    except Exception as e:
        print(f"[!] Erreur: {e}")
