"""Module de scan Nmap"""
import nmap


class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def quick_scan(self, target):
        """Scan rapide des ports courants"""
        try:
            self.nm.scan(target, arguments='-F -T4')
            return self._parse_results(target)
        except Exception as e:
            return {'error': f'Erreur Nmap: {str(e)}'}

    def port_scan(self, target, ports='1-1000'):
        """Scan de ports spécifiques"""
        try:
            self.nm.scan(target, ports, arguments='-sV -T4')
            return self._parse_results(target)
        except Exception as e:
            return {'error': f'Erreur Nmap: {str(e)}'}

    def _parse_results(self, target):
        """Parse les résultats Nmap"""
        if target not in self.nm.all_hosts():
            return {'error': 'Host non trouvé'}

        host = self.nm[target]
        results = {
            'host': target,
            'hostname': host.hostname(),
            'state': host.state(),
            'open_ports': []
        }

        for proto in host.all_protocols():
            ports = host[proto].keys()
            for port in sorted(ports):
                port_info = host[proto][port]
                if port_info['state'] == 'open':
                    results['open_ports'].append({
                        'port': port,
                        'protocol': proto,
                        'service': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', '')
                    })

        results['total_open'] = len(results['open_ports'])
        return results