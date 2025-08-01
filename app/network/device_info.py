"""
Informations détaillées sur les appareils réseau
OS detection, scan de ports, identification de services, fingerprinting
"""

import time
import socket
import threading
import subprocess
import re
from typing import Dict, List, Optional, Set, Tuple, NamedTuple
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from ..core import get_app_logger, NetworkUtils, retry, timed_cache
from .interfaces import NetworkAdapter
from .scanner import NetworkDevice, get_oui_database


class ServiceInfo(NamedTuple):
    """Informations sur un service réseau"""
    port: int
    protocol: str  # TCP/UDP
    service_name: str
    version: str
    banner: str


class OSFingerprint(NamedTuple):
    """Empreinte OS détectée"""
    os_family: str      # Windows, Linux, macOS, iOS, Android, etc.
    os_version: str     # Version spécifique
    confidence: float   # Confiance de 0.0 à 1.0
    method: str        # Méthode de détection utilisée


@dataclass
class DeviceProfile:
    """Profil complet d'un appareil"""
    device: NetworkDevice
    os_fingerprints: List[OSFingerprint] = field(default_factory=list)
    open_ports: List[ServiceInfo] = field(default_factory=list)
    device_type_confidence: float = 0.0
    manufacturer_info: str = ""
    uptime_estimate: Optional[int] = None  # secondes
    network_stack_info: Dict[str, str] = field(default_factory=dict)
    vulnerability_indicators: List[str] = field(default_factory=list)
    last_scan_time: datetime = field(default_factory=datetime.now)
    scan_duration: float = 0.0
    
    @property
    def best_os_guess(self) -> str:
        """Retourne la meilleure estimation d'OS"""
        if not self.os_fingerprints:
            return "Unknown"
        
        # Prendre l'OS avec la plus haute confiance
        best = max(self.os_fingerprints, key=lambda x: x.confidence)
        if best.os_version:
            return f"{best.os_family} {best.os_version}"
        return best.os_family
    
    @property
    def is_vulnerable(self) -> bool:
        """Indique si l'appareil semble vulnérable"""
        return len(self.vulnerability_indicators) > 0


class DeviceInfoScanner:
    """Scanner d'informations détaillées sur les appareils"""
    
    def __init__(self, interface: NetworkAdapter):
        self.interface = interface
        self.logger = get_app_logger("DeviceInfoScanner")
        self.oui_db = get_oui_database()
        
        # Configuration de scan
        self.port_scan_timeout = 1.0
        self.max_scan_threads = 20
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3389, 5900, 8080, 8443, 9100  # Ports courants
        ]
        self.extended_ports = list(range(1, 1025))  # Scan étendu
        
        # Base de données de services
        self._service_db = self._load_service_database()
        
        # Base de données OS fingerprinting
        self._os_signatures = self._load_os_signatures()
        
        # Cache des scans
        self._scan_cache: Dict[str, DeviceProfile] = {}
        self._cache_duration = 3600  # 1 heure
    
    def _load_service_database(self) -> Dict[int, str]:
        """Charge la base de données des services par port"""
        return {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC Endpoint Mapper",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3389: "RDP",
            5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
            9100: "JetDirect", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB", 5984: "CouchDB", 9200: "Elasticsearch"
        }
    
    def _load_os_signatures(self) -> Dict[str, Dict]:
        """Charge les signatures OS pour le fingerprinting"""
        return {
            "windows": {
                "ttl_ranges": [(120, 130), (240, 255)],
                "tcp_window_sizes": [8192, 16384, 65535],
                "tcp_options": ["mss", "nop", "ws", "nop", "nop", "sackOK"],
                "icmp_characteristics": {"df_bit": True, "code_responses": [0, 3]},
                "common_ports": [135, 139, 445, 3389],
                "services": ["microsoft-ds", "netbios-ssn", "ms-wbt-server"]
            },
            "linux": {
                "ttl_ranges": [(60, 65)],
                "tcp_window_sizes": [5840, 14600, 29200],
                "tcp_options": ["mss", "sackOK", "ts", "nop", "ws"],
                "icmp_characteristics": {"df_bit": True, "code_responses": [0, 3, 11]},
                "common_ports": [22, 80, 443],
                "services": ["ssh", "http", "https"]
            },
            "macos": {
                "ttl_ranges": [(60, 65)],
                "tcp_window_sizes": [8760, 65535],
                "tcp_options": ["mss", "nop", "ws", "nop", "nop", "ts", "sackOK", "eol"],
                "icmp_characteristics": {"df_bit": True, "code_responses": [0, 3]},
                "common_ports": [22, 548, 5900],
                "services": ["ssh", "afpovertcp", "vnc"]
            },
            "ios": {
                "ttl_ranges": [(60, 65)],
                "tcp_window_sizes": [65535],
                "tcp_options": ["mss", "nop", "ws", "nop", "nop", "ts", "sackOK", "eol"],
                "icmp_characteristics": {"df_bit": True, "code_responses": [0, 3]},
                "common_ports": [],
                "services": []
            },
            "android": {
                "ttl_ranges": [(60, 65)],
                "tcp_window_sizes": [14600, 29200],
                "tcp_options": ["mss", "sackOK", "ts", "nop", "ws"],
                "icmp_characteristics": {"df_bit": True, "code_responses": [0, 3]},
                "common_ports": [],
                "services": []
            }
        }
    
    @retry(max_attempts=2, delay=0.5)
    def _scan_port(self, ip: str, port: int, protocol: str = "TCP") -> Optional[ServiceInfo]:
        """Scanne un port spécifique"""
        try:
            if protocol.upper() == "TCP":
                return self._tcp_port_scan(ip, port)
            elif protocol.upper() == "UDP":
                return self._udp_port_scan(ip, port)
        except Exception as e:
            self.logger.debug(f"Erreur scan port {ip}:{port}/{protocol}: {e}")
        return None
    
    def _tcp_port_scan(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Scan TCP d'un port avec détection de service"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.port_scan_timeout)
            
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Port ouvert, essayer de récupérer le banner
                banner = self._grab_banner(sock, port)
                service_name = self._identify_service(port, banner)
                version = self._extract_version(banner)
                
                return ServiceInfo(
                    port=port,
                    protocol="TCP",
                    service_name=service_name,
                    version=version,
                    banner=banner
                )
        
        except Exception:
            pass
        finally:
            if sock:
                sock.close()
        
        return None
    
    def _udp_port_scan(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Scan UDP d'un port (basique)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.port_scan_timeout)
            
            # Envoyer un paquet UDP vide
            sock.sendto(b"", (ip, port))
            
            try:
                # Essayer de recevoir une réponse
                data, addr = sock.recvfrom(1024)
                service_name = self._service_db.get(port, f"Unknown UDP/{port}")
                
                return ServiceInfo(
                    port=port,
                    protocol="UDP",
                    service_name=service_name,
                    version="",
                    banner=data.decode('utf-8', errors='ignore')[:100]
                )
            except socket.timeout:
                # Pas de réponse - le port pourrait être ouvert
                if port in [53, 123, 161]:  # DNS, NTP, SNMP
                    service_name = self._service_db.get(port, f"UDP/{port}")
                    return ServiceInfo(
                        port=port,
                        protocol="UDP",
                        service_name=service_name,
                        version="",
                        banner=""
                    )
        
        except Exception:
            pass
        finally:
            if 'sock' in locals():
                sock.close()
        
        return None
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Récupère le banner d'un service"""
        try:
            # Envoyer une requête basique selon le port
            if port == 80:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP envoie automatiquement un banner
            elif port == 22:
                pass  # SSH envoie automatiquement un banner
            elif port == 25:
                pass  # SMTP envoie automatiquement un banner
            elif port == 110:
                pass  # POP3 envoie automatiquement un banner
            else:
                sock.send(b"\r\n")
            
            # Lire la réponse
            sock.settimeout(2.0)
            response = sock.recv(1024)
            return response.decode('utf-8', errors='ignore').strip()
        
        except Exception:
            return ""
    
    def _identify_service(self, port: int, banner: str) -> str:
        """Identifie le service basé sur le port et le banner"""
        # Service par défaut basé sur le port
        default_service = self._service_db.get(port, f"Unknown/{port}")
        
        if not banner:
            return default_service
        
        banner_lower = banner.lower()
        
        # Identification basée sur le banner
        service_patterns = {
            "apache": r"apache[/\s]?([\d\.]+)?",
            "nginx": r"nginx[/\s]?([\d\.]+)?",
            "microsoft-iis": r"microsoft-iis[/\s]?([\d\.]+)?",
            "openssh": r"openssh[_\s]?([\d\.]+)?",
            "postfix": r"postfix[/\s]?([\d\.]+)?",
            "vsftpd": r"vsftpd[/\s]?([\d\.]+)?",
            "proftpd": r"proftpd[/\s]?([\d\.]+)?",
            "mysql": r"mysql[/\s]?([\d\.]+)?",
            "postgresql": r"postgresql[/\s]?([\d\.]+)?",
            "redis": r"redis[/\s]?([\d\.]+)?"
        }
        
        for service, pattern in service_patterns.items():
            if re.search(pattern, banner_lower):
                return service
        
        return default_service
    
    def _extract_version(self, banner: str) -> str:
        """Extrait la version d'un banner"""
        if not banner:
            return ""
        
        # Patterns de version courants
        version_patterns = [
            r"version\s+([\d\.]+)",
            r"v([\d\.]+)",
            r"/([\d\.]+)",
            r"\s([\d\.]+)",
            r"-([\d\.]+)"
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _os_detection_tcp_fingerprint(self, ip: str) -> List[OSFingerprint]:
        """Détection OS par TCP fingerprinting"""
        fingerprints = []
        
        try:
            # Test de réponse TCP avec différentes techniques
            
            # 1. Test TTL via ping ICMP
            ttl = self._get_ttl(ip)
            if ttl:
                os_guess = self._guess_os_from_ttl(ttl)
                if os_guess:
                    fingerprints.append(OSFingerprint(
                        os_family=os_guess["family"],
                        os_version=os_guess.get("version", ""),
                        confidence=os_guess["confidence"],
                        method="TTL Analysis"
                    ))
            
            # 2. Test TCP Window Size
            window_size = self._get_tcp_window_size(ip)
            if window_size:
                os_guess = self._guess_os_from_window_size(window_size)
                if os_guess:
                    fingerprints.append(OSFingerprint(
                        os_family=os_guess["family"],
                        os_version=os_guess.get("version", ""),
                        confidence=os_guess["confidence"],
                        method="TCP Window Analysis"
                    ))
            
            # 3. Test de la pile TCP via options
            tcp_options = self._analyze_tcp_options(ip)
            if tcp_options:
                os_guess = self._guess_os_from_tcp_options(tcp_options)
                if os_guess:
                    fingerprints.append(OSFingerprint(
                        os_family=os_guess["family"],
                        os_version=os_guess.get("version", ""),
                        confidence=os_guess["confidence"],
                        method="TCP Options Analysis"
                    ))
        
        except Exception as e:
            self.logger.debug(f"Erreur lors du fingerprinting TCP pour {ip}: {e}")
        
        return fingerprints
    
    def _get_ttl(self, ip: str) -> Optional[int]:
        """Récupère le TTL via ping ICMP"""
        try:
            icmp_packet = IP(dst=ip) / ICMP()
            response = scapy.sr1(icmp_packet, timeout=3, verbose=False)
            
            if response and response.haslayer(IP):
                return response[IP].ttl
        except Exception:
            pass
        return None
    
    def _guess_os_from_ttl(self, ttl: int) -> Optional[Dict]:
        """Devine l'OS basé sur le TTL"""
        for os_name, signatures in self._os_signatures.items():
            for ttl_min, ttl_max in signatures["ttl_ranges"]:
                if ttl_min <= ttl <= ttl_max:
                    # Calculer la confiance basée sur la distance au TTL initial
                    initial_ttls = [64, 128, 255]  # TTL initiaux courants
                    closest_initial = min(initial_ttls, key=lambda x: abs(x - ttl))
                    hops = closest_initial - ttl
                    confidence = max(0.3, 1.0 - (hops * 0.05))  # Diminue avec le nombre de hops
                    
                    return {
                        "family": os_name.capitalize(),
                        "confidence": min(confidence, 0.8)  # Max 80% pour TTL seul
                    }
        return None
    
    def _get_tcp_window_size(self, ip: str) -> Optional[int]:
        """Récupère la taille de fenêtre TCP"""
        try:
            # Tenter de se connecter à un port commun pour analyser la réponse
            common_ports = [80, 443, 22, 23]
            
            for port in common_ports:
                tcp_packet = IP(dst=ip) / TCP(dport=port, flags="S")
                response = scapy.sr1(tcp_packet, timeout=2, verbose=False)
                
                if response and response.haslayer(TCP):
                    return response[TCP].window
        except Exception:
            pass
        return None
    
    def _guess_os_from_window_size(self, window_size: int) -> Optional[Dict]:
        """Devine l'OS basé sur la taille de fenêtre TCP"""
        for os_name, signatures in self._os_signatures.items():
            if window_size in signatures["tcp_window_sizes"]:
                return {
                    "family": os_name.capitalize(),
                    "confidence": 0.6  # Confiance modérée
                }
        return None
    
    def _analyze_tcp_options(self, ip: str) -> Optional[List[str]]:
        """Analyse les options TCP"""
        try:
            # Envoyer un SYN avec options TCP
            tcp_packet = IP(dst=ip) / TCP(dport=80, flags="S", options=[("MSS", 1460), ("WScale", 7)])
            response = scapy.sr1(tcp_packet, timeout=2, verbose=False)
            
            if response and response.haslayer(TCP):
                options = []
                for option in response[TCP].options:
                    if isinstance(option, tuple):
                        options.append(option[0])
                    else:
                        options.append(str(option))
                return options
        except Exception:
            pass
        return None
    
    def _guess_os_from_tcp_options(self, options: List[str]) -> Optional[Dict]:
        """Devine l'OS basé sur les options TCP"""
        options_str = ",".join(options).lower()
        
        # Patterns spécifiques
        if "timestamp" in options_str and "sackOK" in options_str:
            if "ws" in options_str:
                return {"family": "Linux", "confidence": 0.7}
        
        if "mss" in options_str and len(options) >= 4:
            return {"family": "Windows", "confidence": 0.6}
        
        return None
    
    def _detect_manufacturer_info(self, device: NetworkDevice) -> str:
        """Détecte des informations sur le fabricant"""
        vendor_info = self.oui_db.get_vendor_info(device.mac)
        manufacturer = vendor_info.get("organization", "")
        address = vendor_info.get("address", "")
        
        # Informations enrichies
        info_parts = [manufacturer]
        if address and address != manufacturer:
            info_parts.append(f"({address})")
        
        # Ajouter des infos basées sur le hostname
        if device.hostname:
            hostname_lower = device.hostname.lower()
            if any(keyword in hostname_lower for keyword in ["router", "gateway", "ap-"]):
                info_parts.append("Network Equipment")
            elif any(keyword in hostname_lower for keyword in ["printer", "print"]):
                info_parts.append("Printer")
            elif any(keyword in hostname_lower for keyword in ["camera", "cam"]):
                info_parts.append("Security Camera")
        
        return " ".join(info_parts)
    
    def _estimate_uptime(self, ip: str) -> Optional[int]:
        """Estime l'uptime d'un appareil (basique)"""
        try:
            # Méthode basique: analyser les timestamps TCP si disponibles
            tcp_packet = IP(dst=ip) / TCP(dport=80, flags="S", options=[("Timestamp", (0, 0))])
            response = scapy.sr1(tcp_packet, timeout=2, verbose=False)
            
            if response and response.haslayer(TCP):
                for option in response[TCP].options:
                    if isinstance(option, tuple) and option[0] == "Timestamp":
                        # Estimation très approximative basée sur le timestamp
                        timestamp = option[1][0] if len(option[1]) > 0 else 0
                        if timestamp > 0:
                            # Conversion approximative (dépend du système)
                            return int(timestamp / 100)  # Estimation en secondes
        except Exception:
            pass
        return None
    
    def _check_vulnerabilities(self, device_profile: DeviceProfile) -> List[str]:
        """Vérifie les indicateurs de vulnérabilités"""
        vulnerabilities = []
        
        # Vérifier les services potentiellement vulnérables
        for service in device_profile.open_ports:
            # Services avec authentification faible
            if service.service_name.lower() in ["telnet", "ftp", "rsh", "rlogin"]:
                vulnerabilities.append(f"Insecure service: {service.service_name}")
            
            # Versions obsolètes connues
            if service.version:
                if "openssh" in service.service_name.lower():
                    version_match = re.search(r"(\d+)\.(\d+)", service.version)
                    if version_match:
                        major, minor = int(version_match.group(1)), int(version_match.group(2))
                        if major < 7:
                            vulnerabilities.append("Outdated SSH version")
                
                if "apache" in service.service_name.lower():
                    version_match = re.search(r"(\d+)\.(\d+)", service.version)
                    if version_match:
                        major, minor = int(version_match.group(1)), int(version_match.group(2))
                        if major < 2 or (major == 2 and minor < 4):
                            vulnerabilities.append("Outdated Apache version")
            
            # Ports sensibles ouverts
            if service.port in [135, 139, 445]:  # Windows SMB
                vulnerabilities.append("SMB ports exposed")
            elif service.port == 1433:  # SQL Server
                vulnerabilities.append("Database port exposed")
            elif service.port == 3389:  # RDP
                vulnerabilities.append("RDP exposed to network")
        
        # Vérifier les combinaisons dangereuses
        open_port_numbers = [s.port for s in device_profile.open_ports]
        if 22 in open_port_numbers and 23 in open_port_numbers:
            vulnerabilities.append("Both SSH and Telnet enabled")
        
        return vulnerabilities
    
    def scan_device_detailed(self, device: NetworkDevice, extended_scan: bool = False) -> DeviceProfile:
        """Effectue un scan détaillé d'un appareil"""
        start_time = time.time()
        self.logger.info(f"Scan détaillé de {device.ip} ({device.vendor})")
        
        # Vérifier le cache
        cache_key = f"{device.ip}_{extended_scan}"
        if cache_key in self._scan_cache:
            cached_profile = self._scan_cache[cache_key]
            cache_age = (datetime.now() - cached_profile.last_scan_time).total_seconds()
            if cache_age < self._cache_duration:
                self.logger.debug(f"Utilisation du cache pour {device.ip}")
                return cached_profile
        
        # Créer le profil de base
        profile = DeviceProfile(device=device)
        
        try:
            # 1. Détection OS
            profile.os_fingerprints = self._os_detection_tcp_fingerprint(device.ip)
            
            # 2. Scan de ports
            ports_to_scan = self.extended_ports if extended_scan else self.common_ports
            
            with ThreadPoolExecutor(max_workers=self.max_scan_threads) as executor:
                # Scanner les ports TCP
                tcp_futures = {
                    executor.submit(self._scan_port, device.ip, port, "TCP"): port
                    for port in ports_to_scan
                }
                
                for future in as_completed(tcp_futures):
                    try:
                        result = future.result()
                        if result:
                            profile.open_ports.append(result)
                    except Exception as e:
                        port = tcp_futures[future]
                        self.logger.debug(f"Erreur scan TCP {device.ip}:{port}: {e}")
            
            # 3. Informations fabricant enrichies
            profile.manufacturer_info = self._detect_manufacturer_info(device)
            
            # 4. Estimation uptime
            profile.uptime_estimate = self._estimate_uptime(device.ip)
            
            # 5. Analyse de la pile réseau
            profile.network_stack_info = {
                "tcp_window_size": str(self._get_tcp_window_size(device.ip) or "Unknown"),
                "ttl": str(self._get_ttl(device.ip) or "Unknown"),
                "tcp_options": ",".join(self._analyze_tcp_options(device.ip) or [])
            }
            
            # 6. Évaluation du type d'appareil
            profile.device_type_confidence = self._calculate_device_type_confidence(profile)
            
            # 7. Vérification des vulnérabilités
            profile.vulnerability_indicators = self._check_vulnerabilities(profile)
            
            # Finaliser le profil
            profile.scan_duration = time.time() - start_time
            profile.last_scan_time = datetime.now()
            
            # Mettre en cache
            self._scan_cache[cache_key] = profile
            
            self.logger.info(f"Scan de {device.ip} terminé en {profile.scan_duration:.2f}s - "
                           f"{len(profile.open_ports)} ports ouverts, "
                           f"OS: {profile.best_os_guess}, "
                           f"Vulnérabilités: {len(profile.vulnerability_indicators)}")
        
        except Exception as e:
            self.logger.error(f"Erreur lors du scan détaillé de {device.ip}: {e}")
        
        return profile
    
    def _calculate_device_type_confidence(self, profile: DeviceProfile) -> float:
        """Calcule la confiance du type d'appareil détecté"""
        confidence_factors = []
        
        # Facteur basé sur les ports ouverts
        if any(port.port in [22, 80, 443] for port in profile.open_ports):
            confidence_factors.append(0.3)  # Serveur/ordinateur
        
        if any(port.port in [135, 139, 445] for port in profile.open_ports):
            confidence_factors.append(0.4)  # Windows
        
        if profile.device.vendor:
            confidence_factors.append(0.3)  # Vendor connu
        
        if profile.os_fingerprints:
            avg_os_confidence = sum(fp.confidence for fp in profile.os_fingerprints) / len(profile.os_fingerprints)
            confidence_factors.append(avg_os_confidence * 0.4)
        
        return min(1.0, sum(confidence_factors))
    
    def scan_multiple_devices(self, devices: List[NetworkDevice], extended_scan: bool = False) -> Dict[str, DeviceProfile]:
        """Scanne plusieurs appareils en parallèle"""
        profiles = {}
        
        with ThreadPoolExecutor(max_workers=min(10, len(devices))) as executor:
            futures = {
                executor.submit(self.scan_device_detailed, device, extended_scan): device.ip
                for device in devices
            }
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    profile = future.result()
                    profiles[ip] = profile
                except Exception as e:
                    self.logger.error(f"Erreur lors du scan de {ip}: {e}")
        
        return profiles
    
    def get_cached_profile(self, device_ip: str) -> Optional[DeviceProfile]:
        """Récupère un profil depuis le cache"""
        for cache_key, profile in self._scan_cache.items():
            if cache_key.startswith(device_ip):
                return profile
        return None
    
    def clear_cache(self):
        """Vide le cache des profils"""
        self._scan_cache.clear()
        self.logger.info("Cache des profils vidé")
    
    def get_vulnerability_summary(self, profiles: List[DeviceProfile]) -> Dict[str, int]:
        """Retourne un résumé des vulnérabilités trouvées"""
        vuln_counts = {}
        
        for profile in profiles:
            for vuln in profile.vulnerability_indicators:
                vuln_counts[vuln] = vuln_counts.get(vuln, 0) + 1
        
        return dict(sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True))
    
    def export_profiles_json(self, profiles: Dict[str, DeviceProfile], filename: str) -> bool:
        """Exporte les profils en JSON"""
        try:
            import json
            
            export_data = {}
            for ip, profile in profiles.items():
                export_data[ip] = {
                    "device": {
                        "ip": profile.device.ip,
                        "mac": profile.device.mac,
                        "hostname": profile.device.hostname,
                        "vendor": profile.device.vendor,
                        "device_type": profile.device.device_type
                    },
                    "os_fingerprints": [
                        {
                            "os_family": fp.os_family,
                            "os_version": fp.os_version,
                            "confidence": fp.confidence,
                            "method": fp.method
                        } for fp in profile.os_fingerprints
                    ],
                    "open_ports": [
                        {
                            "port": service.port,
                            "protocol": service.protocol,
                            "service_name": service.service_name,
                            "version": service.version,
                            "banner": service.banner
                        } for service in profile.open_ports
                    ],
                    "manufacturer_info": profile.manufacturer_info,
                    "best_os_guess": profile.best_os_guess,
                    "vulnerability_indicators": profile.vulnerability_indicators,
                    "scan_time": profile.last_scan_time.isoformat(),
                    "scan_duration": profile.scan_duration
                }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Profils exportés vers {filename}")
            return True
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'export JSON: {e}")
            return False


def create_device_info_scanner(interface: NetworkAdapter) -> DeviceInfoScanner:
    """Factory function pour créer un scanner d'informations d'appareils"""
    return DeviceInfoScanner(interface)