"""
Scanner réseau - Découverte d'appareils, scan ARP, détection
Logique de scan sophistiquée avec threading, cache et base de données OUI complète
"""

import time
import threading
import socket
import struct
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Callable, NamedTuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP

from ..core import get_app_logger, NetworkUtils, ThreadSafeCounter, RateLimiter, retry, timed_cache, FileUtils
from .interfaces import NetworkAdapter


class ScanResult(NamedTuple):
    """Résultat d'un scan d'appareil"""
    ip: str
    mac: str
    hostname: str
    response_time: float
    is_gateway: bool
    vendor: str = ""
    os_guess: str = ""


@dataclass
class NetworkDevice:
    """Représentation d'un appareil réseau découvert"""
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    vendor_address: str = ""
    os_guess: str = ""
    device_type: str = ""  # Router, Computer, Phone, IoT, etc.
    is_gateway: bool = False
    is_local_machine: bool = False
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    response_times: List[float] = field(default_factory=list)
    is_online: bool = True
    ports_open: List[int] = field(default_factory=list)
    
    @property
    def avg_response_time(self) -> float:
        """Temps de réponse moyen"""
        return sum(self.response_times) / len(self.response_times) if self.response_times else 0.0
    
    @property
    def uptime_percentage(self) -> float:
        """Pourcentage de disponibilité (basé sur les scans)"""
        return 100.0 if self.is_online else 0.0
    
    @property
    def normalized_mac(self) -> str:
        """Retourne l'adresse MAC normalisée"""
        return NetworkUtils.normalize_mac(self.mac) if NetworkUtils.is_valid_mac(self.mac) else self.mac
    
    @property
    def mac_oui(self) -> str:
        """Retourne l'OUI (3 premiers octets) de l'adresse MAC"""
        if NetworkUtils.is_valid_mac(self.mac):
            return self.normalized_mac.replace(':', '').upper()[:6]
        return ""
    
    def update_last_seen(self, response_time: float = 0.0):
        """Met à jour la dernière fois vu"""
        self.last_seen = datetime.now()
        self.is_online = True
        if response_time > 0:
            self.response_times.append(response_time)
            # Garder seulement les 20 derniers temps de réponse
            if len(self.response_times) > 20:
                self.response_times = self.response_times[-20:]
    
    def mark_offline(self):
        """Marque l'appareil comme hors ligne"""
        self.is_online = False
    
    def guess_device_type(self) -> str:
        """Devine le type d'appareil basé sur le vendor et hostname"""
        vendor_lower = self.vendor.lower()
        hostname_lower = self.hostname.lower()
        
        # Routeurs et points d'accès
        router_keywords = ['router', 'gateway', 'ap-', 'linksys', 'netgear', 'asus', 'tp-link', 'dlink']
        if (self.is_gateway or 
            any(keyword in vendor_lower for keyword in ['cisco', 'linksys', 'netgear', 'asus', 'tp-link', 'd-link']) or
            any(keyword in hostname_lower for keyword in router_keywords)):
            return "Router/Gateway"
        
        # Téléphones et tablettes
        mobile_keywords = ['iphone', 'ipad', 'android', 'samsung', 'huawei', 'xiaomi', 'oneplus']
        if (any(keyword in vendor_lower for keyword in ['apple', 'samsung', 'huawei', 'xiaomi', 'lg electronics']) or
            any(keyword in hostname_lower for keyword in mobile_keywords)):
            return "Mobile/Tablet"
        
        # Ordinateurs
        computer_keywords = ['pc-', 'laptop', 'desktop', 'macbook', 'imac']
        if (any(keyword in vendor_lower for keyword in ['dell', 'hp', 'lenovo', 'microsoft', 'intel']) or
            any(keyword in hostname_lower for keyword in computer_keywords)):
            return "Computer"
        
        # IoT et appareils connectés
        iot_keywords = ['smart', 'alexa', 'chromecast', 'roku', 'philips', 'nest']
        if (any(keyword in vendor_lower for keyword in ['philips', 'amazon', 'google', 'nest']) or
            any(keyword in hostname_lower for keyword in iot_keywords)):
            return "IoT Device"
        
        # Imprimantes
        if any(keyword in vendor_lower for keyword in ['canon', 'epson', 'brother', 'xerox', 'lexmark']):
            return "Printer"
        
        # Consoles de jeu
        if any(keyword in vendor_lower for keyword in ['sony', 'nintendo', 'microsoft']):
            if any(keyword in hostname_lower for keyword in ['playstation', 'xbox', 'nintendo']):
                return "Gaming Console"
        
        # Par défaut
        return "Unknown Device"


class OUIDatabase:
    """Base de données OUI (Organizationally Unique Identifier)"""
    
    def __init__(self, oui_file_path: str = "app/assets/DB/oui.txt"):
        self.oui_file_path = Path(oui_file_path)
        self.oui_data: Dict[str, Dict[str, str]] = {}
        self.logger = get_app_logger("OUIDatabase")
        self._load_oui_database()
    
    def _load_oui_database(self):
        """Charge la base de données OUI depuis le fichier"""
        if not self.oui_file_path.exists():
            self.logger.warning(f"Fichier OUI non trouvé: {self.oui_file_path}")
            self._load_fallback_database()
            return
        
        try:
            self.logger.info("Chargement de la base de données OUI...")
            
            with open(self.oui_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            current_oui = None
            current_org = None
            current_address = []
            
            for line in lines:
                line = line.strip()
                
                # Ligne vide - fin d'entrée
                if not line:
                    if current_oui and current_org:
                        self.oui_data[current_oui] = {
                            'organization': current_org,
                            'address': '\n'.join(current_address)
                        }
                    current_oui = None
                    current_org = None
                    current_address = []
                    continue
                
                # Ligne OUI (format: XX-XX-XX   (hex)		Organization)
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    if len(parts) >= 2:
                        oui_part = parts[0].strip().replace('-', '').upper()
                        org_part = parts[1].strip()
                        
                        if len(oui_part) == 6:  # OUI valide
                            current_oui = oui_part
                            current_org = org_part
                            current_address = []
                
                # Ligne d'adresse (commence par des espaces/tabs)
                elif line.startswith(('\t', ' ')) and current_oui:
                    address_line = line.strip()
                    if address_line and not address_line.startswith('(base 16)'):
                        current_address.append(address_line)
                
                # Ligne organization alternative
                elif current_oui and not current_org and not line.startswith('OUI/MA-L'):
                    current_org = line.strip()
            
            # Traiter la dernière entrée
            if current_oui and current_org:
                self.oui_data[current_oui] = {
                    'organization': current_org,
                    'address': '\n'.join(current_address)
                }
            
            self.logger.info(f"Base de données OUI chargée: {len(self.oui_data)} entrées")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement de la base OUI: {e}")
            self._load_fallback_database()
    
    def _load_fallback_database(self):
        """Charge une base de données de fallback avec les vendors courants"""
        self.logger.info("Chargement de la base de données OUI de secours...")
        
        fallback_data = {
            "000000": {"organization": "Xerox Corporation", "address": ""},
            "000001": {"organization": "Xerox Corporation", "address": ""},
            "000002": {"organization": "Xerox Corporation", "address": ""},
            "000003": {"organization": "Xerox Corporation", "address": ""},
            "000393": {"organization": "Apple, Inc.", "address": ""},
            "000502": {"organization": "Apple, Inc.", "address": ""},
            "000A95": {"organization": "Apple, Inc.", "address": ""},
            "000D93": {"organization": "Apple, Inc.", "address": ""},
            "001124": {"organization": "Apple, Inc.", "address": ""},
            "001451": {"organization": "Apple, Inc.", "address": ""},
            "0016CB": {"organization": "Apple, Inc.", "address": ""},
            "0017F2": {"organization": "Apple, Inc.", "address": ""},
            "0019E3": {"organization": "Apple, Inc.", "address": ""},
            "001B63": {"organization": "Apple, Inc.", "address": ""},
            "001C42": {"organization": "Parallels, Inc.", "address": ""},
            "001E52": {"organization": "Apple, Inc.", "address": ""},
            "001FF3": {"organization": "Apple, Inc.", "address": ""},
            "0021E9": {"organization": "Apple, Inc.", "address": ""},
            "002241": {"organization": "Apple, Inc.", "address": ""},
            "002312": {"organization": "Apple, Inc.", "address": ""},
            "0023DF": {"organization": "Apple, Inc.", "address": ""},
            "002500": {"organization": "Apple, Inc.", "address": ""},
            "00254B": {"organization": "Apple, Inc.", "address": ""},
            "0025BC": {"organization": "Apple, Inc.", "address": ""},
            "002608": {"organization": "Apple, Inc.", "address": ""},
            "00264A": {"organization": "Apple, Inc.", "address": ""},
            "0026B0": {"organization": "Apple, Inc.", "address": ""},
            "0026BB": {"organization": "Apple, Inc.", "address": ""},
            "003EE1": {"organization": "Apple, Inc.", "address": ""},
            "005056": {"organization": "VMware, Inc.", "address": ""},
            "000C29": {"organization": "VMware, Inc.", "address": ""},
            "000569": {"organization": "VMware, Inc.", "address": ""},
            "001C14": {"organization": "VMware, Inc.", "address": ""},
            "080027": {"organization": "PCS Systemtechnik GmbH", "address": "VirtualBox"},
            "0A0027": {"organization": "PCS Systemtechnik GmbH", "address": "VirtualBox"},
            "00155D": {"organization": "Microsoft Corporation", "address": ""},
            "0003FF": {"organization": "Microsoft Corporation", "address": ""},
            "00125A": {"organization": "Microsoft Corporation", "address": ""},
            "0017FA": {"organization": "Microsoft Corporation", "address": ""},
            "002170": {"organization": "Microsoft Corporation", "address": ""},
            "0025AE": {"organization": "Microsoft Corporation", "address": ""},
            "001BDC": {"organization": "Samsung Electronics Co.,Ltd", "address": ""},
            "0024E9": {"organization": "Samsung Electronics Co.,Ltd", "address": ""},
            "002566": {"organization": "Samsung Electronics Co.,Ltd", "address": ""},
            "40A8F0": {"organization": "Huawei Technologies Co.,Ltd", "address": ""},
            "9CE063": {"organization": "Huawei Technologies Co.,Ltd", "address": ""},
            "F81654": {"organization": "Huawei Technologies Co.,Ltd", "address": ""},
            "0019B9": {"organization": "Cisco Systems, Inc", "address": ""},
            "001A2F": {"organization": "Cisco Systems, Inc", "address": ""},
            "001B0C": {"organization": "Cisco Systems, Inc", "address": ""},
            "001C0E": {"organization": "Cisco Systems, Inc", "address": ""},
            "001D45": {"organization": "Cisco Systems, Inc", "address": ""},
            "0010A4": {"organization": "Linksys LLC", "address": ""},
            "001839": {"organization": "Linksys LLC", "address": ""},
            "0020A6": {"organization": "Proxim Corporation", "address": ""},
            "002129": {"organization": "Linksys LLC", "address": ""},
            "68B599": {"organization": "Intel Corporate", "address": ""},
            "7CDDDD": {"organization": "Shenzhen Bilian Electronic Co.,Ltd", "address": ""},
            "2C4D54": {"organization": "Intel Corporate", "address": ""},
            "A45E60": {"organization": "Intel Corporate", "address": ""},
            "28D244": {"organization": "LCFC(HeFei) Electronics Technology co., ltd.", "address": ""}
        }
        
        self.oui_data = fallback_data
        self.logger.info(f"Base de données OUI de secours chargée: {len(self.oui_data)} entrées")
    
    @timed_cache(3600)  # Cache pendant 1 heure
    def get_vendor_info(self, mac: str) -> Dict[str, str]:
        """Récupère les informations vendor à partir d'une adresse MAC"""
        if not NetworkUtils.is_valid_mac(mac):
            return {"organization": "Invalid MAC", "address": ""}
        
        # Extraire l'OUI (3 premiers octets)
        normalized_mac = NetworkUtils.normalize_mac(mac)
        oui = normalized_mac.replace(':', '').upper()[:6]
        
        # Rechercher dans la base de données
        vendor_info = self.oui_data.get(oui, {
            "organization": "Unknown Vendor",
            "address": ""
        })
        
        return vendor_info
    
    def get_vendor_name(self, mac: str) -> str:
        """Récupère uniquement le nom du vendor"""
        vendor_info = self.get_vendor_info(mac)
        return vendor_info.get("organization", "Unknown Vendor")
    
    def get_vendor_address(self, mac: str) -> str:
        """Récupère uniquement l'adresse du vendor"""
        vendor_info = self.get_vendor_info(mac)
        return vendor_info.get("address", "")
    
    def search_vendor(self, query: str) -> List[Dict[str, str]]:
        """Recherche des vendors par nom"""
        query_lower = query.lower()
        results = []
        
        for oui, info in self.oui_data.items():
            if query_lower in info["organization"].lower():
                results.append({
                    "oui": oui,
                    "organization": info["organization"],
                    "address": info["address"]
                })
        
        return results
    
    def get_statistics(self) -> Dict[str, any]:
        """Retourne des statistiques sur la base OUI"""
        return {
            "total_entries": len(self.oui_data),
            "file_exists": self.oui_file_path.exists(),
            "file_path": str(self.oui_file_path),
            "file_size": FileUtils.get_file_size(self.oui_file_path) if self.oui_file_path.exists() else 0
        }


class NetworkScanner:
    """Scanner réseau principal avec base de données OUI complète"""
    
    def __init__(self, interface: NetworkAdapter):
        self.interface = interface
        self.logger = get_app_logger("NetworkScanner")
        
        # Base de données OUI
        self.oui_db = OUIDatabase()
        
        # État du scanner
        self.devices: Dict[str, NetworkDevice] = {}
        self.scanning = False
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Callbacks
        self.on_device_discovered: Optional[Callable[[NetworkDevice], None]] = None
        self.on_device_updated: Optional[Callable[[NetworkDevice], None]] = None
        self.on_device_lost: Optional[Callable[[NetworkDevice], None]] = None
        self.on_scan_complete: Optional[Callable[[List[NetworkDevice]], None]] = None
        self.on_scan_progress: Optional[Callable[[int, int], None]] = None  # (current, total)
        
        # Configuration de scan
        self.scan_timeout = 3.0
        self.max_threads = 50
        self.scan_interval = 5.0
        self.offline_timeout = 30.0  # secondes avant de considérer un appareil hors ligne
        self.deep_scan_enabled = True  # Scan approfondi avec OS detection
        
        # Rate limiting
        self.rate_limiter = RateLimiter(max_calls=100, time_window=1.0)
        
        # Statistiques
        self.total_scans = ThreadSafeCounter()
        self.successful_scans = ThreadSafeCounter()
        self.scan_start_time = 0.0
        self.last_scan_duration = 0.0
    
    @retry(max_attempts=3, delay=0.5)
    def _arp_ping(self, target_ip: str) -> Optional[ScanResult]:
        """Effectue un ping ARP vers une IP cible"""
        if not self.rate_limiter.can_proceed():
            time.sleep(self.rate_limiter.wait_time())
        
        try:
            start_time = time.time()
            
            # Créer la requête ARP avec plus de détails
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=target_ip)
            
            # Utiliser srp avec plus d'options pour Windows
            answered, _ = scapy.srp(
                arp_request, 
                timeout=self.scan_timeout, 
                verbose=False, 
                iface=self.interface.interface,
                retry=1,
                inter=0.1
            )
            
            if answered:
                # Réponse reçue
                response_time = time.time() - start_time
                response = answered[0][1]
                
                mac_address = response.hwsrc
                hostname = self._resolve_hostname(target_ip)
                is_gateway = (target_ip == self.interface.gateway)
                
                # Récupérer les informations vendor depuis la base OUI
                vendor_info = self.oui_db.get_vendor_info(mac_address)
                vendor = vendor_info.get("organization", "Unknown Vendor")
                
                # OS detection si activé
                os_guess = ""
                if self.deep_scan_enabled:
                    os_guess = self._detect_os(target_ip, mac_address)
                
                self.logger.debug(f"Appareil trouvé: {target_ip} -> {mac_address} ({vendor})")
                
                return ScanResult(
                    ip=target_ip,
                    mac=mac_address,
                    hostname=hostname,
                    response_time=response_time,
                    is_gateway=is_gateway,
                    vendor=vendor,
                    os_guess=os_guess
                )
        
        except Exception as e:
            self.logger.debug(f"Erreur ARP ping pour {target_ip}: {e}")
        
        return None
    
    @timed_cache(300)  # Cache pendant 5 minutes
    def _resolve_hostname(self, ip: str) -> str:
        """Résout le nom d'hôte d'une IP"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            # Essayer avec nslookup sur Windows
            try:
                import subprocess
                result = subprocess.run(
                    ['nslookup', ip], 
                    capture_output=True, 
                    text=True, 
                    timeout=2
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'name =' in line:
                            hostname = line.split('name =')[1].strip().rstrip('.')
                            return hostname
            except Exception:
                pass
            
            return ""
    
    def _detect_os(self, ip: str, mac: str) -> str:
        """Détection basique de l'OS basée sur le vendor et des heuristiques"""
        vendor_info = self.oui_db.get_vendor_info(mac)
        vendor = vendor_info.get("organization", "").lower()
        
        # Détection basée sur le vendor
        if "apple" in vendor:
            return "macOS/iOS"
        elif "microsoft" in vendor:
            return "Windows"
        elif "samsung" in vendor:
            return "Android/Tizen"
        elif "huawei" in vendor:
            return "Android/HarmonyOS"
        elif "cisco" in vendor:
            return "Cisco IOS"
        elif "vmware" in vendor:
            return "Virtual Machine"
        elif "virtualbox" in vendor:
            return "VirtualBox VM"
        elif "parallels" in vendor:
            return "Parallels VM"
        elif any(keyword in vendor for keyword in ["router", "linksys", "netgear", "asus", "tp-link"]):
            return "Router/Embedded"
        
        # Tentative de détection par TTL (nécessite ping ICMP)
        try:
            # Créer un paquet ICMP ping
            icmp_packet = IP(dst=ip) / ICMP()
            response = scapy.sr1(icmp_packet, timeout=1, verbose=False)
            
            if response:
                ttl = response.ttl
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Network Device"
        except Exception:
            pass
        
        return "Unknown OS"
    
    def _scan_ip_range(self, ip_list: List[str]) -> List[ScanResult]:
        """Scanne une liste d'IPs avec threading et callbacks de progression"""
        results = []
        completed = 0
        total = len(ip_list)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Soumettre tous les scans
            future_to_ip = {
                executor.submit(self._arp_ping, ip): ip 
                for ip in ip_list
            }
            
            # Collecter les résultats
            for future in as_completed(future_to_ip):
                completed += 1
                self.total_scans.increment()
                
                # Callback de progression
                if self.on_scan_progress:
                    self.on_scan_progress(completed, total)
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.successful_scans.increment()
                        
                except Exception as e:
                    ip = future_to_ip[future]
                    self.logger.debug(f"Erreur lors du scan de {ip}: {e}")
        
        return results
    
    def scan_network(self) -> List[NetworkDevice]:
        """Effectue un scan complet du réseau"""
        self.scan_start_time = time.time()
        self.logger.info(f"Démarrage du scan réseau sur {self.interface.interface}")
        
        # Générer la liste des IPs à scanner
        ip_range = self.interface.network_range
        if not ip_range:
            self.logger.error("Impossible de déterminer la plage d'adresses réseau")
            return []
        
        self.logger.info(f"Scan de {len(ip_range)} adresses IP")
        
        # Scanner toutes les IPs
        scan_results = self._scan_ip_range(ip_range)
        
        # Mettre à jour les appareils découverts
        discovered_devices = []
        for result in scan_results:
            device = self._update_or_create_device(result)
            discovered_devices.append(device)
        
        # Marquer les appareils non vus comme potentiellement hors ligne
        self._check_offline_devices()
        
        # Identifier la machine locale
        self._identify_local_machine()
        
        # Mettre à jour les types d'appareils
        for device in self.devices.values():
            if not device.device_type:
                device.device_type = device.guess_device_type()
        
        self.last_scan_duration = time.time() - self.scan_start_time
        self.logger.info(f"Scan terminé en {self.last_scan_duration:.2f}s: {len(discovered_devices)} appareils trouvés")
        
        # Callback de fin de scan
        if self.on_scan_complete:
            self.on_scan_complete(list(self.devices.values()))
        
        return discovered_devices
    
    def _update_or_create_device(self, scan_result: ScanResult) -> NetworkDevice:
        """Met à jour ou crée un appareil réseau"""
        if scan_result.ip in self.devices:
            # Mettre à jour un appareil existant
            device = self.devices[scan_result.ip]
            device.update_last_seen(scan_result.response_time)
            
            # Mettre à jour les infos si elles ont changé
            if device.hostname != scan_result.hostname and scan_result.hostname:
                device.hostname = scan_result.hostname
            if device.vendor != scan_result.vendor and scan_result.vendor:
                device.vendor = scan_result.vendor
                # Mettre à jour l'adresse vendor aussi
                vendor_info = self.oui_db.get_vendor_info(device.mac)
                device.vendor_address = vendor_info.get("address", "")
            if device.os_guess != scan_result.os_guess and scan_result.os_guess:
                device.os_guess = scan_result.os_guess
            
            # Callback de mise à jour
            if self.on_device_updated:
                self.on_device_updated(device)
        
        else:
            # Récupérer l'adresse du vendor
            vendor_info = self.oui_db.get_vendor_info(scan_result.mac)
            vendor_address = vendor_info.get("address", "")
            
            # Créer un nouvel appareil
            device = NetworkDevice(
                ip=scan_result.ip,
                mac=scan_result.mac,
                hostname=scan_result.hostname,
                vendor=scan_result.vendor,
                vendor_address=vendor_address,
                os_guess=scan_result.os_guess,
                is_gateway=scan_result.is_gateway
            )
            device.update_last_seen(scan_result.response_time)
            
            # Deviner le type d'appareil
            device.device_type = device.guess_device_type()
            
            self.devices[scan_result.ip] = device
            
            # Callback de découverte
            if self.on_device_discovered:
                self.on_device_discovered(device)
            
            self.logger.info(f"Nouvel appareil découvert: {scan_result.ip} ({scan_result.mac}) - {scan_result.vendor}")
        
        return device
    
    def _check_offline_devices(self):
        """Vérifie les appareils potentiellement hors ligne"""
        current_time = datetime.now()
        
        for device in list(self.devices.values()):
            if device.is_online:
                time_since_last_seen = (current_time - device.last_seen).total_seconds()
                
                if time_since_last_seen > self.offline_timeout:
                    device.mark_offline()
                    self.logger.info(f"Appareil marqué hors ligne: {device.ip} ({device.vendor})")
                    
                    # Callback de perte d'appareil
                    if self.on_device_lost:
                        self.on_device_lost(device)
    
    def _identify_local_machine(self):
        """Identifie la machine locale"""
        local_ip = NetworkUtils.get_local_ip()
        if local_ip and local_ip in self.devices:
            self.devices[local_ip].is_local_machine = True
            self.logger.info(f"Machine locale identifiée: {local_ip}")
    
    def start_continuous_scan(self):
        """Démarre un scan continu en arrière-plan"""
        if self.scanning:
            self.logger.warning("Scan déjà en cours")
            return
        
        self.scanning = True
        self.stop_event.clear()
        
        def scan_loop():
            while not self.stop_event.is_set():
                try:
                    self.scan_network()
                    
                    # Attendre avant le prochain scan
                    if self.stop_event.wait(self.scan_interval):
                        break
                        
                except Exception as e:
                    self.logger.error(f"Erreur lors du scan continu: {e}")
                    time.sleep(5)  # Attendre avant de réessayer
        
        self.scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self.scan_thread.start()
        
        self.logger.info("Scan continu démarré")
    
    def stop_continuous_scan(self):
        """Arrête le scan continu"""
        if not self.scanning:
            return
        
        self.scanning = False
        self.stop_event.set()
        
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=5)
        
        self.logger.info("Scan continu arrêté")
    
    def get_device_by_ip(self, ip: str) -> Optional[NetworkDevice]:
        """Récupère un appareil par son IP"""
        return self.devices.get(ip)
    
    def get_device_by_mac(self, mac: str) -> Optional[NetworkDevice]:
        """Récupère un appareil par son MAC"""
        normalized_mac = NetworkUtils.normalize_mac(mac) if NetworkUtils.is_valid_mac(mac) else mac
        
        for device in self.devices.values():
            if device.normalized_mac == normalized_mac:
                return device
        return None
    
    def get_online_devices(self) -> List[NetworkDevice]:
        """Retourne la liste des appareils en ligne"""
        return [device for device in self.devices.values() if device.is_online]
    
    def get_offline_devices(self) -> List[NetworkDevice]:
        """Retourne la liste des appareils hors ligne"""
        return [device for device in self.devices.values() if not device.is_online]
    
    def get_devices_by_vendor(self, vendor_query: str) -> List[NetworkDevice]:
        """Retourne les appareils filtrés par vendor"""
        query_lower = vendor_query.lower()
        return [device for device in self.devices.values() if query_lower in device.vendor.lower()]
    
    def get_devices_by_type(self, device_type: str) -> List[NetworkDevice]:
        """Retourne les appareils filtrés par type"""
        return [device for device in self.devices.values() if device.device_type == device_type]
    
    def get_statistics(self) -> Dict[str, any]:
        """Retourne les statistiques détaillées du scanner"""
        online_count = len(self.get_online_devices())
        offline_count = len(self.get_offline_devices())
        
        # Statistiques par type d'appareil
        device_types = {}
        for device in self.devices.values():
            device_types[device.device_type] = device_types.get(device.device_type, 0) + 1
        
        # Statistiques par vendor
        vendors = {}
        for device in self.devices.values():
            vendor = device.vendor or "Unknown"
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        return {
            'total_devices': len(self.devices),
            'online_devices': online_count,
            'offline_devices': offline_count,
            'total_scans': self.total_scans.get(),
            'successful_scans': self.successful_scans.get(),
            'success_rate': (self.successful_scans.get() / max(1, self.total_scans.get())) * 100,
            'scanning': self.scanning,
            'interface': self.interface.interface,
            'last_scan_duration': self.last_scan_duration,
            'device_types': device_types,
            'top_vendors': dict(sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]),
            'oui_database_stats': self.oui_db.get_statistics()
        }
    
    def clear_devices(self):
        """Efface tous les appareils découverts"""
        self.devices.clear()
        self.total_scans.reset()
        self.successful_scans.reset()
        self.logger.info("Liste des appareils effacée")
    
    def rescan_device(self, ip: str) -> Optional[NetworkDevice]:
        """Rescanne un appareil spécifique"""
        result = self._arp_ping(ip)
        if result:
            return self._update_or_create_device(result)
        return None
    
    def export_devices_csv(self, filename: str) -> bool:
        """Exporte la liste des appareils en CSV"""
        try:
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['IP', 'MAC', 'Hostname', 'Vendor', 'Device_Type', 'OS_Guess', 
                             'Is_Online', 'Is_Gateway', 'First_Seen', 'Last_Seen', 'Avg_Response_Time']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for device in self.devices.values():
                    writer.writerow({
                        'IP': device.ip,
                        'MAC': device.mac,
                        'Hostname': device.hostname,
                        'Vendor': device.vendor,
                        'Device_Type': device.device_type,
                        'OS_Guess': device.os_guess,
                        'Is_Online': device.is_online,
                        'Is_Gateway': device.is_gateway,
                        'First_Seen': device.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
                        'Last_Seen': device.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
                        'Avg_Response_Time': f"{device.avg_response_time:.3f}"
                    })
            
            self.logger.info(f"Appareils exportés vers {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de l'export CSV: {e}")
            return False


def create_network_scanner(interface: NetworkAdapter) -> NetworkScanner:
    """Factory function pour créer un scanner réseau"""
    return NetworkScanner(interface)


# Instance globale de la base OUI (singleton)
_oui_database = None

def get_oui_database() -> OUIDatabase:
    """Retourne l'instance globale de la base de données OUI"""
    global _oui_database
    if _oui_database is None:
        _oui_database = OUIDatabase()
    return _oui_database