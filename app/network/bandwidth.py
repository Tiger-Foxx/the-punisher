"""
Contrôleur de bande passante - Limitation, monitoring, QoS
Gestion sophistiquée du trafic réseau par appareil
"""

import time
import threading
import struct
from typing import Dict, List, Optional, Callable, NamedTuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque
import scapy.all as scapy
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

from ..core import get_app_logger, NetworkUtils, ThreadSafeCounter, safe_division
from .interfaces import NetworkAdapter
from .scanner import NetworkDevice
from .arp_handler import ARPHandler


class TrafficData(NamedTuple):
    """Données de trafic réseau"""
    timestamp: float
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int


@dataclass
class BandwidthLimit:
    """Limite de bande passante pour un appareil"""
    device_ip: str
    download_limit: int  # bytes/sec, 0 = illimité
    upload_limit: int    # bytes/sec, 0 = illimité
    enabled: bool = True
    priority: int = 1    # 1=haute, 2=normale, 3=basse
    
    def is_unlimited(self) -> bool:
        """Vérifie si la limite est illimitée"""
        return self.download_limit == 0 and self.upload_limit == 0


@dataclass
class TrafficStats:
    """Statistiques de trafic pour un appareil"""
    device_ip: str
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    total_packets_in: int = 0
    total_packets_out: int = 0
    current_download_speed: float = 0.0  # bytes/sec
    current_upload_speed: float = 0.0    # bytes/sec
    peak_download_speed: float = 0.0
    peak_upload_speed: float = 0.0
    last_activity: datetime = field(default_factory=datetime.now)
    traffic_history: deque = field(default_factory=lambda: deque(maxlen=100))
    blocked_packets: int = 0
    
    def update_traffic(self, bytes_in: int, bytes_out: int, packets_in: int, packets_out: int):
        """Met à jour les statistiques de trafic"""
        self.total_bytes_in += bytes_in
        self.total_bytes_out += bytes_out
        self.total_packets_in += packets_in
        self.total_packets_out += packets_out
        self.last_activity = datetime.now()
        
        # Ajouter à l'historique
        self.traffic_history.append(TrafficData(
            timestamp=time.time(),
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            packets_in=packets_in,
            packets_out=packets_out
        ))
    
    def calculate_speeds(self, time_window: float = 5.0):
        """Calcule les vitesses actuelles basées sur l'historique"""
        if len(self.traffic_history) < 2:
            return
        
        current_time = time.time()
        recent_data = [
            data for data in self.traffic_history 
            if current_time - data.timestamp <= time_window
        ]
        
        if len(recent_data) < 2:
            return
        
        # Calculer les totaux sur la période
        total_bytes_in = sum(data.bytes_in for data in recent_data)
        total_bytes_out = sum(data.bytes_out for data in recent_data)
        time_span = recent_data[-1].timestamp - recent_data[0].timestamp
        
        if time_span > 0:
            self.current_download_speed = total_bytes_in / time_span
            self.current_upload_speed = total_bytes_out / time_span
            
            # Mettre à jour les pics
            self.peak_download_speed = max(self.peak_download_speed, self.current_download_speed)
            self.peak_upload_speed = max(self.peak_upload_speed, self.current_upload_speed)
    
    def get_total_traffic(self) -> int:
        """Retourne le trafic total en bytes"""
        return self.total_bytes_in + self.total_bytes_out


class BandwidthController:
    """Contrôleur principal de bande passante"""
    
    def __init__(self, interface: NetworkAdapter, arp_handler: ARPHandler):
        self.interface = interface
        self.arp_handler = arp_handler
        self.logger = get_app_logger("BandwidthController")
        
        # État du contrôleur
        self.monitoring = False
        self.controlling = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Limites et statistiques
        self.bandwidth_limits: Dict[str, BandwidthLimit] = {}
        self.traffic_stats: Dict[str, TrafficStats] = {}
        
        # Configuration
        self.monitor_interval = 1.0  # secondes
        self.packet_capture_timeout = 1.0
        self.max_queue_size = 1000
        self.stats_update_interval = 5.0
        
        # Callbacks
        self.on_limit_exceeded: Optional[Callable[[str, str, float], None]] = None  # (ip, type, speed)
        self.on_stats_updated: Optional[Callable[[Dict[str, TrafficStats]], None]] = None
        self.on_device_blocked: Optional[Callable[[str, str], None]] = None  # (ip, reason)
        
        # Threads et synchronisation
        self._packet_queue = deque(maxlen=self.max_queue_size)
        self._queue_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        
        # Compteurs globaux
        self.total_packets_processed = ThreadSafeCounter()
        self.total_packets_blocked = ThreadSafeCounter()
        
        # Dernière mise à jour des stats
        self._last_stats_update = time.time()
    
    def set_bandwidth_limit(self, device_ip: str, download_mbps: float = 0, upload_mbps: float = 0, priority: int = 1) -> bool:
        """Définit une limite de bande passante pour un appareil"""
        try:
            # Convertir Mbps en bytes/sec
            download_limit = int(download_mbps * 1024 * 1024 / 8) if download_mbps > 0 else 0
            upload_limit = int(upload_mbps * 1024 * 1024 / 8) if upload_mbps > 0 else 0
            
            limit = BandwidthLimit(
                device_ip=device_ip,
                download_limit=download_limit,
                upload_limit=upload_limit,
                priority=priority
            )
            
            self.bandwidth_limits[device_ip] = limit
            
            # Créer les stats si elles n'existent pas
            if device_ip not in self.traffic_stats:
                self.traffic_stats[device_ip] = TrafficStats(device_ip=device_ip)
            
            self.logger.info(f"Limite définie pour {device_ip}: ↓{download_mbps}Mbps ↑{upload_mbps}Mbps")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la définition de limite pour {device_ip}: {e}")
            return False
    
    def remove_bandwidth_limit(self, device_ip: str) -> bool:
        """Supprime la limite de bande passante d'un appareil"""
        if device_ip in self.bandwidth_limits:
            del self.bandwidth_limits[device_ip]
            self.logger.info(f"Limite supprimée pour {device_ip}")
            return True
        return False
    
    def enable_limit(self, device_ip: str, enabled: bool = True) -> bool:
        """Active/désactive une limite de bande passante"""
        if device_ip in self.bandwidth_limits:
            self.bandwidth_limits[device_ip].enabled = enabled
            status = "activée" if enabled else "désactivée"
            self.logger.info(f"Limite {status} pour {device_ip}")
            return True
        return False
    
    def _packet_monitor(self):
        """Thread de monitoring des paquets"""
        self.logger.info("Monitoring de bande passante démarré")
        
        try:
            # Filtre pour capturer tout le trafic IP
            packet_filter = "ip"
            
            def packet_handler(packet):
                if self.stop_event.is_set():
                    return
                
                try:
                    self._process_packet(packet)
                except Exception as e:
                    self.logger.debug(f"Erreur lors du traitement de paquet: {e}")
            
            # Capturer les paquets
            scapy.sniff(
                iface=self.interface.interface,
                filter=packet_filter,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: self.stop_event.is_set(),
                timeout=None
            )
            
        except Exception as e:
            self.logger.error(f"Erreur dans le monitoring de paquets: {e}")
        
        self.logger.info("Monitoring de bande passante arrêté")
    
    def _process_packet(self, packet):
        """Traite un paquet capturé"""
        self.total_packets_processed.increment()
        
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        packet_size = len(packet)
        
        # Déterminer la direction du trafic
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        local_network = self.interface.network_range
        
        # Identifier l'appareil local concerné
        device_ip = None
        is_download = False  # True si c'est du téléchargement pour l'appareil local
        
        if src_ip in local_network and dst_ip not in local_network:
            # Trafic sortant (upload)
            device_ip = src_ip
            is_download = False
        elif dst_ip in local_network and src_ip not in local_network:
            # Trafic entrant (download)
            device_ip = dst_ip
            is_download = True
        elif src_ip in local_network and dst_ip in local_network:
            # Trafic interne - on peut le traiter différemment
            return
        
        if not device_ip or device_ip == self.interface.ip:
            return  # Ignorer notre propre trafic
        
        # Mettre à jour les statistiques
        self._update_traffic_stats(device_ip, packet_size, is_download)
        
        # Vérifier les limites si le contrôle est actif
        if self.controlling and device_ip in self.bandwidth_limits:
            if self._should_block_packet(device_ip, packet_size, is_download):
                self._block_packet(packet, device_ip, is_download)
                return
        
        # Packet autorisé - peut être retransmis si nécessaire
        self._forward_packet(packet)
    
    def _update_traffic_stats(self, device_ip: str, packet_size: int, is_download: bool):
        """Met à jour les statistiques de trafic"""
        with self._stats_lock:
            if device_ip not in self.traffic_stats:
                self.traffic_stats[device_ip] = TrafficStats(device_ip=device_ip)
            
            stats = self.traffic_stats[device_ip]
            
            if is_download:
                stats.update_traffic(packet_size, 0, 1, 0)
            else:
                stats.update_traffic(0, packet_size, 0, 1)
            
            # Calculer les vitesses périodiquement
            current_time = time.time()
            if current_time - self._last_stats_update >= self.stats_update_interval:
                for stats in self.traffic_stats.values():
                    stats.calculate_speeds()
                
                self._last_stats_update = current_time
                
                # Callback de mise à jour des stats
                if self.on_stats_updated:
                    self.on_stats_updated(self.traffic_stats.copy())
    
    def _should_block_packet(self, device_ip: str, packet_size: int, is_download: bool) -> bool:
        """Détermine si un paquet doit être bloqué"""
        if device_ip not in self.bandwidth_limits:
            return False
        
        limit = self.bandwidth_limits[device_ip]
        if not limit.enabled:
            return False
        
        stats = self.traffic_stats.get(device_ip)
        if not stats:
            return False
        
        # Vérifier les limites
        if is_download and limit.download_limit > 0:
            if stats.current_download_speed > limit.download_limit:
                # Callback de dépassement
                if self.on_limit_exceeded:
                    speed_mbps = stats.current_download_speed * 8 / (1024 * 1024)
                    self.on_limit_exceeded(device_ip, "download", speed_mbps)
                return True
        
        elif not is_download and limit.upload_limit > 0:
            if stats.current_upload_speed > limit.upload_limit:
                # Callback de dépassement
                if self.on_limit_exceeded:
                    speed_mbps = stats.current_upload_speed * 8 / (1024 * 1024)
                    self.on_limit_exceeded(device_ip, "upload", speed_mbps)
                return True
        
        return False
    
    def _block_packet(self, packet, device_ip: str, is_download: bool):
        """Bloque un paquet (ne le retransmet pas)"""
        self.total_packets_blocked.increment()
        
        # Mettre à jour les stats de blocage
        if device_ip in self.traffic_stats:
            self.traffic_stats[device_ip].blocked_packets += 1
        
        # Callback de blocage
        if self.on_device_blocked:
            direction = "download" if is_download else "upload"
            self.on_device_blocked(device_ip, f"Limite {direction} dépassée")
        
        # Log debug
        self.logger.debug(f"Paquet bloqué pour {device_ip} ({'↓' if is_download else '↑'})")
    
    def _forward_packet(self, packet):
        """Retransmet un paquet autorisé"""
        # Dans une implémentation complète, on retransmettrait le paquet
        # Pour l'instant, on ne fait que le laisser passer (monitoring passif)
        pass
    
    def start_monitoring(self) -> bool:
        """Démarre le monitoring de bande passante"""
        if self.monitoring:
            self.logger.warning("Monitoring déjà actif")
            return False
        
        self.monitoring = True
        self.stop_event.clear()
        
        # Démarrer le thread de monitoring
        self.monitor_thread = threading.Thread(target=self._packet_monitor, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("Monitoring de bande passante démarré")
        return True
    
    def stop_monitoring(self):
        """Arrête le monitoring de bande passante"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        self.controlling = False
        self.stop_event.set()
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Monitoring de bande passante arrêté")
    
    def enable_control(self, enabled: bool = True):
        """Active/désactive le contrôle actif de bande passante"""
        self.controlling = enabled
        status = "activé" if enabled else "désactivé"
        self.logger.info(f"Contrôle de bande passante {status}")
    
    def get_device_stats(self, device_ip: str) -> Optional[TrafficStats]:
        """Récupère les statistiques d'un appareil"""
        return self.traffic_stats.get(device_ip)
    
    def get_all_stats(self) -> Dict[str, TrafficStats]:
        """Récupère toutes les statistiques"""
        with self._stats_lock:
            return self.traffic_stats.copy()
    
    def get_device_limit(self, device_ip: str) -> Optional[BandwidthLimit]:
        """Récupère la limite d'un appareil"""
        return self.bandwidth_limits.get(device_ip)
    
    def get_all_limits(self) -> Dict[str, BandwidthLimit]:
        """Récupère toutes les limites"""
        return self.bandwidth_limits.copy()
    
    def reset_stats(self, device_ip: str = None):
        """Remet à zéro les statistiques"""
        with self._stats_lock:
            if device_ip:
                if device_ip in self.traffic_stats:
                    self.traffic_stats[device_ip] = TrafficStats(device_ip=device_ip)
                    self.logger.info(f"Statistiques remises à zéro pour {device_ip}")
            else:
                device_ips = list(self.traffic_stats.keys())
                self.traffic_stats.clear()
                for ip in device_ips:
                    self.traffic_stats[ip] = TrafficStats(device_ip=ip)
                self.total_packets_processed.reset()
                self.total_packets_blocked.reset()
                self.logger.info("Toutes les statistiques remises à zéro")
    
    def get_top_consumers(self, limit: int = 10) -> List[TrafficStats]:
        """Retourne les plus gros consommateurs de bande passante"""
        all_stats = list(self.traffic_stats.values())
        all_stats.sort(key=lambda x: x.get_total_traffic(), reverse=True)
        return all_stats[:limit]
    
    def get_active_devices(self, time_threshold: int = 300) -> List[TrafficStats]:
        """Retourne les appareils actifs dans les X dernières secondes"""
        current_time = datetime.now()
        active_devices = []
        
        for stats in self.traffic_stats.values():
            time_since_activity = (current_time - stats.last_activity).total_seconds()
            if time_since_activity <= time_threshold:
                active_devices.append(stats)
        
        return active_devices
    
    def get_global_statistics(self) -> Dict[str, any]:
        """Retourne les statistiques globales"""
        total_download = sum(stats.current_download_speed for stats in self.traffic_stats.values())
        total_upload = sum(stats.current_upload_speed for stats in self.traffic_stats.values())
        
        # Conversion en Mbps
        total_download_mbps = total_download * 8 / (1024 * 1024)
        total_upload_mbps = total_upload * 8 / (1024 * 1024)
        
        return {
            'monitoring': self.monitoring,
            'controlling': self.controlling,
            'total_devices': len(self.traffic_stats),
            'devices_with_limits': len(self.bandwidth_limits),
            'active_limits': len([l for l in self.bandwidth_limits.values() if l.enabled]),
            'total_download_speed_mbps': total_download_mbps,
            'total_upload_speed_mbps': total_upload_mbps,
            'total_packets_processed': self.total_packets_processed.get(),
            'total_packets_blocked': self.total_packets_blocked.get(),
            'block_rate': safe_division(self.total_packets_blocked.get() * 100, self.total_packets_processed.get()),
            'interface': self.interface.interface
        }
    
    def export_stats_csv(self, filename: str) -> bool:
        """Exporte les statistiques en CSV"""
        try:
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Device_IP', 'Total_Download_MB', 'Total_Upload_MB', 'Current_Download_Mbps', 
                             'Current_Upload_Mbps', 'Peak_Download_Mbps', 'Peak_Upload_Mbps', 
                             'Total_Packets_In', 'Total_Packets_Out', 'Blocked_Packets', 'Last_Activity']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for stats in self.traffic_stats.values():
                    writer.writerow({
                        'Device_IP': stats.device_ip,
                        'Total_Download_MB': stats.total_bytes_in / (1024 * 1024),
                        'Total_Upload_MB': stats.total_bytes_out / (1024 * 1024),
                        'Current_Download_Mbps': stats.current_download_speed * 8 / (1024 * 1024),
                        'Current_Upload_Mbps': stats.current_upload_speed * 8 / (1024 * 1024),
                        'Peak_Download_Mbps': stats.peak_download_speed * 8 / (1024 * 1024),
                        'Peak_Upload_Mbps': stats.peak_upload_speed * 8 / (1024 * 1024),
                        'Total_Packets_In': stats.total_packets_in,
                        'Total_Packets_Out': stats.total_packets_out,
                        'Blocked_Packets': stats.blocked_packets,
                        'Last_Activity': stats.last_activity.strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            self.logger.info(f"Statistiques exportées vers {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de l'export CSV: {e}")
            return False


def create_bandwidth_controller(interface: NetworkAdapter, arp_handler: ARPHandler) -> BandwidthController:
    """Factory function pour créer un contrôleur de bande passante"""
    return BandwidthController(interface, arp_handler)