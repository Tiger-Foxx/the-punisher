"""
Détection et gestion des interfaces réseau
Sélection d'adaptateurs, informations réseau, configuration
"""

import psutil
import netifaces
import socket
import subprocess
import re
from typing import List, Dict, Optional, Tuple, NamedTuple
from dataclasses import dataclass
from ..core import get_app_logger, NetworkUtils, retry, timed_cache


class InterfaceInfo(NamedTuple):
    """Informations sur une interface réseau"""
    name: str
    display_name: str
    ip_address: str
    netmask: str
    gateway: str
    mac_address: str
    is_wireless: bool
    is_active: bool
    speed_mbps: Optional[int]
    mtu: int
    interface_type: str


@dataclass
class NetworkAdapter:
    """Représentation d'un adaptateur réseau"""
    interface: str
    name: str
    description: str
    ip: str
    netmask: str
    gateway: str
    mac: str
    is_wireless: bool
    is_active: bool
    speed: Optional[int] = None
    mtu: int = 1500
    
    @property
    def network_range(self) -> List[str]:
        """Retourne la plage d'adresses du réseau"""
        return NetworkUtils.get_network_range(self.ip, self.netmask)
    
    @property
    def is_gateway(self) -> bool:
        """Vérifie si cette interface est configurée comme passerelle"""
        # Vérifier si l'IP de l'interface correspond à une passerelle courante
        return self.ip == self.gateway or self.ip.endswith('.1')
    
    @property
    def is_suitable_for_attack(self) -> bool:
        """Vérifie si l'interface est adaptée pour les attaques réseau"""
        return (
            self.is_active and 
            self.ip != "127.0.0.1" and 
            self.gateway and 
            self.gateway != "0.0.0.0" and
            len(self.network_range) > 1
        )


class NetworkInterfaceManager:
    """Gestionnaire des interfaces réseau"""
    
    def __init__(self):
        self.logger = get_app_logger("NetworkInterfaces")
        self._interfaces_cache = None
        self._cache_timestamp = 0
        self._cache_duration = 30  # secondes
    
    @timed_cache(30)
    def get_all_interfaces(self) -> List[NetworkAdapter]:
        """Récupère toutes les interfaces réseau disponibles"""
        interfaces = []
        
        try:
            # Utiliser netifaces pour la détection d'interfaces
            for interface_name in netifaces.interfaces():
                adapter = self._create_adapter_from_interface(interface_name)
                if adapter:
                    interfaces.append(adapter)
                    
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des interfaces: {e}")
        
        # Trier par priorité (actives en premier, puis par nom)
        interfaces.sort(key=lambda x: (not x.is_active, x.name))
        return interfaces
    
    def _create_adapter_from_interface(self, interface_name: str) -> Optional[NetworkAdapter]:
        """Crée un NetworkAdapter à partir d'un nom d'interface"""
        try:
            # Récupérer les adresses de l'interface
            addrs = netifaces.ifaddresses(interface_name)
            
            # Vérifier s'il y a une adresse IPv4
            if netifaces.AF_INET not in addrs:
                return None
            
            ipv4_info = addrs[netifaces.AF_INET][0]
            ip_address = ipv4_info.get('addr', '')
            netmask = ipv4_info.get('netmask', '')
            
            if not ip_address or ip_address == '0.0.0.0':
                return None
            
            # Récupérer l'adresse MAC
            mac_address = ''
            if netifaces.AF_LINK in addrs:
                mac_address = addrs[netifaces.AF_LINK][0].get('addr', '')
            
            # Récupérer la passerelle
            gateway = self._get_gateway_for_interface(interface_name)
            
            # Déterminer si c'est sans fil
            is_wireless = self._is_wireless_interface(interface_name)
            
            # Vérifier si l'interface est active
            is_active = self._is_interface_active(interface_name)
            
            # Récupérer les détails de l'interface
            description = self._get_interface_description(interface_name)
            speed = self._get_interface_speed(interface_name)
            mtu = self._get_interface_mtu(interface_name)
            
            return NetworkAdapter(
                interface=interface_name,
                name=interface_name,
                description=description,
                ip=ip_address,
                netmask=netmask,
                gateway=gateway,
                mac=mac_address,
                is_wireless=is_wireless,
                is_active=is_active,
                speed=speed,
                mtu=mtu
            )
            
        except Exception as e:
            self.logger.debug(f"Erreur lors de la création de l'adaptateur pour {interface_name}: {e}")
            return None
    
    def _get_gateway_for_interface(self, interface_name: str) -> str:
        """Récupère la passerelle pour une interface donnée"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})
            
            if netifaces.AF_INET in default_gateway:
                gateway_ip, gateway_interface = default_gateway[netifaces.AF_INET]
                if gateway_interface == interface_name:
                    return gateway_ip
            
            # Chercher dans toutes les passerelles
            for family, gateway_list in gateways.items():
                if family == 'default':
                    continue
                for gateway_ip, gateway_interface, _ in gateway_list:
                    if gateway_interface == interface_name:
                        return gateway_ip
                        
        except Exception as e:
            self.logger.debug(f"Erreur lors de la récupération de la passerelle pour {interface_name}: {e}")
        
        return ""
    
    def _is_wireless_interface(self, interface_name: str) -> bool:
        """Détermine si une interface est sans fil"""
        wireless_indicators = ['wifi', 'wlan', 'wireless', 'wi-fi', '802.11']
        interface_lower = interface_name.lower()
        
        # Vérifier le nom de l'interface
        for indicator in wireless_indicators:
            if indicator in interface_lower:
                return True
        
        # Sur Windows, vérifier via WMI si possible
        try:
            if hasattr(psutil, 'net_if_stats'):
                stats = psutil.net_if_stats()
                if interface_name in stats and hasattr(stats[interface_name], 'isup'):
                    # Logique spécifique pour détecter le sans fil
                    pass
        except Exception:
            pass
        
        return False
    
    def _is_interface_active(self, interface_name: str) -> bool:
        """Vérifie si une interface est active"""
        try:
            if hasattr(psutil, 'net_if_stats'):
                stats = psutil.net_if_stats()
                if interface_name in stats:
                    return stats[interface_name].isup
            
            # Méthode alternative : ping de la passerelle
            addrs = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0].get('addr', '')
                return ip != '' and ip != '0.0.0.0'
                
        except Exception:
            pass
        
        return False
    
    def _get_interface_description(self, interface_name: str) -> str:
        """Récupère la description d'une interface"""
        try:
            # Sur Windows, utiliser netsh
            if hasattr(psutil, 'net_if_addrs'):
                # Utiliser psutil pour obtenir plus d'infos
                return interface_name
            
            # Description par défaut
            return interface_name
            
        except Exception:
            return interface_name
    
    def _get_interface_speed(self, interface_name: str) -> Optional[int]:
        """Récupère la vitesse d'une interface en Mbps"""
        try:
            if hasattr(psutil, 'net_if_stats'):
                stats = psutil.net_if_stats()
                if interface_name in stats:
                    speed = stats[interface_name].speed
                    return speed if speed > 0 else None
        except Exception:
            pass
        return None
    
    def _get_interface_mtu(self, interface_name: str) -> int:
        """Récupère le MTU d'une interface"""
        try:
            if hasattr(psutil, 'net_if_stats'):
                stats = psutil.net_if_stats()
                if interface_name in stats:
                    return stats[interface_name].mtu
        except Exception:
            pass
        return 1500  # MTU par défaut
    
    def get_suitable_interfaces(self) -> List[NetworkAdapter]:
        """Retourne les interfaces adaptées pour les attaques réseau"""
        all_interfaces = self.get_all_interfaces()
        return [iface for iface in all_interfaces if iface.is_suitable_for_attack]
    
    def get_default_interface(self) -> Optional[NetworkAdapter]:
        """Retourne l'interface par défaut (celle avec la route par défaut)"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})
            
            if netifaces.AF_INET in default_gateway:
                _, default_interface = default_gateway[netifaces.AF_INET]
                
                all_interfaces = self.get_all_interfaces()
                for interface in all_interfaces:
                    if interface.interface == default_interface:
                        return interface
                        
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de l'interface par défaut: {e}")
        
        # Fallback: première interface active
        suitable = self.get_suitable_interfaces()
        return suitable[0] if suitable else None
    
    def get_interface_by_name(self, name: str) -> Optional[NetworkAdapter]:
        """Récupère une interface par son nom"""
        all_interfaces = self.get_all_interfaces()
        for interface in all_interfaces:
            if interface.interface == name or interface.name == name:
                return interface
        return None
    
    @retry(max_attempts=3, delay=1.0)
    def test_interface_connectivity(self, adapter: NetworkAdapter) -> bool:
        """Teste la connectivité d'une interface"""
        if not adapter.gateway:
            return False
        
        # Ping de la passerelle
        if NetworkUtils.ping(adapter.gateway, timeout=2.0):
            return True
        
        # Test ping vers Google DNS
        if NetworkUtils.ping("8.8.8.8", timeout=3.0):
            return True
        
        return False
    
    def get_interface_statistics(self, interface_name: str) -> Dict[str, int]:
        """Récupère les statistiques d'une interface"""
        stats = {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0,
            'errin': 0,
            'errout': 0,
            'dropin': 0,
            'dropout': 0
        }
        
        try:
            if hasattr(psutil, 'net_io_counters'):
                io_counters = psutil.net_io_counters(pernic=True)
                if interface_name in io_counters:
                    counter = io_counters[interface_name]
                    stats.update({
                        'bytes_sent': counter.bytes_sent,
                        'bytes_recv': counter.bytes_recv,
                        'packets_sent': counter.packets_sent,
                        'packets_recv': counter.packets_recv,
                        'errin': counter.errin,
                        'errout': counter.errout,
                        'dropin': counter.dropin,
                        'dropout': counter.dropout
                    })
        except Exception as e:
            self.logger.debug(f"Erreur lors de la récupération des stats pour {interface_name}: {e}")
        
        return stats
    
    def refresh_interfaces(self) -> List[NetworkAdapter]:
        """Force le rafraîchissement de la liste des interfaces"""
        self._interfaces_cache = None
        self._cache_timestamp = 0
        return self.get_all_interfaces()


# Instance globale du gestionnaire d'interfaces
interface_manager = NetworkInterfaceManager()


def get_network_interfaces() -> List[NetworkAdapter]:
    """Fonction utilitaire pour récupérer les interfaces réseau"""
    return interface_manager.get_all_interfaces()


def get_default_interface() -> Optional[NetworkAdapter]:
    """Fonction utilitaire pour récupérer l'interface par défaut"""
    return interface_manager.get_default_interface()


def get_suitable_interfaces() -> List[NetworkAdapter]:
    """Fonction utilitaire pour récupérer les interfaces adaptées"""
    return interface_manager.get_suitable_interfaces()