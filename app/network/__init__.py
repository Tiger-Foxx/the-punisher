"""
Module réseau de NetworkController
Gestion complète du réseau, scan, contrôle et manipulation
"""

from .interfaces import (
    NetworkAdapter,
    NetworkInterfaceManager,
    interface_manager,
    get_network_interfaces,
    get_default_interface,
    get_suitable_interfaces
)

from .scanner import (
    NetworkDevice,
    NetworkScanner,
    ScanResult,
    OUIDatabase,
    create_network_scanner,
    get_oui_database
)

from .arp_handler import (
    ARPHandler,
    ARPAttackSession,
    ARPAttackTarget,
    create_arp_handler
)

from .bandwidth import (
    BandwidthController,
    BandwidthLimit,
    TrafficStats,
    TrafficData,
    create_bandwidth_controller
)

from .device_info import (
    DeviceInfoScanner,
    DeviceProfile,
    ServiceInfo,
    OSFingerprint,
    create_device_info_scanner
)

__all__ = [
    # Interfaces
    'NetworkAdapter',
    'NetworkInterfaceManager', 
    'interface_manager',
    'get_network_interfaces',
    'get_default_interface',
    'get_suitable_interfaces',
    
    # Scanner
    'NetworkDevice',
    'NetworkScanner',
    'ScanResult',
    'OUIDatabase',
    'create_network_scanner',
    'get_oui_database',
    
    # ARP Handler
    'ARPHandler',
    'ARPAttackSession',
    'ARPAttackTarget', 
    'create_arp_handler',
    
    # Bandwidth
    'BandwidthController',
    'BandwidthLimit',
    'TrafficStats',
    'TrafficData',
    'create_bandwidth_controller',
    
    # Device Info
    'DeviceInfoScanner',
    'DeviceProfile',
    'ServiceInfo',
    'OSFingerprint',
    'create_device_info_scanner'
]