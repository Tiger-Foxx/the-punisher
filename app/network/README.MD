# Module Network - THE PUNISHER

## Vue d'ensemble

Le module `network` est le cœur technique de l'application **THE PUNISHER**. Il contient tous les composants nécessaires pour la découverte, l'analyse, le contrôle et la manipulation du réseau. Ce module fournit une architecture complète et sophistiquée pour la gestion réseau avancée.

## Structure du module

```
app/network/
├── __init__.py          # Exports et initialisation du module
├── interfaces.py         # Détection et gestion des interfaces réseau
├── scanner.py           # Scanner réseau avec base OUI complète
├── arp_handler.py       # Gestionnaire ARP et attaques réseau
├── bandwidth.py         # Contrôleur de bande passante
├── device_info.py       # Informations détaillées sur les appareils
└── README.md           # Cette documentation
```

## Composants détaillés

### 1. Interfaces réseau (`interfaces.py`)

#### Classes principales

##### `NetworkAdapter`
Représentation complète d'un adaptateur réseau avec toutes ses propriétés :

**Propriétés de base :**
- `interface` : Nom de l'interface système
- `name` : Nom d'affichage
- `description` : Description détaillée
- `ip` : Adresse IP de l'interface
- `netmask` : Masque de sous-réseau
- `gateway` : Passerelle par défaut
- `mac` : Adresse MAC
- `is_wireless` : Interface sans fil
- `is_active` : Interface active
- `speed` : Vitesse en Mbps (optionnel)
- `mtu` : Taille MTU

**Propriétés calculées :**
- `network_range` : Liste des IPs dans le réseau
- `is_suitable_for_attack` : Vérifie si l'interface est adaptée pour les attaques

##### `NetworkInterfaceManager`
Gestionnaire principal des interfaces réseau avec fonctionnalités avancées :

**Méthodes principales :**
- `get_all_interfaces()` : Récupère toutes les interfaces avec cache intelligent
- `get_suitable_interfaces()` : Interfaces adaptées pour les attaques
- `get_default_interface()` : Interface par défaut (route par défaut)
- `test_interface_connectivity()` : Test de connectivité avec ping
- `get_interface_statistics()` : Statistiques détaillées de l'interface
- `refresh_interfaces()` : Force le rafraîchissement

**Fonctionnalités avancées :**
- Cache intelligent avec expiration (30s)
- Détection automatique du type d'interface (WiFi/Ethernet)
- Validation de connectivité
- Support multi-plateforme (Windows/Linux/Mac)
- Gestion des erreurs robuste

#### Données renvoyées à la GUI

**Format des interfaces :**
```python
{
    "interface": "eth0",
    "name": "Ethernet",
    "description": "Intel Ethernet Controller",
    "ip": "192.168.1.100",
    "netmask": "255.255.255.0",
    "gateway": "192.168.1.1",
    "mac": "00:11:22:33:44:55",
    "is_wireless": False,
    "is_active": True,
    "speed": 1000,  # Mbps
    "mtu": 1500,
    "network_range": ["192.168.1.1", "192.168.1.2", ...],
    "is_suitable_for_attack": True
}
```

**Statistiques d'interface :**
```python
{
    "bytes_sent": 1024000,
    "bytes_recv": 2048000,
    "packets_sent": 1500,
    "packets_recv": 3000,
    "errin": 0,
    "errout": 0,
    "dropin": 0,
    "dropout": 0
}
```

### 2. Scanner réseau (`scanner.py`)

#### Classes principales

##### `NetworkDevice`
Représentation complète d'un appareil réseau découvert :

**Propriétés de base :**
- `ip` : Adresse IP
- `mac` : Adresse MAC
- `hostname` : Nom d'hôte résolu
- `vendor` : Fabricant (depuis base OUI)
- `vendor_address` : Adresse du fabricant
- `os_guess` : Estimation du système d'exploitation
- `device_type` : Type d'appareil (Router, Computer, Phone, etc.)
- `is_gateway` : Est-ce la passerelle
- `is_local_machine` : Est-ce la machine locale

**Propriétés temporelles :**
- `first_seen` : Première détection
- `last_seen` : Dernière détection
- `response_times` : Historique des temps de réponse
- `is_online` : Statut en ligne/hors ligne

**Propriétés calculées :**
- `avg_response_time` : Temps de réponse moyen
- `uptime_percentage` : Pourcentage de disponibilité
- `normalized_mac` : MAC normalisée
- `mac_oui` : OUI (3 premiers octets)

**Méthodes intelligentes :**
- `guess_device_type()` : Détection automatique du type d'appareil
- `update_last_seen()` : Mise à jour du statut
- `mark_offline()` : Marquer comme hors ligne

##### `OUIDatabase`
Base de données complète des fabricants (Organizationally Unique Identifier) :

**Fonctionnalités :**
- Chargement depuis fichier OUI.txt
- Base de données de fallback intégrée
- Cache intelligent avec expiration (1h)
- Recherche par nom de fabricant
- Statistiques détaillées

**Méthodes principales :**
- `get_vendor_info(mac)` : Informations complètes du fabricant
- `get_vendor_name(mac)` : Nom du fabricant
- `search_vendor(query)` : Recherche par nom
- `get_statistics()` : Statistiques de la base

##### `NetworkScanner`
Scanner réseau principal avec fonctionnalités avancées :

**Configuration :**
- `scan_timeout` : 3.0s
- `max_threads` : 50 threads simultanés
- `scan_interval` : 5.0s pour le scan continu
- `offline_timeout` : 30s avant marquage hors ligne
- `deep_scan_enabled` : Scan approfondi avec OS detection

**Fonctionnalités de scan :**
- Scan ARP intelligent avec threading
- Résolution automatique des noms d'hôte
- Détection OS basée sur TTL et signatures
- Base OUI intégrée pour identification fabricant
- Cache intelligent des résultats
- Rate limiting pour éviter la surcharge

**Callbacks pour la GUI :**
- `on_device_discovered(device)` : Nouvel appareil trouvé
- `on_device_updated(device)` : Appareil mis à jour
- `on_device_lost(device)` : Appareil perdu
- `on_scan_complete(devices)` : Scan terminé
- `on_scan_progress(current, total)` : Progression du scan

**Méthodes principales :**
- `scan_network()` : Scan complet du réseau
- `start_continuous_scan()` : Scan continu en arrière-plan
- `stop_continuous_scan()` : Arrêt du scan continu
- `rescan_device(ip)` : Rescan d'un appareil spécifique

#### Données renvoyées à la GUI

**Format d'un appareil découvert :**
```python
{
    "ip": "192.168.1.50",
    "mac": "00:11:22:33:44:55",
    "hostname": "DESKTOP-ABC123",
    "vendor": "Dell Inc.",
    "vendor_address": "Round Rock, TX, US",
    "os_guess": "Windows 10",
    "device_type": "Computer",
    "is_gateway": False,
    "is_local_machine": False,
    "first_seen": "2024-01-15T10:30:00",
    "last_seen": "2024-01-15T10:35:00",
    "response_times": [1.2, 1.1, 1.3, 1.0],
    "is_online": True,
    "avg_response_time": 1.15,
    "uptime_percentage": 100.0,
    "ports_open": [80, 443, 22]
}
```

**Statistiques du scanner :**
```python
{
    "total_devices": 15,
    "online_devices": 12,
    "offline_devices": 3,
    "total_scans": 1500,
    "successful_scans": 1420,
    "success_rate": 94.67,
    "scanning": True,
    "interface": "eth0",
    "last_scan_duration": 2.45,
    "device_types": {
        "Computer": 8,
        "Mobile/Tablet": 4,
        "Router/Gateway": 1,
        "IoT Device": 2
    },
    "top_vendors": {
        "Apple, Inc.": 4,
        "Samsung Electronics": 3,
        "Dell Inc.": 2
    }
}
```

### 3. Gestionnaire ARP (`arp_handler.py`)

#### Classes principales

##### `ARPAttackSession`
Session d'attaque ARP active avec suivi détaillé :

**Propriétés :**
- `target_ip` : IP de la cible
- `target_mac` : MAC de la cible
- `gateway_ip` : IP de la passerelle
- `gateway_mac` : MAC de la passerelle
- `attack_type` : Type d'attaque ("block", "mitm", "redirect")
- `start_time` : Début de l'attaque
- `packets_sent` : Nombre de paquets envoyés
- `is_active` : Attaque active
- `last_packet_time` : Dernier paquet envoyé

**Méthodes calculées :**
- `get_duration()` : Durée de l'attaque
- `get_packets_per_second()` : Taux de paquets/seconde

##### `ARPHandler`
Gestionnaire principal des attaques ARP :

**Types d'attaques supportées :**
- **BLOCK** : Blocage complet (pas d'accès Internet)
- **MITM** : Man-in-the-Middle (interception du trafic)
- **REDIRECT** : Redirection du trafic vers nous

**Configuration :**
- `attack_interval` : 1.0s entre les paquets
- `max_attack_threads` : 20 threads max
- `packet_burst_size` : Nombre de paquets par burst
- `restore_on_stop` : Restauration automatique des tables ARP

**Méthodes principales :**
- `start_attack(device, attack_type)` : Démarre une attaque
- `stop_attack(target_ip, attack_type)` : Arrête une attaque
- `stop_all_attacks()` : Arrête toutes les attaques
- `block_device(device)` : Bloque un appareil
- `unblock_device(device)` : Débloque un appareil
- `start_mitm(device)` : Démarre MITM
- `mass_block(devices)` : Blocage en masse

**Callbacks pour la GUI :**
- `on_attack_started(session_id, session)` : Attaque démarrée
- `on_attack_stopped(session_id, session)` : Attaque arrêtée
- `on_packet_sent(session_id, count)` : Paquets envoyés

#### Données renvoyées à la GUI

**Format d'une session d'attaque :**
```python
{
    "target_ip": "192.168.1.50",
    "target_mac": "00:11:22:33:44:55",
    "gateway_ip": "192.168.1.1",
    "gateway_mac": "AA:BB:CC:DD:EE:FF",
    "attack_type": "block",
    "start_time": "2024-01-15T10:30:00",
    "packets_sent": 150,
    "is_active": True,
    "last_packet_time": "2024-01-15T10:32:30",
    "duration": 150.5,  # secondes
    "packets_per_second": 1.0
}
```

**Statistiques des attaques :**
```python
{
    "attacking": True,
    "active_sessions": 3,
    "total_packets_sent": 450,
    "session_packets_sent": 450,
    "attack_types": {
        "block": 2,
        "mitm": 1
    },
    "average_duration": 120.5,
    "attack_interval": 1.0,
    "interface": "eth0",
    "gateway_mac": "AA:BB:CC:DD:EE:FF",
    "local_mac": "11:22:33:44:55:66"
}
```

### 4. Contrôleur de bande passante (`bandwidth.py`)

#### Classes principales

##### `BandwidthLimit`
Limite de bande passante pour un appareil :

**Propriétés :**
- `device_ip` : IP de l'appareil
- `download_limit` : Limite téléchargement (bytes/sec, 0=illimité)
- `upload_limit` : Limite upload (bytes/sec, 0=illimité)
- `enabled` : Limite active
- `priority` : Priorité (1=haute, 2=normale, 3=basse)

##### `TrafficStats`
Statistiques détaillées du trafic :

**Propriétés de base :**
- `device_ip` : IP de l'appareil
- `total_bytes_in` : Total bytes reçus
- `total_bytes_out` : Total bytes envoyés
- `total_packets_in` : Total paquets reçus
- `total_packets_out` : Total paquets envoyés

**Vitesses calculées :**
- `current_download_speed` : Vitesse téléchargement actuelle (bytes/sec)
- `current_upload_speed` : Vitesse upload actuelle (bytes/sec)
- `peak_download_speed` : Pic de vitesse téléchargement
- `peak_upload_speed` : Pic de vitesse upload

**Données temporelles :**
- `last_activity` : Dernière activité
- `traffic_history` : Historique du trafic (100 points max)
- `blocked_packets` : Paquets bloqués

##### `BandwidthController`
Contrôleur principal de bande passante :

**Fonctionnalités :**
- Monitoring passif du trafic réseau
- Contrôle actif avec blocage de paquets
- Limites configurables par appareil
- Historique détaillé du trafic
- Statistiques en temps réel

**Configuration :**
- `monitor_interval` : 1.0s pour le monitoring
- `packet_capture_timeout` : 1.0s timeout capture
- `max_queue_size` : 1000 paquets en queue
- `stats_update_interval` : 5.0s mise à jour stats

**Méthodes principales :**
- `set_bandwidth_limit(ip, download_mbps, upload_mbps)` : Définit une limite
- `remove_bandwidth_limit(ip)` : Supprime une limite
- `enable_limit(ip, enabled)` : Active/désactive une limite
- `start_monitoring()` : Démarre le monitoring
- `enable_control(enabled)` : Active le contrôle actif

**Callbacks pour la GUI :**
- `on_limit_exceeded(ip, type, speed)` : Limite dépassée
- `on_stats_updated(stats)` : Stats mises à jour
- `on_device_blocked(ip, reason)` : Appareil bloqué

#### Données renvoyées à la GUI

**Format des statistiques de trafic :**
```python
{
    "device_ip": "192.168.1.50",
    "total_bytes_in": 104857600,  # 100 MB
    "total_bytes_out": 52428800,   # 50 MB
    "total_packets_in": 15000,
    "total_packets_out": 8000,
    "current_download_speed": 1048576,  # 1 MB/s
    "current_upload_speed": 524288,     # 512 KB/s
    "peak_download_speed": 2097152,     # 2 MB/s
    "peak_upload_speed": 1048576,       # 1 MB/s
    "last_activity": "2024-01-15T10:35:00",
    "blocked_packets": 150,
    "traffic_history": [
        {
            "timestamp": 1705312500.0,
            "bytes_in": 1024,
            "bytes_out": 512,
            "packets_in": 1,
            "packets_out": 1
        }
    ]
}
```

**Format d'une limite de bande passante :**
```python
{
    "device_ip": "192.168.1.50",
    "download_limit": 1048576,  # 1 MB/s
    "upload_limit": 524288,      # 512 KB/s
    "enabled": True,
    "priority": 1,
    "is_unlimited": False
}
```

**Statistiques globales :**
```python
{
    "monitoring": True,
    "controlling": True,
    "total_devices": 15,
    "devices_with_limits": 8,
    "active_limits": 6,
    "total_download_speed_mbps": 25.6,
    "total_upload_speed_mbps": 12.8,
    "total_packets_processed": 50000,
    "total_packets_blocked": 1500,
    "block_rate": 3.0,  # pourcentage
    "interface": "eth0"
}
```

### 5. Informations détaillées sur les appareils (`device_info.py`)

#### Classes principales

##### `ServiceInfo`
Informations sur un service réseau :

**Propriétés :**
- `port` : Numéro de port
- `protocol` : Protocole (TCP/UDP)
- `service_name` : Nom du service
- `version` : Version détectée
- `banner` : Banner du service

##### `OSFingerprint`
Empreinte OS détectée :

**Propriétés :**
- `os_family` : Famille OS (Windows, Linux, macOS, etc.)
- `os_version` : Version spécifique
- `confidence` : Confiance (0.0 à 1.0)
- `method` : Méthode de détection

##### `DeviceProfile`
Profil complet d'un appareil :

**Propriétés de base :**
- `device` : Référence vers NetworkDevice
- `os_fingerprints` : Liste des empreintes OS
- `open_ports` : Liste des ports ouverts
- `device_type_confidence` : Confiance du type d'appareil
- `manufacturer_info` : Informations fabricant enrichies

**Propriétés avancées :**
- `uptime_estimate` : Estimation de l'uptime (secondes)
- `network_stack_info` : Informations pile réseau
- `vulnerability_indicators` : Indicateurs de vulnérabilités
- `last_scan_time` : Dernier scan
- `scan_duration` : Durée du scan

**Propriétés calculées :**
- `best_os_guess` : Meilleure estimation OS
- `is_vulnerable` : Appareil vulnérable

##### `DeviceInfoScanner`
Scanner d'informations détaillées :

**Fonctionnalités :**
- Scan de ports TCP/UDP
- Détection de services et versions
- OS fingerprinting avancé
- Analyse de vulnérabilités
- Cache intelligent des résultats

**Configuration :**
- `port_scan_timeout` : 1.0s timeout scan
- `max_scan_threads` : 20 threads max
- `common_ports` : Ports courants (21, 22, 80, 443, etc.)
- `extended_ports` : Scan étendu (1-1024)

**Méthodes principales :**
- `scan_device_detailed(device, extended_scan)` : Scan détaillé
- `scan_multiple_devices(devices, extended_scan)` : Scan multiple
- `get_cached_profile(device_ip)` : Profil depuis cache
- `get_vulnerability_summary(profiles)` : Résumé vulnérabilités

#### Données renvoyées à la GUI

**Format d'un profil d'appareil :**
```python
{
    "device": {
        "ip": "192.168.1.50",
        "mac": "00:11:22:33:44:55",
        "hostname": "DESKTOP-ABC123",
        "vendor": "Dell Inc.",
        "device_type": "Computer"
    },
    "os_fingerprints": [
        {
            "os_family": "Windows",
            "os_version": "10",
            "confidence": 0.85,
            "method": "TTL Analysis"
        },
        {
            "os_family": "Windows",
            "os_version": "10",
            "confidence": 0.75,
            "method": "TCP Window Analysis"
        }
    ],
    "open_ports": [
        {
            "port": 80,
            "protocol": "TCP",
            "service_name": "HTTP",
            "version": "2.4.41",
            "banner": "Apache/2.4.41 (Ubuntu)"
        },
        {
            "port": 22,
            "protocol": "TCP",
            "service_name": "SSH",
            "version": "8.2p1",
            "banner": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.2"
        }
    ],
    "device_type_confidence": 0.92,
    "manufacturer_info": "Dell Inc. (Round Rock, TX, US) Computer",
    "uptime_estimate": 86400,  # 24h en secondes
    "network_stack_info": {
        "tcp_window_size": "65535",
        "ttl": "128",
        "tcp_options": "mss,nop,ws,nop,nop,sackOK"
    },
    "vulnerability_indicators": [
        "SMB ports exposed",
        "RDP exposed to network"
    ],
    "best_os_guess": "Windows 10",
    "is_vulnerable": True,
    "last_scan_time": "2024-01-15T10:30:00",
    "scan_duration": 15.5
}
```

**Résumé des vulnérabilités :**
```python
{
    "SMB ports exposed": 5,
    "RDP exposed to network": 3,
    "Outdated SSH version": 2,
    "Insecure service: Telnet": 1,
    "Database port exposed": 1
}
```

## Intégration avec la GUI

### Flux de données typique

1. **Initialisation :**
   ```python
   # Récupérer l'interface par défaut
   interface = get_default_interface()
   
   # Créer les composants
   scanner = create_network_scanner(interface)
   arp_handler = create_arp_handler(interface)
   bandwidth_controller = create_bandwidth_controller(interface, arp_handler)
   device_scanner = create_device_info_scanner(interface)
   ```

2. **Découverte d'appareils :**
   ```python
   # Configurer les callbacks
   scanner.on_device_discovered = gui.add_device
   scanner.on_device_updated = gui.update_device
   scanner.on_device_lost = gui.remove_device
   scanner.on_scan_complete = gui.refresh_device_list
   
   # Démarrer le scan
   devices = scanner.scan_network()
   ```

3. **Contrôle des appareils :**
   ```python
   # Bloquer un appareil
   arp_handler.block_device(device)
   
   # Limiter la bande passante
   bandwidth_controller.set_bandwidth_limit(device.ip, 5.0, 2.0)  # 5Mbps down, 2Mbps up
   
   # Scan détaillé
   profile = device_scanner.scan_device_detailed(device, extended_scan=True)
   ```

### Formats de données pour l'interface utilisateur

#### Liste des appareils
```python
[
    {
        "ip": "192.168.1.50",
        "mac": "00:11:22:33:44:55",
        "hostname": "DESKTOP-ABC123",
        "vendor": "Dell Inc.",
        "device_type": "Computer",
        "is_online": True,
        "is_gateway": False,
        "is_local_machine": False,
        "avg_response_time": 1.15,
        "last_seen": "2024-01-15T10:35:00",
        "status": "online",  # online/offline/blocked
        "bandwidth_limit": {
            "download_mbps": 5.0,
            "upload_mbps": 2.0,
            "enabled": True
        },
        "current_speeds": {
            "download_mbps": 2.5,
            "upload_mbps": 1.0
        }
    }
]
```

#### Statistiques en temps réel
```python
{
    "network": {
        "interface": "eth0",
        "total_devices": 15,
        "online_devices": 12,
        "blocked_devices": 3,
        "total_bandwidth_mbps": 25.6
    },
    "scanner": {
        "scanning": True,
        "last_scan_duration": 2.45,
        "success_rate": 94.67
    },
    "attacks": {
        "active_attacks": 3,
        "total_packets_sent": 450,
        "average_duration": 120.5
    },
    "bandwidth": {
        "monitoring": True,
        "controlling": True,
        "total_packets_processed": 50000,
        "block_rate": 3.0
    }
}
```

#### Détails d'un appareil
```python
{
    "basic_info": {
        "ip": "192.168.1.50",
        "mac": "00:11:22:33:44:55",
        "hostname": "DESKTOP-ABC123",
        "vendor": "Dell Inc.",
        "device_type": "Computer",
        "os_guess": "Windows 10"
    },
    "network_stats": {
        "avg_response_time": 1.15,
        "uptime_percentage": 100.0,
        "first_seen": "2024-01-15T10:30:00",
        "last_seen": "2024-01-15T10:35:00"
    },
    "traffic_stats": {
        "total_download_mb": 100.5,
        "total_upload_mb": 50.2,
        "current_download_mbps": 2.5,
        "current_upload_mbps": 1.0,
        "peak_download_mbps": 5.0,
        "peak_upload_mbps": 2.5
    },
    "bandwidth_control": {
        "download_limit_mbps": 5.0,
        "upload_limit_mbps": 2.0,
        "enabled": True,
        "blocked_packets": 150
    },
    "attack_status": {
        "is_attacked": True,
        "attack_type": "block",
        "attack_duration": 150.5,
        "packets_sent": 150
    },
    "detailed_info": {
        "open_ports": [80, 443, 22],
        "services": ["HTTP", "HTTPS", "SSH"],
        "vulnerabilities": ["SMB ports exposed"],
        "manufacturer_info": "Dell Inc. (Round Rock, TX, US)"
    }
}
```

### Callbacks pour la GUI

#### Scanner réseau
```python
def on_device_discovered(device):
    """Nouvel appareil découvert"""
    gui.add_device_to_list(device)
    gui.show_notification(f"Nouvel appareil: {device.ip} ({device.vendor})")

def on_device_updated(device):
    """Appareil mis à jour"""
    gui.update_device_in_list(device)
    gui.update_device_stats(device)

def on_device_lost(device):
    """Appareil perdu"""
    gui.mark_device_offline(device)
    gui.show_notification(f"Appareil hors ligne: {device.ip}")

def on_scan_complete(devices):
    """Scan terminé"""
    gui.refresh_device_list(devices)
    gui.update_scan_statistics()

def on_scan_progress(current, total):
    """Progression du scan"""
    gui.update_scan_progress(current, total)
```

#### Attaques ARP
```python
def on_attack_started(session_id, session):
    """Attaque démarrée"""
    gui.show_attack_started(session.target_ip, session.attack_type)
    gui.update_device_status(session.target_ip, "attacked")

def on_attack_stopped(session_id, session):
    """Attaque arrêtée"""
    gui.show_attack_stopped(session.target_ip)
    gui.update_device_status(session.target_ip, "normal")

def on_packet_sent(session_id, count):
    """Paquets envoyés"""
    gui.update_attack_progress(session_id, count)
```

#### Contrôle de bande passante
```python
def on_limit_exceeded(ip, type, speed):
    """Limite dépassée"""
    gui.show_limit_exceeded(ip, type, speed)
    gui.highlight_device(ip, "limit_exceeded")

def on_stats_updated(stats):
    """Stats mises à jour"""
    gui.update_bandwidth_stats(stats)

def on_device_blocked(ip, reason):
    """Appareil bloqué"""
    gui.show_device_blocked(ip, reason)
    gui.update_device_status(ip, "blocked")
```

## Gestion des erreurs

### Types d'erreurs courantes

1. **Erreurs réseau :**
   - Interface non disponible
   - Pas de connectivité
   - Timeout de scan
   - Paquets corrompus

2. **Erreurs de privilèges :**
   - Pas de droits administrateur
   - Interface en mode promiscuous non autorisée
   - Accès aux tables ARP refusé

3. **Erreurs de configuration :**
   - Interface invalide
   - Paramètres de scan incorrects
   - Limites de bande passante invalides

### Gestion robuste

```python
# Exemple de gestion d'erreur
try:
    scanner.scan_network()
except NetworkError as e:
    gui.show_error(f"Erreur réseau: {e}")
    logger.error(f"Scan failed: {e}")
except PermissionError as e:
    gui.show_error("Privilèges administrateur requis")
    logger.error(f"Permission denied: {e}")
except Exception as e:
    gui.show_error(f"Erreur inattendue: {e}")
    logger.error(f"Unexpected error: {e}")
```

## Performance et optimisation

### Optimisations incluses

1. **Cache intelligent :**
   - Cache des interfaces (30s)
   - Cache des profils d'appareils (1h)
   - Cache de la base OUI (1h)

2. **Threading optimisé :**
   - Threads de scan parallèles
   - Threads d'attaque séparés
   - Monitoring en arrière-plan

3. **Rate limiting :**
   - Limitation des paquets ARP
   - Contrôle du débit de scan
   - Protection contre la surcharge

4. **Gestion mémoire :**
   - Historique limité (100 points)
   - Rotation des logs
   - Nettoyage automatique

### Métriques de performance

```python
{
    "scan_performance": {
        "devices_per_second": 25.5,
        "average_scan_time": 2.45,
        "success_rate": 94.67,
        "thread_efficiency": 0.85
    },
    "attack_performance": {
        "packets_per_second": 1.0,
        "attack_success_rate": 98.5,
        "restoration_success_rate": 99.2
    },
    "bandwidth_performance": {
        "packets_processed_per_second": 1000,
        "monitoring_overhead": 0.5,  # pourcentage
        "control_latency": 0.1  # secondes
    }
}
```

## Sécurité et éthique

### Mesures de sécurité

1. **Validation stricte :**
   - Validation des adresses IP/MAC
   - Vérification des paramètres
   - Sanitisation des entrées

2. **Logging sécurisé :**
   - Pas d'informations sensibles dans les logs
   - Rotation automatique des fichiers
   - Niveaux de log appropriés

3. **Gestion des privilèges :**
   - Vérification des droits administrateur
   - Restauration automatique des tables ARP
   - Arrêt propre des attaques

### Considérations éthiques

1. **Utilisation responsable :**
   - Avertissements sur l'utilisation
   - Documentation des risques
   - Recommandations de sécurité

2. **Transparence :**
   - Logs détaillés des actions
   - Notifications utilisateur
   - Possibilité d'annulation

3. **Conformité :**
   - Respect des lois locales
   - Utilisation uniquement sur réseaux autorisés
   - Documentation des limitations

## Conclusion

Le module `network` fournit une architecture complète et sophistiquée pour la gestion réseau avancée. Il encapsule toutes les fonctionnalités nécessaires pour la découverte, l'analyse, le contrôle et la manipulation du réseau dans **THE PUNISHER**.

Cette architecture modulaire permet une intégration facile avec la GUI tout en fournissant des données riches et détaillées pour une expérience utilisateur optimale. Tous les composants sont conçus pour être robustes, performants et éthiques.

---

*Documentation générée pour le projet THE PUNISHER - NetworkController v1.0.0*