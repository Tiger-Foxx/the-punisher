# Module Core - NetworkController

## Vue d'ensemble

Le module `core` est le cœur de l'application **THE PUNISHER** (NetworkController). Il contient tous les composants fondamentaux nécessaires au fonctionnement de l'application : configuration, utilitaires système, fonctions réseau, et gestion des paramètres.

Ce module est conçu pour être **modulaire**, **réutilisable** et **thread-safe**, fournissant une base solide pour toutes les autres parties de l'application.

## Structure du module

```
app/core/
├── __init__.py      # Exports et initialisation du module
├── config.py        # Gestion de la configuration
├── utils.py         # Utilitaires et fonctions helper
└── README.md        # Cette documentation
```

## Composants principaux

### 1. Configuration (`config.py`)

#### Classes de configuration

##### `AppConfig`
Configuration principale de l'application contenant toutes les sections :
- `network` : Paramètres réseau
- `ui` : Configuration interface utilisateur  
- `security` : Paramètres de sécurité
- `version` : Version de l'application
- `app_name` : Nom de l'application
- `author` : Auteur du projet

##### `NetworkConfig`
Paramètres spécifiques au réseau :
- `scan_timeout` : Timeout des scans réseau (3.0s)
- `scan_interval` : Intervalle entre les scans (5s)
- `arp_interval` : Intervalle des paquets ARP (1.0s)
- `bandwidth_update_interval` : Mise à jour bande passante (0.5s)
- `max_scan_threads` : Nombre max de threads de scan (50)
- `default_scan_mode` : Mode de scan par défaut
- `enable_hostname_resolution` : Résolution des noms d'hôte
- `enable_os_detection` : Détection du système d'exploitation
- `ping_timeout` : Timeout des pings (1.0s)

##### `UIConfig`
Configuration de l'interface utilisateur :
- `theme` : Thème (dark/light/auto)
- `window_width` : Largeur de fenêtre (1200px)
- `window_height` : Hauteur de fenêtre (800px)
- `window_resizable` : Fenêtre redimensionnable
- `show_splash_screen` : Affichage écran de démarrage
- `splash_duration` : Durée du splash (3.0s)
- `auto_refresh` : Actualisation automatique
- `refresh_interval` : Intervalle d'actualisation (2s)
- `show_notifications` : Affichage des notifications
- `animation_speed` : Vitesse des animations (1.0)

##### `SecurityConfig`
Paramètres de sécurité :
- `require_admin` : Privilèges administrateur requis
- `log_level` : Niveau de log ("INFO")
- `max_log_files` : Nombre max de fichiers de log (5)
- `log_file_size_mb` : Taille max des logs (10MB)
- `enable_backup_restore` : Sauvegarde/restauration activée
- `auto_restore_on_exit` : Restauration automatique à la sortie

#### Modes de scan (`ScanMode`)

- `AUTO` : Mode automatique (bloque tout sauf machine locale)
- `MANUAL` : Mode manuel (utilisateur choisit quoi bloquer)
- `MONITOR` : Mode surveillance seulement

#### Thèmes (`ThemeMode`)

- `DARK` : Thème sombre
- `LIGHT` : Thème clair
- `AUTO` : Thème automatique

#### Gestionnaire de configuration (`ConfigManager`)

**Fonctionnalités principales :**
- Chargement/sauvegarde automatique de la configuration
- Gestion des backups et restauration
- Support multi-plateforme (Windows/Linux/Mac)
- Validation et conversion des paramètres
- Mise à jour thread-safe de la configuration

**Méthodes principales :**
- `load_config()` : Charge la configuration depuis le fichier
- `save_config()` : Sauvegarde la configuration
- `restore_backup()` : Restaure depuis un backup
- `update_config()` : Met à jour des paramètres spécifiques
- `get_config()` : Retourne la configuration actuelle

### 2. Utilitaires (`utils.py`)

#### NetworkUtils - Utilitaires réseau

**Validation et conversion :**
- `is_valid_ip(ip)` : Vérifie la validité d'une adresse IP
- `is_valid_mac(mac)` : Vérifie la validité d'une adresse MAC
- `normalize_mac(mac)` : Normalise une MAC au format xx:xx:xx:xx:xx:xx
- `ip_to_int(ip)` : Convertit une IP en entier
- `int_to_ip(ip_int)` : Convertit un entier en IP

**Fonctions réseau :**
- `get_network_range(ip, netmask)` : Liste des IPs dans une plage
- `get_local_ip()` : IP locale de la machine
- `ping(host, timeout)` : Ping simple d'un host
- `bytes_to_human(bytes_value)` : Conversion octets → format humain
- `speed_to_human(bytes_per_sec)` : Conversion vitesse → format humain

#### SystemUtils - Utilitaires système

**Gestion des privilèges :**
- `is_admin()` : Vérifie les privilèges administrateur
- `request_admin()` : Demande les privilèges admin (Windows)

**Informations système :**
- `get_system_info()` : Informations détaillées du système
- `create_shortcut(target, shortcut_path, description)` : Création raccourci Windows

#### FileUtils - Utilitaires fichiers

**Gestion des fichiers :**
- `ensure_dir(path)` : Création de dossier avec vérification
- `get_file_size(file_path)` : Taille d'un fichier en octets
- `backup_file(file_path, backup_suffix)` : Création de backup
- `rotate_logs(log_file, max_files)` : Rotation des fichiers de log

#### ThreadSafeCounter - Compteur thread-safe

**Méthodes :**
- `increment(amount)` : Incrémente le compteur
- `decrement(amount)` : Décrémente le compteur
- `reset()` : Remet le compteur à zéro
- `get()` : Retourne la valeur actuelle

#### RateLimiter - Limiteur de débit

**Fonctionnalités :**
- `can_proceed()` : Vérifie si on peut procéder
- `wait_time()` : Temps d'attente avant prochain appel possible

#### Logger - Logger personnalisé

**Niveaux de log :**
- `debug(message)` : Messages de débogage
- `info(message)` : Informations générales
- `warning(message)` : Avertissements
- `error(message)` : Erreurs
- `critical(message)` : Erreurs critiques

**Configuration automatique :**
- Handler fichier (niveau DEBUG)
- Handler console (niveau INFO)
- Rotation automatique des logs
- Formatage personnalisé des messages

#### Décorateurs utilitaires

**`@singleton`**
Crée des classes singleton pour éviter les instances multiples.

**`@retry(max_attempts, delay, exceptions)`**
Retry automatique en cas d'échec avec délai configurable.

**`@timed_cache(seconds)`**
Cache avec expiration automatique pour optimiser les performances.

#### Fonctions utilitaires globales

**Formatage et conversion :**
- `format_timestamp(timestamp)` : Formatage de timestamp
- `safe_division(numerator, denominator, default)` : Division sécurisée
- `clamp(value, min_value, max_value)` : Limitation de valeur
- `percentage(part, total)` : Calcul de pourcentage

## Constantes importantes

### Application
- `APP_NAME` : "NetworkController"
- `APP_VERSION` : "1.0.0"
- `APP_AUTHOR` : "The Fox"
- `APP_DESCRIPTION` : "Contrôleur de réseau avancé avec interface moderne"

### Réseau
- `DEFAULT_SCAN_TIMEOUT` : 3.0s
- `DEFAULT_ARP_INTERVAL` : 1.0s
- `DEFAULT_BANDWIDTH_UPDATE` : 0.5s

### Interface
- `PUNISHER_LOGO_PATH` : "app/assets/punisher_logo.png"
- `PUNISHER_LOGO_WHITE_PATH` : "app/assets/punisher_logo_white.png"
- `PUNISHER_ICON_PATH` : "app/assets/icons/punisher_icon.ico"

### Thèmes
- `DARK_THEME` : Palette de couleurs sombre
- `LIGHT_THEME` : Palette de couleurs claire

## Utilisation typique

### Chargement de la configuration
```python
from app.core import get_config, config_manager

# Récupérer la configuration
config = get_config()

# Accéder aux paramètres
scan_timeout = config.network.scan_timeout
theme = config.ui.theme
require_admin = config.security.require_admin
```

### Utilisation des utilitaires réseau
```python
from app.core import NetworkUtils

# Validation d'adresses
if NetworkUtils.is_valid_ip("192.168.1.1"):
    print("IP valide")

# Conversion
human_size = NetworkUtils.bytes_to_human(1024)  # "1.0 KB"
human_speed = NetworkUtils.speed_to_human(1024)  # "1.0 KB/s"
```

### Utilisation des utilitaires système
```python
from app.core import SystemUtils

# Vérification des privilèges
if SystemUtils.is_admin():
    print("Privilèges administrateur")

# Informations système
info = SystemUtils.get_system_info()
print(f"Système: {info['system']}")
```

### Utilisation du logger
```python
from app.core import get_app_logger

logger = get_app_logger("MonModule")
logger.info("Application démarrée")
logger.warning("Attention: paramètre manquant")
logger.error("Erreur critique détectée")
```

### Utilisation des compteurs thread-safe
```python
from app.core import ThreadSafeCounter

counter = ThreadSafeCounter()
counter.increment(5)
current_value = counter.get()  # 5
counter.reset()  # Remet à 0
```

### Utilisation du rate limiter
```python
from app.core import RateLimiter

limiter = RateLimiter(max_calls=10, time_window=60.0)
if limiter.can_proceed():
    # Effectuer l'opération
    pass
else:
    wait_time = limiter.wait_time()
    time.sleep(wait_time)
```

## Gestion des erreurs

Le module core inclut une gestion d'erreurs robuste :

1. **Validation des entrées** : Toutes les fonctions valident leurs paramètres
2. **Gestion des exceptions** : Try-catch appropriés dans les fonctions critiques
3. **Logging automatique** : Toutes les erreurs sont loggées
4. **Valeurs par défaut** : Fallback sur des valeurs sûres en cas d'erreur
5. **Thread-safety** : Protection contre les conditions de course

## Performance et optimisation

### Optimisations incluses :
- **Cache avec expiration** : `@timed_cache` pour éviter les calculs répétés
- **Rate limiting** : Protection contre la surcharge
- **Thread-safe counters** : Compteurs optimisés pour la concurrence
- **Validation efficace** : Regex optimisées pour les adresses MAC/IP
- **Gestion mémoire** : Rotation automatique des logs

### Bonnes pratiques :
- Utiliser les décorateurs `@retry` pour les opérations réseau
- Utiliser `@timed_cache` pour les calculs coûteux
- Utiliser `ThreadSafeCounter` pour les compteurs partagés
- Utiliser `RateLimiter` pour limiter les appels API

## Sécurité

### Mesures de sécurité intégrées :
- **Validation stricte** : Toutes les entrées sont validées
- **Privilèges administrateur** : Vérification automatique
- **Logging sécurisé** : Pas d'informations sensibles dans les logs
- **Backup automatique** : Sauvegarde avant modification de config
- **Gestion d'erreurs** : Pas d'exposition d'informations sensibles

## Compatibilité

### Plateformes supportées :
- **Windows** : Support complet avec privilèges administrateur
- **Linux** : Support complet (testé sur Ubuntu/Debian)
- **macOS** : Support complet (testé sur macOS 10.15+)

### Versions Python :
- **Python 3.8+** : Support complet
- **Python 3.9+** : Fonctionnalités avancées
- **Python 3.10+** : Optimisations de performance

## Dépendances

### Dépendances principales :
- `pathlib` : Gestion des chemins (Python 3.4+)
- `dataclasses` : Classes de données (Python 3.7+)
- `typing` : Annotations de type
- `threading` : Threading et synchronisation
- `socket` : Opérations réseau
- `subprocess` : Exécution de commandes système
- `logging` : Système de logging
- `json` : Sérialisation JSON
- `re` : Expressions régulières
- `time` : Gestion du temps
- `datetime` : Manipulation de dates

### Dépendances optionnelles :
- `win32com.client` : Raccourcis Windows (Windows uniquement)
- `ctypes` : Interface avec les DLLs système

## Tests et validation

### Tests recommandés :
1. **Validation des adresses** : IP et MAC
2. **Gestion des erreurs** : Cas d'erreur et exceptions
3. **Thread-safety** : Tests de concurrence
4. **Performance** : Tests de charge et de stress
5. **Compatibilité** : Tests multi-plateforme

### Exemples de tests :
```python
# Test de validation IP
assert NetworkUtils.is_valid_ip("192.168.1.1") == True
assert NetworkUtils.is_valid_ip("256.256.256.256") == False

# Test de conversion
assert NetworkUtils.bytes_to_human(1024) == "1.0 KB"
assert NetworkUtils.normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

# Test thread-safety
counter = ThreadSafeCounter()
# Tests en parallèle...
```

## Maintenance et évolution

### Points d'extension :
1. **Nouveaux utilitaires** : Ajouter dans `utils.py`
2. **Nouveaux paramètres** : Étendre les classes de config
3. **Nouveaux thèmes** : Ajouter dans `ThemeMode`
4. **Nouveaux modes** : Étendre `ScanMode`

### Bonnes pratiques de développement :
1. **Documentation** : Toujours documenter les nouvelles fonctions
2. **Tests** : Ajouter des tests pour les nouvelles fonctionnalités
3. **Validation** : Valider toutes les entrées
4. **Logging** : Logger les opérations importantes
5. **Thread-safety** : Protéger les ressources partagées

## Conclusion

Le module `core` fournit une base solide et complète pour l'application **THE PUNISHER**. Il encapsule toutes les fonctionnalités fondamentales nécessaires au contrôle réseau, à la gestion de la configuration et aux utilitaires système.

Cette architecture modulaire permet une maintenance facile, une évolution simple et une réutilisation maximale du code. Tous les composants sont conçus pour être robustes, performants et thread-safe.

---

*Documentation générée pour le projet THE PUNISHER - NetworkController v1.0.0* 