"""
Configuration globale de l'application NetworkController
Gestion des paramètres, préférences utilisateur et constantes
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class ScanMode(Enum):
    """Modes de scan disponibles"""
    AUTO = "auto"           # Mode automatique (bloque tout sauf machine locale)
    MANUAL = "manual"       # Mode manuel (utilisateur choisit quoi bloquer)
    MONITOR = "monitor"     # Mode surveillance seulement


class ThemeMode(Enum):
    """Thèmes disponibles"""
    DARK = "dark"
    LIGHT = "light"
    AUTO = "auto"


@dataclass
class NetworkConfig:
    """Configuration réseau"""
    scan_timeout: float = 3.0
    scan_interval: int = 5
    arp_interval: float = 1.0
    bandwidth_update_interval: float = 0.5
    max_scan_threads: int = 50
    default_scan_mode: ScanMode = ScanMode.AUTO
    enable_hostname_resolution: bool = True
    enable_os_detection: bool = True
    ping_timeout: float = 1.0


@dataclass
class UIConfig:
    """Configuration interface utilisateur"""
    theme: ThemeMode = ThemeMode.DARK
    window_width: int = 1200
    window_height: int = 800
    window_resizable: bool = True
    show_splash_screen: bool = True
    splash_duration: float = 3.0
    auto_refresh: bool = True
    refresh_interval: int = 2
    show_notifications: bool = True
    animation_speed: float = 1.0


@dataclass
class SecurityConfig:
    """Configuration sécurité"""
    require_admin: bool = True
    log_level: str = "INFO"
    max_log_files: int = 5
    log_file_size_mb: int = 10
    enable_backup_restore: bool = True
    auto_restore_on_exit: bool = True


@dataclass
class AppConfig:
    """Configuration principale de l'application"""
    network: NetworkConfig
    ui: UIConfig
    security: SecurityConfig
    version: str = "1.0.0"
    app_name: str = "NetworkController"
    author: str = "The Fox"
    
    @classmethod
    def default(cls) -> 'AppConfig':
        """Retourne la configuration par défaut"""
        return cls(
            network=NetworkConfig(),
            ui=UIConfig(),
            security=SecurityConfig()
        )


class ConfigManager:
    """Gestionnaire de configuration"""
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir) if config_dir else self._get_default_config_dir()
        self.config_file = self.config_dir / "config.json"
        self.backup_file = self.config_dir / "config_backup.json"
        self._config: Optional[AppConfig] = None
        
        # Créer le dossier de config si nécessaire
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Logger
        self.logger = logging.getLogger(__name__)
    
    def _get_default_config_dir(self) -> Path:
        """Détermine le dossier de configuration par défaut"""
        if os.name == 'nt':  # Windows
            app_data = os.getenv('APPDATA', os.path.expanduser('~'))
            return Path(app_data) / "NetworkController"
        else:  # Linux/Mac
            return Path.home() / ".config" / "networkcontroller"
    
    def load_config(self) -> AppConfig:
        """Charge la configuration depuis le fichier"""
        if self._config is not None:
            return self._config
        
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._config = self._dict_to_config(data)
                self.logger.info("Configuration chargée depuis le fichier")
            else:
                self._config = AppConfig.default()
                self.save_config()
                self.logger.info("Configuration par défaut créée")
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement de la configuration: {e}")
            self._config = AppConfig.default()
        
        return self._config
    
    def save_config(self) -> bool:
        """Sauvegarde la configuration dans le fichier"""
        if self._config is None:
            return False
        
        try:
            # Backup de l'ancienne config
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    backup_data = f.read()
                with open(self.backup_file, 'w', encoding='utf-8') as f:
                    f.write(backup_data)
            
            # Sauvegarde de la nouvelle config
            data = self._config_to_dict(self._config)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            
            self.logger.info("Configuration sauvegardée")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde: {e}")
            return False
    
    def restore_backup(self) -> bool:
        """Restaure la configuration depuis le backup"""
        try:
            if self.backup_file.exists():
                with open(self.backup_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._config = self._dict_to_config(data)
                self.save_config()
                self.logger.info("Configuration restaurée depuis le backup")
                return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la restauration: {e}")
        return False
    
    def _config_to_dict(self, config: AppConfig) -> Dict[str, Any]:
        """Convertit la config en dictionnaire"""
        result = {}
        
        # Convertir les dataclasses
        result['network'] = asdict(config.network)
        result['ui'] = asdict(config.ui)
        result['security'] = asdict(config.security)
        result['version'] = config.version
        result['app_name'] = config.app_name
        result['author'] = config.author
        
        # Convertir les enums en string
        result['network']['default_scan_mode'] = config.network.default_scan_mode.value
        result['ui']['theme'] = config.ui.theme.value
        
        return result
    
    def _dict_to_config(self, data: Dict[str, Any]) -> AppConfig:
        """Convertit un dictionnaire en config"""
        # Récupérer les sections
        network_data = data.get('network', {})
        ui_data = data.get('ui', {})
        security_data = data.get('security', {})
        
        # Convertir les enums
        if 'default_scan_mode' in network_data:
            network_data['default_scan_mode'] = ScanMode(network_data['default_scan_mode'])
        if 'theme' in ui_data:
            ui_data['theme'] = ThemeMode(ui_data['theme'])
        
        # Créer les objets de config
        network_config = NetworkConfig(**{k: v for k, v in network_data.items() if hasattr(NetworkConfig, k)})
        ui_config = UIConfig(**{k: v for k, v in ui_data.items() if hasattr(UIConfig, k)})
        security_config = SecurityConfig(**{k: v for k, v in security_data.items() if hasattr(SecurityConfig, k)})
        
        return AppConfig(
            network=network_config,
            ui=ui_config,
            security=security_config,
            version=data.get('version', '1.0.0'),
            app_name=data.get('app_name', 'NetworkController'),
            author=data.get('author', 'theTigerFox')
        )
    
    def get_config(self) -> AppConfig:
        """Retourne la configuration actuelle"""
        if self._config is None:
            return self.load_config()
        return self._config
    
    def update_config(self, **kwargs) -> bool:
        """Met à jour la configuration"""
        if self._config is None:
            self.load_config()
        
        try:
            for section, updates in kwargs.items():
                if hasattr(self._config, section):
                    section_obj = getattr(self._config, section)
                    for key, value in updates.items():
                        if hasattr(section_obj, key):
                            setattr(section_obj, key, value)
            
            return self.save_config()
        except Exception as e:
            self.logger.error(f"Erreur lors de la mise à jour: {e}")
            return False


# Instance globale du gestionnaire de configuration
config_manager = ConfigManager()


def get_config() -> AppConfig:
    """Fonction utilitaire pour récupérer la configuration"""
    return config_manager.get_config()


def save_config() -> bool:
    """Fonction utilitaire pour sauvegarder la configuration"""
    return config_manager.save_config()


# Constantes de l'application
APP_NAME = "NetworkController"
APP_VERSION = "1.0.0"
APP_AUTHOR = "The Fox"
APP_DESCRIPTION = "Contrôleur de réseau avancé avec interface moderne"

# Constantes réseau
DEFAULT_SCAN_TIMEOUT = 3.0
DEFAULT_ARP_INTERVAL = 1.0
DEFAULT_BANDWIDTH_UPDATE = 0.5

# Constantes UI
PUNISHER_LOGO_PATH = "app/assets/punisher_logo.png"
PUNISHER_LOGO_WHITE_PATH = "app/assets/punisher_logo_white.png"
PUNISHER_ICON_PATH = "app/assets/icons/punisher_icon.ico"

# Couleurs du thème dark
DARK_THEME = {
    'bg_color': '#1a1a1a',
    'fg_color': '#ffffff',
    'accent_color': '#ff4444',
    'secondary_color': '#333333',
    'success_color': '#00ff00',
    'warning_color': '#ffaa00',
    'error_color': '#ff0000',
    'info_color': '#00aaff'
}

# Couleurs du thème light
LIGHT_THEME = {
    'bg_color': '#ffffff',
    'fg_color': '#000000',
    'accent_color': '#cc0000',
    'secondary_color': '#f0f0f0',
    'success_color': '#008800',
    'warning_color': '#cc8800',
    'error_color': '#cc0000',
    'info_color': '#0088cc'
}
