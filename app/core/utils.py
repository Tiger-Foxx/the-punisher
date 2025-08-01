"""
Utilitaires communs pour l'application NetworkController
Fonctions helper, validation, conversion, logging, etc.
"""

import os
import sys
import time
import socket
import struct
import ctypes
import logging
import threading
import subprocess
from typing import List, Dict, Any, Optional, Union, Tuple
from pathlib import Path
from datetime import datetime
from functools import wraps
import ipaddress
import re


class NetworkUtils:
    """Utilitaires réseau"""
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Vérifie si une adresse IP est valide"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        """Vérifie si une adresse MAC est valide"""
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))
    
    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Normalise une adresse MAC au format xx:xx:xx:xx:xx:xx"""
        if not NetworkUtils.is_valid_mac(mac):
            raise ValueError(f"Adresse MAC invalide: {mac}")
        
        # Supprimer tous les séparateurs et convertir en minuscules
        clean_mac = re.sub(r'[:-]', '', mac.lower())
        
        # Reformater avec des ':'
        return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
    
    @staticmethod
    def ip_to_int(ip: str) -> int:
        """Convertit une IP en entier"""
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    @staticmethod
    def int_to_ip(ip_int: int) -> str:
        """Convertit un entier en IP"""
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    
    @staticmethod
    def get_network_range(ip: str, netmask: str) -> List[str]:
        """Retourne la liste des IPs dans une plage réseau"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
    
    @staticmethod
    def get_local_ip() -> Optional[str]:
        """Retourne l'IP locale de la machine"""
        try:
            # Méthode rapide: se connecter à Google DNS
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return None
    
    @staticmethod
    def ping(host: str, timeout: float = 1.0) -> bool:
        """Ping simple d'un host"""
        try:
            if os.name == 'nt':  # Windows
                cmd = f"ping -n 1 -w {int(timeout * 1000)} {host}"
            else:  # Linux/Mac
                cmd = f"ping -c 1 -W {int(timeout)} {host}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def bytes_to_human(bytes_value: int) -> str:
        """Convertit des octets en format humain (KB, MB, GB)"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    @staticmethod
    def speed_to_human(bytes_per_sec: float) -> str:
        """Convertit une vitesse en format humain (KB/s, MB/s, etc.)"""
        return f"{NetworkUtils.bytes_to_human(int(bytes_per_sec))}/s"


class SystemUtils:
    """Utilitaires système"""
    
    @staticmethod
    def is_admin() -> bool:
        """Vérifie si l'application a les privilèges administrateur"""
        if os.name == 'nt':  # Windows
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                return False
        else:  # Linux/Mac
            return os.geteuid() == 0
    
    @staticmethod
    def request_admin() -> bool:
        """Demande les privilèges administrateur (Windows uniquement)"""
        if os.name == 'nt' and not SystemUtils.is_admin():
            try:
                # Relancer le script avec des privilèges admin
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                return True
            except Exception:
                return False
        return SystemUtils.is_admin()
    
    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Retourne des informations système"""
        import platform
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }
    
    @staticmethod
    def create_shortcut(target: str, shortcut_path: str, description: str = "") -> bool:
        """Crée un raccourci Windows"""
        if os.name != 'nt':
            return False
        
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = target
            shortcut.Description = description
            shortcut.save()
            return True
        except Exception:
            return False


class FileUtils:
    """Utilitaires fichiers"""
    
    @staticmethod
    def ensure_dir(path: Union[str, Path]) -> bool:
        """S'assure qu'un dossier existe"""
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """Retourne la taille d'un fichier en octets"""
        try:
            return Path(file_path).stat().st_size
        except Exception:
            return 0
    
    @staticmethod
    def backup_file(file_path: Union[str, Path], backup_suffix: str = ".bak") -> bool:
        """Crée un backup d'un fichier"""
        try:
            source = Path(file_path)
            if source.exists():
                backup = source.with_suffix(source.suffix + backup_suffix)
                import shutil
                shutil.copy2(source, backup)
                return True
        except Exception:
            pass
        return False
    
    @staticmethod
    def rotate_logs(log_file: Union[str, Path], max_files: int = 5) -> bool:
        """Effectue une rotation des fichiers de log"""
        try:
            log_path = Path(log_file)
            if not log_path.exists():
                return True
            
            # Décaler les fichiers existants
            for i in range(max_files - 1, 0, -1):
                old_file = log_path.with_suffix(f"{log_path.suffix}.{i}")
                new_file = log_path.with_suffix(f"{log_path.suffix}.{i + 1}")
                if old_file.exists():
                    if new_file.exists():
                        new_file.unlink()
                    old_file.rename(new_file)
            
            # Renommer le fichier actuel
            rotated_file = log_path.with_suffix(f"{log_path.suffix}.1")
            if rotated_file.exists():
                rotated_file.unlink()
            log_path.rename(rotated_file)
            
            return True
        except Exception:
            return False


class ThreadSafeCounter:
    """Compteur thread-safe"""
    
    def __init__(self, initial_value: int = 0):
        self._value = initial_value
        self._lock = threading.Lock()
    
    def increment(self, amount: int = 1) -> int:
        """Incrémente le compteur"""
        with self._lock:
            self._value += amount
            return self._value
    
    def decrement(self, amount: int = 1) -> int:
        """Décrémente le compteur"""
        with self._lock:
            self._value -= amount
            return self._value
    
    def reset(self) -> int:
        """Remet le compteur à zéro"""
        with self._lock:
            old_value = self._value
            self._value = 0
            return old_value
    
    def get(self) -> int:
        """Retourne la valeur actuelle"""
        with self._lock:
            return self._value


class RateLimiter:
    """Limiteur de débit simple"""
    
    def __init__(self, max_calls: int, time_window: float):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
        self._lock = threading.Lock()
    
    def can_proceed(self) -> bool:
        """Vérifie si on peut procéder (respect du rate limit)"""
        with self._lock:
            now = time.time()
            
            # Supprimer les appels trop anciens
            self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]
            
            # Vérifier si on peut ajouter un nouvel appel
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return True
            
            return False
    
    def wait_time(self) -> float:
        """Retourne le temps d'attente avant le prochain appel possible"""
        with self._lock:
            if len(self.calls) < self.max_calls:
                return 0.0
            
            oldest_call = min(self.calls)
            return self.time_window - (time.time() - oldest_call)


def singleton(cls):
    """Décorateur pour créer des singletons"""
    instances = {}
    
    @wraps(cls)
    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    
    return get_instance


def retry(max_attempts: int = 3, delay: float = 1.0, exceptions: Tuple = (Exception,)):
    """Décorateur pour retry automatique"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        time.sleep(delay)
                    continue
            
            raise last_exception
        return wrapper
    return decorator


def timed_cache(seconds: float):
    """Décorateur pour cache avec expiration"""
    def decorator(func):
        cache = {}
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(sorted(kwargs.items()))
            now = time.time()
            
            if key in cache:
                result, timestamp = cache[key]
                if now - timestamp < seconds:
                    return result
            
            result = func(*args, **kwargs)
            cache[key] = (result, now)
            return result
        return wrapper
    return decorator


class Logger:
    """Logger personnalisé pour l'application"""
    
    def __init__(self, name: str, log_dir: str = "logs"):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / f"{name}.log"
        
        # Créer le dossier de logs
        FileUtils.ensure_dir(self.log_dir)
        
        # Configurer le logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Handler fichier
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Handler console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str, *args, **kwargs):
        self.logger.debug(message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        self.logger.info(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        self.logger.error(message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        self.logger.critical(message, *args, **kwargs)


def get_app_logger(name: str = "NetworkController") -> Logger:
    """Retourne le logger principal de l'application"""
    return Logger(name)


# Fonctions utilitaires globales
def format_timestamp(timestamp: Optional[float] = None) -> str:
    """Formate un timestamp en string lisible"""
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def safe_division(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Division sécurisée (évite la division par zéro)"""
    try:
        return numerator / denominator if denominator != 0 else default
    except (TypeError, ZeroDivisionError):
        return default


def clamp(value: float, min_value: float, max_value: float) -> float:
    """Limite une valeur entre min et max"""
    return max(min_value, min(value, max_value))


def percentage(part: float, total: float) -> float:
    """Calcule un pourcentage"""
    return safe_division(part * 100, total, 0.0)