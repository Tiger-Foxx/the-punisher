"""
NetworkController - THE PUNISHER
Advanced Network Controller with Modern Dark Interface

Main application package containing all modules:
- core: Configuration, utilities, and common functions
- network: Network scanning, ARP handling, bandwidth control
- gui: Modern dark interface with Punisher theme

Author: theTigerFox
Version: 1.0.0
"""

from .core import (
    APP_NAME, APP_VERSION, APP_AUTHOR, APP_DESCRIPTION,
    get_config, save_config, get_app_logger
)

__version__ = "1.0.0"
__author__ = "The Fox"
__description__ = "Advanced Network Controller - Punisher Edition"

__all__ = [
    'APP_NAME',
    'APP_VERSION', 
    'APP_AUTHOR',
    'APP_DESCRIPTION',
    'get_config',
    'save_config',
    'get_app_logger'
]