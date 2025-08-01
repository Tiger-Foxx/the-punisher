"""
NetworkController - THE PUNISHER
Point d'entrée principal de l'application
Advanced Network Controller with Modern Dark Interface
"""

import sys
import os
import threading
import time
from pathlib import Path

# Ajouter le dossier app au path pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core import (
    get_app_logger, get_config, SystemUtils, APP_NAME, APP_VERSION, APP_AUTHOR
)
from app.gui import show_splash_screen, create_main_window


def check_requirements():
    """Vérifie les prérequis de l'application"""
    logger = get_app_logger("Startup")
    
    # Vérifier Python version
    if sys.version_info < (3, 8):
        logger.critical("Python 3.8+ requis")
        return False
    
    # Vérifier les privilèges administrateur
    if not SystemUtils.is_admin():
        logger.warning("Privilèges administrateur recommandés")
        # Ne pas bloquer, juste avertir
    
    # Vérifier les dépendances critiques
    try:
        import scapy
        import customtkinter
        import psutil
        import netifaces
        logger.info("Toutes les dépendances sont disponibles")
        return True
    except ImportError as e:
        logger.critical(f"Dépendance manquante: {e}")
        return False


def show_startup_info():
    """Affiche les informations de démarrage"""
    logger = get_app_logger("Startup")
    
    print("=" * 60)
    print(f"🔥 {APP_NAME} v{APP_VERSION} 🔥")
    print("💀 Advanced Network Controller - Punisher Edition 💀")
    print(f"👤 Author: {APP_AUTHOR}")
    print("=" * 60)
    print()
    
    # Informations système
    system_info = SystemUtils.get_system_info()
    print(f"🖥️  System: {system_info['system']} {system_info['release']}")
    print(f"🐍 Python: {system_info['python_version']}")
    print(f"⚡ Admin: {'Yes' if SystemUtils.is_admin() else 'No'}")
    print()
    
    # Avertissement de sécurité
    print("⚠️  SECURITY WARNING ⚠️")
    print("This tool is for authorized network testing only!")
    print("Use responsibly and in compliance with local laws.")
    print("The author is not responsible for misuse.")
    print()
    
    logger.info(f"{APP_NAME} v{APP_VERSION} starting up...")
    logger.info(f"System: {system_info['system']} {system_info['release']}")
    logger.info(f"Python: {system_info['python_version']}")
    logger.info(f"Admin privileges: {'Yes' if SystemUtils.is_admin() else 'No'}")

def request_admin_if_needed():
    """Demande les privilèges admin si nécessaire (Windows)"""
    if os.name == 'nt' and not SystemUtils.is_admin():
        logger = get_app_logger("AdminRequest")
        
        print("⚠️  Privilèges administrateur requis pour un fonctionnement optimal")
        print("🔄 Tentative de relancement en mode administrateur...")
        
        try:
            import ctypes
            # Relancer le script avec des privilèges admin
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                f'"{" ".join(sys.argv)}"',
                None, 
                1
            )
            logger.info("Relancement en mode administrateur demandé")
            return False  # Arrêter l'instance actuelle
        except Exception as e:
            logger.warning(f"Impossible de relancer en admin: {e}")
            print("❌ Impossible de relancer automatiquement en mode administrateur")
            print("📝 Veuillez utiliser run_as_admin.bat ou lancer manuellement en admin")
            return True  # Continuer quand même
    
    return True  # Déjà admin ou pas Windows

def main():
    """Point d'entrée principal de l'application"""
    
    # Afficher les informations de démarrage
    show_startup_info()
    
    # Demander admin si nécessaire
    if not request_admin_if_needed():
        return  # Arrêter si relancement en admin
    
    # Vérifier les prérequis
    if not check_requirements():
        print("❌ Les prérequis ne sont pas satisfaits. Arrêt de l'application.")
        input("Appuyez sur Entrée pour quitter...")
        sys.exit(1)
    
    logger = get_app_logger("Main")
    config = get_config()
    
    # Avertissement si pas admin
    if not SystemUtils.is_admin():
        print("⚠️  ATTENTION: Application lancée sans privilèges administrateur")
        print("💡 Certaines fonctionnalités peuvent ne pas fonctionner correctement")
        print("🎯 Utilisez run_as_admin.bat pour un fonctionnement optimal")
        print()
        
        # Demander confirmation
        response = input("Continuer quand même ? (y/N): ").lower().strip()
        if response not in ['y', 'yes', 'o', 'oui']:
            print("💀 The Punisher needs more power... 💀")
            return
    
    try:
        # Variable pour la fenêtre principale
        main_window = None
        
        def on_splash_complete():
            """Callback de fin de splash screen"""
            nonlocal main_window
            try:
                # Créer et lancer la fenêtre principale
                main_window = create_main_window()
                main_window.run()
            except Exception as e:
                logger.critical(f"Erreur fatale dans la fenêtre principale: {e}")
                import traceback
                traceback.print_exc()
        
        # Afficher le splash screen si activé
        if config.ui.show_splash_screen:
            print("🚀 Launching application...")
            print("💀 Preparing the Punisher interface...")
            
            # Lancer le splash screen
            splash_thread = threading.Thread(
                target=show_splash_screen,
                args=(config.ui.splash_duration, on_splash_complete),
                daemon=False
            )
            splash_thread.start()
            splash_thread.join()
        else:
            # Lancer directement la fenêtre principale
            on_splash_complete()
    
    except KeyboardInterrupt:
        logger.info("Application interrompue par l'utilisateur")
        print("\n💀 The Punisher says goodbye... 💀")
    
    except Exception as e:
        logger.critical(f"Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        
        # Afficher l'erreur à l'utilisateur
        try:
            import tkinter.messagebox as mb
            mb.showerror(
                "Fatal Error",
                f"Une erreur fatale s'est produite:\n\n{e}\n\n"
                f"Consultez les logs pour plus de détails."
            )
        except:
            print(f"❌ Erreur fatale: {e}")
            input("Appuyez sur Entrée pour quitter...")
    
    finally:
        logger.info("Application fermée")
        print("\n💀 The Punisher has left the network... 💀")


if __name__ == "__main__":
    main()