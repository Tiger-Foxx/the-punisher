"""
Écran de démarrage (Splash Screen) de NetworkController
Interface moderne avec logo Punisher et animations
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import ttk
import threading
import time
from pathlib import Path
from PIL import Image, ImageTk
from typing import Optional, Callable

from ..core import get_app_logger, APP_NAME, APP_VERSION, APP_AUTHOR, PUNISHER_LOGO_WHITE_PATH, DARK_THEME


class SplashScreen:
    """Écran de démarrage sophistiqué avec animations"""
    
    def __init__(self, duration: float = 3.0, on_complete: Optional[Callable] = None):
        self.duration = duration
        self.on_complete = on_complete
        self.logger = get_app_logger("SplashScreen")
        
        # Configuration de l'apparence
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Créer la fenêtre
        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME} - Loading...")
        self.root.geometry("500x350")
        self.root.resizable(False, False)
        
        # Centrer la fenêtre
        self._center_window()
        
        # Supprimer la barre de titre et les bordures
        self.root.overrideredirect(True)
        
        # Variables d'animation
        self.progress_value = 0
        self.animation_running = True
        self.fade_alpha = 0.0
        
        # Interface
        self._create_interface()
        
        # Démarrer les animations
        self._start_animations()
    
    def _center_window(self):
        """Centre la fenêtre sur l'écran"""
        self.root.update_idletasks()
        width = 500
        height = 350
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def _create_interface(self):
        """Crée l'interface du splash screen"""
        # Frame principal avec bordure
        self.main_frame = ctk.CTkFrame(
            self.root,
            fg_color=DARK_THEME['bg_color'],
            border_width=2,
            border_color=DARK_THEME['accent_color'],
            corner_radius=10
        )
        self.main_frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Logo Punisher
        self._load_logo()
        
        # Titre principal
        self.title_label = ctk.CTkLabel(
            self.main_frame,
            text=APP_NAME,
            font=ctk.CTkFont(family="Arial Black", size=32, weight="bold"),
            text_color=DARK_THEME['accent_color']
        )
        self.title_label.pack(pady=(20, 5))
        
        # Sous-titre
        self.subtitle_label = ctk.CTkLabel(
            self.main_frame,
            text="Advanced Network Controller",
            font=ctk.CTkFont(family="Arial", size=14, weight="normal"),
            text_color=DARK_THEME['fg_color']
        )
        self.subtitle_label.pack(pady=(0, 10))
        
        # Message de chargement
        self.loading_label = ctk.CTkLabel(
            self.main_frame,
            text="Initializing network modules...",
            font=ctk.CTkFont(family="Arial", size=11),
            text_color=DARK_THEME['info_color']
        )
        self.loading_label.pack(pady=(10, 15))
        
        # Barre de progression stylée
        self.progress_frame = ctk.CTkFrame(
            self.main_frame,
            fg_color="transparent",
            height=30
        )
        self.progress_frame.pack(pady=10, padx=40, fill="x")
        
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            width=400,
            height=8,
            progress_color=DARK_THEME['accent_color'],
            fg_color=DARK_THEME['secondary_color']
        )
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)
        
        # Pourcentage
        self.percent_label = ctk.CTkLabel(
            self.main_frame,
            text="0%",
            font=ctk.CTkFont(family="Arial", size=10),
            text_color=DARK_THEME['fg_color']
        )
        self.percent_label.pack()
        
        # Version et auteur
        self.version_label = ctk.CTkLabel(
            self.main_frame,
            text=f"Version {APP_VERSION} • by {APP_AUTHOR}",
            font=ctk.CTkFont(family="Arial", size=9),
            text_color=DARK_THEME['secondary_color']
        )
        self.version_label.pack(side="bottom", pady=10)
        
        # Copyright/Warning
        self.warning_label = ctk.CTkLabel(
            self.main_frame,
            text="⚠️ For authorized network testing only",
            font=ctk.CTkFont(family="Arial", size=9),
            text_color=DARK_THEME['warning_color']
        )
        self.warning_label.pack(side="bottom", pady=(0, 5))
    
    def _load_logo(self):
        """Charge et affiche le logo Punisher"""
        try:
            logo_path = Path(PUNISHER_LOGO_WHITE_PATH)
            if logo_path.exists():
                # Charger l'image avec CTkImage (pour HighDPI)
                pil_image = Image.open(logo_path)
                
                # Créer un CTkImage au lieu de ImageTk.PhotoImage
                self.logo_image = ctk.CTkImage(
                    light_image=pil_image,
                    dark_image=pil_image,
                    size=(80, 80)
                )
                
                # Afficher le logo
                self.logo_label = ctk.CTkLabel(
                    self.main_frame,
                    image=self.logo_image,
                    text=""
                )
                self.logo_label.pack(pady=(15, 10))
            else:
                # Logo texte de fallback
                self.logo_label = ctk.CTkLabel(
                    self.main_frame,
                    text="💀",
                    font=ctk.CTkFont(size=60),
                    text_color=DARK_THEME['accent_color']
                )
                self.logo_label.pack(pady=(15, 10))
                
        except Exception as e:
            self.logger.warning(f"Impossible de charger le logo: {e}")
            # Logo emoji de fallback
            self.logo_label = ctk.CTkLabel(
                self.main_frame,
                text="💀",
                font=ctk.CTkFont(size=60),
                text_color=DARK_THEME['accent_color']
            )
            self.logo_label.pack(pady=(15, 10))
    
    def _start_animations(self):
        """Démarre les animations du splash screen"""
        # Animation de la barre de progression
        threading.Thread(target=self._progress_animation, daemon=True).start()
        
        # Animation de fade in
        threading.Thread(target=self._fade_animation, daemon=True).start()
        
        # Messages de chargement
        threading.Thread(target=self._loading_messages, daemon=True).start()
    
    def _progress_animation(self):
        """Animation de la barre de progression"""
        steps = 100
        step_duration = self.duration / steps
        
        for i in range(steps + 1):
            if not self.animation_running:
                break
            
            self.progress_value = i / 100
            
            # Mettre à jour l'interface dans le thread principal
            self.root.after(0, self._update_progress)
            
            time.sleep(step_duration)
        
        # Terminer le splash screen
        if self.animation_running:
            self.root.after(500, self._finish_splash)
    
    def _update_progress(self):
        """Met à jour la barre de progression"""
        if hasattr(self, 'progress_bar'):
            self.progress_bar.set(self.progress_value)
            self.percent_label.configure(text=f"{int(self.progress_value * 100)}%")
    
    def _fade_animation(self):
        """Animation de fade in"""
        fade_steps = 20
        fade_duration = 0.5
        step_time = fade_duration / fade_steps
        
        for i in range(fade_steps + 1):
            if not self.animation_running:
                break
            
            alpha = i / fade_steps
            self.fade_alpha = alpha
            
            # Appliquer l'effet de fade (simulé par la couleur)
            self.root.after(0, self._apply_fade)
            
            time.sleep(step_time)
    
    def _apply_fade(self):
        """Applique l'effet de fade"""
        # Simuler le fade en ajustant l'opacité des couleurs
        # (CustomTkinter ne supporte pas l'alpha natif)
        pass
    
    def _loading_messages(self):
        """Affiche des messages de chargement animés"""
        messages = [
            "Initializing network modules...",
            "Loading network interfaces...",
            "Starting ARP scanner...",
            "Preparing attack modules...",
            "Loading OUI database...",
            "Configuring bandwidth control...",
            "Initializing device scanner...",
            "Ready to dominate the network! 💀"
        ]
        
        message_duration = self.duration / len(messages)
        
        for i, message in enumerate(messages):
            if not self.animation_running:
                break
            
            self.root.after(0, lambda msg=message: self.loading_label.configure(text=msg))
            time.sleep(message_duration)
    
    def _finish_splash(self):
        """Termine le splash screen"""
        self.animation_running = False
        
        # Animation de fade out
        def fade_out():
            try:
                self.root.withdraw()  # Cacher la fenêtre
                
                # Appeler le callback de completion
                if self.on_complete:
                    self.on_complete()
                
                # Détruire la fenêtre
                self.root.destroy()
                
            except Exception as e:
                self.logger.error(f"Erreur lors de la fermeture du splash: {e}")
        
        self.root.after(100, fade_out)
    
    def show(self):
        """Affiche le splash screen"""
        try:
            # Garder la fenêtre au premier plan
            self.root.lift()
            self.root.attributes('-topmost', True)
            
            # Démarrer la boucle principale
            self.root.mainloop()
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'affichage du splash: {e}")
    
    def close(self):
        """Force la fermeture du splash screen"""
        self.animation_running = False
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass


def show_splash_screen(duration: float = 3.0, on_complete: Optional[Callable] = None):
    """Fonction utilitaire pour afficher le splash screen"""
    splash = SplashScreen(duration=duration, on_complete=on_complete)
    splash.show()
    return splash