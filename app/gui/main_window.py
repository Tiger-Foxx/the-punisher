"""
Fenêtre principale de NetworkController
Interface moderne avec tous les contrôles et fonctionnalités
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import time
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

from ..core import (
    get_app_logger, get_config, save_config, APP_NAME, APP_VERSION, 
    DARK_THEME, PUNISHER_ICON_PATH, SystemUtils
)
from ..network import (
    get_suitable_interfaces, get_default_interface, NetworkAdapter,
    create_network_scanner, create_arp_handler, create_bandwidth_controller,
    create_device_info_scanner, NetworkDevice
)
from .components import (
    DeviceListFrame, StatisticsPanel, LogViewer, 
    BandwidthControlPanel, AttackControlPanel
)


class NetworkControllerMainWindow:
    """Fenêtre principale de l'application"""
    
    def __init__(self):
        self.logger = get_app_logger("MainWindow")
        self.config = get_config()
        
        # Configuration de l'apparence
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        # Fenêtre principale
        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME} v{APP_VERSION} - Network Domination Tool 💀")
        self.root.geometry(f"{self.config.ui.window_width}x{self.config.ui.window_height}")
        self.root.minsize(1000, 700)
        
        # Configuration de la fenêtre
        self._setup_window()
        
        # Variables d'état
        self.current_interface: Optional[NetworkAdapter] = None
        self.network_scanner = None
        self.arp_handler = None
        self.bandwidth_controller = None
        self.device_scanner = None
        
        # États d'application
        self.scanning = False
        self.attacking = False
        self.monitoring_bandwidth = False
        
        # Données
        self.discovered_devices: Dict[str, NetworkDevice] = {}
        self.attack_sessions = {}
        
        # Interface utilisateur
        self._create_interface()
        
        # Timers et threads
        self.stats_update_timer = None
        self.auto_scan_timer = None
        
        # Initialisation
        self._initialize_network()
        self._start_timers()
        
        # Logs de démarrage
        self._log_startup_info()
    
    def _setup_window(self):
        """Configure la fenêtre principale"""
        # Icône de la fenêtre
        try:
            icon_path = Path(PUNISHER_ICON_PATH)
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except Exception:
            pass
        
        # Protocole de fermeture
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        # Centrer la fenêtre
        self._center_window()
        
        # Garder la fenêtre au premier plan au démarrage
        self.root.lift()
        self.root.attributes('-topmost', True)
        self.root.after(2000, lambda: self.root.attributes('-topmost', False))
    
    def _center_window(self):
        """Centre la fenêtre sur l'écran"""
        self.root.update_idletasks()
        width = self.config.ui.window_width
        height = self.config.ui.window_height
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def _create_interface(self):
        """Crée l'interface utilisateur principale"""
        # Barre de menu supérieure
        self._create_top_menu()
        
        # Conteneur principal avec sidebar
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Sidebar gauche
        self._create_sidebar(main_container)
        
        # Zone principale droite
        self._create_main_area(main_container)
        
        # Barre de statut
        self._create_status_bar()
    
    def _create_top_menu(self):
        """Crée la barre de menu supérieure"""
        menu_frame = ctk.CTkFrame(
            self.root,
            height=50,
            fg_color=DARK_THEME['accent_color'],
            corner_radius=0
        )
        menu_frame.pack(fill="x", padx=0, pady=0)
        menu_frame.pack_propagate(False)
        
        # Logo et titre
        title_frame = ctk.CTkFrame(menu_frame, fg_color="transparent")
        title_frame.pack(side="left", fill="y", padx=10)
        
        # Titre principal
        title_label = ctk.CTkLabel(
            title_frame,
            text=f"💀 {APP_NAME}",
            font=ctk.CTkFont(family="Arial Black", size=18, weight="bold"),
            text_color="white"
        )
        title_label.pack(side="left", pady=15)
        
        # Sous-titre
        subtitle_label = ctk.CTkLabel(
            title_frame,
            text="Network Domination Tool",
            font=ctk.CTkFont(size=10),
            text_color="white"
        )
        subtitle_label.pack(side="left", padx=(10, 0), pady=15)
        
        # Boutons de menu
        menu_buttons_frame = ctk.CTkFrame(menu_frame, fg_color="transparent")
        menu_buttons_frame.pack(side="right", fill="y", padx=10)
        
        # Bouton About
        about_button = ctk.CTkButton(
            menu_buttons_frame,
            text="ℹ️ About",
            width=80,
            height=30,
            fg_color="transparent",
            text_color="white",
            hover_color="#ff6666",
            command=self._show_about
        )
        about_button.pack(side="right", padx=5, pady=10)
        
        # Bouton Settings
        settings_button = ctk.CTkButton(
            menu_buttons_frame,
            text="⚙️ Settings",
            width=80,
            height=30,
            fg_color="transparent",
            text_color="white", 
            hover_color="#ff6666",
            command=self._show_settings
        )
        settings_button.pack(side="right", padx=5, pady=10)
    
    def _create_sidebar(self, parent):
        """Crée la sidebar gauche avec les contrôles"""
        self.sidebar = ctk.CTkFrame(
            parent,
            width=350,
            fg_color=DARK_THEME['secondary_color'],
            corner_radius=10
        )
        self.sidebar.pack(side="left", fill="y", padx=(0, 10), pady=5)
        self.sidebar.pack_propagate(False)
        
        # Section Interface Network
        self._create_interface_section()
        
        # Section Statistics
        self.stats_panel = StatisticsPanel(self.sidebar)
        self.stats_panel.pack(fill="x", padx=10, pady=10)
        
        # Section Bandwidth Control
        self.bandwidth_panel = BandwidthControlPanel(self.sidebar)
        self.bandwidth_panel.pack(fill="x", padx=10, pady=10)
        self.bandwidth_panel.on_limit_set = self._on_bandwidth_limit_set
        self.bandwidth_panel.on_limit_removed = self._on_bandwidth_limit_removed
        
        # Section Attack Control
        self.attack_panel = AttackControlPanel(self.sidebar)
        self.attack_panel.pack(fill="x", padx=10, pady=10)
        self.attack_panel.on_attack_started = self._on_attack_started
        self.attack_panel.on_attack_stopped = self._on_attack_stopped
    
    def _create_interface_section(self):
        """Crée la section de sélection d'interface"""
        interface_frame = ctk.CTkFrame(
            self.sidebar,
            fg_color=DARK_THEME['bg_color'],
            corner_radius=10
        )
        interface_frame.pack(fill="x", padx=10, pady=10)
        
        # Titre
        title_label = ctk.CTkLabel(
            interface_frame,
            text="🌐 Network Interface",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=DARK_THEME['accent_color']
        )
        title_label.pack(pady=10)
        
        # Sélection d'interface
        self.interface_var = tk.StringVar()
        self.interface_combo = ctk.CTkComboBox(
            interface_frame,
            variable=self.interface_var,
            command=self._on_interface_changed,
            width=300
        )
        self.interface_combo.pack(padx=10, pady=5)
        
        # Informations de l'interface actuelle
        self.interface_info_label = ctk.CTkLabel(
            interface_frame,
            text="No interface selected",
            font=ctk.CTkFont(size=10),
            text_color=DARK_THEME['info_color'],
            wraplength=300
        )
        self.interface_info_label.pack(padx=10, pady=5)
        
        # Bouton Refresh
        refresh_button = ctk.CTkButton(
            interface_frame,
            text="🔄 Refresh Interfaces",
            command=self._refresh_interfaces,
            width=200,
            height=30
        )
        refresh_button.pack(pady=10)
        
        # Charger les interfaces
        self._refresh_interfaces()
    
    def _create_main_area(self, parent):
        """Crée la zone principale avec onglets"""
        self.main_area = ctk.CTkFrame(
            parent,
            fg_color=DARK_THEME['bg_color'],
            corner_radius=10
        )
        self.main_area.pack(side="right", fill="both", expand=True, pady=5)
        
        # Notebook pour les onglets
        self.notebook = ctk.CTkTabview(self.main_area)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Onglet Devices
        self._create_devices_tab()
        
        # Onglet Monitoring
        self._create_monitoring_tab()
        
        # Onglet Logs
        self._create_logs_tab()
    
    def _create_devices_tab(self):
        """Crée l'onglet des appareils"""
        devices_tab = self.notebook.add("🔍 Devices")
        
        # Barre de contrôle du scan
        scan_control_frame = ctk.CTkFrame(devices_tab, fg_color="transparent")
        scan_control_frame.pack(fill="x", padx=5, pady=5)
        
        # Bouton Scan
        self.scan_button = ctk.CTkButton(
            scan_control_frame,
            text="🔍 Start Network Scan",
            command=self._toggle_scanning,
            fg_color=DARK_THEME['success_color'],
            height=35,
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.scan_button.pack(side="left", padx=5)
        
        # Bouton Deep Scan
        deep_scan_button = ctk.CTkButton(
            scan_control_frame,
            text="🔬 Deep Scan Selected",
            command=self._deep_scan_selected,
            fg_color=DARK_THEME['info_color'],
            height=35
        )
        deep_scan_button.pack(side="left", padx=5)
        
        # Bouton Export
        export_button = ctk.CTkButton(
            scan_control_frame,
            text="💾 Export",
            command=self._export_devices,
            fg_color=DARK_THEME['warning_color'],
            height=35,
            width=80
        )
        export_button.pack(side="right", padx=5)
        
        # Actions en lot
        batch_frame = ctk.CTkFrame(scan_control_frame, fg_color="transparent")
        batch_frame.pack(side="right", padx=10)
        
        batch_block_button = ctk.CTkButton(
            batch_frame,
            text="🚫 Block Selected",
            command=self._block_selected_devices,
            fg_color=DARK_THEME['error_color'],
            height=35,
            width=120
        )
        batch_block_button.pack(side="right", padx=2)
        
        # Liste des appareils
        self.device_list = DeviceListFrame(
            devices_tab,
            fg_color=DARK_THEME['secondary_color']
        )
        self.device_list.pack(fill="both", expand=True, padx=5, pady=5)
        self.device_list.on_device_selected = self._on_device_selected
        self.device_list.on_device_action = self._on_device_action
    
    def _create_monitoring_tab(self):
        """Crée l'onglet de monitoring"""
        monitoring_tab = self.notebook.add("📊 Monitoring")
        
        # Contrôles de monitoring
        monitor_control_frame = ctk.CTkFrame(monitoring_tab, fg_color="transparent")
        monitor_control_frame.pack(fill="x", padx=5, pady=5)
        
        # Bouton Start/Stop Monitoring
        self.monitor_button = ctk.CTkButton(
            monitor_control_frame,
            text="📡 Start Bandwidth Monitoring",
            command=self._toggle_bandwidth_monitoring,
            fg_color=DARK_THEME['info_color'],
            height=35,
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.monitor_button.pack(side="left", padx=5)
        
        # Auto-refresh
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_check = ctk.CTkCheckBox(
            monitor_control_frame,
            text="Auto-refresh",
            variable=self.auto_refresh_var
        )
        auto_refresh_check.pack(side="right", padx=5)
        
        # Zone de monitoring (sera remplie avec des graphiques plus tard)
        monitoring_content = ctk.CTkScrollableFrame(
            monitoring_tab,
            fg_color=DARK_THEME['secondary_color']
        )
        monitoring_content.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Placeholder pour le monitoring
        monitor_placeholder = ctk.CTkLabel(
            monitoring_content,
            text="📊 Real-time bandwidth monitoring will appear here\n\n" +
                 "Start monitoring to see:\n" +
                 "• Live traffic graphs\n" +
                 "• Per-device bandwidth usage\n" +
                 "• Network utilization charts\n" +
                 "• Attack success rates",
            font=ctk.CTkFont(size=14),
            text_color=DARK_THEME['info_color'],
            justify="center"
        )
        monitor_placeholder.pack(expand=True, pady=50)
    
    def _create_logs_tab(self):
        """Crée l'onglet des logs"""
        logs_tab = self.notebook.add("📋 Logs")
        
        # Visualiseur de logs
        self.log_viewer = LogViewer(
            logs_tab,
            fg_color=DARK_THEME['secondary_color']
        )
        self.log_viewer.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Ajouter quelques logs de démonstration
        self.log_viewer.add_log("INFO", "Application started successfully")
        self.log_viewer.add_log("INFO", "Network modules initialized")
    
    def _create_status_bar(self):
        """Crée la barre de statut"""
        self.status_bar = ctk.CTkFrame(
            self.root,
            height=30,
            fg_color=DARK_THEME['secondary_color'],
            corner_radius=0
        )
        self.status_bar.pack(fill="x", side="bottom")
        self.status_bar.pack_propagate(False)
        
        # Status principal
        self.status_var = tk.StringVar(value="Ready - Select a network interface to begin")
        status_label = ctk.CTkLabel(
            self.status_bar,
            textvariable=self.status_var,
            font=ctk.CTkFont(size=10),
            text_color=DARK_THEME['fg_color']
        )
        status_label.pack(side="left", padx=10, pady=5)
        
        # Indicateurs d'état
        self.indicators_frame = ctk.CTkFrame(self.status_bar, fg_color="transparent")
        self.indicators_frame.pack(side="right", padx=10, pady=2)
        
        # Indicateur de scan
        self.scan_indicator = ctk.CTkLabel(
            self.indicators_frame,
            text="⚫ Scan",
            font=ctk.CTkFont(size=9),
            text_color=DARK_THEME['fg_color']
        )
        self.scan_indicator.pack(side="right", padx=5)
        
        # Indicateur d'attaque
        self.attack_indicator = ctk.CTkLabel(
            self.indicators_frame,
            text="⚫ Attack",
            font=ctk.CTkFont(size=9),
            text_color=DARK_THEME['fg_color']
        )
        self.attack_indicator.pack(side="right", padx=5)
        
        # Indicateur de monitoring
        self.monitor_indicator = ctk.CTkLabel(
            self.indicators_frame,
            text="⚫ Monitor",
            font=ctk.CTkFont(size=9),
            text_color=DARK_THEME['fg_color']
        )
        self.monitor_indicator.pack(side="right", padx=5)
    
    def _initialize_network(self):
        """Initialise les modules réseau"""
        try:
            # Vérifier les privilèges administrateur
            if not SystemUtils.is_admin():
                messagebox.showwarning(
                    "Admin Rights Required",
                    "This application requires administrator privileges to function properly.\n\n" +
                    "Please restart as administrator."
                )
                self.logger.warning("Application démarrée sans privilèges administrateur")
            
            # Sélectionner l'interface par défaut
            default_interface = get_default_interface()
            if default_interface:
                self._setup_network_modules(default_interface)
                self.interface_var.set(f"{default_interface.name} ({default_interface.ip})")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation réseau: {e}")
            messagebox.showerror("Network Error", f"Failed to initialize network modules:\n{e}")
    
    def _setup_network_modules(self, interface: NetworkAdapter):
        """Configure les modules réseau pour une interface"""
        try:
            self.current_interface = interface
            
            # Créer les modules réseau
            self.network_scanner = create_network_scanner(interface)
            self.arp_handler = create_arp_handler(interface)
            self.bandwidth_controller = create_bandwidth_controller(interface, self.arp_handler)
            self.device_scanner = create_device_info_scanner(interface)
            
            # Configurer les callbacks
            self._setup_callbacks()
            
            # Mettre à jour l'interface
            self._update_interface_info()
            self._update_status(f"Interface configured: {interface.name}")
            
            self.logger.info(f"Modules réseau configurés pour {interface.name}")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la configuration des modules: {e}")
            messagebox.showerror("Configuration Error", f"Failed to setup network modules:\n{e}")
    
    def _setup_callbacks(self):
        """Configure les callbacks des modules réseau"""
        if self.network_scanner:
            self.network_scanner.on_device_discovered = self._on_device_discovered
            self.network_scanner.on_device_updated = self._on_device_updated
            self.network_scanner.on_device_lost = self._on_device_lost
            self.network_scanner.on_scan_complete = self._on_scan_complete
            self.network_scanner.on_scan_progress = self._on_scan_progress
        
        if self.arp_handler:
            self.arp_handler.on_attack_started = self._on_arp_attack_started
            self.arp_handler.on_attack_stopped = self._on_arp_attack_stopped
            self.arp_handler.on_packet_sent = self._on_arp_packet_sent
        
        if self.bandwidth_controller:
            self.bandwidth_controller.on_limit_exceeded = self._on_bandwidth_limit_exceeded
            self.bandwidth_controller.on_stats_updated = self._on_bandwidth_stats_updated
            self.bandwidth_controller.on_device_blocked = self._on_device_bandwidth_blocked
    
    def _start_timers(self):
        """Démarre les timers de mise à jour"""
        # Timer de mise à jour des statistiques
        self._update_statistics()
        
        # Timer d'auto-scan (si activé)
        if self.config.ui.auto_refresh:
            self._schedule_auto_scan()
    
    def _update_statistics(self):
        """Met à jour les statistiques affichées"""
        try:
            stats = {}
            
            # Stats du scanner
            if self.network_scanner:
                scanner_stats = self.network_scanner.get_statistics()
                stats.update(scanner_stats)
            
            # Stats de l'ARP handler
            if self.arp_handler:
                arp_stats = self.arp_handler.get_statistics()
                stats.update(arp_stats)
            
            # Stats du bandwidth controller
            if self.bandwidth_controller:
                bandwidth_stats = self.bandwidth_controller.get_global_statistics()
                stats.update(bandwidth_stats)
            
            # Mettre à jour le panel de stats
            self.stats_panel.update_stats(stats)
            
            # Programmer la prochaine mise à jour
            self.stats_update_timer = self.root.after(2000, self._update_statistics)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la mise à jour des stats: {e}")
    
    def _schedule_auto_scan(self):
        """Programme un scan automatique"""
        if self.config.ui.auto_refresh and not self.scanning:
            auto_scan_interval = self.config.ui.refresh_interval * 1000  # Convertir en ms
            self.auto_scan_timer = self.root.after(auto_scan_interval, self._auto_scan)
    
    def _auto_scan(self):
        """Effectue un scan automatique"""
        if self.network_scanner and not self.scanning:
            threading.Thread(target=self._perform_network_scan, daemon=True).start()
        
        # Programmer le prochain scan
        self._schedule_auto_scan()
    
    def _log_startup_info(self):
        """Log les informations de démarrage"""
        self.log_viewer.add_log("INFO", f"{APP_NAME} v{APP_VERSION} started")
        self.log_viewer.add_log("INFO", f"User: {self.config.author}")
        self.log_viewer.add_log("INFO", f"Admin privileges: {'Yes' if SystemUtils.is_admin() else 'No'}")
        
        if self.current_interface:
            self.log_viewer.add_log("INFO", f"Interface: {self.current_interface.name} ({self.current_interface.ip})")
        else:
            self.log_viewer.add_log("WARNING", "No network interface selected")
    
    # Event handlers pour l'interface
    def _refresh_interfaces(self):
        """Rafraîchit la liste des interfaces réseau"""
        try:
            interfaces = get_suitable_interfaces()
            interface_options = []
            
            for interface in interfaces:
                option = f"{interface.name} ({interface.ip})"
                if interface.is_wireless:
                    option += " [WiFi]"
                if interface.is_gateway:
                    option += " [Gateway]"
                interface_options.append(option)
            
            self.interface_combo.configure(values=interface_options)
            
            if interface_options and not self.interface_var.get():
                self.interface_var.set(interface_options[0])
                self._on_interface_changed(interface_options[0])
            
            self.logger.info(f"Interfaces rafraîchies: {len(interfaces)} trouvées")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du rafraîchissement des interfaces: {e}")
            messagebox.showerror("Interface Error", f"Failed to refresh interfaces:\n{e}")
    
    def _on_interface_changed(self, selection):
        """Callback de changement d'interface"""
        try:
            # Extraire le nom de l'interface
            interface_name = selection.split(" (")[0]
            
            # Trouver l'interface correspondante
            interfaces = get_suitable_interfaces()
            for interface in interfaces:
                if interface.name == interface_name:
                    self._setup_network_modules(interface)
                    break
            
        except Exception as e:
            self.logger.error(f"Erreur lors du changement d'interface: {e}")
    
    def _update_interface_info(self):
        """Met à jour les informations de l'interface actuelle"""
        if self.current_interface:
            info_text = (
                f"IP: {self.current_interface.ip}\n"
                f"Gateway: {self.current_interface.gateway}\n"
                f"MAC: {self.current_interface.mac}\n"
                f"Type: {'Wireless' if self.current_interface.is_wireless else 'Wired'}"
            )
            self.interface_info_label.configure(text=info_text)
        else:
            self.interface_info_label.configure(text="No interface selected")
    
    def _toggle_scanning(self):
        """Démarre/arrête le scan réseau"""
        if not self.current_interface:
            messagebox.showwarning("No Interface", "Please select a network interface first.")
            return
        
        if not self.scanning:
            self._start_network_scan()
        else:
            self._stop_network_scan()
    
    def _start_network_scan(self):
        """Démarre le scan réseau"""
        try:
            self.scanning = True
            self.scan_button.configure(text="⏹️ Stop Scanning", fg_color=DARK_THEME['error_color'])
            self.scan_indicator.configure(text="🟢 Scan", text_color=DARK_THEME['success_color'])
            
            # Démarrer le scan en arrière-plan
            threading.Thread(target=self._perform_network_scan, daemon=True).start()
            
            self._update_status("Network scan started...")
            self.log_viewer.add_log("INFO", "Network scan started")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du démarrage du scan: {e}")
            messagebox.showerror("Scan Error", f"Failed to start network scan:\n{e}")
    
    def _stop_network_scan(self):
        """Arrête le scan réseau"""
        try:
            self.scanning = False
            
            if self.network_scanner:
                self.network_scanner.stop_continuous_scan()
            
            self.scan_button.configure(text="🔍 Start Network Scan", fg_color=DARK_THEME['success_color'])
            self.scan_indicator.configure(text="⚫ Scan", text_color=DARK_THEME['fg_color'])
            
            self._update_status("Network scan stopped")
            self.log_viewer.add_log("INFO", "Network scan stopped")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'arrêt du scan: {e}")
    
    def _perform_network_scan(self):
        """Effectue le scan réseau (thread séparé)"""
        try:
            if self.network_scanner:
                self.network_scanner.start_continuous_scan()
        except Exception as e:
            self.logger.error(f"Erreur lors du scan réseau: {e}")
            self.root.after(0, lambda: messagebox.showerror("Scan Error", f"Network scan failed:\n{e}"))
    
    def _deep_scan_selected(self):
        """Effectue un scan détaillé des appareils sélectionnés"""
        selected_devices = self.device_list.get_selected_devices()
        if not selected_devices:
            messagebox.showinfo("No Selection", "Please select devices to perform deep scan.")
            return
        
        if not self.device_scanner:
            messagebox.showerror("Scanner Error", "Device scanner not available.")
            return
        
        # Lancer le scan détaillé en arrière-plan
        threading.Thread(
            target=self._perform_deep_scan,
            args=(selected_devices,),
            daemon=True
        ).start()
        
        self._update_status(f"Deep scanning {len(selected_devices)} devices...")
        self.log_viewer.add_log("INFO", f"Deep scan started for {len(selected_devices)} devices")
    
    def _perform_deep_scan(self, devices: List[NetworkDevice]):
        """Effectue le scan détaillé (thread séparé)"""
        try:
            profiles = self.device_scanner.scan_multiple_devices(devices, extended_scan=True)
            
            # Traiter les résultats dans le thread principal
            self.root.after(0, lambda: self._on_deep_scan_complete(profiles))
            
        except Exception as e:
            self.logger.error(f"Erreur lors du scan détaillé: {e}")
            self.root.after(0, lambda: messagebox.showerror("Deep Scan Error", f"Deep scan failed:\n{e}"))
    
    def _on_deep_scan_complete(self, profiles):
        """Callback de fin de scan détaillé"""
        self._update_status(f"Deep scan completed - {len(profiles)} devices analyzed")
        self.log_viewer.add_log("INFO", f"Deep scan completed for {len(profiles)} devices")
        
        # Afficher les résultats (pour l'instant juste un message)
        vulnerability_count = sum(1 for profile in profiles.values() if profile.is_vulnerable)
        
        messagebox.showinfo(
            "Deep Scan Complete",
            f"Scan completed!\n\n"
            f"Devices analyzed: {len(profiles)}\n"
            f"Vulnerabilities found: {vulnerability_count}\n\n"
            f"Check logs for detailed information."
        )
        
        # Log des vulnérabilités trouvées
        for ip, profile in profiles.items():
            if profile.vulnerability_indicators:
                for vuln in profile.vulnerability_indicators:
                    self.log_viewer.add_log("WARNING", f"{ip}: {vuln}")

    # Je vais continuer avec les autres méthodes dans le message suivant pour respecter la limite de longueur...
    
    def run(self):
        """Lance l'application"""
        try:
            self.root.mainloop()
        except Exception as e:
            self.logger.critical(f"Erreur critique dans l'application: {e}")
        finally:
            self._cleanup()
    
    def _cleanup(self):
        """Nettoie les ressources avant fermeture"""
        try:
            # Arrêter tous les scans et attaques
            if self.scanning:
                self._stop_network_scan()
            
            if self.attacking:
                self._stop_all_attacks()
            
            if self.monitoring_bandwidth:
                self._stop_bandwidth_monitoring()
            
            # Annuler les timers
            if self.stats_update_timer:
                self.root.after_cancel(self.stats_update_timer)
            
            if self.auto_scan_timer:
                self.root.after_cancel(self.auto_scan_timer)
            
            # Sauvegarder la configuration
            save_config()
            
            self.logger.info("Application fermée proprement")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du nettoyage: {e}")
    
    def _on_closing(self):
        """Callback de fermeture de l'application"""
        if self.attacking or self.scanning:
            result = messagebox.askyesno(
                "Confirm Exit",
                "Active operations detected!\n\n"
                "Are you sure you want to exit?\n"
                "This will stop all attacks and restore network tables."
            )
            if not result:
                return
        
        self._cleanup()
        self.root.quit()
        self.root.destroy()