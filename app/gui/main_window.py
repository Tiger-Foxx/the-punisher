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
        
    # Event handlers pour les appareils
    def _on_device_discovered(self, device: NetworkDevice):
        """Callback de découverte d'appareil"""
        self.root.after(0, lambda: self._handle_device_discovered(device))
    
    def _handle_device_discovered(self, device: NetworkDevice):
        """Traite la découverte d'appareil dans le thread principal"""
        self.discovered_devices[device.ip] = device
        self.device_list.add_device(device)
        
        # Mettre à jour la liste des appareils dans le bandwidth panel
        self.bandwidth_panel.update_devices(list(self.discovered_devices.values()))
        
        # Log de découverte
        self.log_viewer.add_log("INFO", f"Appareil découvert: {device.ip} ({device.vendor})")
        
        # Notification si activée
        if self.config.ui.show_notifications:
            self._show_toast_notification(f"Nouvel appareil: {device.ip}", device.vendor)
    
    def _on_device_updated(self, device: NetworkDevice):
        """Callback de mise à jour d'appareil"""
        self.root.after(0, lambda: self._handle_device_updated(device))
    
    def _handle_device_updated(self, device: NetworkDevice):
        """Traite la mise à jour d'appareil dans le thread principal"""
        self.discovered_devices[device.ip] = device
        self.device_list.update_device(device)
    
    def _on_device_lost(self, device: NetworkDevice):
        """Callback de perte d'appareil"""
        self.root.after(0, lambda: self._handle_device_lost(device))
    
    def _handle_device_lost(self, device: NetworkDevice):
        """Traite la perte d'appareil dans le thread principal"""
        if device.ip in self.discovered_devices:
            self.discovered_devices[device.ip] = device
            self.device_list.update_device(device)
        
        self.log_viewer.add_log("WARNING", f"Appareil hors ligne: {device.ip}")
    
    def _on_scan_complete(self, devices: List[NetworkDevice]):
        """Callback de fin de scan"""
        self.root.after(0, lambda: self._handle_scan_complete(devices))
    
    def _handle_scan_complete(self, devices: List[NetworkDevice]):
        """Traite la fin de scan dans le thread principal"""
        device_count = len([d for d in devices if d.is_online])
        self._update_status(f"Scan terminé - {device_count} appareils trouvés")
        
        # Mettre à jour la liste des appareils dans les panels
        self.bandwidth_panel.update_devices(devices)
    
    def _on_scan_progress(self, current: int, total: int):
        """Callback de progression de scan"""
        percentage = (current / total) * 100 if total > 0 else 0
        status_text = f"Scan en cours... {current}/{total} ({percentage:.1f}%)"
        self.root.after(0, lambda: self._update_status(status_text))
    
    def _on_device_selected(self, device: NetworkDevice, selected: bool):
        """Callback de sélection d'appareil"""
        if selected:
            self.log_viewer.add_log("DEBUG", f"Appareil sélectionné: {device.ip}")
        else:
            self.log_viewer.add_log("DEBUG", f"Appareil désélectionné: {device.ip}")
    
    def _on_device_action(self, device: NetworkDevice, action: str):
        """Callback d'action sur appareil"""
        try:
            if action == "block":
                self._block_device(device)
            elif action == "unblock":
                self._unblock_device(device)
            elif action == "info":
                self._show_device_info(device)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'action {action} sur {device.ip}: {e}")
            messagebox.showerror("Action Error", f"Failed to {action} device:\n{e}")
    
    # Event handlers pour les attaques ARP
    def _on_arp_attack_started(self, session_id: str, session):
        """Callback de démarrage d'attaque ARP"""
        self.attack_sessions[session_id] = session
        self.log_viewer.add_log("WARNING", f"Attaque {session.attack_type} démarrée sur {session.target_ip}")
        
        # Mettre à jour l'indicateur d'attaque
        self.attack_indicator.configure(text="🔴 Attack", text_color=DARK_THEME['error_color'])
        self.attacking = True
    
    def _on_arp_attack_stopped(self, session_id: str, session):
        """Callback d'arrêt d'attaque ARP"""
        if session_id in self.attack_sessions:
            del self.attack_sessions[session_id]
        
        self.log_viewer.add_log("INFO", f"Attaque {session.attack_type} arrêtée sur {session.target_ip}")
        
        # Mettre à jour l'indicateur si plus d'attaques
        if not self.attack_sessions:
            self.attack_indicator.configure(text="⚫ Attack", text_color=DARK_THEME['fg_color'])
            self.attacking = False
    
    def _on_arp_packet_sent(self, session_id: str, count: int):
        """Callback de paquet ARP envoyé"""
        # Mettre à jour les stats en temps réel (optionnel, peut être trop verbeux)
        pass
    
    # Event handlers pour le contrôle de bande passante
    def _on_bandwidth_limit_set(self, device_ip: str, download_mbps: float, upload_mbps: float):
        """Callback de définition de limite de bande passante"""
        try:
            if self.bandwidth_controller:
                success = self.bandwidth_controller.set_bandwidth_limit(
                    device_ip, download_mbps, upload_mbps
                )
                if success:
                    self.log_viewer.add_log(
                        "INFO", 
                        f"Limite définie pour {device_ip}: ↓{download_mbps}Mbps ↑{upload_mbps}Mbps"
                    )
                    self._show_toast_notification(
                        "Limite appliquée",
                        f"{device_ip}: {download_mbps}↓ {upload_mbps}↑ Mbps"
                    )
                else:
                    raise Exception("Échec de la définition de limite")
        except Exception as e:
            self.logger.error(f"Erreur lors de la définition de limite: {e}")
            messagebox.showerror("Bandwidth Error", f"Failed to set bandwidth limit:\n{e}")
    
    def _on_bandwidth_limit_removed(self, device_ip: str):
        """Callback de suppression de limite de bande passante"""
        try:
            if self.bandwidth_controller:
                success = self.bandwidth_controller.remove_bandwidth_limit(device_ip)
                if success:
                    self.log_viewer.add_log("INFO", f"Limite supprimée pour {device_ip}")
                else:
                    raise Exception("Échec de la suppression de limite")
        except Exception as e:
            self.logger.error(f"Erreur lors de la suppression de limite: {e}")
            messagebox.showerror("Bandwidth Error", f"Failed to remove bandwidth limit:\n{e}")
    
    def _on_bandwidth_limit_exceeded(self, ip: str, limit_type: str, speed: float):
        """Callback de dépassement de limite"""
        self.log_viewer.add_log(
            "WARNING", 
            f"Limite {limit_type} dépassée pour {ip}: {speed:.1f}Mbps"
        )
        
        if self.config.ui.show_notifications:
            self._show_toast_notification(
                "Limite dépassée",
                f"{ip}: {limit_type} {speed:.1f}Mbps"
            )
    
    def _on_bandwidth_stats_updated(self, stats: Dict):
        """Callback de mise à jour des stats de bande passante"""
        # Les stats sont déjà mises à jour par _update_statistics()
        pass
    
    def _on_device_bandwidth_blocked(self, ip: str, reason: str):
        """Callback de blocage d'appareil pour bande passante"""
        self.log_viewer.add_log("WARNING", f"Appareil bloqué {ip}: {reason}")
    
    # Event handlers pour les attaques
    def _on_attack_started(self, selected_ips: List[str], mode: str):
        """Démarre une attaque selon le mode sélectionné"""
        if not self.arp_handler:
            messagebox.showerror("ARP Error", "ARP handler not available.")
            return
        
        try:
            if mode == "auto":
                # Mode auto: bloquer tous les appareils sauf la machine locale
                devices_to_block = [
                    device for device in self.discovered_devices.values()
                    if device.is_online and not device.is_local_machine and not device.is_gateway
                ]
            else:
                # Mode manuel: bloquer les appareils sélectionnés
                selected_devices = self.device_list.get_selected_devices()
                if not selected_devices:
                    messagebox.showinfo("No Selection", "Please select devices to attack.")
                    self.attack_panel.set_attack_state(False)
                    return
                devices_to_block = selected_devices
            
            if not devices_to_block:
                messagebox.showinfo("No Targets", "No valid targets found for attack.")
                self.attack_panel.set_attack_state(False)
                return
            
            # Confirmation utilisateur
            device_count = len(devices_to_block)
            device_list = "\n".join([f"• {d.ip} ({d.vendor})" for d in devices_to_block[:5]])
            if device_count > 5:
                device_list += f"\n... et {device_count - 5} autres"
            
            result = messagebox.askyesno(
                "Confirm Attack",
                f"⚠️ ATTENTION ⚠️\n\n"
                f"Vous allez attaquer {device_count} appareil(s):\n\n"
                f"{device_list}\n\n"
                f"Cette action va interrompre leur accès Internet.\n"
                f"Êtes-vous sûr de vouloir continuer ?"
            )
            
            if not result:
                self.attack_panel.set_attack_state(False)
                return
            
            # Lancer les attaques en parallèle
            threading.Thread(
                target=self._perform_mass_attack,
                args=(devices_to_block,),
                daemon=True
            ).start()
            
            self._update_status(f"Attaque démarrée sur {device_count} appareils...")
            self.log_viewer.add_log("WARNING", f"Attaque de masse démarrée: {device_count} cibles")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du démarrage d'attaque: {e}")
            messagebox.showerror("Attack Error", f"Failed to start attack:\n{e}")
            self.attack_panel.set_attack_state(False)
    
    def _perform_mass_attack(self, devices: List[NetworkDevice]):
        """Effectue une attaque de masse (thread séparé)"""
        try:
            results = self.arp_handler.mass_block(devices)
            
            successful_attacks = sum(1 for success in results.values() if success)
            total_attacks = len(results)
            
            self.root.after(0, lambda: self._on_mass_attack_complete(successful_attacks, total_attacks))
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'attaque de masse: {e}")
            self.root.after(0, lambda: messagebox.showerror("Mass Attack Error", f"Mass attack failed:\n{e}"))
    
    def _on_mass_attack_complete(self, successful: int, total: int):
        """Callback de fin d'attaque de masse"""
        self._update_status(f"Attaque terminée: {successful}/{total} appareils bloqués")
        self.log_viewer.add_log("INFO", f"Attaque de masse terminée: {successful}/{total} succès")
        
        if successful < total:
            messagebox.showwarning(
                "Partial Success",
                f"Attaque partiellement réussie:\n\n"
                f"Succès: {successful}/{total} appareils\n"
                f"Échecs: {total - successful} appareils\n\n"
                f"Vérifiez les logs pour plus de détails."
            )
    
    def _on_attack_stopped(self):
        """Arrête toutes les attaques"""
        try:
            if self.arp_handler:
                self.arp_handler.stop_all_attacks()
            
            self._update_status("Toutes les attaques arrêtées")
            self.log_viewer.add_log("INFO", "Toutes les attaques ARP arrêtées")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'arrêt des attaques: {e}")
            messagebox.showerror("Stop Attack Error", f"Failed to stop attacks:\n{e}")
    
    # Actions sur les appareils
    def _block_device(self, device: NetworkDevice):
        """Bloque un appareil spécifique"""
        try:
            if not self.arp_handler:
                raise Exception("ARP handler not available")
            
            success = self.arp_handler.block_device(device)
            if success:
                self.log_viewer.add_log("WARNING", f"Appareil bloqué: {device.ip}")
                self._show_toast_notification("Appareil bloqué", f"{device.ip} ({device.vendor})")
            else:
                raise Exception("Échec du blocage")
                
        except Exception as e:
            self.logger.error(f"Erreur lors du blocage de {device.ip}: {e}")
            messagebox.showerror("Block Error", f"Failed to block device:\n{e}")
    
    def _unblock_device(self, device: NetworkDevice):
        """Débloque un appareil spécifique"""
        try:
            if not self.arp_handler:
                raise Exception("ARP handler not available")
            
            success = self.arp_handler.unblock_device(device)
            if success:
                self.log_viewer.add_log("INFO", f"Appareil débloqué: {device.ip}")
                self._show_toast_notification("Appareil débloqué", f"{device.ip} ({device.vendor})")
            else:
                raise Exception("Échec du déblocage")
                
        except Exception as e:
            self.logger.error(f"Erreur lors du déblocage de {device.ip}: {e}")
            messagebox.showerror("Unblock Error", f"Failed to unblock device:\n{e}")
    
    def _block_selected_devices(self):
        """Bloque tous les appareils sélectionnés"""
        selected_devices = self.device_list.get_selected_devices()
        if not selected_devices:
            messagebox.showinfo("No Selection", "Please select devices to block.")
            return
        
        # Confirmation
        device_count = len(selected_devices)
        result = messagebox.askyesno(
            "Confirm Block",
            f"Block {device_count} selected device(s)?\n\n"
            f"This will interrupt their Internet access."
        )
        
        if result:
            threading.Thread(
                target=self._perform_batch_block,
                args=(selected_devices,),
                daemon=True
            ).start()
    
    def _perform_batch_block(self, devices: List[NetworkDevice]):
        """Effectue un blocage par lot (thread séparé)"""
        try:
            if self.arp_handler:
                results = self.arp_handler.mass_block(devices)
                successful = sum(1 for success in results.values() if success)
                total = len(results)
                
                self.root.after(0, lambda: self._update_status(f"Blocage terminé: {successful}/{total}"))
                self.root.after(0, lambda: self.log_viewer.add_log("INFO", f"Blocage par lot: {successful}/{total}"))
                
        except Exception as e:
            self.logger.error(f"Erreur lors du blocage par lot: {e}")
    
    def _show_device_info(self, device: NetworkDevice):
        """Affiche les informations détaillées d'un appareil"""
        try:
            # Créer une fenêtre popup avec les infos
            info_window = ctk.CTkToplevel(self.root)
            info_window.title(f"Device Info - {device.ip}")
            info_window.geometry("500x400")
            info_window.configure(fg_color=DARK_THEME['bg_color'])
            
            # Rendre la fenêtre modale
            info_window.transient(self.root)
            info_window.grab_set()
            
            # Titre
            title_label = ctk.CTkLabel(
                info_window,
                text=f"📱 {device.ip}",
                font=ctk.CTkFont(size=18, weight="bold"),
                text_color=DARK_THEME['accent_color']
            )
            title_label.pack(pady=10)
            
            # Frame scrollable pour les informations
            info_frame = ctk.CTkScrollableFrame(info_window)
            info_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Informations de base
            info_data = [
                ("IP Address", device.ip),
                ("MAC Address", device.mac),
                ("Hostname", device.hostname or "Unknown"),
                ("Vendor", device.vendor or "Unknown"),
                ("Device Type", device.device_type or "Unknown"),
                ("OS Guess", device.os_guess or "Unknown"),
                ("Status", "Online" if device.is_online else "Offline"),
                ("Is Gateway", "Yes" if device.is_gateway else "No"),
                ("Is Local Machine", "Yes" if device.is_local_machine else "No"),
                ("First Seen", device.first_seen.strftime("%Y-%m-%d %H:%M:%S")),
                ("Last Seen", device.last_seen.strftime("%Y-%m-%d %H:%M:%S")),
                ("Average Response Time", f"{device.avg_response_time:.3f}s")
            ]
            
            for label, value in info_data:
                row_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
                row_frame.pack(fill="x", pady=2)
                
                label_widget = ctk.CTkLabel(
                    row_frame,
                    text=f"{label}:",
                    font=ctk.CTkFont(weight="bold"),
                    width=150,
                    anchor="w"
                )
                label_widget.pack(side="left", padx=5)
                
                value_widget = ctk.CTkLabel(
                    row_frame,
                    text=str(value),
                    anchor="w"
                )
                value_widget.pack(side="left", padx=5, fill="x", expand=True)
            
            # Boutons d'action
            button_frame = ctk.CTkFrame(info_window, fg_color="transparent")
            button_frame.pack(fill="x", padx=10, pady=10)
            
            deep_scan_button = ctk.CTkButton(
                button_frame,
                text="🔬 Deep Scan",
                command=lambda: self._deep_scan_single_device(device, info_window),
                fg_color=DARK_THEME['info_color']
            )
            deep_scan_button.pack(side="left", padx=5)
            
            close_button = ctk.CTkButton(
                button_frame,
                text="Close",
                command=info_window.destroy,
                fg_color=DARK_THEME['secondary_color']
            )
            close_button.pack(side="right", padx=5)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'affichage des infos de {device.ip}: {e}")
            messagebox.showerror("Info Error", f"Failed to show device info:\n{e}")
    
    def _deep_scan_single_device(self, device: NetworkDevice, parent_window):
        """Effectue un scan détaillé d'un seul appareil"""
        try:
            if not self.device_scanner:
                messagebox.showerror("Scanner Error", "Device scanner not available.")
                return
            
            # Fermer la fenêtre parent
            parent_window.destroy()
            
            # Lancer le scan en arrière-plan
            threading.Thread(
                target=self._perform_single_deep_scan,
                args=(device,),
                daemon=True
            ).start()
            
            self._update_status(f"Deep scan en cours pour {device.ip}...")
            self.log_viewer.add_log("INFO", f"Deep scan démarré pour {device.ip}")
            
        except Exception as e:
            self.logger.error(f"Erreur lors du deep scan de {device.ip}: {e}")
            messagebox.showerror("Deep Scan Error", f"Failed to start deep scan:\n{e}")
    
    def _perform_single_deep_scan(self, device: NetworkDevice):
        """Effectue le scan détaillé d'un appareil (thread séparé)"""
        try:
            profile = self.device_scanner.scan_device_detailed(device, extended_scan=True)
            
            # Afficher les résultats dans le thread principal
            self.root.after(0, lambda: self._show_deep_scan_results(profile))
            
        except Exception as e:
            self.logger.error(f"Erreur lors du deep scan de {device.ip}: {e}")
            self.root.after(0, lambda: messagebox.showerror("Deep Scan Error", f"Deep scan failed:\n{e}"))
    
    def _show_deep_scan_results(self, profile):
        """Affiche les résultats du scan détaillé"""
        # Pour l'instant, afficher un résumé simple
        vuln_count = len(profile.vulnerability_indicators)
        port_count = len(profile.open_ports)
        
        result_text = (
            f"Deep Scan Results for {profile.device.ip}\n\n"
            f"OS Detection: {profile.best_os_guess}\n"
            f"Open Ports: {port_count}\n"
            f"Vulnerabilities: {vuln_count}\n"
            f"Scan Duration: {profile.scan_duration:.1f}s\n\n"
        )
        
        if profile.open_ports:
            result_text += "Open Ports:\n"
            for service in profile.open_ports[:10]:  # Limiter à 10
                result_text += f"• {service.port}/{service.protocol} - {service.service_name}\n"
        
        if profile.vulnerability_indicators:
            result_text += "\nVulnerabilities:\n"
            for vuln in profile.vulnerability_indicators:
                result_text += f"⚠️ {vuln}\n"
        
        messagebox.showinfo("Deep Scan Complete", result_text)
        
        # Log des résultats
        self.log_viewer.add_log("INFO", f"Deep scan terminé pour {profile.device.ip}: {port_count} ports, {vuln_count} vulnérabilités")
    
    # Contrôle de la bande passante
    def _toggle_bandwidth_monitoring(self):
        """Démarre/arrête le monitoring de bande passante"""
        if not self.current_interface:
            messagebox.showwarning("No Interface", "Please select a network interface first.")
            return
        
        if not self.monitoring_bandwidth:
            self._start_bandwidth_monitoring()
        else:
            self._stop_bandwidth_monitoring()
    
    def _start_bandwidth_monitoring(self):
        """Démarre le monitoring de bande passante"""
        try:
            if not self.bandwidth_controller:
                raise Exception("Bandwidth controller not available")
            
            success = self.bandwidth_controller.start_monitoring()
            if success:
                self.monitoring_bandwidth = True
                self.monitor_button.configure(
                    text="⏹️ Stop Bandwidth Monitoring",
                    fg_color=DARK_THEME['error_color']
                )
                self.monitor_indicator.configure(
                    text="🟢 Monitor",
                    text_color=DARK_THEME['success_color']
                )
                
                self._update_status("Bandwidth monitoring started")
                self.log_viewer.add_log("INFO", "Monitoring de bande passante démarré")
            else:
                raise Exception("Failed to start monitoring")
                
        except Exception as e:
            self.logger.error(f"Erreur lors du démarrage du monitoring: {e}")
            messagebox.showerror("Monitoring Error", f"Failed to start bandwidth monitoring:\n{e}")
    
    def _stop_bandwidth_monitoring(self):
        """Arrête le monitoring de bande passante"""
        try:
            if self.bandwidth_controller:
                self.bandwidth_controller.stop_monitoring()
            
            self.monitoring_bandwidth = False
            self.monitor_button.configure(
                text="📡 Start Bandwidth Monitoring",
                fg_color=DARK_THEME['info_color']
            )
            self.monitor_indicator.configure(
                text="⚫ Monitor",
                text_color=DARK_THEME['fg_color']
            )
            
            self._update_status("Bandwidth monitoring stopped")
            self.log_viewer.add_log("INFO", "Monitoring de bande passante arrêté")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'arrêt du monitoring: {e}")
    
    # Fonctions d'export
    def _export_devices(self):
        """Exporte la liste des appareils"""
        if not self.discovered_devices:
            messagebox.showinfo("No Data", "No devices to export.")
            return
        
        try:
            # Sélectionner le fichier de destination
            filename = filedialog.asksaveasfilename(
                title="Export Devices",
                defaultextension=".csv",
                filetypes=[
                    ("CSV files", "*.csv"),
                    ("JSON files", "*.json"),
                    ("All files", "*.*")
                ]
            )
            
            if not filename:
                return
            
            if filename.endswith('.csv'):
                success = self._export_devices_csv(filename)
            elif filename.endswith('.json'):
                success = self._export_devices_json(filename)
            else:
                messagebox.showerror("Export Error", "Unsupported file format.")
                return
            
            if success:
                messagebox.showinfo("Export Complete", f"Devices exported to:\n{filename}")
                self.log_viewer.add_log("INFO", f"Appareils exportés vers {filename}")
            else:
                messagebox.showerror("Export Error", "Failed to export devices.")
                
        except Exception as e:
            self.logger.error(f"Erreur lors de l'export: {e}")
            messagebox.showerror("Export Error", f"Export failed:\n{e}")
    
    def _export_devices_csv(self, filename: str) -> bool:
        """Exporte les appareils en CSV"""
        try:
            if self.network_scanner:
                return self.network_scanner.export_devices_csv(filename)
        except Exception as e:
            self.logger.error(f"Erreur export CSV: {e}")
        return False
    
    def _export_devices_json(self, filename: str) -> bool:
        """Exporte les appareils en JSON"""
        try:
            import json
            export_data = {}
            
            for ip, device in self.discovered_devices.items():
                export_data[ip] = {
                    "ip": device.ip,
                    "mac": device.mac,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "device_type": device.device_type,
                    "os_guess": device.os_guess,
                    "is_online": device.is_online,
                    "is_gateway": device.is_gateway,
                    "is_local_machine": device.is_local_machine,
                    "first_seen": device.first_seen.isoformat(),
                    "last_seen": device.last_seen.isoformat(),
                    "avg_response_time": device.avg_response_time
                }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur export JSON: {e}")
            return False
    
    # Fonctions utilitaires d'interface
    def _update_status(self, message: str):
        """Met à jour la barre de statut"""
        self.status_var.set(message)
        self.logger.debug(f"Status: {message}")
    
    def _show_toast_notification(self, title: str, message: str):
        """Affiche une notification toast simple"""
        # Pour l'instant, utiliser messagebox simple
        # Dans une vraie implémentation, on utiliserait une notification système
        if self.config.ui.show_notifications:
            self.log_viewer.add_log("INFO", f"Notification: {title} - {message}")
    
    def _show_about(self):
        """Affiche la fenêtre À propos"""
        about_text = (
            f"{APP_NAME} v{APP_VERSION}\n\n"
            f"Advanced Network Controller with Modern Interface\n\n"
            f"Author: {self.config.author}\n"
            f"Theme: Dark Punisher Edition 💀\n\n"
            f"Features:\n"
            f"• Network device discovery\n"
            f"• ARP attack capabilities\n"
            f"• Bandwidth control\n"
            f"• Deep device scanning\n"
            f"• Real-time monitoring\n\n"
            f"⚠️ For authorized network testing only!\n"
            f"Use responsibly and in compliance with local laws."
        )
        
        messagebox.showinfo("About NetworkController", about_text)
    
    def _show_settings(self):
        """Affiche la fenêtre des paramètres"""
        # Pour l'instant, afficher un message simple
        # Dans une vraie implémentation, on créerait une fenêtre de settings
        messagebox.showinfo(
            "Settings",
            "Settings panel will be implemented in future version.\n\n"
            "Current configuration can be modified in:\n"
            f"{self.config.author}'s AppData folder"
        )
    
    def _stop_all_attacks(self):
        """Arrête toutes les attaques en cours"""
        try:
            if self.arp_handler:
                self.arp_handler.stop_all_attacks()
            
            self.attack_panel.set_attack_state(False)
            self.attacking = False
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'arrêt des attaques: {e}")


def create_main_window() -> NetworkControllerMainWindow:
    """Factory function pour créer la fenêtre principale"""
    return NetworkControllerMainWindow()