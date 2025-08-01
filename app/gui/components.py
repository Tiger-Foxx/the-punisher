"""
Composants GUI réutilisables pour NetworkController
Widgets personnalisés, tableaux, graphiques, etc.
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import ttk
from typing import List, Dict, Any, Optional, Callable
import time
from datetime import datetime
from PIL import Image, ImageTk
from pathlib import Path

from ..core import DARK_THEME, NetworkUtils
from ..network import NetworkDevice, TrafficStats, BandwidthLimit, ARPAttackSession


class DeviceListFrame(ctk.CTkScrollableFrame):
    """Frame scrollable pour afficher la liste des appareils"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.devices: List[NetworkDevice] = []
        self.device_frames: Dict[str, ctk.CTkFrame] = {}
        self.selected_devices: set = set()
        
        # Callbacks
        self.on_device_selected: Optional[Callable[[NetworkDevice, bool], None]] = None
        self.on_device_action: Optional[Callable[[NetworkDevice, str], None]] = None
        
        # Configuration
        self.configure(fg_color="transparent")
    
    def add_device(self, device: NetworkDevice):
        """Ajoute un appareil à la liste"""
        if device.ip not in self.device_frames:
            device_frame = self._create_device_frame(device)
            self.device_frames[device.ip] = device_frame
            device_frame.pack(fill="x", padx=5, pady=2)
        
        self.devices.append(device)
    
    def update_device(self, device: NetworkDevice):
        """Met à jour un appareil existant"""
        if device.ip in self.device_frames:
            # Supprimer l'ancien frame
            self.device_frames[device.ip].destroy()
            del self.device_frames[device.ip]
            
            # Recréer le frame
            device_frame = self._create_device_frame(device)
            self.device_frames[device.ip] = device_frame
            device_frame.pack(fill="x", padx=5, pady=2)
    
    def _create_device_frame(self, device: NetworkDevice) -> ctk.CTkFrame:
        """Crée le frame d'un appareil"""
        # Frame principal
        device_frame = ctk.CTkFrame(
            self,
            fg_color=DARK_THEME['secondary_color'],
            border_width=1,
            border_color=DARK_THEME['accent_color'] if device.is_online else DARK_THEME['error_color'],
            corner_radius=8
        )
        
        # Checkbox de sélection
        checkbox_var = tk.BooleanVar()
        checkbox = ctk.CTkCheckBox(
            device_frame,
            text="",
            variable=checkbox_var,
            width=20,
            checkbox_width=18,
            checkbox_height=18,
            command=lambda: self._on_device_selected(device, checkbox_var.get())
        )
        checkbox.pack(side="left", padx=5, pady=5)
        
        # Informations de l'appareil
        info_frame = ctk.CTkFrame(device_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        # Ligne 1: IP, Status, Type
        line1_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        line1_frame.pack(fill="x", pady=2)
        
        # IP
        ip_label = ctk.CTkLabel(
            line1_frame,
            text=device.ip,
            font=ctk.CTkFont(family="Courier", size=12, weight="bold"),
            text_color=DARK_THEME['accent_color']
        )
        ip_label.pack(side="left")
        
        # Status
        status_color = DARK_THEME['success_color'] if device.is_online else DARK_THEME['error_color']
        status_text = "🟢 Online" if device.is_online else "🔴 Offline"
        status_label = ctk.CTkLabel(
            line1_frame,
            text=status_text,
            font=ctk.CTkFont(size=10),
            text_color=status_color
        )
        status_label.pack(side="right")
        
        # Type d'appareil
        if device.device_type:
            type_label = ctk.CTkLabel(
                line1_frame,
                text=f"[{device.device_type}]",
                font=ctk.CTkFont(size=10),
                text_color=DARK_THEME['info_color']
            )
            type_label.pack(side="right", padx=(0, 10))
        
        # Ligne 2: MAC, Vendor
        line2_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        line2_frame.pack(fill="x", pady=2)
        
        # MAC
        mac_label = ctk.CTkLabel(
            line2_frame,
            text=f"MAC: {device.mac}",
            font=ctk.CTkFont(family="Courier", size=10),
            text_color=DARK_THEME['fg_color']
        )
        mac_label.pack(side="left")
        
        # Vendor
        if device.vendor and device.vendor != "Unknown Vendor":
            vendor_label = ctk.CTkLabel(
                line2_frame,
                text=device.vendor[:30] + "..." if len(device.vendor) > 30 else device.vendor,
                font=ctk.CTkFont(size=10),
                text_color=DARK_THEME['info_color']
            )
            vendor_label.pack(side="right")
        
        # Ligne 3: Hostname (si disponible)
        if device.hostname:
            hostname_label = ctk.CTkLabel(
                info_frame,
                text=f"🏠 {device.hostname}",
                font=ctk.CTkFont(size=10),
                text_color=DARK_THEME['warning_color']
            )
            hostname_label.pack(anchor="w", pady=2)
        
        # Boutons d'action
        action_frame = ctk.CTkFrame(device_frame, fg_color="transparent")
        action_frame.pack(side="right", padx=5, pady=5)
        
        # Bouton Block/Unblock
        block_button = ctk.CTkButton(
            action_frame,
            text="🚫 Block" if device.is_online else "✅ Unblock",
            width=80,
            height=25,
            font=ctk.CTkFont(size=10),
            fg_color=DARK_THEME['error_color'] if device.is_online else DARK_THEME['success_color'],
            command=lambda: self._on_device_action(device, "block" if device.is_online else "unblock")
        )
        block_button.pack(pady=1)
        
        # Bouton Info
        info_button = ctk.CTkButton(
            action_frame,
            text="ℹ️ Info",
            width=80,
            height=25,
            font=ctk.CTkFont(size=10),
            fg_color=DARK_THEME['info_color'],
            command=lambda: self._on_device_action(device, "info")
        )
        info_button.pack(pady=1)
        
        return device_frame
    
    def _on_device_selected(self, device: NetworkDevice, selected: bool):
        """Callback de sélection d'appareil"""
        if selected:
            self.selected_devices.add(device.ip)
        else:
            self.selected_devices.discard(device.ip)
        
        if self.on_device_selected:
            self.on_device_selected(device, selected)
    
    def _on_device_action(self, device: NetworkDevice, action: str):
        """Callback d'action sur appareil"""
        if self.on_device_action:
            self.on_device_action(device, action)
    
    def clear_devices(self):
        """Vide la liste des appareils"""
        for frame in self.device_frames.values():
            frame.destroy()
        
        self.device_frames.clear()
        self.devices.clear()
        self.selected_devices.clear()
    
    def get_selected_devices(self) -> List[NetworkDevice]:
        """Retourne la liste des appareils sélectionnés"""
        return [device for device in self.devices if device.ip in self.selected_devices]


class StatisticsPanel(ctk.CTkFrame):
    """Panel d'affichage des statistiques réseau"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.configure(fg_color=DARK_THEME['bg_color'], corner_radius=10)
        
        # Titre
        title_label = ctk.CTkLabel(
            self,
            text="📊 Network Statistics",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=DARK_THEME['accent_color']
        )
        title_label.pack(pady=(10, 20))
        
        # Grid pour les stats
        self.stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Variables des stats
        self.stats_vars = {}
        self._create_stats_layout()
    
    def _create_stats_layout(self):
        """Crée la disposition des statistiques"""
        stats_config = [
            ("Devices Found", "devices_found", "🔍"),
            ("Online Devices", "online_devices", "🟢"),
            ("Blocked Devices", "blocked_devices", "🚫"),
            ("Total Traffic", "total_traffic", "📡"),
            ("Current Speed", "current_speed", "⚡"),
            ("Packets Sent", "packets_sent", "📤"),
            ("Attack Sessions", "attack_sessions", "💀"),
            ("Scan Duration", "scan_duration", "⏱️")
        ]
        
        for i, (label, key, icon) in enumerate(stats_config):
            row = i // 2
            col = i % 2
            
            stat_frame = ctk.CTkFrame(
                self.stats_frame,
                fg_color=DARK_THEME['secondary_color'],
                corner_radius=8
            )
            stat_frame.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
            
            # Configuration du grid
            self.stats_frame.grid_columnconfigure(col, weight=1)
            
            # Icon
            icon_label = ctk.CTkLabel(
                stat_frame,
                text=icon,
                font=ctk.CTkFont(size=20)
            )
            icon_label.pack(pady=(5, 0))
            
            # Label
            label_widget = ctk.CTkLabel(
                stat_frame,
                text=label,
                font=ctk.CTkFont(size=10),
                text_color=DARK_THEME['fg_color']
            )
            label_widget.pack()
            
            # Valeur
            var = tk.StringVar(value="0")
            value_label = ctk.CTkLabel(
                stat_frame,
                textvariable=var,
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=DARK_THEME['accent_color']
            )
            value_label.pack(pady=(0, 5))
            
            self.stats_vars[key] = var
    
    def update_stats(self, stats: Dict[str, Any]):
        """Met à jour les statistiques affichées"""
        mappings = {
            "devices_found": lambda s: str(s.get("total_devices", 0)),
            "online_devices": lambda s: str(s.get("online_devices", 0)),
            "blocked_devices": lambda s: str(s.get("blocked_devices", 0)),
            "total_traffic": lambda s: NetworkUtils.bytes_to_human(s.get("total_traffic", 0)),
            "current_speed": lambda s: f"{s.get('current_speed_mbps', 0):.1f} Mbps",
            "packets_sent": lambda s: str(s.get("total_packets_sent", 0)),
            "attack_sessions": lambda s: str(s.get("active_sessions", 0)),
            "scan_duration": lambda s: f"{s.get('scan_duration', 0):.1f}s"
        }
        
        for key, formatter in mappings.items():
            if key in self.stats_vars:
                try:
                    value = formatter(stats)
                    self.stats_vars[key].set(value)
                except Exception:
                    self.stats_vars[key].set("N/A")


class LogViewer(ctk.CTkScrollableFrame):
    """Visualiseur de logs avec filtrage"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.configure(fg_color=DARK_THEME['bg_color'])
        self.max_logs = 1000
        self.logs: List[Dict] = []
        
        # Frame pour les contrôles
        control_frame = ctk.CTkFrame(self, fg_color="transparent")
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Filtres
        filter_label = ctk.CTkLabel(
            control_frame,
            text="Filter:",
            font=ctk.CTkFont(size=12)
        )
        filter_label.pack(side="left", padx=5)
        
        self.filter_var = tk.StringVar(value="ALL")
        filter_combo = ctk.CTkComboBox(
            control_frame,
            values=["ALL", "INFO", "WARNING", "ERROR", "DEBUG"],
            variable=self.filter_var,
            width=100,
            command=self._filter_logs
        )
        filter_combo.pack(side="left", padx=5)
        
        # Bouton clear
        clear_button = ctk.CTkButton(
            control_frame,
            text="Clear",
            width=60,
            height=25,
            command=self.clear_logs
        )
        clear_button.pack(side="right", padx=5)
        
        # Zone de logs
        self.log_text = ctk.CTkTextbox(
            self,
            height=200,
            font=ctk.CTkFont(family="Courier", size=10),
            fg_color=DARK_THEME['secondary_color'],
            text_color=DARK_THEME['fg_color']
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
    
    def add_log(self, level: str, message: str, timestamp: Optional[datetime] = None):
        """Ajoute un log"""
        if not timestamp:
            timestamp = datetime.now()
        
        log_entry = {
            "level": level,
            "message": message,
            "timestamp": timestamp,
            "formatted": f"[{timestamp.strftime('%H:%M:%S')}] {level}: {message}"
        }
        
        self.logs.append(log_entry)
        
        # Limiter le nombre de logs
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
        
        self._update_display()
    
    def _filter_logs(self, *args):
        """Filtre les logs selon le niveau sélectionné"""
        self._update_display()
    
    def _update_display(self):
        """Met à jour l'affichage des logs"""
        filter_level = self.filter_var.get()
        
        # Effacer le contenu actuel
        self.log_text.delete("1.0", "end")
        
        # Ajouter les logs filtrés
        for log in self.logs:
            if filter_level == "ALL" or log["level"] == filter_level:
                # Couleur selon le niveau
                color = {
                    "INFO": DARK_THEME['info_color'],
                    "WARNING": DARK_THEME['warning_color'],
                    "ERROR": DARK_THEME['error_color'],
                    "DEBUG": DARK_THEME['fg_color']
                }.get(log["level"], DARK_THEME['fg_color'])
                
                self.log_text.insert("end", log["formatted"] + "\n")
        
        # Scroller vers le bas
        self.log_text.see("end")
    
    def clear_logs(self):
        """Efface tous les logs"""
        self.logs.clear()
        self.log_text.delete("1.0", "end")


class BandwidthControlPanel(ctk.CTkFrame):
    """Panel de contrôle de bande passante"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.configure(fg_color=DARK_THEME['bg_color'], corner_radius=10)
        
        # Callbacks
        self.on_limit_set: Optional[Callable[[str, float, float], None]] = None
        self.on_limit_removed: Optional[Callable[[str], None]] = None
        
        self._create_interface()
    
    def _create_interface(self):
        """Crée l'interface du panel"""
        # Titre
        title_label = ctk.CTkLabel(
            self,
            text="⚡ Bandwidth Control",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=DARK_THEME['accent_color']
        )
        title_label.pack(pady=10)
        
        # Frame pour les contrôles
        control_frame = ctk.CTkFrame(self, fg_color="transparent")
        control_frame.pack(fill="x", padx=10, pady=10)
        
        # Sélection d'appareil
        device_label = ctk.CTkLabel(
            control_frame,
            text="Device IP:",
            font=ctk.CTkFont(size=12)
        )
        device_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.device_var = tk.StringVar()
        self.device_combo = ctk.CTkComboBox(
            control_frame,
            variable=self.device_var,
            width=150
        )
        self.device_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Limite download
        down_label = ctk.CTkLabel(
            control_frame,
            text="Download (Mbps):",
            font=ctk.CTkFont(size=12)
        )
        down_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        self.download_var = tk.StringVar(value="0")
        download_entry = ctk.CTkEntry(
            control_frame,
            textvariable=self.download_var,
            width=100
        )
        download_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Limite upload
        up_label = ctk.CTkLabel(
            control_frame,
            text="Upload (Mbps):",
            font=ctk.CTkFont(size=12)
        )
        up_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        
        self.upload_var = tk.StringVar(value="0")
        upload_entry = ctk.CTkEntry(
            control_frame,
            textvariable=self.upload_var,
            width=100
        )
        upload_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Boutons
        button_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        set_button = ctk.CTkButton(
            button_frame,
            text="Set Limit",
            command=self._set_limit,
            fg_color=DARK_THEME['success_color']
        )
        set_button.pack(side="left", padx=5)
        
        remove_button = ctk.CTkButton(
            button_frame,
            text="Remove Limit",
            command=self._remove_limit,
            fg_color=DARK_THEME['error_color']
        )
        remove_button.pack(side="left", padx=5)
    
    def update_devices(self, devices: List[NetworkDevice]):
        """Met à jour la liste des appareils"""
        device_ips = [device.ip for device in devices if device.is_online]
        self.device_combo.configure(values=device_ips)
        
        if device_ips and not self.device_var.get():
            self.device_var.set(device_ips[0])
    
    def _set_limit(self):
        """Définit une limite de bande passante"""
        try:
            device_ip = self.device_var.get()
            download_mbps = float(self.download_var.get() or "0")
            upload_mbps = float(self.upload_var.get() or "0")
            
            if device_ip and (download_mbps > 0 or upload_mbps > 0):
                if self.on_limit_set:
                    self.on_limit_set(device_ip, download_mbps, upload_mbps)
        except ValueError:
            pass  # Ignorer les valeurs invalides
    
    def _remove_limit(self):
        """Supprime une limite de bande passante"""
        device_ip = self.device_var.get()
        if device_ip and self.on_limit_removed:
            self.on_limit_removed(device_ip)


class AttackControlPanel(ctk.CTkFrame):
    """Panel de contrôle des attaques"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.configure(fg_color=DARK_THEME['bg_color'], corner_radius=10)
        
        # Callbacks
        self.on_attack_started: Optional[Callable[[List[str], str], None]] = None
        self.on_attack_stopped: Optional[Callable[[], None]] = None
        
        self._create_interface()
    
    def _create_interface(self):
        """Crée l'interface du panel"""
        # Titre avec crâne
        title_label = ctk.CTkLabel(
            self,
            text="💀 Attack Control",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=DARK_THEME['accent_color']
        )
        title_label.pack(pady=10)
        
        # Mode d'attaque
        mode_frame = ctk.CTkFrame(self, fg_color="transparent")
        mode_frame.pack(fill="x", padx=10, pady=10)
        
        mode_label = ctk.CTkLabel(
            mode_frame,
            text="Attack Mode:",
            font=ctk.CTkFont(size=12)
        )
        mode_label.pack(anchor="w")
        
        self.mode_var = tk.StringVar(value="auto")
        
        auto_radio = ctk.CTkRadioButton(
            mode_frame,
            text="🔴 Auto Block (Block all except this PC)",
            variable=self.mode_var,
            value="auto"
        )
        auto_radio.pack(anchor="w", pady=2)
        
        manual_radio = ctk.CTkRadioButton(
            mode_frame,
            text="🎯 Manual Selection (Block selected devices)",
            variable=self.mode_var,
            value="manual"
        )
        manual_radio.pack(anchor="w", pady=2)
        
        # Boutons de contrôle
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=20)
        
        self.start_button = ctk.CTkButton(
            button_frame,
            text="🚀 Start Attack",
            command=self._start_attack,
            fg_color=DARK_THEME['error_color'],
            hover_color="#ff6666",
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.start_button.pack(fill="x", pady=5)
        
        self.stop_button = ctk.CTkButton(
            button_frame,
            text="⏹️ Stop All Attacks",
            command=self._stop_attack,
            fg_color=DARK_THEME['success_color'],
            state="disabled",
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.stop_button.pack(fill="x", pady=5)
        
        # Warning
        warning_label = ctk.CTkLabel(
            self,
            text="⚠️ WARNING: Use only on authorized networks!",
            font=ctk.CTkFont(size=10),
            text_color=DARK_THEME['warning_color']
        )
        warning_label.pack(pady=10)
    
    def _start_attack(self):
        """Démarre l'attaque"""
        mode = self.mode_var.get()
        if self.on_attack_started:
            self.on_attack_started([], mode)  # La logique de sélection est dans la fenêtre principale
        
        # Mettre à jour l'état des boutons
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
    
    def _stop_attack(self):
        """Arrête toutes les attaques"""
        if self.on_attack_stopped:
            self.on_attack_stopped()
        
        # Mettre à jour l'état des boutons
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
    
    def set_attack_state(self, attacking: bool):
        """Met à jour l'état des boutons selon l'état d'attaque"""
        if attacking:
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
        else:
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")