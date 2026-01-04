#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗            ║
║  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝            ║
║  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝             ║
║  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗             ║
║  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗            ║
║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝            ║
║                                                                   ║
║  Advanced Bug Bounty Reconnaissance Tool v2.0                     ║
║  Author: Security Researcher | For Educational Purposes Only     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import json
import csv
import os
import sys
from datetime import datetime
import webbrowser

# Import modules
from modules.subdomain import SubdomainEnumerator
from modules.portscan import PortScanner
from modules.dirbrute import DirectoryBruter
from modules.techdetect import TechDetector
from modules.dnsenum import DNSEnumerator
from modules.headers import HeaderAnalyzer
from modules.wayback import WaybackMachine
from modules.whois_lookup import WhoisLookup
from modules.vulnscan import VulnScanner


class CyberTheme:
    """Modern Cyberpunk/Hacking Theme Colors"""
    
    # Main colors
    BG_DARK = "#0a0a0f"
    BG_MEDIUM = "#12121a"
    BG_LIGHT = "#1a1a2e"
    BG_CARD = "#16213e"
    
    # Accent colors
    NEON_GREEN = "#00ff41"
    NEON_BLUE = "#00d4ff"
    NEON_PURPLE = "#b829dd"
    NEON_PINK = "#ff006e"
    NEON_ORANGE = "#ff6b35"
    NEON_RED = "#ff0040"
    NEON_YELLOW = "#ffd600"
    
    # Text colors
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#a0a0a0"
    TEXT_DIM = "#606060"
    
    # Status colors
    SUCCESS = "#00ff41"
    WARNING = "#ffd600"
    ERROR = "#ff0040"
    INFO = "#00d4ff"
    
    # Fonts
    FONT_MAIN = ("Consolas", 10)
    FONT_HEADER = ("Consolas", 14, "bold")
    FONT_TITLE = ("Consolas", 24, "bold")
    FONT_CODE = ("Fira Code", 9)
    FONT_SMALL = ("Consolas", 8)


class AnimatedBanner(tk.Canvas):
    """Animated ASCII banner with glitch effect"""
    
    BANNER = """
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
    """
    
    def __init__(self, parent):
        super().__init__(parent, bg=CyberTheme.BG_DARK, highlightthickness=0, height=120)
        self.colors = [CyberTheme.NEON_GREEN, CyberTheme.NEON_BLUE, CyberTheme.NEON_PURPLE]
        self.color_index = 0
        self.text_id = None
        self.draw_banner()
        self.animate()
    
    def draw_banner(self):
        if self.text_id:
            self.delete(self.text_id)
        self.text_id = self.create_text(
            self.winfo_reqwidth() // 2 + 300, 60,
            text=self.BANNER,
            font=("Consolas", 8, "bold"),
            fill=self.colors[self.color_index],
            anchor="center"
        )
    
    def animate(self):
        self.color_index = (self.color_index + 1) % len(self.colors)
        self.itemconfig(self.text_id, fill=self.colors[self.color_index])
        self.after(1500, self.animate)


class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    
    def __init__(self, parent, text, command, color=CyberTheme.NEON_GREEN, width=150, height=40):
        super().__init__(parent, width=width, height=height, 
                        bg=CyberTheme.BG_DARK, highlightthickness=0)
        
        self.command = command
        self.color = color
        self.text = text
        self.width = width
        self.height = height
        self.is_hovered = False
        
        self.draw_button()
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
    
    def draw_button(self):
        self.delete("all")
        
        # Draw border
        border_color = self.color if self.is_hovered else CyberTheme.TEXT_DIM
        fill_color = self.color if self.is_hovered else CyberTheme.BG_CARD
        text_color = CyberTheme.BG_DARK if self.is_hovered else self.color
        
        # Glow effect when hovered
        if self.is_hovered:
            for i in range(3):
                self.create_rectangle(
                    2-i, 2-i, self.width-2+i, self.height-2+i,
                    outline=self.color, width=1
                )
        
        self.create_rectangle(
            2, 2, self.width-2, self.height-2,
            outline=border_color, fill=fill_color, width=2
        )
        
        self.create_text(
            self.width//2, self.height//2,
            text=self.text, font=CyberTheme.FONT_MAIN,
            fill=text_color
        )
    
    def on_enter(self, event):
        self.is_hovered = True
        self.draw_button()
    
    def on_leave(self, event):
        self.is_hovered = False
        self.draw_button()
    
    def on_click(self, event):
        if self.command:
            self.command()


class StatusBar(tk.Frame):
    """Animated status bar with progress indication"""
    
    def __init__(self, parent):
        super().__init__(parent, bg=CyberTheme.BG_DARK)
        
        self.status_label = tk.Label(
            self, text="[ READY ]", font=CyberTheme.FONT_SMALL,
            fg=CyberTheme.NEON_GREEN, bg=CyberTheme.BG_DARK
        )
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(self, mode='indeterminate', length=200)
        self.progress.pack(side=tk.LEFT, padx=10)
        
        self.time_label = tk.Label(
            self, text="", font=CyberTheme.FONT_SMALL,
            fg=CyberTheme.TEXT_SECONDARY, bg=CyberTheme.BG_DARK
        )
        self.time_label.pack(side=tk.RIGHT, padx=10)
        
        self.update_time()
    
    def update_time(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=f"⏱ {current_time}")
        self.after(1000, self.update_time)
    
    def set_status(self, text, status_type="info"):
        colors = {
            "info": CyberTheme.NEON_BLUE,
            "success": CyberTheme.NEON_GREEN,
            "warning": CyberTheme.NEON_YELLOW,
            "error": CyberTheme.NEON_RED,
            "running": CyberTheme.NEON_PURPLE
        }
        self.status_label.config(text=f"[ {text.upper()} ]", fg=colors.get(status_type, CyberTheme.TEXT_PRIMARY))
    
    def start_progress(self):
        self.progress.start(10)
    
    def stop_progress(self):
        self.progress.stop()


class OutputConsole(tk.Frame):
    """Matrix-style output console"""
    
    def __init__(self, parent):
        super().__init__(parent, bg=CyberTheme.BG_DARK)
        
        # Header
        header = tk.Frame(self, bg=CyberTheme.BG_CARD)
        header.pack(fill=tk.X)
        
        tk.Label(
            header, text="◉ OUTPUT CONSOLE", font=CyberTheme.FONT_MAIN,
            fg=CyberTheme.NEON_GREEN, bg=CyberTheme.BG_CARD
        ).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Clear button
        tk.Button(
            header, text="CLEAR", font=CyberTheme.FONT_SMALL,
            fg=CyberTheme.NEON_RED, bg=CyberTheme.BG_CARD,
            command=self.clear, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Export button
        tk.Button(
            header, text="EXPORT", font=CyberTheme.FONT_SMALL,
            fg=CyberTheme.NEON_BLUE, bg=CyberTheme.BG_CARD,
            command=self.export, relief=tk.FLAT, cursor="hand2"
        ).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Text area
        self.text = scrolledtext.ScrolledText(
            self, font=("Fira Code", 9), bg=CyberTheme.BG_MEDIUM,
            fg=CyberTheme.NEON_GREEN, insertbackground=CyberTheme.NEON_GREEN,
            relief=tk.FLAT, wrap=tk.WORD
        )
        self.text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Configure tags for colored output
        self.text.tag_config("info", foreground=CyberTheme.NEON_BLUE)
        self.text.tag_config("success", foreground=CyberTheme.NEON_GREEN)
        self.text.tag_config("warning", foreground=CyberTheme.NEON_YELLOW)
        self.text.tag_config("error", foreground=CyberTheme.NEON_RED)
        self.text.tag_config("header", foreground=CyberTheme.NEON_PURPLE, font=("Consolas", 10, "bold"))
        self.text.tag_config("highlight", foreground=CyberTheme.NEON_PINK)
        self.text.tag_config("dim", foreground=CyberTheme.TEXT_DIM)
        
        self.log_queue = queue.Queue()
        self.process_queue()
    
    def process_queue(self):
        try:
            while True:
                message, tag = self.log_queue.get_nowait()
                self.text.insert(tk.END, message + "\n", tag)
                self.text.see(tk.END)
        except queue.Empty:
            pass
        self.after(100, self.process_queue)
    
    def log(self, message, tag="success"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put((f"[{timestamp}] {message}", tag))
    
    def log_header(self, title):
        separator = "═" * 60
        self.log(f"\n{separator}", "header")
        self.log(f"  {title}", "header")
        self.log(f"{separator}\n", "header")
    
    def clear(self):
        self.text.delete(1.0, tk.END)
    
    def export(self):
        content = self.text.get(1.0, tk.END)
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(content)


class TargetInput(tk.Frame):
    """Styled target input section"""
    
    def __init__(self, parent):
        super().__init__(parent, bg=CyberTheme.BG_DARK)
        
        # Label
        tk.Label(
            self, text="🎯 TARGET:", font=CyberTheme.FONT_HEADER,
            fg=CyberTheme.NEON_GREEN, bg=CyberTheme.BG_DARK
        ).pack(side=tk.LEFT, padx=5)
        
        # Entry
        self.entry = tk.Entry(
            self, font=CyberTheme.FONT_MAIN, width=50,
            bg=CyberTheme.BG_CARD, fg=CyberTheme.NEON_BLUE,
            insertbackground=CyberTheme.NEON_BLUE, relief=tk.FLAT
        )
        self.entry.pack(side=tk.LEFT, padx=10, ipady=8)
        self.entry.insert(0, "example.com")
        
        # Scope indicator
        self.scope_label = tk.Label(
            self, text="● IN SCOPE", font=CyberTheme.FONT_SMALL,
            fg=CyberTheme.NEON_GREEN, bg=CyberTheme.BG_DARK
        )
        self.scope_label.pack(side=tk.LEFT, padx=10)
    
    def get_target(self):
        return self.entry.get().strip()


class ModuleCard(tk.Frame):
    """Individual module card with icon and description"""
    
    def __init__(self, parent, title, description, icon, color, command):
        super().__init__(parent, bg=CyberTheme.BG_CARD, cursor="hand2")
        
        self.color = color
        self.configure(highlightbackground=CyberTheme.TEXT_DIM, highlightthickness=1)
        
        # Icon and title
        header = tk.Frame(self, bg=CyberTheme.BG_CARD)
        header.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(
            header, text=icon, font=("Segoe UI Emoji", 16),
            bg=CyberTheme.BG_CARD
        ).pack(side=tk.LEFT)
        
        tk.Label(
            header, text=title, font=CyberTheme.FONT_MAIN,
            fg=color, bg=CyberTheme.BG_CARD
        ).pack(side=tk.LEFT, padx=5)
        
        # Description
        tk.Label(
            self, text=description, font=CyberTheme.FONT_SMALL,
            fg=CyberTheme.TEXT_SECONDARY, bg=CyberTheme.BG_CARD,
            wraplength=150
        ).pack(padx=10, pady=5)
        
        # Bind events
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", lambda e: command())
        
        for child in self.winfo_children():
            child.bind("<Enter>", self.on_enter)
            child.bind("<Leave>", self.on_leave)
            child.bind("<Button-1>", lambda e: command())
            for subchild in child.winfo_children():
                subchild.bind("<Button-1>", lambda e: command())
    
    def on_enter(self, event):
        self.configure(highlightbackground=self.color, highlightthickness=2)
    
    def on_leave(self, event):
        self.configure(highlightbackground=CyberTheme.TEXT_DIM, highlightthickness=1)


class ResultsTable(tk.Frame):
    """Styled results table"""
    
    def __init__(self, parent):
        super().__init__(parent, bg=CyberTheme.BG_DARK)
        
        # Header
        header = tk.Frame(self, bg=CyberTheme.BG_CARD)
        header.pack(fill=tk.X)
        
        tk.Label(
            header, text="📊 RESULTS", font=CyberTheme.FONT_MAIN,
            fg=CyberTheme.NEON_PURPLE, bg=CyberTheme.BG_CARD
        ).pack(side=tk.LEFT, padx=10, pady=5)
        
        self.count_label = tk.Label(
            header, text="[0 items]", font=CyberTheme.FONT_SMALL,
            fg=CyberTheme.TEXT_SECONDARY, bg=CyberTheme.BG_CARD
        )
        self.count_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Treeview
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Cyber.Treeview",
            background=CyberTheme.BG_MEDIUM,
            foreground=CyberTheme.NEON_GREEN,
            fieldbackground=CyberTheme.BG_MEDIUM,
            font=CyberTheme.FONT_SMALL
        )
        style.configure("Cyber.Treeview.Heading",
            background=CyberTheme.BG_CARD,
            foreground=CyberTheme.NEON_BLUE,
            font=CyberTheme.FONT_MAIN
        )
        style.map("Cyber.Treeview",
            background=[('selected', CyberTheme.BG_CARD)],
            foreground=[('selected', CyberTheme.NEON_PINK)]
        )
        
        columns = ("Type", "Value", "Status", "Details")
        self.tree = ttk.Treeview(self, columns=columns, show='headings', style="Cyber.Treeview")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Context menu
        self.context_menu = tk.Menu(self, tearoff=0, bg=CyberTheme.BG_CARD, fg=CyberTheme.NEON_GREEN)
        self.context_menu.add_command(label="Copy", command=self.copy_selected)
        self.context_menu.add_command(label="Open in Browser", command=self.open_in_browser)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Export All", command=self.export_results)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def add_result(self, type_name, value, status="Found", details=""):
        self.tree.insert('', tk.END, values=(type_name, value, status, details))
        count = len(self.tree.get_children())
        self.count_label.config(text=f"[{count} items]")
    
    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.count_label.config(text="[0 items]")
    
    def show_context_menu(self, event):
        try:
            self.tree.selection_set(self.tree.identify_row(event.y))
            self.context_menu.post(event.x_root, event.y_root)
        except:
            pass
    
    def copy_selected(self):
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0])['values']
            self.clipboard_clear()
            self.clipboard_append(str(values[1]))
    
    def open_in_browser(self):
        selected = self.tree.selection()
        if selected:
            value = self.tree.item(selected[0])['values'][1]
            if not value.startswith('http'):
                value = f"https://{value}"
            webbrowser.open(value)
    
    def export_results(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json")]
        )
        if filename:
            data = []
            for item in self.tree.get_children():
                data.append(self.tree.item(item)['values'])
            
            if filename.endswith('.json'):
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Type", "Value", "Status", "Details"])
                    writer.writerows(data)


class SettingsPanel(tk.Toplevel):
    """Settings configuration panel"""
    
    def __init__(self, parent, settings):
        super().__init__(parent)
        
        self.settings = settings
        self.title("⚙ Settings")
        self.geometry("500x600")
        self.configure(bg=CyberTheme.BG_DARK)
        
        # Make it modal
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
    
    def create_widgets(self):
        # Title
        tk.Label(
            self, text="⚙ CONFIGURATION", font=CyberTheme.FONT_HEADER,
            fg=CyberTheme.NEON_PURPLE, bg=CyberTheme.BG_DARK
        ).pack(pady=20)
        
        settings_frame = tk.Frame(self, bg=CyberTheme.BG_DARK)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        # Threading settings
        self.create_section(settings_frame, "Threading", [
            ("Threads:", "threads", 10),
            ("Timeout (s):", "timeout", 5),
            ("Rate Limit:", "rate_limit", 100)
        ])
        
        # Port scan settings
        self.create_section(settings_frame, "Port Scanner", [
            ("Port Range:", "port_range", "1-1000"),
            ("Scan Type:", "scan_type", "TCP")
        ])
        
        # Wordlist settings
        self.create_section(settings_frame, "Wordlists", [
            ("Subdomain List:", "subdomain_wordlist", "wordlists/subdomains.txt"),
            ("Directory List:", "dir_wordlist", "wordlists/directories.txt")
        ])
        
        # Save button
        ModernButton(
            self, "SAVE SETTINGS", self.save_settings,
            color=CyberTheme.NEON_GREEN, width=200
        ).pack(pady=20)
    
    def create_section(self, parent, title, fields):
        frame = tk.LabelFrame(
            parent, text=title, font=CyberTheme.FONT_MAIN,
            fg=CyberTheme.NEON_BLUE, bg=CyberTheme.BG_DARK
        )
        frame.pack(fill=tk.X, pady=10)
        
        for label, key, default in fields:
            row = tk.Frame(frame, bg=CyberTheme.BG_DARK)
            row.pack(fill=tk.X, padx=10, pady=5)
            
            tk.Label(
                row, text=label, font=CyberTheme.FONT_SMALL,
                fg=CyberTheme.TEXT_SECONDARY, bg=CyberTheme.BG_DARK,
                width=15, anchor='w'
            ).pack(side=tk.LEFT)
            
            entry = tk.Entry(
                row, font=CyberTheme.FONT_SMALL,
                bg=CyberTheme.BG_CARD, fg=CyberTheme.NEON_GREEN,
                insertbackground=CyberTheme.NEON_GREEN, relief=tk.FLAT
            )
            entry.insert(0, self.settings.get(key, default))
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)
            
            setattr(self, f"entry_{key}", entry)
    
    def save_settings(self):
        for key in self.settings.keys():
            entry = getattr(self, f"entry_{key}", None)
            if entry:
                self.settings[key] = entry.get()
        
        messagebox.showinfo("Settings", "Settings saved successfully!")
        self.destroy()


class ReconX(tk.Tk):
    """Main Application Window"""
    
    def __init__(self):
        super().__init__()
        
        self.title("ReconX - Advanced Bug Bounty Recon Tool")
        self.geometry("1400x900")
        self.configure(bg=CyberTheme.BG_DARK)
        
        # Settings
        self.settings = {
            "threads": 10,
            "timeout": 5,
            "rate_limit": 100,
            "port_range": "1-1000",
            "scan_type": "TCP",
            "subdomain_wordlist": "wordlists/subdomains.txt",
            "dir_wordlist": "wordlists/directories.txt"
        }
        
        # Task queue
        self.task_queue = queue.Queue()
        self.is_running = False
        
        self.create_widgets()
        self.create_menu()
    
    def create_menu(self):
        menubar = tk.Menu(self, bg=CyberTheme.BG_CARD, fg=CyberTheme.NEON_GREEN)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=CyberTheme.BG_CARD, fg=CyberTheme.NEON_GREEN)
        file_menu.add_command(label="Import Targets", command=self.import_targets)
        file_menu.add_command(label="Export Results", command=self.export_all)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=CyberTheme.BG_CARD, fg=CyberTheme.NEON_GREEN)
        tools_menu.add_command(label="Settings", command=self.open_settings)
        tools_menu.add_command(label="Clear All", command=self.clear_all)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=CyberTheme.BG_CARD, fg=CyberTheme.NEON_GREEN)
        help_menu.add_command(label="Documentation", command=lambda: webbrowser.open("https://github.com"))
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.config(menu=menubar)
    
    def create_widgets(self):
        # Main container
        main_container = tk.Frame(self, bg=CyberTheme.BG_DARK)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Banner
        self.banner = AnimatedBanner(main_container)
        self.banner.pack(fill=tk.X, pady=(0, 10))
        
        # Target input
        self.target_input = TargetInput(main_container)
        self.target_input.pack(fill=tk.X, pady=10)
        
        # Content area
        content = tk.Frame(main_container, bg=CyberTheme.BG_DARK)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Modules
        left_panel = tk.Frame(content, bg=CyberTheme.BG_DARK, width=400)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Module header
        tk.Label(
            left_panel, text="🔧 RECON MODULES", font=CyberTheme.FONT_HEADER,
            fg=CyberTheme.NEON_BLUE, bg=CyberTheme.BG_DARK
        ).pack(anchor='w', pady=10)
        
        # Module grid
        modules_frame = tk.Frame(left_panel, bg=CyberTheme.BG_DARK)
        modules_frame.pack(fill=tk.BOTH, expand=True)
        
        modules = [
            ("Subdomain Enum", "Find subdomains", "🌐", CyberTheme.NEON_GREEN, self.run_subdomain),
            ("Port Scanner", "Scan open ports", "🔌", CyberTheme.NEON_BLUE, self.run_portscan),
            ("Dir Bruteforce", "Find directories", "📁", CyberTheme.NEON_PURPLE, self.run_dirbrute),
            ("Tech Detection", "Identify technologies", "🔬", CyberTheme.NEON_PINK, self.run_techdetect),
            ("DNS Enum", "DNS records", "📡", CyberTheme.NEON_ORANGE, self.run_dnsenum),
            ("Header Analysis", "Security headers", "🛡", CyberTheme.NEON_YELLOW, self.run_headers),
            ("Wayback URLs", "Historical URLs", "⏰", CyberTheme.NEON_GREEN, self.run_wayback),
            ("WHOIS Lookup", "Domain info", "📋", CyberTheme.NEON_BLUE, self.run_whois),
            ("Vuln Scanner", "Basic vuln scan", "🐛", CyberTheme.NEON_RED, self.run_vulnscan),
            ("Full Recon", "Run all modules", "🚀", CyberTheme.NEON_PURPLE, self.run_full_recon),
        ]
        
        for i, (title, desc, icon, color, cmd) in enumerate(modules):
            card = ModuleCard(modules_frame, title, desc, icon, color, cmd)
            card.grid(row=i//2, column=i%2, padx=5, pady=5, sticky='nsew')
        
        modules_frame.columnconfigure(0, weight=1)
        modules_frame.columnconfigure(1, weight=1)
        
        # Quick actions
        quick_frame = tk.Frame(left_panel, bg=CyberTheme.BG_DARK)
        quick_frame.pack(fill=tk.X, pady=10)
        
        ModernButton(
            quick_frame, "⏹ STOP", self.stop_scan,
            color=CyberTheme.NEON_RED, width=120
        ).pack(side=tk.LEFT, padx=5)
        
        ModernButton(
            quick_frame, "🔄 CLEAR", self.clear_all,
            color=CyberTheme.NEON_YELLOW, width=120
        ).pack(side=tk.LEFT, padx=5)
        
        # Right panel - Output and Results
        right_panel = tk.Frame(content, bg=CyberTheme.BG_DARK)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Notebook for tabs
        style = ttk.Style()
        style.configure("Cyber.TNotebook", background=CyberTheme.BG_DARK)
        style.configure("Cyber.TNotebook.Tab", 
            background=CyberTheme.BG_CARD,
            foreground=CyberTheme.NEON_GREEN,
            padding=[20, 10]
        )
        style.map("Cyber.TNotebook.Tab",
            background=[("selected", CyberTheme.BG_LIGHT)],
            foreground=[("selected", CyberTheme.NEON_BLUE)]
        )
        
        notebook = ttk.Notebook(right_panel, style="Cyber.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Console tab
        console_frame = tk.Frame(notebook, bg=CyberTheme.BG_DARK)
        self.console = OutputConsole(console_frame)
        self.console.pack(fill=tk.BOTH, expand=True)
        notebook.add(console_frame, text="📟 Console")
        
        # Results tab
        results_frame = tk.Frame(notebook, bg=CyberTheme.BG_DARK)
        self.results_table = ResultsTable(results_frame)
        self.results_table.pack(fill=tk.BOTH, expand=True)
        notebook.add(results_frame, text="📊 Results")
        
        # Stats tab
        stats_frame = tk.Frame(notebook, bg=CyberTheme.BG_DARK)
        self.create_stats_panel(stats_frame)
        notebook.add(stats_frame, text="📈 Statistics")
        
        # Status bar
        self.status_bar = StatusBar(main_container)
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Welcome message
        self.console.log_header("RECONX INITIALIZED")
        self.console.log("Welcome to ReconX - Advanced Bug Bounty Recon Tool", "info")
        self.console.log("Enter a target domain and select a module to begin", "dim")
        self.console.log("Use responsibly and only on authorized targets!", "warning")
    
    def create_stats_panel(self, parent):
        """Create statistics panel"""
        stats = tk.Frame(parent, bg=CyberTheme.BG_DARK)
        stats.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Stats counters
        self.stats = {
            "subdomains": tk.StringVar(value="0"),
            "ports": tk.StringVar(value="0"),
            "directories": tk.StringVar(value="0"),
            "vulnerabilities": tk.StringVar(value="0")
        }
        
        stat_items = [
            ("🌐 Subdomains", "subdomains", CyberTheme.NEON_GREEN),
            ("🔌 Open Ports", "ports", CyberTheme.NEON_BLUE),
            ("📁 Directories", "directories", CyberTheme.NEON_PURPLE),
            ("🐛 Vulnerabilities", "vulnerabilities", CyberTheme.NEON_RED)
        ]
        
        for i, (label, key, color) in enumerate(stat_items):
            frame = tk.Frame(stats, bg=CyberTheme.BG_CARD, padx=30, pady=20)
            frame.grid(row=0, column=i, padx=10, pady=10, sticky='nsew')
            
            tk.Label(
                frame, textvariable=self.stats[key],
                font=("Consolas", 36, "bold"),
                fg=color, bg=CyberTheme.BG_CARD
            ).pack()
            
            tk.Label(
                frame, text=label, font=CyberTheme.FONT_SMALL,
                fg=CyberTheme.TEXT_SECONDARY, bg=CyberTheme.BG_CARD
            ).pack()
        
        stats.columnconfigure((0,1,2,3), weight=1)
    
    def get_target(self):
        target = self.target_input.get_target()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target domain!")
            return None
        return target
    
    def run_in_thread(self, func, *args):
        """Run function in separate thread"""
        if self.is_running:
            messagebox.showinfo("Info", "A scan is already running!")
            return
        
        self.is_running = True
        self.status_bar.start_progress()
        
        def wrapper():
            try:
                func(*args)
            except Exception as e:
                self.console.log(f"Error: {str(e)}", "error")
            finally:
                self.is_running = False
                self.status_bar.stop_progress()
                self.status_bar.set_status("Completed", "success")
        
        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()
    
    # Module execution methods
    def run_subdomain(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"SUBDOMAIN ENUMERATION: {target}")
        self.status_bar.set_status("Enumerating Subdomains", "running")
        
        def scan():
            enumerator = SubdomainEnumerator(
                target,
                wordlist=self.settings.get("subdomain_wordlist"),
                threads=int(self.settings.get("threads", 10))
            )
            
            count = 0
            for subdomain in enumerator.enumerate():
                self.console.log(f"[+] Found: {subdomain}", "success")
                self.results_table.add_result("Subdomain", subdomain, "Active", "")
                count += 1
            
            self.stats["subdomains"].set(str(count))
            self.console.log(f"\n[*] Total subdomains found: {count}", "info")
        
        self.run_in_thread(scan)
    
    def run_portscan(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"PORT SCANNING: {target}")
        self.status_bar.set_status("Scanning Ports", "running")
        
        def scan():
            scanner = PortScanner(
                target,
                port_range=self.settings.get("port_range", "1-1000"),
                threads=int(self.settings.get("threads", 10)),
                timeout=int(self.settings.get("timeout", 5))
            )
            
            count = 0
            for port, service in scanner.scan():
                self.console.log(f"[+] Port {port} - {service}", "success")
                self.results_table.add_result("Port", str(port), "Open", service)
                count += 1
            
            self.stats["ports"].set(str(count))
            self.console.log(f"\n[*] Total open ports: {count}", "info")
        
        self.run_in_thread(scan)
    
    def run_dirbrute(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"DIRECTORY BRUTEFORCE: {target}")
        self.status_bar.set_status("Bruteforcing Directories", "running")
        
        def scan():
            bruter = DirectoryBruter(
                target,
                wordlist=self.settings.get("dir_wordlist"),
                threads=int(self.settings.get("threads", 10))
            )
            
            count = 0
            for path, status, size in bruter.brute():
                color = "success" if status == 200 else "warning"
                self.console.log(f"[{status}] {path} - {size} bytes", color)
                self.results_table.add_result("Directory", path, str(status), f"{size} bytes")
                count += 1
            
            self.stats["directories"].set(str(count))
            self.console.log(f"\n[*] Total paths found: {count}", "info")
        
        self.run_in_thread(scan)
    
    def run_techdetect(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"TECHNOLOGY DETECTION: {target}")
        self.status_bar.set_status("Detecting Technologies", "running")
        
        def scan():
            detector = TechDetector(target)
            
            for tech, version, category in detector.detect():
                self.console.log(f"[+] {category}: {tech} {version}", "success")
                self.results_table.add_result("Technology", tech, category, version)
            
            self.console.log("\n[*] Technology detection complete", "info")
        
        self.run_in_thread(scan)
    
    def run_dnsenum(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"DNS ENUMERATION: {target}")
        self.status_bar.set_status("Enumerating DNS", "running")
        
        def scan():
            enumerator = DNSEnumerator(target)
            
            for record_type, value in enumerator.enumerate():
                self.console.log(f"[{record_type}] {value}", "success")
                self.results_table.add_result("DNS", value, record_type, "")
            
            self.console.log("\n[*] DNS enumeration complete", "info")
        
        self.run_in_thread(scan)
    
    def run_headers(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"HEADER ANALYSIS: {target}")
        self.status_bar.set_status("Analyzing Headers", "running")
        
        def scan():
            analyzer = HeaderAnalyzer(target)
            
            for header, value, status in analyzer.analyze():
                color = "success" if status == "secure" else "warning" if status == "info" else "error"
                self.console.log(f"[{status.upper()}] {header}: {value}", color)
                self.results_table.add_result("Header", header, status, value[:50])
            
            self.console.log("\n[*] Header analysis complete", "info")
        
        self.run_in_thread(scan)
    
    def run_wayback(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"WAYBACK MACHINE: {target}")
        self.status_bar.set_status("Fetching Wayback URLs", "running")
        
        def scan():
            wayback = WaybackMachine(target)
            
            count = 0
            for url in wayback.get_urls():
                self.console.log(f"[+] {url}", "success")
                self.results_table.add_result("Wayback URL", url, "Archived", "")
                count += 1
                if count >= 100:  # Limit output
                    self.console.log("[*] Limiting to 100 URLs...", "warning")
                    break
            
            self.console.log(f"\n[*] Total archived URLs: {count}", "info")
        
        self.run_in_thread(scan)
    
    def run_whois(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"WHOIS LOOKUP: {target}")
        self.status_bar.set_status("Performing WHOIS Lookup", "running")
        
        def scan():
            lookup = WhoisLookup(target)
            
            for field, value in lookup.lookup():
                self.console.log(f"[+] {field}: {value}", "success")
                self.results_table.add_result("WHOIS", field, "Info", value[:50])
            
            self.console.log("\n[*] WHOIS lookup complete", "info")
        
        self.run_in_thread(scan)
    
    def run_vulnscan(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"VULNERABILITY SCAN: {target}")
        self.status_bar.set_status("Scanning for Vulnerabilities", "running")
        
        def scan():
            scanner = VulnScanner(target)
            
            count = 0
            for vuln_type, details, severity in scanner.scan():
                color = "error" if severity == "high" else "warning" if severity == "medium" else "info"
                self.console.log(f"[{severity.upper()}] {vuln_type}: {details}", color)
                self.results_table.add_result("Vulnerability", vuln_type, severity, details[:50])
                count += 1
            
            self.stats["vulnerabilities"].set(str(count))
            self.console.log(f"\n[*] Total potential vulnerabilities: {count}", "info")
        
        self.run_in_thread(scan)
    
    def run_full_recon(self):
        target = self.get_target()
        if not target:
            return
        
        self.console.log_header(f"FULL RECONNAISSANCE: {target}")
        self.status_bar.set_status("Running Full Recon", "running")
        
        def full_scan():
            modules = [
                ("Subdomain Enumeration", self.run_subdomain),
                ("Port Scanning", self.run_portscan),
                ("Technology Detection", self.run_techdetect),
                ("DNS Enumeration", self.run_dnsenum),
                ("Header Analysis", self.run_headers),
                ("WHOIS Lookup", self.run_whois),
                ("Vulnerability Scan", self.run_vulnscan)
            ]
            
            for name, func in modules:
                self.console.log(f"\n[*] Starting {name}...", "info")
                self.is_running = False  # Allow next module
                func()
                import time
                time.sleep(2)  # Wait between modules
            
            self.console.log_header("FULL RECONNAISSANCE COMPLETE")
        
        thread = threading.Thread(target=full_scan, daemon=True)
        thread.start()
    
    def stop_scan(self):
        self.is_running = False
        self.status_bar.stop_progress()
        self.status_bar.set_status("Stopped", "warning")
        self.console.log("\n[!] Scan stopped by user", "warning")
    
    def clear_all(self):
        self.console.clear()
        self.results_table.clear()
        for key in self.stats:
            self.stats[key].set("0")
        self.status_bar.set_status("Ready", "info")
    
    def import_targets(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'r') as f:
                targets = f.read().strip().split('\n')
            self.console.log(f"[*] Imported {len(targets)} targets", "info")
    
    def export_all(self):
        self.results_table.export_results()
    
    def open_settings(self):
        SettingsPanel(self, self.settings)
    
    def show_about(self):
        about_text = """
╔══════════════════════════════════════╗
║         RECONX v2.0                  ║
║  Advanced Bug Bounty Recon Tool      ║
║                                      ║
║  Features:                           ║
║  • Subdomain Enumeration             ║
║  • Port Scanning                     ║
║  • Directory Bruteforcing            ║
║  • Technology Detection              ║
║  • DNS Enumeration                   ║
║  • Security Header Analysis          ║
║  • Wayback Machine Integration       ║
║  • WHOIS Lookup                      ║
║  • Basic Vulnerability Scanning      ║
║                                      ║
║  For Educational Purposes Only       ║
║  Use Responsibly!                    ║
╚══════════════════════════════════════╝
        """
        messagebox.showinfo("About ReconX", about_text)


if __name__ == "__main__":
    app = ReconX()
    app.mainloop()
