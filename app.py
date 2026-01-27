# hsdcm.py - VERSÃO CORRIGIDA PARA PRODUÇÃO COM PÁGINAS DE ERRO E ABOUT
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import asyncio
import aiohttp
import socketio
import json
import os
import hashlib
import base64
import time
import threading
import uuid
from pathlib import Path
import mimetypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import tempfile
import webbrowser
import io
import logging
import socket
import random
import secrets
from datetime import datetime, timedelta
import math
import struct
import sqlite3
import ssl
import subprocess
import platform
import zipfile
import shutil
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from socketserver import ThreadingMixIn
import requests
from PIL import Image, ImageTk
import sys
import contextlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import queue
import re
import inspect

if not hasattr(aiohttp, "ClientWSTimeout"):
    class ClientWSTimeout(aiohttp.ClientTimeout):
        """Compatibility shim for aiohttp versions missing ClientWSTimeout."""
        def __init__(self, *args, **kwargs):
            allowed = set(inspect.signature(aiohttp.ClientTimeout).parameters.keys())
            if kwargs:
                kwargs = {k: v for k, v in kwargs.items() if k in allowed}
            super().__init__(*args, **kwargs)

    aiohttp.ClientWSTimeout = ClientWSTimeout

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HSDCM")

class TextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.see(tk.END)
            self.text_widget.config(state=tk.DISABLED)
        self.text_widget.after(0, append)

class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_db()
            return cls._instance

    def _init_db(self):
        self.db_path = os.path.join(os.path.expanduser("~"), ".hsdcm", "hsdcm.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._connection_lock = threading.RLock()
        self._init_schema()

    def _init_schema(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_content_cache (
                    content_hash TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    last_accessed REAL NOT NULL,
                    title TEXT,
                    description TEXT,
                    username TEXT,
                    signature TEXT,
                    public_key TEXT,
                    verified INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'cached',
                    network_sources INTEGER DEFAULT 0,
                    last_network_check REAL DEFAULT 0,
                    is_published INTEGER DEFAULT 0,
                    integrity_ok INTEGER DEFAULT 1,
                    reputation INTEGER DEFAULT 100,
                    created_at REAL NOT NULL,
                    header_present INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_dns_cache (
                    domain TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    verified INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL,
                    ttl INTEGER DEFAULT 3600,
                    last_resolved REAL DEFAULT 0,
                    resolution_count INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_pending_requests (
                    request_id TEXT PRIMARY KEY,
                    handler_data TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    request_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    connection_keep_alive BOOLEAN DEFAULT 1,
                    status TEXT DEFAULT 'pending',
                    retry_count INTEGER DEFAULT 0,
                    last_retry REAL DEFAULT 0,
                    priority INTEGER DEFAULT 1
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_server_cache (
                    server_address TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    reputation INTEGER DEFAULT 100,
                    last_connected REAL NOT NULL,
                    connection_count INTEGER DEFAULT 0,
                    avg_latency REAL DEFAULT 0,
                    successful_auths INTEGER DEFAULT 0,
                    failed_auths INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_node_stats (
                    node_id TEXT PRIMARY KEY,
                    total_downloads INTEGER DEFAULT 0,
                    total_uploads INTEGER DEFAULT 0,
                    total_searches INTEGER DEFAULT 0,
                    total_dns_resolutions INTEGER DEFAULT 0,
                    total_connections INTEGER DEFAULT 0,
                    total_bytes_sent INTEGER DEFAULT 0,
                    total_bytes_received INTEGER DEFAULT 0,
                    uptime REAL DEFAULT 0,
                    last_active REAL NOT NULL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_security_logs (
                    log_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    content_hash TEXT,
                    domain TEXT,
                    username TEXT,
                    result TEXT NOT NULL,
                    details TEXT,
                    timestamp REAL NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_reports (
                    report_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    reported_user TEXT NOT NULL,
                    reporter_user TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    status TEXT DEFAULT 'pending',
                    reason TEXT DEFAULT ''
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hsdcm_recent_files (
                    file_path TEXT PRIMARY KEY,
                    file_hash TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    processed INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_recent_files_timestamp
                ON hsdcm_recent_files(timestamp)
            ''')

            conn.commit()

    @contextlib.contextmanager
    def _get_connection(self):
        with self._connection_lock:
            conn = None
            try:
                conn = sqlite3.connect(self.db_path, timeout=30.0)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA cache_size=10000")
                conn.execute("PRAGMA foreign_keys=ON")
                conn.row_factory = sqlite3.Row
                yield conn
            except sqlite3.Error as e:
                logger.error(f"Database error: {e}")
                raise
            finally:
                if conn:
                    conn.close()

    def execute_query(self, query, params=()):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor

    def fetch_one(self, query, params=()):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()

    def fetch_all(self, query, params=()):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()

    def log_security_action(self, action, content_hash=None, domain=None, username=None, result="success", details="", ip_address="", user_agent=""):
        try:
            log_id = hashlib.sha256(f"{action}{content_hash}{domain}{username}{time.time()}".encode()).hexdigest()
            self.execute_query('''
                INSERT INTO hsdcm_security_logs
                (log_id, action, content_hash, domain, username, result, details, timestamp, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (log_id, action, content_hash, domain, username, result, details, time.time(), ip_address, user_agent))
        except Exception as e:
            logger.error(f"Erro ao registrar ação de segurança: {e}")

    def add_recent_file(self, file_path, file_hash, action):
        try:
            self.execute_query('''
                INSERT OR REPLACE INTO hsdcm_recent_files
                (file_path, file_hash, action, timestamp, processed)
                VALUES (?, ?, ?, ?, ?)
            ''', (file_path, file_hash, action, time.time(), 0))
        except Exception as e:
            logger.error(f"Erro ao registrar arquivo recente: {e}")

    def is_recent_file(self, file_path, max_age_seconds=10):
        try:
            result = self.fetch_one(
                'SELECT file_path FROM hsdcm_recent_files WHERE file_path = ? AND timestamp > ?',
                (file_path, time.time() - max_age_seconds)
            )
            return result is not None
        except Exception as e:
            logger.error(f"Erro ao verificar arquivo recente: {e}")
            return False

    def cleanup_old_recent_files(self, max_age_seconds=300):
        try:
            self.execute_query(
                'DELETE FROM hsdcm_recent_files WHERE timestamp < ?',
                (time.time() - max_age_seconds,)
            )
        except Exception as e:
            logger.error(f"Erro ao limpar arquivos recentes antigos: {e}")

class SecurityDialog:
    def __init__(self, parent, content_info, action="download", client=None):
        self.window = tk.Toplevel(parent)
        self.window.title("Verificação de Segurança")
        self.window.geometry("950x700")
        self.window.transient(parent)
        self.window.grab_set()

        self.content_info = content_info
        self.action = action
        self.client = client
        self.user_choice = None

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Verificação de Segurança do Conteúdo", font=("Arial", 16, "bold")).pack(pady=10)

        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=10)

        verified = self.content_info.get('verified', False)
        integrity_ok = self.content_info.get('integrity_ok', True)

        if not integrity_ok:
            status_text = "CONTEÚDO ADULTERADO"
            status_color = "red"
        elif verified:
            status_text = "CONTEÚDO VERIFICADO"
            status_color = "green"
        else:
            status_text = "CONTEÚDO NÃO VERIFICADO"
            status_color = "orange"

        ttk.Label(status_frame, text=status_text, foreground=status_color, font=("Arial", 14, "bold")).pack()

        details_frame = ttk.LabelFrame(main_frame, text="Detalhes do Conteúdo", padding="10")
        details_frame.pack(fill=tk.X, pady=10)

        info_grid = ttk.Frame(details_frame)
        info_grid.pack(fill=tk.X)

        details = [
            ("Ação:", self.action.title()),
            ("Título:", self.content_info.get('title', 'N/A')),
            ("Autor:", self.content_info.get('username', 'N/A')),
            ("Hash:", self.content_info.get('content_hash', 'N/A')[:20] + "..." + self.content_info.get('content_hash', 'N/A')[-20:]),
            ("Tipo MIME:", self.content_info.get('mime_type', 'N/A')),
            ("Reputação do Autor:", str(self.content_info.get('reputation', 100))),
            ("Origem:", "Rede P2P HPS"),
            ("Tamanho:", self.format_size(self.content_info.get('size', 0))),
            ("Assinatura:", "VÁLIDA" if verified else "NÃO VERIFICADA"),
            ("Integridade:", "OK" if integrity_ok else "COMPROMETIDA"),
        ]

        for i, (label, value) in enumerate(details):
            ttk.Label(info_grid, text=label, font=("Arial", 10, "bold")).grid(row=i, column=0, sticky=tk.W, pady=1, padx=5)
            ttk.Label(info_grid, text=value, font=("Arial", 10)).grid(row=i, column=1, sticky=tk.W, pady=1, padx=5)

        sig_frame = ttk.LabelFrame(main_frame, text="Assinatura Digital", padding="10")
        sig_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        ttk.Label(sig_frame, text="Chave Pública do Autor:").pack(anchor=tk.W)
        pub_key_text = scrolledtext.ScrolledText(sig_frame, height=3)
        pub_key_text.pack(fill=tk.X, pady=5)

        pub_key = self.content_info.get('public_key', 'N/A')
        if pub_key and len(pub_key) > 100:
            pub_key_display = pub_key[:100] + "\n..." + pub_key[-100:]
        else:
            pub_key_display = pub_key

        pub_key_text.insert(tk.END, pub_key_display)
        pub_key_text.config(state=tk.DISABLED)

        ttk.Label(sig_frame, text="Assinatura:").pack(anchor=tk.W)
        sig_text = scrolledtext.ScrolledText(sig_frame, height=2)
        sig_text.pack(fill=tk.X, pady=5)

        signature = self.content_info.get('signature', 'N/A')
        if signature and len(signature) > 100:
            sig_display = signature[:50] + "..." + signature[-50:]
        else:
            sig_display = signature

        sig_text.insert(tk.END, sig_display)
        sig_text.config(state=tk.DISABLED)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=15)

        if self.action == "upload":
            ttk.Button(button_frame, text="Continuar Upload", command=lambda: self.allow_action(True), width=20).pack(side=tk.LEFT, padx=5)
        else:
            ttk.Button(button_frame, text="Permitir", command=lambda: self.allow_action(True), width=20).pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Copiar Hash", command=self.copy_hash, width=20).pack(side=tk.LEFT, padx=5)

        if self.action != "upload":
            ttk.Button(button_frame, text="Reportar", command=self.report_content, width=20).pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Cancelar", command=lambda: self.allow_action(False), width=20).pack(side=tk.LEFT, padx=5)

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def copy_hash(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.content_info.get('content_hash', ''))
        messagebox.showinfo("Copiado", "Hash copiado para área de transferência")

    def report_content(self):
        if not self.client:
            messagebox.showwarning("Aviso", "Cliente HPS indisponível para reporte.")
            return

        if not self.client.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar logado para reportar conteúdo.")
            return

        reported_user = self.content_info.get('username', '')
        if not reported_user:
            messagebox.showwarning("Aviso", "Autor não identificado para reporte.")
            return

        if reported_user == self.client.current_user:
            messagebox.showwarning("Aviso", "Você não pode reportar seu próprio conteúdo.")
            return

        if self.client.reputation < 20:
            messagebox.showwarning("Aviso", "Sua reputação é muito baixa para reportar conteúdo.")
            return

        if not messagebox.askyesno("Reportar Conteúdo", "Deseja reportar este conteúdo como inadequado?"):
            return

        content_hash = self.content_info.get('content_hash', '')
        if not content_hash:
            messagebox.showwarning("Aviso", "Hash do conteúdo não encontrado.")
            return

        def report_thread():
            success, result = self.client.report_content(content_hash, reported_user)
            if success:
                self.content_info['reported'] = True
                messagebox.showinfo("Reportado", f"Conteúdo reportado com sucesso.\nID: {result}")
            else:
                messagebox.showerror("Erro", f"Falha ao reportar conteúdo: {result}")

        threading.Thread(target=report_thread, daemon=True).start()

    def allow_action(self, allowed):
        self.user_choice = allowed
        self.window.destroy()

    def wait_for_choice(self):
        self.window.wait_window()
        return self.user_choice

class FastPowSolver:
    def __init__(self):
        self.is_solving = False
        self.current_challenge = None
        self.current_target_bits = 0
        self.solution_found = threading.Event()
        self.nonce_solution = None
        self.hashrate_observed = 0.0
        self.hash_count = 0
        self.start_time = 0
        self.stop_requested = False

    def leading_zero_bits(self, h: bytes) -> int:
        count = 0
        for byte in h:
            if byte == 0:
                count += 8
            else:
                count += bin(byte)[2:].zfill(8).index('1')
                break
        return count

    def solve_challenge(self, challenge: str, target_bits: int, timeout=30):
        if self.is_solving:
            return

        self.is_solving = True
        self.stop_requested = False
        self.solution_found.clear()
        self.nonce_solution = None
        self.current_challenge = challenge
        self.current_target_bits = target_bits
        self.hash_count = 0

        def solve_thread():
            try:
                challenge_bytes = base64.b64decode(challenge)
                self.start_time = time.time()

                num_threads = 4
                results_queue = queue.Queue()
                threads = []

                def worker(start_nonce, step):
                    nonce = start_nonce
                    local_hash_count = 0
                    local_start_time = time.time()

                    while not self.stop_requested and time.time() - self.start_time < timeout:
                        data = challenge_bytes + struct.pack(">Q", nonce)
                        hash_result = hashlib.sha256(data).digest()
                        local_hash_count += 1

                        lzb = self.leading_zero_bits(hash_result)

                        if lzb >= target_bits:
                            results_queue.put((nonce, local_hash_count / (time.time() - local_start_time)))
                            return

                        nonce += step

                    results_queue.put(None)

                for i in range(num_threads):
                    t = threading.Thread(target=worker, args=(i, num_threads), daemon=True)
                    t.start()
                    threads.append(t)

                solved = False
                for _ in range(num_threads):
                    result = results_queue.get(timeout=timeout + 5)
                    if result is not None and not solved:
                        nonce, hashrate = result
                        self.nonce_solution = str(nonce)
                        self.hashrate_observed = hashrate
                        solved = True
                        self.is_solving = False
                        self.solution_found.set()

                if not solved:
                    logger.warning(f"PoW não resolvido em {timeout} segundos")

                for t in threads:
                    t.join(timeout=1)

            except Exception as e:
                logger.error(f"Erro na mineração PoW: {e}")
            finally:
                self.is_solving = False

        threading.Thread(target=solve_thread, daemon=True).start()

    def stop_solving(self):
        self.stop_requested = True
        self.is_solving = False

class HPSClient:
    def __init__(self):
        self.current_user = None
        self.private_key = None
        self.public_key_pem = None
        self.session_id = str(uuid.uuid4())
        self.node_id = hashlib.sha256(self.session_id.encode()).hexdigest()[:32]
        self.connected = False
        self.current_server = None
        self.reputation = 100
        self.client_identifier = self.generate_client_identifier()
        self.server_public_keys = {}
        self.client_auth_challenge = None
        self.server_auth_challenge = None
        self.waiting_for_auth = False
        self.auth_success_event = threading.Event()
        self.server_auth_success = False
        self.content_request_timeout = 60
        self.max_retries = 3
        self.retry_delay = 5
        self.max_upload_size = 100 * 1024 * 1024
        self.disk_quota = 500 * 1024 * 1024
        self.upload_event = threading.Event()
        self.dns_event = threading.Event()
        self.report_event = threading.Event()
        self.upload_result = None
        self.dns_result = None
        self.report_result = None
        self.pow_event = threading.Event()
        self.pow_lock = threading.Lock()
        self.pow_challenge = None
        self.pow_solver = FastPowSolver()
        self.usage_contract_event = threading.Event()
        self.usage_contract_data = None
        self.usage_contract_ack_event = threading.Event()
        self.usage_contract_ack_data = None
        self.last_auth_error = None

        self.loop = None
        self.sio = None
        self.network_thread = None

        self.crypto_dir = os.path.join(os.path.expanduser("~"), ".hsdcm")
        os.makedirs(self.crypto_dir, exist_ok=True)
        self.db = DatabaseManager()

        self.content_availability_cache = {}
        self.content_download_events = {}
        self.content_download_locks = {}
        self.active_downloads = {}
        self.response_callbacks = {}
        self.callback_lock = threading.Lock()
        self.security_checks = {}
        self.upload_lock = threading.Lock()
        self.active_uploads = {}
        self.dns_resolution_cache = {}
        self.dns_lock = threading.Lock()

        self.setup_cryptography()
        self.start_network_thread()
        self.load_server_cache()
        self.start_stats_monitor()
        self.start_cleanup_thread()

    def generate_client_identifier(self):
        machine_id = hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()
        return hashlib.sha256((machine_id + self.session_id).encode()).hexdigest()

    def setup_cryptography(self):
        private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
        public_key_path = os.path.join(self.crypto_dir, "public_key.pem")

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                with open(public_key_path, "rb") as f:
                    self.public_key_pem = f.read()
                logger.info("Chaves criptográficas carregadas do armazenamento local.")
            except Exception as e:
                logger.error(f"Erro ao carregar chaves existentes: {e}. Gerando novas chaves.")
                self.generate_keys()
        else:
            self.generate_keys()

    def generate_keys(self):
        try:
            private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
            public_key_path = os.path.join(self.crypto_dir, "public_key.pem")

            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            self.public_key_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open(private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(public_key_path, "wb") as f:
                f.write(self.public_key_pem)

            logger.info("Novas chaves criptográficas geradas.")
        except Exception as e:
            logger.error(f"Erro ao gerar chaves: {e}")

    def load_server_cache(self):
        rows = self.db.fetch_all('SELECT server_address, public_key, reputation FROM hsdcm_server_cache')
        for row in rows:
            self.server_public_keys[row[0]] = row[1]

    def save_server_cache(self, server_address, public_key, reputation=100):
        try:
            self.db.execute_query('''
                INSERT OR REPLACE INTO hsdcm_server_cache
                (server_address, public_key, reputation, last_connected, connection_count, successful_auths)
                VALUES (?, ?, ?, ?, COALESCE((SELECT connection_count + 1 FROM hsdcm_server_cache WHERE server_address = ?), 1),
                COALESCE((SELECT successful_auths + 1 FROM hsdcm_server_cache WHERE server_address = ?), 1))
            ''', (server_address, public_key, reputation, time.time(), server_address, server_address))
        except Exception as e:
            logger.error(f"Erro ao salvar cache do servidor: {e}")

    def start_stats_monitor(self):
        def monitor():
            while True:
                try:
                    self.update_node_stats()
                    time.sleep(60)
                except Exception as e:
                    logger.error(f"Erro no monitor de estatísticas: {e}")
                    time.sleep(60)

        threading.Thread(target=monitor, daemon=True).start()

    def start_cleanup_thread(self):
        def cleanup():
            while True:
                try:
                    self.db.cleanup_old_recent_files(300)
                    time.sleep(60)
                except Exception as e:
                    logger.error(f"Erro na limpeza: {e}")
                    time.sleep(60)

        threading.Thread(target=cleanup, daemon=True).start()

    def update_node_stats(self):
        try:
            self.db.execute_query('''
                INSERT OR REPLACE INTO hsdcm_node_stats
                (node_id, last_active, uptime)
                VALUES (?, ?, COALESCE((SELECT uptime + 60 FROM hsdcm_node_stats WHERE node_id = ?), 60))
            ''', (self.node_id, time.time(), self.node_id))
        except Exception as e:
            logger.error(f"Erro ao atualizar estatísticas do nó: {e}")

    def start_network_thread(self):
        def run_network():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            self.sio = socketio.AsyncClient(
                ssl_verify=False,
                reconnection=True,
                reconnection_attempts=5,
                reconnection_delay=1,
                reconnection_delay_max=5,
                request_timeout=120
            )
            self.setup_socket_handlers()
            self.loop.run_forever()

        self.network_thread = threading.Thread(target=run_network, daemon=True)
        self.network_thread.start()

    def setup_socket_handlers(self):
        @self.sio.event
        async def connect():
            logger.info(f"Conectado ao servidor {self.current_server}")
            self.connected = True
            await self.sio.emit('request_server_auth_challenge', {})

        @self.sio.event
        async def disconnect():
            logger.info(f"Desconectado do servidor {self.current_server}")
            self.connected = False
            self.server_auth_success = False

        @self.sio.event
        async def server_auth_challenge(data):
            challenge = data.get('challenge')
            server_public_key_b64 = data.get('server_public_key')
            server_signature_b64 = data.get('signature')

            if not all([challenge, server_public_key_b64, server_signature_b64]):
                logger.error("Desafio de autenticação do servidor incompleto")
                self.auth_success_event.set()
                return

            try:
                server_public_key = serialization.load_pem_public_key(base64.b64decode(server_public_key_b64), backend=default_backend())
                server_public_key.verify(
                    base64.b64decode(server_signature_b64),
                    challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )

                self.server_public_keys[self.current_server] = server_public_key_b64
                self.save_server_cache(self.current_server, server_public_key_b64)

                client_challenge = secrets.token_urlsafe(32)
                self.client_auth_challenge = client_challenge

                client_signature = self.private_key.sign(
                    client_challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )

                await self.sio.emit('verify_server_auth_response', {
                    'client_challenge': client_challenge,
                    'client_signature': base64.b64encode(client_signature).decode('utf-8'),
                    'client_public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
                })

                logger.info("Resposta de autenticação do servidor enviada")

            except InvalidSignature:
                logger.error("Assinatura do servidor inválida")
                self.auth_success_event.set()
            except Exception as e:
                logger.error(f"Erro na autenticação do servidor: {e}")
                self.auth_success_event.set()

        @self.sio.event
        async def server_auth_result(data):
            success = data.get('success', False)
            if success:
                logger.info("Autenticação do servidor bem-sucedida")
                self.server_auth_success = True
            else:
                error = data.get('error', 'Erro desconhecido')
                logger.error(f"Falha na autenticação do servidor: {error}")
                self.server_auth_success = False
            self.auth_success_event.set()

        @self.sio.event
        async def content_response(data):
            content_hash = data.get('content_hash', '')

            if 'error' in data:
                logger.error(f"Erro no conteúdo {content_hash}: {data['error']}")
                with self.callback_lock:
                    if content_hash in self.response_callbacks:
                        callback = self.response_callbacks[content_hash]
                        if callback:
                            callback(data)
                        del self.response_callbacks[content_hash]
                if content_hash in self.content_download_events:
                    self.content_download_events[content_hash].set()
                return

            content_b64 = data.get('content')

            try:
                content = base64.b64decode(content_b64)

                header_present = 1 if b'### :END START' in content else 0

                content_info = {
                    'content_hash': content_hash,
                    'title': data.get('title', ''),
                    'description': data.get('description', ''),
                    'mime_type': data.get('mime_type', 'application/octet-stream'),
                    'username': data.get('username', ''),
                    'signature': data.get('signature', ''),
                    'public_key': data.get('public_key', ''),
                    'verified': data.get('verified', False),
                    'reputation': data.get('reputation', 100),
                    'size': len(content),
                    'header_present': header_present
                }

                self.save_content_to_storage(content_hash, content, content_info)

                with self.callback_lock:
                    if content_hash in self.response_callbacks:
                        callback = self.response_callbacks[content_hash]
                        if callback:
                            callback(data)
                        del self.response_callbacks[content_hash]

                if content_hash in self.content_download_events:
                    self.content_download_events[content_hash].set()

                logger.info(f"Conteúdo {content_hash} recebido e salvo")

            except Exception as e:
                logger.error(f"Erro ao processar conteúdo {content_hash}: {e}")
                if content_hash in self.content_download_events:
                    self.content_download_events[content_hash].set()

        @self.sio.event
        async def authentication_result(data):
            success = data.get('success', False)
            if success:
                self.current_user = data.get('username')
                self.reputation = data.get('reputation', 100)
                self.last_auth_error = None
                logger.info(f"Login bem-sucedido: {self.current_user}")
                if self.waiting_for_auth:
                    self.auth_success_event.set()
            else:
                self.last_auth_error = data.get('error', 'Erro desconhecido')
                logger.error(f"Falha no login: {self.last_auth_error}")
                if self.waiting_for_auth:
                    self.auth_success_event.set()

        @self.sio.event
        async def search_results(data):
            search_id = data.get('search_id', '')
            if 'error' in data:
                logger.error(f"Erro na busca {search_id}: {data['error']}")
                with self.callback_lock:
                    if search_id in self.response_callbacks:
                        callback = self.response_callbacks[search_id]
                        if callback:
                            callback(data)
                        del self.response_callbacks[search_id]
                return

            logger.info(f"Busca {search_id} retornou {len(data.get('results', []))} resultados")
            with self.callback_lock:
                if search_id in self.response_callbacks:
                    callback = self.response_callbacks[search_id]
                    if callback:
                        callback(data)
                    del self.response_callbacks[search_id]

        @self.sio.event
        async def dns_resolution(data):
            domain = data.get('domain', '')

            with self.callback_lock:
                if domain in self.response_callbacks:
                    callback = self.response_callbacks[domain]
                    if callback:
                        callback(data)
                    del self.response_callbacks[domain]

            if 'error' in data:
                logger.error(f"Falha na resolução DNS {domain}: {data.get('error', 'Erro desconhecido')}")
                return

            content_hash = data.get('content_hash')
            self.dns_resolution_cache[domain] = {
                'content_hash': content_hash,
                'timestamp': time.time(),
                'ttl': data.get('ttl', 3600)
            }

            logger.info(f"DNS resolvido: {domain} -> {content_hash}")

        @self.sio.event
        async def pow_challenge(data):
            if 'error' in data:
                logger.error(f"Erro no desafio PoW: {data['error']}")
            else:
                logger.info(f"Desafio PoW recebido: {data.get('target_bits', 0)} bits")
            with self.pow_lock:
                self.pow_challenge = data
            self.pow_event.set()

        @self.sio.event
        async def usage_contract_required(data):
            self.usage_contract_data = {'required': True, 'data': data}
            self.usage_contract_event.set()

        @self.sio.event
        async def usage_contract_status(data):
            self.usage_contract_data = {'required': data.get('required', False), 'data': data}
            self.usage_contract_event.set()

        @self.sio.event
        async def usage_contract_ack(data):
            self.usage_contract_ack_data = data
            self.usage_contract_ack_event.set()

        @self.sio.event
        async def content_availability(data):
            content_hash = data.get('content_hash', '')
            available = data.get('available', False)
            sources = data.get('sources', 0)

            self.content_availability_cache[content_hash] = {
                'available': available,
                'sources': sources,
                'timestamp': time.time()
            }

            if available:
                logger.info(f"Conteúdo {content_hash} disponível em {sources} fontes")
            else:
                logger.info(f"Conteúdo {content_hash} não disponível na rede")

        @self.sio.event
        async def publish_result(data):
            self.upload_result = data
            self.upload_event.set()

        @self.sio.event
        async def dns_result(data):
            self.dns_result = data
            self.dns_event.set()

        @self.sio.event
        async def report_result(data):
            self.report_result = data
            self.report_event.set()

        @self.sio.event
        async def reputation_update(data):
            self.reputation = data.get('reputation', self.reputation)

    async def connect_to_server(self, server_address):
        try:
            if self.sio:
                try:
                    await self.sio.disconnect()
                except Exception:
                    pass

            if server_address.startswith('https://'):
                server_url = server_address
            elif '://' in server_address:
                server_url = server_address
            else:
                server_url = f"https://{server_address}"

            logger.info(f"Conectando a {server_url}")

            connect_task = self.sio.connect(server_url, wait_timeout=10)
            await asyncio.wait_for(connect_task, timeout=15)

            self.current_server = server_address

            self.waiting_for_auth = True
            self.auth_success_event.clear()
            self.server_auth_success = False

            auth_task = asyncio.get_event_loop().run_in_executor(None, self.auth_success_event.wait, 15)
            success = await asyncio.wait_for(auth_task, timeout=20)

            self.waiting_for_auth = False

            return self.connected and self.server_auth_success
        except asyncio.TimeoutError:
            logger.error(f"Timeout ao conectar a {server_address}")
            self.waiting_for_auth = False
            return False
        except Exception as e:
            logger.error(f"Erro de conexão: {e}")
            self.waiting_for_auth = False
            return False

    async def authenticate(self, username, password, pow_nonce, hashrate_observed):
        if not self.connected:
            return False

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        client_challenge_signature = self.private_key.sign(
            self.client_auth_challenge.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        self.waiting_for_auth = True
        self.auth_success_event.clear()

        auth_data = {
            'username': username,
            'password_hash': password_hash,
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'node_type': 'client',
            'client_identifier': self.client_identifier,
            'pow_nonce': pow_nonce,
            'hashrate_observed': hashrate_observed,
            'client_challenge_signature': base64.b64encode(client_challenge_signature).decode('utf-8'),
            'client_challenge': self.client_auth_challenge
        }

        await self.sio.emit('authenticate', auth_data)

        auth_task = asyncio.get_event_loop().run_in_executor(None, self.auth_success_event.wait, 20)
        try:
            success = await asyncio.wait_for(auth_task, timeout=25)
            self.waiting_for_auth = False
            return self.current_user is not None
        except asyncio.TimeoutError:
            logger.error("Timeout na autenticação")
            self.waiting_for_auth = False
            return False

    async def request_content(self, content_hash, force_network=False):
        if not self.connected:
            return False

        if content_hash in self.active_downloads:
            return True

        self.active_downloads[content_hash] = True

        try:
            for attempt in range(self.max_retries):
                try:
                    request_task = self.sio.emit('request_content', {'content_hash': content_hash, 'force_network': force_network})
                    await asyncio.wait_for(request_task, timeout=5)

                    if content_hash not in self.content_download_events:
                        self.content_download_events[content_hash] = threading.Event()

                    event = self.content_download_events[content_hash]
                    event.clear()

                    success = event.wait(timeout=10)

                    if success:
                        return True
                    else:
                        logger.warning(f"Tentativa {attempt + 1}/{self.max_retries} falhou para {content_hash}")
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(self.retry_delay)

                except asyncio.TimeoutError:
                    logger.warning(f"Timeout na tentativa {attempt + 1} para {content_hash}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay)
                except Exception as e:
                    logger.error(f"Erro na tentativa {attempt + 1} para {content_hash}: {e}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay)

            return False

        finally:
            if content_hash in self.active_downloads:
                del self.active_downloads[content_hash]

    async def check_content_availability(self, content_hash):
        if not self.connected:
            return False

        try:
            await asyncio.wait_for(
                self.sio.emit('check_content_availability', {'content_hash': content_hash}),
                timeout=5
            )
            return True
        except asyncio.TimeoutError:
            logger.error(f"Timeout ao verificar disponibilidade de {content_hash}")
            return False
        except Exception as e:
            logger.error(f"Erro ao verificar disponibilidade: {e}")
            return False

    async def request_pow_challenge(self, action_type="upload"):
        if not self.connected:
            return None

        try:
            await asyncio.wait_for(
                self.sio.emit('request_pow_challenge', {
                    'client_identifier': self.client_identifier,
                    'action_type': action_type
                }),
                timeout=5
            )
            return True
        except asyncio.TimeoutError:
            logger.error("Timeout ao solicitar desafio PoW")
            return False
        except Exception as e:
            logger.error(f"Erro ao solicitar desafio PoW: {e}")
            return False

    def request_pow_solution(self, action_type, solver=None, timeout=30):
        if not self.connected:
            return None

        pow_solver = solver or self.pow_solver
        if pow_solver.is_solving:
            pow_solver.stop_solving()

        with self.pow_lock:
            self.pow_challenge = None
        self.pow_event.clear()

        try:
            request_task = asyncio.run_coroutine_threadsafe(
                self.sio.emit('request_pow_challenge', {
                    'client_identifier': self.client_identifier,
                    'action_type': action_type
                }),
                self.loop
            )
            request_task.result(timeout=5)
        except Exception as e:
            logger.error(f"Erro ao solicitar PoW: {e}")
            return None

        if not self.pow_event.wait(timeout=5):
            logger.error("Nenhum desafio PoW recebido")
            return None

        with self.pow_lock:
            pow_data = self.pow_challenge or {}

        if 'error' in pow_data:
            logger.error(f"Erro no desafio PoW: {pow_data.get('error')}")
            return None

        challenge = pow_data.get('challenge')
        target_bits = pow_data.get('target_bits')
        if not challenge or not target_bits:
            logger.error("Desafio PoW inválido")
            return None

        pow_solver.solve_challenge(challenge, target_bits, timeout=timeout)
        if not pow_solver.solution_found.wait(timeout=timeout + 5):
            logger.error("PoW não resolvido dentro do tempo limite")
            return None

        return pow_solver.nonce_solution, pow_solver.hashrate_observed

    def reset_usage_contract_state(self):
        self.usage_contract_event.clear()
        self.usage_contract_data = None
        self.usage_contract_ack_event.clear()
        self.usage_contract_ack_data = None

    async def request_usage_contract(self, username):
        if not self.connected:
            return False
        await self.sio.emit('request_usage_contract', {'username': username})
        return True

    async def accept_usage_contract(self, contract_text, pow_nonce, hashrate_observed):
        if not self.connected:
            return False
        payload = {
            'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'client_identifier': self.client_identifier,
            'pow_nonce': pow_nonce,
            'hashrate_observed': hashrate_observed
        }
        await self.sio.emit('accept_usage_contract', payload)
        return True

    def build_usage_contract_template(self, terms_text, contract_hash, username):
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            "# ACTION: accept_usage",
            f"# USAGE_CONTRACT_HASH: {contract_hash}",
            "### :END DETAILS",
            "### TERMS:"
        ]
        for line in (terms_text or "").splitlines():
            lines.append(f"# {line}")
        lines.extend([
            "### :END TERMS",
            "### START:",
            f"# USER: {username}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ])
        return "\n".join(lines) + "\n"

    def build_contract_template(self, action_type, details, username=None):
        username = username or self.current_user or ""
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            f"# ACTION: {action_type}"
        ]
        for key, value in details:
            lines.append(f"# {key}: {value}")
        lines.extend([
            "### :END DETAILS",
            "### START:",
            f"# USER: {username}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ])
        return "\n".join(lines) + "\n"

    def apply_contract_signature(self, contract_text):
        lines = contract_text.splitlines()
        signature_index = None
        signed_lines = []
        for idx, line in enumerate(lines):
            if line.strip().startswith("# SIGNATURE:"):
                signature_index = idx
                continue
            signed_lines.append(line)
        if signature_index is None:
            raise ValueError("Linha de assinatura não encontrada no contrato")
        signed_text = "\n".join(signed_lines)
        signature = self.private_key.sign(
            signed_text.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        lines[signature_index] = f"# SIGNATURE: {signature_b64}"
        return "\n".join(lines).strip() + "\n", signature_b64

    def validate_contract_text_allowed(self, contract_text, allowed_actions, username):
        if not contract_text.startswith("# HSYST P2P SERVICE"):
            return False, "Cabeçalho HSYST não encontrado"
        if "## :END CONTRACT" not in contract_text:
            return False, "Final do contrato não encontrado"
        action = None
        user = None
        current_section = None
        for line in contract_text.splitlines():
            line = line.strip()
            if line.startswith("### "):
                if line.endswith(":"):
                    current_section = line[4:-1].lower()
            elif line.startswith("### :END "):
                current_section = None
            elif line.startswith("# "):
                if current_section == "details" and line.startswith("# ACTION:"):
                    action = line.split(":", 1)[1].strip()
                elif current_section == "start" and line.startswith("# USER:"):
                    user = line.split(":", 1)[1].strip()
        if not action:
            return False, "Ação não informada no contrato"
        if action not in allowed_actions:
            return False, f"Ação inválida no contrato (permitido: {', '.join(allowed_actions)})"
        if not user:
            return False, "Usuário não informado no contrato"
        if user != username:
            return False, "Usuário do contrato não corresponde ao usuário informado"
        return True, ""

    def create_signed_usage_contract(self, terms_text, contract_hash, username):
        template = self.build_usage_contract_template(terms_text, contract_hash, username)
        signed_text, _ = self.apply_contract_signature(template)
        signed_text = signed_text.strip()
        valid, error = self.validate_contract_text_allowed(signed_text, ["accept_usage"], username)
        if not valid:
            raise ValueError(error)
        return signed_text

    async def search_content(self, query, content_type="", sort_by="reputation", limit=50):
        if not self.connected:
            return False

        search_id = str(uuid.uuid4())
        try:
            await asyncio.wait_for(
                self.sio.emit('search_content', {
                    'search_id': search_id,
                    'query': query,
                    'content_type': content_type,
                    'sort_by': sort_by,
                    'limit': limit
                }),
                timeout=5
            )
            return search_id
        except asyncio.TimeoutError:
            logger.error("Timeout ao buscar conteúdo")
            return False
        except Exception as e:
            logger.error(f"Erro ao buscar conteúdo: {e}")
            return False

    async def resolve_dns(self, domain):
        if not self.connected:
            return False

        with self.dns_lock:
            if domain in self.dns_resolution_cache:
                cache_entry = self.dns_resolution_cache[domain]
                if time.time() - cache_entry['timestamp'] < cache_entry['ttl']:
                    return True

        try:
            await asyncio.wait_for(
                self.sio.emit('resolve_dns', {'domain': domain}),
                timeout=5
            )
            return True
        except asyncio.TimeoutError:
            logger.error(f"Timeout ao resolver DNS: {domain}")
            return False
        except Exception as e:
            logger.error(f"Erro ao resolver DNS: {e}")
            return False

    async def register_dns(self, domain, ddns_content, signature, pow_nonce=None, hashrate_observed=None):
        if not self.connected:
            return False

        try:
            payload = {
                'domain': domain,
                'ddns_content': base64.b64encode(ddns_content).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
            }
            if pow_nonce is not None:
                payload['pow_nonce'] = pow_nonce
            if hashrate_observed is not None:
                payload['hashrate_observed'] = hashrate_observed

            await asyncio.wait_for(
                self.sio.emit('register_dns', payload),
                timeout=5
            )
            return True
        except asyncio.TimeoutError:
            logger.error("Timeout ao registrar DNS")
            return False
        except Exception as e:
            logger.error(f"Erro ao registrar DNS: {e}")
            return False

    def create_content_header(self):
        header = b"# HSYST P2P SERVICE"
        header += b"### START:"
        header += b"# USER: " + self.current_user.encode('utf-8')
        header += b"# KEY: " + base64.b64encode(self.public_key_pem)
        header += b"### :END START"
        return header

    def create_ddns_file(self, domain, content_hash):
        ddns_content = f"""# HSYST P2P SERVICE
### START:
# USER: {self.current_user}
# KEY: {base64.b64encode(self.public_key_pem).decode('utf-8')}
### :END START
### DNS:
# DNAME: {domain} = {content_hash}
### :END DNS
"""
        return ddns_content.encode('utf-8')

    def save_ddns_to_storage(self, domain, ddns_content, content_hash):
        try:
            dns_dir = os.path.join(self.crypto_dir, "dns")
            os.makedirs(dns_dir, exist_ok=True)
            file_path = os.path.join(dns_dir, f"{domain}.ddns")
            with open(file_path, 'wb') as f:
                f.write(ddns_content)

            self.db.execute_query('''
                INSERT OR REPLACE INTO hsdcm_dns_cache
                (domain, content_hash, username, verified, timestamp, ttl, last_resolved, resolution_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (domain, content_hash, self.current_user, 1, time.time(), 3600, time.time(), 1))

            with self.dns_lock:
                self.dns_resolution_cache[domain] = {
                    'content_hash': content_hash,
                    'timestamp': time.time(),
                    'ttl': 3600
                }
        except Exception as e:
            logger.error(f"Erro ao salvar DNS local: {e}")

    def upload_file(self, file_path, title=None, description="", mime_type=None):
        if not self.current_user:
            return False, "Usuário não autenticado"

        if not os.path.exists(file_path):
            return False, "Arquivo não encontrado"

        if title is None:
            title = os.path.basename(file_path)

        if mime_type is None:
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            header = self.create_content_header()
            full_content_with_header = header + content
            if len(full_content_with_header) > self.max_upload_size:
                return False, "Arquivo excede o tamanho máximo permitido"

            content_hash = hashlib.sha256(full_content_with_header).hexdigest()
            file_hash = hashlib.sha256(content).hexdigest()
            details = [
                ("FILE_NAME", os.path.basename(file_path)),
                ("FILE_SIZE", str(len(content))),
                ("FILE_HASH", file_hash),
                ("TITLE", title),
                ("MIME", mime_type),
                ("DESCRIPTION", description),
                ("CONTENT_HASH", content_hash),
                ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
            ]
            contract_template = self.build_contract_template("upload_file", details)
            signed_text, _ = self.apply_contract_signature(contract_template)
            contract_text = signed_text.strip()
            valid, error = self.validate_contract_text_allowed(contract_text, ["upload_file"], self.current_user)
            if not valid:
                return False, error
            contract_text = contract_text + "\n"
            full_content_with_contract = full_content_with_header + contract_text.encode('utf-8')

            signature = self.private_key.sign(
                content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            self.save_content_to_storage(content_hash, full_content_with_header, {
                'title': title,
                'description': description,
                'mime_type': mime_type,
                'username': self.current_user,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'verified': True,
                'header_present': 1
            })

            pow_solution = self.request_pow_solution("upload")
            if not pow_solution:
                return False, "Falha ao resolver PoW"

            pow_nonce, hashrate_observed = pow_solution
            self.upload_event.clear()
            self.upload_result = None

            asyncio.run_coroutine_threadsafe(
                self._upload_file(
                    content_hash, title, description, mime_type,
                    len(full_content_with_header), signature, full_content_with_contract,
                    pow_nonce, hashrate_observed
                ),
                self.loop
            )

            if not self.upload_event.wait(300):
                return False, "Timeout no upload"

            if self.upload_result and self.upload_result.get('success'):
                return True, content_hash
            error_msg = self.upload_result.get('error', 'Falha desconhecida') if self.upload_result else "Falha no upload"
            return False, error_msg

        except Exception as e:
            logger.error(f"Erro no upload: {e}")
            return False, str(e)

    async def _upload_file(self, content_hash, title, description, mime_type, size, signature, full_content_with_contract, pow_nonce, hashrate_observed):
        if not self.connected:
            return

        try:
            content_b64 = base64.b64encode(full_content_with_contract).decode('utf-8')
            data = {
                'content_hash': content_hash,
                'title': title,
                'description': description,
                'mime_type': mime_type,
                'size': size,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'content_b64': content_b64,
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            }
            await self.sio.emit('publish_content', data)
        except Exception as e:
            logger.error(f"Erro ao enviar upload: {e}")

    def register_dns_with_hash(self, domain, content_hash):
        if not self.current_user:
            return False, "Usuário não autenticado"

        if not self.is_valid_domain(domain):
            return False, "Domínio inválido"

        try:
            ddns_content = self.create_ddns_file(domain, content_hash)
            details = [
                ("DOMAIN", domain),
                ("CONTENT_HASH", content_hash),
                ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
            ]
            contract_template = self.build_contract_template("register_dns", details)
            signed_text, _ = self.apply_contract_signature(contract_template)
            contract_text = signed_text.strip()
            valid, error = self.validate_contract_text_allowed(contract_text, ["register_dns"], self.current_user)
            if not valid:
                return False, error
            contract_text = contract_text + "\n"
            ddns_content_full = ddns_content + contract_text.encode('utf-8')

            header_end = b'### :END START'
            if header_end in ddns_content:
                _, ddns_data_signed = ddns_content.split(header_end, 1)
            else:
                ddns_data_signed = ddns_content

            signature = self.private_key.sign(
                ddns_data_signed,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            self.save_ddns_to_storage(domain, ddns_content, content_hash)

            pow_solution = self.request_pow_solution("dns")
            if not pow_solution:
                return False, "Falha ao resolver PoW"

            pow_nonce, hashrate_observed = pow_solution
            self.dns_event.clear()
            self.dns_result = None

            asyncio.run_coroutine_threadsafe(
                self.register_dns(domain, ddns_content_full, signature, pow_nonce, hashrate_observed),
                self.loop
            )

            if not self.dns_event.wait(300):
                return False, "Timeout no registro DNS"

            if self.dns_result and self.dns_result.get('success'):
                return True, domain
            error_msg = self.dns_result.get('error', 'Falha desconhecida') if self.dns_result else "Falha no registro DNS"
            return False, error_msg

        except Exception as e:
            logger.error(f"Erro no registro DNS: {e}")
            return False, str(e)

    def report_content(self, content_hash, reported_user):
        if not self.current_user:
            return False, "Usuário não autenticado"

        if reported_user == self.current_user:
            return False, "Não é permitido reportar seu próprio conteúdo"

        if self.reputation < 20:
            return False, "Reputação insuficiente para reportar conteúdo"

        existing = self.db.fetch_one('''
            SELECT report_id FROM hsdcm_reports
            WHERE reporter_user = ? AND content_hash = ?
        ''', (self.current_user, content_hash))
        if existing:
            return False, "Conteúdo já reportado por este usuário"

        try:
            pow_solution = self.request_pow_solution("report")
            if not pow_solution:
                return False, "Falha ao resolver PoW"

            pow_nonce, hashrate_observed = pow_solution
            details = [
                ("CONTENT_HASH", content_hash),
                ("REPORTED_USER", reported_user),
                ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
            ]
            contract_template = self.build_contract_template("report_content", details)
            signed_text, _ = self.apply_contract_signature(contract_template)
            contract_text = signed_text.strip()
            valid, error = self.validate_contract_text_allowed(contract_text, ["report_content"], self.current_user)
            if not valid:
                return False, error
            contract_text = contract_text + "\n"

            report_id = hashlib.sha256(
                f"{content_hash}{reported_user}{self.current_user}{time.time()}".encode()
            ).hexdigest()
            self.db.execute_query('''
                INSERT INTO hsdcm_reports
                (report_id, content_hash, reported_user, reporter_user, timestamp, status, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (report_id, content_hash, reported_user, self.current_user, time.time(), 'pending', ''))

            self.report_event.clear()
            self.report_result = None

            asyncio.run_coroutine_threadsafe(
                self._report_content(content_hash, reported_user, contract_text, pow_nonce, hashrate_observed),
                self.loop
            )

            if not self.report_event.wait(300):
                return False, "Timeout no reporte"

            if self.report_result and self.report_result.get('success'):
                return True, report_id

            error_msg = self.report_result.get('error', 'Falha desconhecida') if self.report_result else "Falha no reporte"
            return False, error_msg

        except Exception as e:
            logger.error(f"Erro no reporte: {e}")
            return False, str(e)

    async def _report_content(self, content_hash, reported_user, contract_text, pow_nonce, hashrate_observed):
        if not self.connected:
            return

        try:
            await self.sio.emit('report_content', {
                'content_hash': content_hash,
                'reported_user': reported_user,
                'reporter': self.current_user,
                'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            })
        except Exception as e:
            logger.error(f"Erro ao enviar reporte: {e}")

    def is_valid_domain(self, domain):
        return bool(re.match(r'^[a-zA-Z0-9-]+(\\.[a-zA-Z0-9-]+)*$', domain))

    def verify_content_integrity(self, content_hash, content):
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != content_hash:
            logger.warning(f"Integridade do arquivo comprometida: {content_hash}. Esperado: {content_hash}, Real: {actual_hash}")
            return False
        return True

    def verify_signature(self, content, signature_b64, public_key_b64):
        try:
            public_key = serialization.load_pem_public_key(base64.b64decode(public_key_b64), backend=default_backend())
            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature,
                content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Falha na verificação da assinatura: {e}")
            return False

    def save_content_to_storage(self, content_hash, content, metadata=None):
        content_dir = os.path.join(self.crypto_dir, "content")
        os.makedirs(content_dir, exist_ok=True)

        file_path = os.path.join(content_dir, f"{content_hash}.dat")
        with open(file_path, 'wb') as f:
            f.write(content)

        header_present = metadata.get('header_present', 0) if metadata else 0

        content_without_header = self.extract_content_from_header(content)

        if header_present:
            integrity_ok = self.verify_content_integrity(content_hash, content)
        else:
            integrity_ok = self.verify_content_integrity(content_hash, content_without_header)

        verified = 0

        if metadata and metadata.get('signature') and metadata.get('public_key'):
            if header_present:
                signature_ok = self.verify_signature(content_without_header, metadata['signature'], metadata['public_key'])
            else:
                signature_ok = self.verify_signature(content_without_header, metadata['signature'], metadata['public_key'])
            verified = 1 if signature_ok else 0

        try:
            self.db.execute_query('''
                INSERT OR REPLACE INTO hsdcm_content_cache
                (content_hash, file_path, file_name, mime_type, size, last_accessed, title, description, username, signature, public_key, verified, status, network_sources, last_network_check, integrity_ok, reputation, created_at, header_present)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                content_hash, file_path, f"{content_hash}.dat",
                metadata.get('mime_type', 'application/octet-stream') if metadata else 'application/octet-stream',
                len(content_without_header), time.time(),
                metadata.get('title', '') if metadata else '',
                metadata.get('description', '') if metadata else '',
                metadata.get('username', '') if metadata else '',
                metadata.get('signature', '') if metadata else '',
                metadata.get('public_key', '') if metadata else '',
                verified,
                'cached',
                metadata.get('sources', 0) if metadata else 0,
                time.time(),
                1 if integrity_ok else 0,
                metadata.get('reputation', 100) if metadata else 100,
                time.time(),
                header_present
            ))
        except Exception as e:
            logger.error(f"Erro ao salvar conteúdo no banco: {e}")

    def get_content_file_path(self, content_hash):
        row = self.db.fetch_one('SELECT file_path, header_present FROM hsdcm_content_cache WHERE content_hash = ?', (content_hash,))
        if row:
            file_path = row[0]
            if os.path.exists(file_path):
                self.db.execute_query('''
                    UPDATE hsdcm_content_cache
                    SET last_accessed = ?
                    WHERE content_hash = ?
                ''', (time.time(), content_hash))
                return file_path
        return None

    def get_content_info(self, content_hash):
        row = self.db.fetch_one('SELECT title, description, mime_type, username, verified, status, network_sources, integrity_ok, reputation, signature, public_key, size, header_present FROM hsdcm_content_cache WHERE content_hash = ?', (content_hash,))
        if row:
            return {
                'title': row[0],
                'description': row[1],
                'mime_type': row[2],
                'username': row[3],
                'verified': row[4],
                'status': row[5],
                'sources': row[6],
                'integrity_ok': row[7],
                'reputation': row[8],
                'signature': row[9],
                'public_key': row[10],
                'size': row[11],
                'header_present': row[12],
                'content_hash': content_hash
            }
        return None

    def extract_content_from_header(self, content_with_header):
        header_end = content_with_header.find(b'### :END START')
        if header_end != -1:
            content = content_with_header[header_end + len(b'### :END START'):]
            return content
        return content_with_header

    def get_dns_resolution(self, domain):
        with self.dns_lock:
            if domain in self.dns_resolution_cache:
                cache_entry = self.dns_resolution_cache[domain]
                if time.time() - cache_entry['timestamp'] < cache_entry['ttl']:
                    return cache_entry['content_hash']
        return None

class UsageContractDialog:
    def __init__(self, parent, terms_text, contract_hash, username):
        self.window = tk.Toplevel(parent)
        self.window.title("Contrato de Uso")
        self.window.geometry("720x620")
        self.window.transient(parent)
        self.window.grab_set()
        self.confirmed = False
        self.accept_var = tk.BooleanVar(value=False)

        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Contrato de Uso", font=("Arial", 14, "bold")).pack(pady=(0, 10))
        ttk.Label(main_frame, text=f"Usuário: {username}", font=("Arial", 10)).pack(anchor=tk.W)
        ttk.Label(main_frame, text=f"Hash do contrato: {contract_hash}", font=("Arial", 9)).pack(anchor=tk.W, pady=(0, 10))
        ttk.Label(
            main_frame,
            text="Ao aceitar, voce autoriza o uso da sua chave privada para assinar operacoes.",
            font=("Arial", 9)
        ).pack(anchor=tk.W, pady=(0, 10))

        terms_box = scrolledtext.ScrolledText(main_frame, height=18, font=("Arial", 10))
        terms_box.pack(fill=tk.BOTH, expand=True)
        terms_box.insert(tk.END, terms_text or "")
        terms_box.config(state=tk.DISABLED)

        ttk.Checkbutton(
            main_frame,
            text="Li e concordo com os termos acima",
            variable=self.accept_var
        ).pack(anchor=tk.W, pady=(8, 0))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Aceitar e Assinar", command=self.accept, width=18).pack(side=tk.LEFT, padx=8)
        ttk.Button(button_frame, text="Cancelar", command=self.cancel, width=18).pack(side=tk.LEFT, padx=8)

        self.window.protocol("WM_DELETE_WINDOW", self.cancel)

    def accept(self):
        if not self.accept_var.get():
            messagebox.showwarning("Aviso", "Confirme que leu e concorda com o contrato.")
            return
        self.confirmed = True
        self.window.destroy()

    def cancel(self):
        self.confirmed = False
        self.window.destroy()

class FastLoginDialog:
    def __init__(self, parent, client, action_description=""):
        if parent is None or not parent.winfo_exists():
            self.root = tk.Tk()
            self.root.withdraw()
            parent = self.root

        self.client = client
        self.window = tk.Toplevel(parent)
        self.window.title("Login HSDCM")
        self.window.geometry("950x800")
        self.window.transient(parent)
        self.window.grab_set()

        self.action_description = action_description
        self.pow_solver = FastPowSolver()
        self.login_success = False
        self.pow_nonce = None
        self.hashrate_observed = 0.0
        self._closed = False
        self.result_queue = queue.Queue()

        self.setup_ui()
        self.window.after(100, self.process_queue)

        if hasattr(self, 'root'):
            self.window.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        if self.action_description:
            ttk.Label(main_frame, text=self.action_description, font=("Arial", 11), wraplength=600).pack(pady=10)

        ttk.Label(main_frame, text="Login HSDCM", font=("Arial", 18, "bold")).pack(pady=15)

        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill=tk.X, pady=15)

        ttk.Label(form_frame, text="Servidor:", font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=8)
        self.server_var = tk.StringVar(value="server1.hps.hsyst.xyz")
        server_entry = ttk.Entry(form_frame, textvariable=self.server_var, font=("Arial", 11))
        server_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=8, padx=(15, 0))

        ttk.Label(form_frame, text="Usuário:", font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=8)
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, font=("Arial", 11))
        username_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=8, padx=(15, 0))

        ttk.Label(form_frame, text="Senha:", font=("Arial", 11)).grid(row=2, column=0, sticky=tk.W, pady=8)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show="*", font=("Arial", 11))
        password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=8, padx=(15, 0))

        form_frame.columnconfigure(1, weight=1)

        self.status_var = tk.StringVar(value="Preparando...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Arial", 11))
        status_label.pack(pady=15)

        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=15)

        self.details_text = scrolledtext.ScrolledText(main_frame, height=15, font=("Arial", 10))
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=15)
        self.details_text.config(state=tk.DISABLED)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=15)

        ttk.Button(button_frame, text="Login", command=self.do_login, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancelar", command=self.cancel, width=18).pack(side=tk.LEFT, padx=10)

        self.window.protocol("WM_DELETE_WINDOW", self.cancel)

    def process_queue(self):
        try:
            while True:
                func, args = self.result_queue.get_nowait()
                func(*args)
        except queue.Empty:
            pass
        if not self._closed and self.window.winfo_exists():
            self.window.after(100, self.process_queue)

    def queue_message(self, func, *args):
        self.result_queue.put((func, args))

    def log_message(self, message):
        if self._closed:
            return
        self.queue_message(self._log_message, message)

    def _log_message(self, message):
        if self._closed or not self.window.winfo_exists():
            return
        try:
            self.details_text.config(state=tk.NORMAL)
            self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
            self.details_text.see(tk.END)
            self.details_text.config(state=tk.DISABLED)
        except tk.TclError:
            pass

    def update_status(self, status):
        if self._closed:
            return
        self.queue_message(self._update_status, status)

    def _update_status(self, status):
        if self._closed or not self.window.winfo_exists():
            return
        self.status_var.set(status)
        self.window.update_idletasks()

    def do_login(self):
        server = self.server_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not server or not username or not password:
            messagebox.showwarning("Aviso", "Preencha todos os campos.")
            return

        self.update_status("Conectando ao servidor...")
        self.progress.start()
        self.log_message(f"Conectando a {server}...")

        threading.Thread(target=self._connect_thread, args=(server, username, password), daemon=True).start()

    def _connect_thread(self, server, username, password):
        try:
            connect_task = asyncio.run_coroutine_threadsafe(self.client.connect_to_server(server), self.client.loop)
            connected = connect_task.result(timeout=20)

            if connected:
                self.queue_message(self._request_usage_contract, username, password)
            else:
                self.queue_message(self._login_failed, "Falha na conexão com o servidor")

        except asyncio.TimeoutError:
            self.queue_message(self._login_failed, "Timeout na conexão com o servidor")
        except Exception as e:
            self.queue_message(self._login_failed, f"Erro de conexão: {e}")

    def _request_usage_contract(self, username, password):
        self.update_status("Verificando contrato de uso...")
        self.log_message("Solicitando contrato de uso ao servidor...")
        self.client.reset_usage_contract_state()

        try:
            request_task = asyncio.run_coroutine_threadsafe(
                self.client.request_usage_contract(username),
                self.client.loop
            )
            request_task.result(timeout=5)
        except Exception as e:
            self._login_failed(f"Erro ao solicitar contrato de uso: {e}")
            return

        threading.Thread(target=self._wait_usage_contract, args=(username, password), daemon=True).start()

    def _wait_usage_contract(self, username, password):
        if not self.client.usage_contract_event.wait(timeout=20):
            self.queue_message(self._login_failed, "Timeout ao verificar contrato de uso")
            return

        result = self.client.usage_contract_data or {}
        data = result.get('data', {})

        if result.get('required'):
            self.queue_message(self._handle_usage_contract_required, username, password, data)
            return

        if not data.get('success', True):
            self.queue_message(self._login_failed, data.get('error', 'Falha no contrato de uso'))
            return

        self.queue_message(self._request_pow_challenge, username, password)

    def _handle_usage_contract_required(self, username, password, data):
        terms_text = data.get('contract_text', '') or ""
        contract_hash = data.get('contract_hash', '')
        if not contract_hash:
            self._login_failed("Contrato de uso indisponível no servidor")
            return

        dialog = UsageContractDialog(self.window, terms_text, contract_hash, username)
        self.window.wait_window(dialog.window)
        if not dialog.confirmed:
            self._login_failed("Contrato de uso não aceito")
            return

        try:
            contract_text = self.client.create_signed_usage_contract(terms_text, contract_hash, username)
        except Exception as e:
            self._login_failed(f"Erro ao assinar contrato: {e}")
            return

        self.update_status("Resolvendo PoW do contrato de uso...")
        self.log_message("Iniciando mineração PoW para contrato de uso...")
        threading.Thread(
            target=self._accept_usage_contract_thread,
            args=(contract_text, username, password),
            daemon=True
        ).start()

    def _accept_usage_contract_thread(self, contract_text, username, password):
        self.client.reset_usage_contract_state()
        try:
            solution = self.client.request_pow_solution("usage_contract", solver=self.pow_solver)
            if not solution:
                self.queue_message(self._login_failed, "PoW do contrato de uso não resolvido")
                return

            pow_nonce, hashrate = solution
            send_task = asyncio.run_coroutine_threadsafe(
                self.client.accept_usage_contract(contract_text, pow_nonce, hashrate),
                self.client.loop
            )
            send_task.result(timeout=5)
        except Exception as e:
            self.queue_message(self._login_failed, f"Erro ao enviar contrato de uso: {e}")
            return

        if not self.client.usage_contract_ack_event.wait(timeout=20):
            self.queue_message(self._login_failed, "Timeout ao validar contrato de uso")
            return

        ack = self.client.usage_contract_ack_data or {}
        if ack.get('success'):
            self.queue_message(self._request_pow_challenge, username, password)
        else:
            self.queue_message(self._login_failed, ack.get('error', 'Contrato de uso rejeitado'))

    def _request_pow_challenge(self, username, password):
        self.update_status("Solicitando prova de trabalho...")
        self.log_message("Solicitando desafio PoW...")

        def solve_thread():
            try:
                self.update_status("Resolvendo PoW...")
                self.log_message("Iniciando mineração PoW para login...")
                solution = self.client.request_pow_solution("login", solver=self.pow_solver)
                if not solution:
                    self.queue_message(self._login_failed, "PoW não resolvido em 30 segundos")
                    return

                pow_nonce, hashrate = solution
                self.queue_message(self._pow_solved, username, password, pow_nonce, hashrate)
            except Exception as e:
                self.queue_message(self._login_failed, f"Erro ao resolver PoW: {e}")

        threading.Thread(target=solve_thread, daemon=True).start()

    def _pow_solved(self, username, password, pow_nonce, hashrate_observed):
        self.update_status("PoW resolvido - Autenticando...")
        self.log_message(f"PoW resolvido! Nonce: {pow_nonce}, Hashrate: {hashrate_observed:.2f} H/s")

        def authenticate_thread():
            try:
                auth_task = asyncio.run_coroutine_threadsafe(
                    self.client.authenticate(username, password, pow_nonce, hashrate_observed),
                    self.client.loop
                )
                success = auth_task.result(timeout=15)

                if success:
                    self.queue_message(self._login_successful)
                else:
                    error = self.client.last_auth_error or "Falha na autenticação"
                    self.queue_message(self._login_failed, error)

            except asyncio.TimeoutError:
                self.queue_message(self._login_failed, "Timeout na autenticação")
            except Exception as e:
                self.queue_message(self._login_failed, f"Erro na autenticação: {e}")

        threading.Thread(target=authenticate_thread, daemon=True).start()

    def _login_successful(self):
        if self._closed or not self.window.winfo_exists():
            return
        self.progress.stop()
        self.update_status("Login bem-sucedido!")
        self.log_message(f"Login bem-sucedido como {self.client.current_user}")
        self.login_success = True
        self._closed = True
        self.window.destroy()
        if hasattr(self, 'root'):
            self.root.quit()

    def _login_failed(self, error):
        if self._closed or not self.window.winfo_exists():
            return
        try:
            self.progress.stop()
        except:
            pass
        self.update_status("Falha no login")
        self.log_message(f"Erro: {error}")
        self.queue_message(messagebox.showerror, "Erro", f"Falha no login: {error}")

    def on_close(self):
        self.cancel()
        if hasattr(self, 'root'):
            self.root.destroy()

    def cancel(self):
        self.pow_solver.stop_solving()
        self._closed = True
        if self.window.winfo_exists():
            self.window.destroy()
        if hasattr(self, 'root'):
            self.root.quit()

    def wait_for_login(self):
        self.window.wait_window()
        return self.login_success

class HSDCM_DI:
    def __init__(self, client, main_app):
        self.client = client
        self.main_app = main_app
        self.virtual_disk_path = None
        self.monitoring = False
        self._monitor_thread = None
        self._stop_monitoring = threading.Event()
        self.pending_actions = {}
        self.recently_processed = set()
        self.setup_virtual_disk()

    def setup_virtual_disk(self):
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        if platform.system() == "Linux":
            self.virtual_disk_path = os.path.join(os.path.expanduser("~"), "HPS_Virtual_Disk")
        else:
            self.virtual_disk_path = os.path.join(desktop_path, "HPS_Virtual_Disk")

        os.makedirs(self.virtual_disk_path, exist_ok=True)

        readme_path = os.path.join(self.virtual_disk_path, "README.TXT")
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write("""HPS Virtual Disk - Manual de Uso

Este é um disco virtual integrado com a rede P2P HPS.

COMO USAR:

1. DOWNLOAD DE ARQUIVOS:
   - Crie um arquivo com extensão .download (ex: ABC123.download)
   - O sistema irá buscar o conteúdo com hash ABC123 na rede
   - Um popup aparecerá solicitando login e mostrando informações de segurança
   - Após confirmação, será feito o download
   - Após o download, o arquivo .download será substituído pelo conteúdo real

2. DOWNLOAD VIA DNS:
   - Crie um arquivo com extensão .dns.download (ex: exemplo.com.dns.download)
   - O sistema resolverá o domínio DNS na rede HPS
   - Baixará o conteúdo associado ao domínio

3. EXPORTAÇÃO:
   - Use a interface do HSDCM para exportar este disco virtual
   - O arquivo exportado será criptografado e só poderá ser aberto com suas credenciais

OBSERVAÇÕES:
- Mantenha o HSDCM rodando em segundo plano para o funcionamento correto
- A rede usa criptografia e prova de trabalho para segurança
- Todas as ações requerem confirmação explícita do usuário
""")

    def start_monitoring(self):
        if self.monitoring:
            return

        self.monitoring = True
        self._stop_monitoring.clear()
        logger.info(f"Iniciando monitoramento do disco virtual: {self.virtual_disk_path}")

        def monitor_thread():
            known_files = set()

            while not self._stop_monitoring.is_set():
                try:
                    current_files = set()
                    for filename in os.listdir(self.virtual_disk_path):
                        filepath = os.path.join(self.virtual_disk_path, filename)
                        if os.path.isfile(filepath):
                            current_files.add(filename)

                    new_files = current_files - known_files
                    for filename in new_files:
                        if filename != "README.TXT":
                            filepath = os.path.join(self.virtual_disk_path, filename)

                            if self.client.db.is_recent_file(filepath):
                                logger.info(f"Ignorando arquivo recentemente processado: {filename}")
                                continue

                            if os.path.isfile(filepath):
                                self.handle_new_file(filepath)

                    known_files = current_files
                    time.sleep(2)

                except Exception as e:
                    logger.error(f"Erro no monitoramento: {e}")
                    time.sleep(5)

        self._monitor_thread = threading.Thread(target=monitor_thread, daemon=True)
        self._monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self._stop_monitoring.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None

    def handle_new_file(self, filepath):
        filename = os.path.basename(filepath)

        if self.client.db.is_recent_file(filepath):
            return

        if filename.endswith('.download'):
            if filename.endswith('.dns.download'):
                domain = filename[:-len('.dns.download')]
                self.request_download_by_domain(domain, filepath)
            else:
                content_hash = filename[:-len('.download')]
                if len(content_hash) == 64:
                    self.request_download(content_hash, filepath)

    def request_download(self, content_hash, filepath):
        action_id = str(uuid.uuid4())
        self.pending_actions[action_id] = {
            'type': 'download',
            'content_hash': content_hash,
            'filepath': filepath,
            'timestamp': time.time()
        }

        def show_dialog():
            try:
                response = tk.messagebox.askyesno(
                    "HSDCM-DI - Permissão de Download",
                    f"Um arquivo .download foi detectado:\n\n"
                    f"Hash: {content_hash}\n\n"
                    f"Deseja fazer o download deste conteúdo da rede HPS?\n\n"
                    f"Após confirmação, será mostrado um diálogo de segurança "
                    f"com todas as informações do arquivo antes do download."
                )

                if response:
                    if not self.client.current_user:
                        def login_and_security():
                            dialog = FastLoginDialog(None, self.client,
                                           f"Download do arquivo: {content_hash}")
                            if dialog.wait_for_login():
                                self.show_download_security(action_id)
                            else:
                                del self.pending_actions[action_id]
                                try:
                                    os.remove(filepath)
                                except:
                                    pass

                        threading.Thread(target=login_and_security, daemon=True).start()
                    else:
                        self.show_download_security(action_id)
                else:
                    del self.pending_actions[action_id]
                    try:
                        os.remove(filepath)
                    except:
                        pass
            except Exception as e:
                logger.error(f"Erro ao mostrar diálogo de download: {e}")

        threading.Thread(target=show_dialog, daemon=True).start()

    def request_download_by_domain(self, domain, filepath):
        action_id = str(uuid.uuid4())
        self.pending_actions[action_id] = {
            'type': 'dns_download',
            'domain': domain,
            'filepath': filepath,
            'timestamp': time.time()
        }

        def show_dialog():
            try:
                response = tk.messagebox.askyesno(
                    "HSDCM-DI - Permissão de Download via DNS",
                    f"Um arquivo .dns.download foi detectado:\n\n"
                    f"Domínio: {domain}\n\n"
                    f"Deseja resolver este domínio DNS e baixar o conteúdo associado?\n\n"
                    f"O sistema resolverá o domínio na rede HPS e baixará o conteúdo."
                )

                if response:
                    if not self.client.current_user:
                        def login_and_resolve():
                            dialog = FastLoginDialog(None, self.client,
                                           f"Resolução DNS: {domain}")
                            if dialog.wait_for_login():
                                self.resolve_domain_and_download(domain, filepath, action_id)
                            else:
                                del self.pending_actions[action_id]
                                try:
                                    os.remove(filepath)
                                except:
                                    pass

                        threading.Thread(target=login_and_resolve, daemon=True).start()
                    else:
                        self.resolve_domain_and_download(domain, filepath, action_id)
                else:
                    del self.pending_actions[action_id]
                    try:
                        os.remove(filepath)
                    except:
                        pass
            except Exception as e:
                logger.error(f"Erro ao mostrar diálogo de download DNS: {e}")

        threading.Thread(target=show_dialog, daemon=True).start()

    def resolve_domain_and_download(self, domain, filepath, action_id):
        def resolve_thread():
            try:
                cached_hash = self.client.get_dns_resolution(domain)
                if cached_hash:
                    self.show_download_security_by_hash(cached_hash, filepath, domain, action_id=action_id)
                    return

                if not self.client.connected:
                    def show_error():
                        messagebox.showerror("Erro", "Cliente não conectado ao servidor")
                        try:
                            os.remove(filepath)
                        except:
                            pass
                        if action_id in self.pending_actions:
                            del self.pending_actions[action_id]

                    threading.Thread(target=show_error, daemon=True).start()
                    return

                dns_event = threading.Event()
                dns_result = [None]

                def dns_callback(data):
                    if data.get('domain') == domain:
                        dns_result[0] = data
                        dns_event.set()

                with self.client.callback_lock:
                    self.client.response_callbacks[domain] = dns_callback

                request_task = asyncio.run_coroutine_threadsafe(
                    self.client.resolve_dns(domain),
                    self.client.loop
                )
                request_success = request_task.result(timeout=5)

                if request_success and dns_event.wait(timeout=15):
                    data = dns_result[0]
                    if data and 'error' not in data:
                        content_hash = data.get('content_hash')
                        if content_hash:
                            self.show_download_security_by_hash(content_hash, filepath, domain, action_id=action_id)
                        else:
                            def show_error():
                                messagebox.showerror("Erro", f"Domínio {domain} não encontrado na rede")
                                try:
                                    os.remove(filepath)
                                except:
                                    pass
                                if action_id in self.pending_actions:
                                    del self.pending_actions[action_id]

                            threading.Thread(target=show_error, daemon=True).start()
                    else:
                        error = data.get('error', 'Erro desconhecido') if data else 'Timeout'
                        def show_error():
                            messagebox.showerror("Erro", f"Falha na resolução DNS: {error}")
                            try:
                                os.remove(filepath)
                            except:
                                pass
                            if action_id in self.pending_actions:
                                del self.pending_actions[action_id]

                        threading.Thread(target=show_error, daemon=True).start()
                else:
                    def show_error():
                        messagebox.showerror("Erro", "Timeout na resolução DNS")
                        try:
                            os.remove(filepath)
                        except:
                            pass
                        if action_id in self.pending_actions:
                            del self.pending_actions[action_id]

                    threading.Thread(target=show_error, daemon=True).start()

                with self.client.callback_lock:
                    if domain in self.client.response_callbacks:
                        del self.client.response_callbacks[domain]

            except Exception as e:
                logger.error(f"Erro na resolução DNS: {e}")
                def show_error():
                    messagebox.showerror("Erro", f"Erro na resolução DNS: {e}")
                    try:
                        os.remove(filepath)
                    except:
                        pass
                    if action_id in self.pending_actions:
                        del self.pending_actions[action_id]

                threading.Thread(target=show_error, daemon=True).start()

        threading.Thread(target=resolve_thread, daemon=True).start()

    def show_download_security_by_hash(self, content_hash, filepath, domain=None, action_id=None):
        file_info = self.client.get_content_info(content_hash)
        if file_info:
            def show_dialog():
                try:
                    description = f"Download via DNS: {domain}" if domain else "Download"

                    dialog = SecurityDialog(
                        None,
                        file_info,
                        "download",
                        client=self.client
                    )

                    if dialog.wait_for_choice():
                        if dialog.user_choice:
                            self.do_download(content_hash, filepath)
                        else:
                            logger.info(f"Download negado pelo usuário: {content_hash}")
                            try:
                                os.remove(filepath)
                            except:
                                pass
                    else:
                        logger.info(f"Diálogo de segurança fechado: {content_hash}")
                        try:
                            os.remove(filepath)
                        except:
                            pass
                    if action_id and action_id in self.pending_actions:
                        del self.pending_actions[action_id]
                except Exception as e:
                    logger.error(f"Erro no diálogo de segurança: {e}")
                    try:
                        os.remove(filepath)
                    except:
                        pass
                    if action_id and action_id in self.pending_actions:
                        del self.pending_actions[action_id]

            threading.Thread(target=show_dialog, daemon=True).start()
        else:
            if action_id and action_id in self.pending_actions:
                del self.pending_actions[action_id]
            self.do_download(content_hash, filepath)

    def show_download_security(self, action_id):
        if action_id not in self.pending_actions:
            return

        action = self.pending_actions[action_id]
        content_hash = action['content_hash']
        filepath = action['filepath']

        file_info = self.client.get_content_info(content_hash)
        if file_info:
            def show_dialog():
                try:
                    dialog = SecurityDialog(
                        None,
                        file_info,
                        "download",
                        client=self.client
                    )

                    if dialog.wait_for_choice():
                        if dialog.user_choice:
                            self.do_download(content_hash, filepath)
                        else:
                            logger.info(f"Download negado pelo usuário: {content_hash}")
                            try:
                                os.remove(filepath)
                            except:
                                pass
                    else:
                        logger.info(f"Diálogo de segurança fechado: {content_hash}")
                        try:
                            os.remove(filepath)
                        except:
                            pass

                    del self.pending_actions[action_id]
                except Exception as e:
                    logger.error(f"Erro no diálogo de segurança: {e}")

            threading.Thread(target=show_dialog, daemon=True).start()
        else:
            self.do_download(content_hash, filepath)

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def do_download(self, content_hash, download_filepath):
        def download_thread():
            try:
                def finalize_from_cache(path, success_message):
                    with open(path, 'rb') as f:
                        content_with_header = f.read()

                    content = self.client.extract_content_from_header(content_with_header)

                    final_filepath = download_filepath[:-9] if download_filepath.endswith('.download') else download_filepath

                    with open(final_filepath, 'wb') as f:
                        f.write(content)

                    self.client.db.add_recent_file(final_filepath, content_hash, "download")

                    try:
                        os.remove(download_filepath)
                    except:
                        pass

                    def show_success():
                        try:
                            messagebox.showinfo("Download Concluído", success_message.format(path=final_filepath))
                        except:
                            pass

                    threading.Thread(target=show_success, daemon=True).start()
                    logger.info(success_message.format(path=final_filepath))

                def wait_for_cache(max_wait=60):
                    deadline = time.time() + max_wait
                    while time.time() < deadline:
                        file_path = self.client.get_content_file_path(content_hash)
                        if file_path and os.path.exists(file_path):
                            finalize_from_cache(file_path, "Arquivo baixado do cache: {path}")
                            return True
                        time.sleep(2)
                    return False

                file_path = self.client.get_content_file_path(content_hash)

                if file_path and os.path.exists(file_path):
                    finalize_from_cache(file_path, "Arquivo baixado do cache: {path}")
                else:
                    download_event = threading.Event()
                    download_success = [False]

                    def content_callback(data):
                        if data.get('content_hash') == content_hash:
                            if 'error' not in data:
                                download_success[0] = True
                            download_event.set()

                    with self.client.callback_lock:
                        self.client.response_callbacks[content_hash] = content_callback

                    def request_content():
                        async def request():
                            return await self.client.request_content(content_hash)

                        try:
                            future = asyncio.run_coroutine_threadsafe(request(), self.client.loop)
                            return future.result(timeout=10)
                        except Exception as e:
                            logger.error(f"Erro ao solicitar conteúdo: {e}")
                            return False

                    request_success = request_content()

                    if request_success and download_event.wait(timeout=15):
                        if download_success[0]:
                            file_path = self.client.get_content_file_path(content_hash)
                            if file_path and os.path.exists(file_path):
                                finalize_from_cache(file_path, "Arquivo baixado: {path}")
                            else:
                                if not wait_for_cache():
                                    def show_error():
                                        try:
                                            messagebox.showerror("Erro", "Arquivo não encontrado após download.")
                                        except:
                                            pass

                                    threading.Thread(target=show_error, daemon=True).start()
                        else:
                            if not wait_for_cache():
                                def show_error():
                                    try:
                                        messagebox.showerror("Erro", "Conteúdo não disponível na rede.")
                                    except:
                                        pass

                                threading.Thread(target=show_error, daemon=True).start()
                    else:
                        if not wait_for_cache():
                            def show_error():
                                try:
                                    messagebox.showerror("Erro", "Timeout ao baixar conteúdo.")
                                except:
                                    pass

                            threading.Thread(target=show_error, daemon=True).start()

                    with self.client.callback_lock:
                        if content_hash in self.client.response_callbacks:
                            del self.client.response_callbacks[content_hash]

            except Exception as e:
                logger.error(f"Erro no download: {e}")
                def show_error():
                    try:
                        messagebox.showerror(
                            "Erro",
                            f"Falha no download: {e}"
                        )
                    except:
                        pass

                threading.Thread(target=show_error, daemon=True).start()

        threading.Thread(target=download_thread, daemon=True).start()

class PermissionRequest:
    def __init__(self, description, content_info=None):
        self.description = description
        self.content_info = content_info
        self.event = threading.Event()
        self.allowed = None

class HSDCM_WI:
    def __init__(self, client, main_app):
        self.client = client
        self.main_app = main_app
        self.server = None
        self.port = 18238
        self.running = False
        self.permission_queue = queue.Queue()
        self.permission_processor_running = False
        self.permission_processor_thread = None
        self.permission_processor_lock = threading.Lock()
        self.current_permission_dialog = None

        self.start_permission_processor()

    def start_permission_processor(self):
        if self.permission_processor_running:
            return

        self.permission_processor_running = True

        def process_permissions():
            while self.permission_processor_running:
                try:
                    request = self.permission_queue.get(timeout=1)
                    if request is None:
                        continue

                    processed = False
                    while not processed and self.permission_processor_running:
                        with self.permission_processor_lock:
                            if self.current_permission_dialog is None:
                                self.current_permission_dialog = request
                                processed = True
                        time.sleep(0.1)

                    if processed and self.current_permission_dialog:
                        self.show_permission_dialog(request)

                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Erro no processador de permissões: {e}")
                    time.sleep(1)

        self.permission_processor_thread = threading.Thread(target=process_permissions, daemon=True)
        self.permission_processor_thread.start()

    def show_permission_dialog(self, request):
        try:
            if request.content_info:
                dialog = SecurityDialog(
                    None,
                    request.content_info,
                    "web_access",
                    client=self.client
                )

                if dialog.wait_for_choice():
                    request.allowed = dialog.user_choice
                else:
                    request.allowed = False
            else:
                response = tk.messagebox.askyesno(
                    "HSDCM-WI - Permissão Requerida",
                    f"Um serviço web está tentando acessar:\n{request.description}\n\nPermitir esta ação?"
                )
                request.allowed = response

            request.event.set()
        except Exception as e:
            logger.error(f"Erro no diálogo de permissão: {e}")
            request.allowed = False
            request.event.set()
        finally:
            with self.permission_processor_lock:
                self.current_permission_dialog = None

    def start_api(self):
        if self.running:
            return

        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            pass

        def run_server():
            handler = lambda *args, **kwargs: FastHTTPHandler(*args, wi_instance=self, **kwargs)
            self.server = ThreadedHTTPServer(('localhost', self.port), handler)
            self.running = True
            logger.info(f"HSDCM-WI API rodando em http://localhost:{self.port}")
            try:
                self.server.serve_forever()
            except Exception as e:
                logger.error(f"Erro no servidor WI: {e}")
            finally:
                self.running = False

        threading.Thread(target=run_server, daemon=True).start()

    def stop_api(self):
        if self.server:
            self.server.shutdown()
            self.server = None
            self.running = False
            logger.info("HSDCM-WI API parada")

    def stop_permission_processor(self):
        self.permission_processor_running = False
        if self.permission_processor_thread:
            self.permission_processor_thread.join(timeout=5)

    def ask_permission(self, description, content_info=None):
        request = PermissionRequest(description, content_info)
        self.permission_queue.put(request)
        request.event.wait(timeout=30)
        if request.allowed is None:
            return False
        return request.allowed

    def request_login(self, description):
        login_event = threading.Event()
        login_success = [False]

        def show_dialog():
            try:
                dialog = FastLoginDialog(None, self.client, description)
                login_success[0] = dialog.wait_for_login()
                login_event.set()
            except Exception as e:
                logger.error(f"Erro no diálogo de login: {e}")
                login_event.set()

        threading.Thread(target=show_dialog, daemon=True).start()

        login_event.wait(timeout=60)
        return login_success[0]

    def handle_get_file_async(self, content_hash, handler):
        content_info = self.client.get_content_info(content_hash)

        if not self.ask_permission(f"Baixar arquivo: {content_hash}", content_info):
            self.send_error_page(handler, 403, "Ação não permitida pelo usuário",
                               "O usuário negou a permissão para baixar este arquivo.",
                               "Tente novamente após permitir o acesso.")
            self.client.db.log_security_action(
                "web_download_denied",
                content_hash=content_hash,
                result="denied",
                details="Usuário negou permissão"
            )
            return

        if not self.client.current_user:
            if not self.request_login(f"Download de arquivo: {content_hash}"):
                self.send_error_page(handler, 403, "Login falhou ou foi cancelado",
                                   "É necessário fazer login para baixar este arquivo.",
                                   "Clique no botão abaixo para tentar fazer login novamente.")
                self.client.db.log_security_action(
                    "web_download_failed",
                    content_hash=content_hash,
                    result="login_failed",
                    details="Login falhou ou cancelado"
                )
                return

        self.do_api_download(content_hash, handler)

    def do_api_download(self, content_hash, handler):
        file_path = self.client.get_content_file_path(content_hash)
        if file_path and os.path.exists(file_path):
            self._serve_file(handler, file_path, content_hash)
            return

        try:
            request_task = asyncio.run_coroutine_threadsafe(
                self.client.request_content(content_hash),
                self.client.loop
            )
            request_success = request_task.result(timeout=5)

            if not request_success:
                self.send_error_page(handler, 500, "Falha ao solicitar conteúdo",
                                   "Não foi possível solicitar o conteúdo ao servidor.",
                                   "Verifique sua conexão com a rede HPS.")
                return

            event = self.client.content_download_events.get(content_hash)
            if event:
                if event.wait(timeout=40):
                    file_path = self.client.get_content_file_path(content_hash)
                    if file_path and os.path.exists(file_path):
                        self._serve_file(handler, file_path, content_hash)
                        self.client.db.log_security_action(
                            "web_download_success",
                            content_hash=content_hash,
                            result="success"
                        )
                    else:
                        self.send_error_page(handler, 404, "Arquivo não encontrado após download",
                                           "O arquivo não pôde ser localizado após o download.",
                                           "Tente baixar novamente.")
                        self.client.db.log_security_action(
                            "web_download_failed",
                            content_hash=content_hash,
                            result="file_not_found",
                            details="Arquivo não encontrado após download"
                        )
                else:
                    self.send_error_page(handler, 408, "Timeout ao baixar arquivo",
                                       "O tempo para baixar o arquivo expirou.",
                                       "Tente novamente em alguns instantes.")
                    self.client.db.log_security_action(
                        "web_download_timeout",
                        content_hash=content_hash,
                        result="timeout",
                        details="Timeout ao baixar arquivo"
                    )
            else:
                self.send_error_page(handler, 500, "Erro interno: evento de download não criado",
                                   "Ocorreu um erro interno no processo de download.",
                                   "Reinicie o HSDCM e tente novamente.")

        except asyncio.TimeoutError:
            self.send_error_page(handler, 408, "Timeout ao solicitar conteúdo",
                               "O tempo para solicitar o conteúdo expirou.",
                               "Verifique sua conexão com a rede HPS.")
            self.client.db.log_security_action(
                "web_download_timeout",
                content_hash=content_hash,
                result="timeout",
                details="Timeout ao solicitar conteúdo"
            )
        except Exception as e:
            logger.error(f"Erro ao solicitar download: {e}")
            self.send_error_page(handler, 500, f"Erro interno: {e}",
                               "Ocorreu um erro durante o processo de download.",
                               "Tente novamente mais tarde.")
            self.client.db.log_security_action(
                "web_download_error",
                content_hash=content_hash,
                result="error",
                details=f"Erro interno: {e}"
            )

    def _serve_file(self, handler, file_path, content_hash):
        try:
            with open(file_path, 'rb') as f:
                content_with_header = f.read()

            content = self.client.extract_content_from_header(content_with_header)

            handler.send_response(200)
            handler.send_header('Content-Type', 'application/octet-stream')
            handler.send_header('Content-Length', str(len(content)))
            handler.send_header('Content-Disposition', f'attachment; filename="{content_hash}"')
            handler.end_headers()
            handler.wfile.write(content)

            logger.info(f"Download via API concluído: {content_hash}")
            self.client.db.log_security_action(
                "web_download_served",
                content_hash=content_hash,
                result="served"
            )
        except (BrokenPipeError, ConnectionError):
            logger.warning("Cliente fechou a conexão durante o envio do arquivo")
            self.client.db.log_security_action(
                "web_download_connection_lost",
                content_hash=content_hash,
                result="connection_lost"
            )
        except Exception as e:
            logger.error(f"Erro ao servir arquivo: {e}")
            if not handler.wfile.closed:
                self.send_error_page(handler, 500, f"Erro interno: {e}",
                                   "Ocorreu um erro ao servir o arquivo.",
                                   "Tente baixar novamente.")
            self.client.db.log_security_action(
                "web_download_error",
                content_hash=content_hash,
                result="error",
                details=f"Erro ao servir arquivo: {e}"
            )

    def send_error_page(self, handler, code, title, message, suggestion=""):
        try:
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HSDCM - {title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 80%;
            max-width: 800px;
            text-align: center;
        }}
        .header {{
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
            font-weight: bold;
        }}
        .subheader {{
            color: #666;
            font-size: 18px;
            margin-bottom: 30px;
        }}
        .error-box {{
            background: linear-gradient(135deg, #fdfcfb 0%, #e2d1c3 100%);
            border: 2px solid #e0e0e0;
            border-radius: 15px;
            padding: 30px;
            margin: 30px 0;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        .error-title {{
            color: #e74c3c;
            font-size: 24px;
            margin-bottom: 15px;
            font-weight: bold;
        }}
        .error-message {{
            color: #555;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .suggestion {{
            color: #3498db;
            font-size: 14px;
            font-style: italic;
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 4px solid #3498db;
        }}
        .button-container {{
            margin-top: 30px;
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
        }}
        .button {{
            padding: 12px 30px;
            border: none;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }}
        .button-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .button-primary:hover {{
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }}
        .button-secondary {{
            background: #f8f9fa;
            color: #333;
            border: 2px solid #ddd;
        }}
        .button-secondary:hover {{
            background: #e9ecef;
            transform: translateY(-3px);
        }}
        .code {{
            font-family: 'Courier New', monospace;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 14px;
        }}
        .footer {{
            margin-top: 40px;
            color: #888;
            font-size: 12px;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">HSDCM - HPS Surface and Desktop Compatibility Module</div>
        <div class="subheader">Integração Web - Portal de Erros</div>

        <div class="error-box">
            <div class="error-title">⚠️ {title}</div>
            <div class="error-message">{message}</div>

            <div class="code">
                Código do Erro: {code}<br>
                Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>

            {f'<div class="suggestion">💡 Sugestão: {suggestion}</div>' if suggestion else ''}
        </div>

        <div class="button-container">
            <button class="button button-primary" onclick="window.location.href='/'">Voltar ao Início</button>
            <button class="button button-secondary" onclick="window.location.reload()">Tentar Novamente</button>
            {f'<button class="button button-primary" onclick="window.location.href=\'/login?retry=true\'">Fazer Login</button>' if code == 403 else ''}
        </div>

        <div class="footer">
            HSDCM Web Integration v1.0 • Sistema descentralizado HPS • {datetime.now().year}
        </div>
    </div>
</body>
</html>"""

            handler.send_response(code)
            handler.send_header('Content-Type', 'text/html; charset=utf-8')
            handler.send_header('Content-Length', str(len(html.encode('utf-8'))))
            handler.end_headers()
            handler.wfile.write(html.encode('utf-8'))
        except:
            pass

    def handle_search_async(self, query, content_type, handler):
        if not self.ask_permission(f"Buscar: {query}"):
            self.send_error_page(handler, 403, "Ação não permitida pelo usuário",
                               "O usuário negou a permissão para realizar esta busca.",
                               "Tente novamente após permitir o acesso.")
            self.client.db.log_security_action(
                "web_search_denied",
                result="denied",
                details=f"Busca: {query}"
            )
            return

        if not self.client.current_user:
            if not self.request_login(f"Busca: {query}"):
                self.send_error_page(handler, 403, "Login falhou ou foi cancelado",
                                   "É necessário fazer login para realizar buscas.",
                                   "Clique no botão abaixo para tentar fazer login novamente.")
                self.client.db.log_security_action(
                    "web_search_failed",
                    result="login_failed",
                    details=f"Busca: {query}"
                )
                return

        self.do_api_search(query, content_type, handler)

    def do_api_search(self, query, content_type, handler):
        search_id = str(uuid.uuid4())
        search_event = threading.Event()
        search_result = [None]

        def search_callback(data):
            if data.get('search_id') == search_id:
                search_result[0] = data
                search_event.set()

        with self.client.callback_lock:
            self.client.response_callbacks[search_id] = search_callback

        try:
            request_task = asyncio.run_coroutine_threadsafe(
                self.client.search_content(query, content_type),
                self.client.loop
            )
            request_success = request_task.result(timeout=5)

            if not request_success:
                self.send_error_page(handler, 500, "Falha ao iniciar busca",
                                   "Não foi possível iniciar a busca no servidor.",
                                   "Verifique sua conexão com a rede HPS.")
                self.client.db.log_security_action(
                    "web_search_error",
                    result="error",
                    details=f"Falha ao iniciar busca: {query}"
                )
                return

            if search_event.wait(timeout=30):
                data = search_result[0]
                if data and 'error' not in data:
                    handler.send_response(200)
                    handler.send_header('Content-Type', 'application/json')
                    handler.end_headers()
                    handler.wfile.write(json.dumps(data).encode('utf-8'))
                    self.client.db.log_security_action(
                        "web_search_success",
                        result="success",
                        details=f"Busca: {query}, Resultados: {len(data.get('results', []))}"
                    )
                else:
                    self.send_error_page(handler, 404, "Nenhum resultado encontrado",
                                       f"Não foram encontrados resultados para a busca: '{query}'",
                                       "Tente usar termos diferentes ou verificar a ortografia.")
                    self.client.db.log_security_action(
                        "web_search_no_results",
                        result="no_results",
                        details=f"Busca: {query}"
                    )
            else:
                self.send_error_page(handler, 408, "Timeout na busca",
                                   "O tempo para realizar a busca expirou.",
                                   "Tente novamente com uma conexão mais estável.")
                self.client.db.log_security_action(
                    "web_search_timeout",
                    result="timeout",
                    details=f"Busca: {query}"
                )
        except asyncio.TimeoutError:
            self.send_error_page(handler, 408, "Timeout ao iniciar busca",
                               "Não foi possível iniciar a busca devido a timeout.",
                               "Verifique sua conexão com a rede HPS.")
            self.client.db.log_security_action(
                "web_search_timeout",
                result="timeout",
                details=f"Busca: {query}"
            )
        except Exception as e:
            logger.error(f"Erro na busca: {e}")
            self.send_error_page(handler, 500, f"Erro interno: {e}",
                               "Ocorreu um erro durante a busca.",
                               "Tente novamente mais tarde.")
            self.client.db.log_security_action(
                "web_search_error",
                result="error",
                details=f"Erro: {e}, Busca: {query}"
            )
        finally:
            with self.client.callback_lock:
                if search_id in self.client.response_callbacks:
                    del self.client.response_callbacks[search_id]

    def handle_resolve_dns_async(self, domain, handler):
        if not self.ask_permission(f"Resolver DNS: {domain}"):
            self.send_error_page(handler, 403, "Ação não permitida pelo usuário",
                               "O usuário negou a permissão para resolver este domínio DNS.",
                               "Tente novamente após permitir o acesso.")
            self.client.db.log_security_action(
                "web_dns_denied",
                domain=domain,
                result="denied"
            )
            return

        if not self.client.current_user:
            if not self.request_login(f"Resolução DNS: {domain}"):
                self.send_error_page(handler, 403, "Login falhou ou foi cancelado",
                                   "É necessário fazer login para resolver domínios DNS.",
                                   "Clique no botão abaixo para tentar fazer login novamente.")
                self.client.db.log_security_action(
                    "web_dns_failed",
                    domain=domain,
                    result="login_failed"
                )
                return

        self.do_api_resolve_dns(domain, handler)

    def do_api_resolve_dns(self, domain, handler):
        dns_event = threading.Event()
        dns_result = [None]

        def dns_callback(data):
            if data.get('domain') == domain:
                dns_result[0] = data
                dns_event.set()

        with self.client.callback_lock:
            self.client.response_callbacks[domain] = dns_callback

        try:
            request_task = asyncio.run_coroutine_threadsafe(
                self.client.resolve_dns(domain),
                self.client.loop
            )
            request_success = request_task.result(timeout=5)

            if not request_success:
                self.send_error_page(handler, 500, "Falha ao iniciar resolução DNS",
                                   "Não foi possível iniciar a resolução DNS.",
                                   "Verifique sua conexão com a rede HPS.")
                self.client.db.log_security_action(
                    "web_dns_error",
                    domain=domain,
                    result="error",
                    details="Falha ao iniciar resolução"
                )
                return

            if dns_event.wait(timeout=40):
                data = dns_result[0]
                if data and 'error' not in data:
                    handler.send_response(200)
                    handler.send_header('Content-Type', 'application/json')
                    handler.end_headers()
                    handler.wfile.write(json.dumps(data).encode('utf-8'))
                    self.client.db.log_security_action(
                        "web_dns_success",
                        domain=domain,
                        result="success"
                    )
                else:
                    error_msg = data.get('error', 'Nenhum resultado encontrado') if data else 'Timeout'
                    self.send_error_page(handler, 404, "Domínio não encontrado",
                                       f"O domínio '{domain}' não foi encontrado na rede HPS.",
                                       "Verifique se o domínio está correto e registrado na rede.")
                    self.client.db.log_security_action(
                        "web_dns_not_found",
                        domain=domain,
                        result="not_found",
                        details=f"Erro: {error_msg}"
                    )
            else:
                self.send_error_page(handler, 408, "Timeout na resolução DNS",
                                   "O tempo para resolver o domínio DNS expirou.",
                                   "Tente novamente em alguns instantes.")
                self.client.db.log_security_action(
                    "web_dns_timeout",
                    domain=domain,
                    result="timeout"
                )
        except asyncio.TimeoutError:
            self.send_error_page(handler, 408, "Timeout ao iniciar resolução DNS",
                               "Não foi possível iniciar a resolução DNS devido a timeout.",
                               "Verifique sua conexão com a rede HPS.")
            self.client.db.log_security_action(
                "web_dns_timeout",
                domain=domain,
                result="timeout"
            )
        except Exception as e:
            logger.error(f"Erro na resolução DNS: {e}")
            self.send_error_page(handler, 500, f"Erro interno: {e}",
                               "Ocorreu um erro durante a resolução DNS.",
                               "Tente novamente mais tarde.")
            self.client.db.log_security_action(
                "web_dns_error",
                domain=domain,
                result="error",
                details=f"Erro: {e}"
            )
        finally:
            with self.client.callback_lock:
                if domain in self.client.response_callbacks:
                    del self.client.response_callbacks[domain]

    def handle_file_info_async(self, content_hash, handler):
        content_info = self.client.get_content_info(content_hash)

        if not self.ask_permission(f"Obter informações do arquivo: {content_hash}", content_info):
            self.send_error_page(handler, 403, "Ação não permitida pelo usuário",
                               "O usuário negou a permissão para obter informações deste arquivo.",
                               "Tente novamente após permitir o acesso.")
            return

        if not self.client.current_user:
            if not self.request_login(f"Informações do arquivo: {content_hash}"):
                self.send_error_page(handler, 403, "Login falhou ou foi cancelado",
                                   "É necessário fazer login para obter informações de arquivos.",
                                   "Clique no botão abaixo para tentar fazer login novamente.")
                return

        self.do_file_info(content_hash, handler)

    def do_file_info(self, content_hash, handler):
        try:
            file_info = self.client.get_content_info(content_hash)
            if file_info:
                response_data = {
                    'content_hash': content_hash,
                    'title': file_info['title'],
                    'description': file_info['description'],
                    'mime_type': file_info['mime_type'],
                    'username': file_info['username'],
                    'verified': file_info['verified'],
                    'status': file_info['status'],
                    'sources': file_info['sources'],
                    'integrity_ok': file_info['integrity_ok'],
                    'reputation': file_info['reputation'],
                    'size': file_info['size']
                }
                handler.send_response(200)
                handler.send_header('Content-Type', 'application/json')
                handler.end_headers()
                handler.wfile.write(json.dumps(response_data).encode('utf-8'))
                self.client.db.log_security_action(
                    "web_file_info",
                    content_hash=content_hash,
                    result="success"
                )
            else:
                self.send_error_page(handler, 404, "Arquivo não encontrado",
                                   f"O arquivo com hash '{content_hash[:20]}...' não foi encontrado.",
                                   "Verifique se o hash está correto e se o arquivo está disponível na rede.")
                self.client.db.log_security_action(
                    "web_file_info_not_found",
                    content_hash=content_hash,
                    result="not_found"
                )
        except Exception as e:
            logger.error(f"Erro ao obter informações: {e}")
            self.send_error_page(handler, 500, f"Erro interno: {e}",
                               "Ocorreu um erro ao obter informações do arquivo.",
                               "Tente novamente mais tarde.")
            self.client.db.log_security_action(
                "web_file_info_error",
                content_hash=content_hash,
                result="error",
                details=f"Erro: {e}"
            )

class FastHTTPHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.wi_instance = kwargs.pop('wi_instance')
        super().__init__(*args, **kwargs)

    def do_GET(self):
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_path.query)

            if parsed_path.path == '/get-file':
                content_hash = query_params.get('hash', [''])[0]
                if content_hash and len(content_hash) == 64:
                    self.wi_instance.handle_get_file_async(content_hash, self)
                else:
                    self.wi_instance.send_error_page(self, 400, "Hash inválido ou não especificado",
                                                    "O hash fornecido é inválido ou não foi especificado.",
                                                    "Forneça um hash válido de 64 caracteres hexadecimal.")


            elif parsed_path.path == '/resolve-dns':
                domain = query_params.get('domain', [''])[0]
                if domain:
                    self.wi_instance.handle_resolve_dns_async(domain, self)
                else:
                    self.wi_instance.send_error_page(self, 400, "Domínio não especificado",
                                                    "Nenhum domínio foi fornecido para resolução.",
                                                    "Forneça um domínio válido para resolução DNS.")

            elif parsed_path.path == '/file-info':
                content_hash = query_params.get('hash', [''])[0]
                if content_hash:
                    self.wi_instance.handle_file_info_async(content_hash, self)
                else:
                    self.wi_instance.send_error_page(self, 400, "Hash não especificado",
                                                    "Nenhum hash foi fornecido para obter informações.",
                                                    "Forneça um hash válido de 64 caracteres hexadecimal.")

            elif parsed_path.path == '/health':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                response = {
                    'status': 'ok',
                    'connected': self.wi_instance.client.connected,
                    'authenticated': self.wi_instance.client.current_user is not None,
                    'user': self.wi_instance.client.current_user or 'anonymous',
                    'server': self.wi_instance.client.current_server or 'none',
                    'timestamp': time.time()
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))

            elif parsed_path.path == '/':
                self.send_home_page()

            else:
                self.wi_instance.send_error_page(self, 404, "Endpoint não encontrado",
                                                f"A página '{parsed_path.path}' não foi encontrada.",
                                                "Verifique a URL e tente novamente.")

        except Exception as e:
            logger.error(f"Erro no handler HTTP: {e}")
            self.wi_instance.send_error_page(self, 500, f"Erro interno: {e}",
                                            "Ocorreu um erro interno no servidor.",
                                            "Tente novamente mais tarde.")

    def send_home_page(self):
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HSDCM - Web Integration</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 90%;
            max-width: 1000px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .main-title {
            color: #333;
            font-size: 36px;
            margin-bottom: 10px;
            font-weight: bold;
        }
        .subtitle {
            color: #666;
            font-size: 20px;
            margin-bottom: 30px;
        }
        .status-box {
            background: linear-gradient(135deg, #fdfcfb 0%, #e2d1c3 100%);
            border: 2px solid #e0e0e0;
            border-radius: 15px;
            padding: 20px;
            margin: 20px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        .status-connected {
            background: #2ecc71;
        }
        .status-disconnected {
            background: #e74c3c;
        }
        .endpoints {
            margin-top: 40px;
        }
        .endpoint-card {
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
            transition: all 0.3s ease;
        }
        .endpoint-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            border-color: #667eea;
        }
        .endpoint-method {
            display: inline-block;
            padding: 5px 15px;
            background: #667eea;
            color: white;
            border-radius: 20px;
            font-weight: bold;
            margin-right: 10px;
        }
        .endpoint-path {
            font-family: 'Courier New', monospace;
            font-size: 16px;
            color: #333;
        }
        .endpoint-desc {
            color: #666;
            margin-top: 10px;
            font-size: 14px;
        }
        .button-container {
            text-align: center;
            margin-top: 40px;
        }
        .button {
            padding: 12px 30px;
            border: none;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            margin: 0 10px;
        }
        .button-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .button-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .button-secondary {
            background: #f8f9fa;
            color: #333;
            border: 2px solid #ddd;
        }
        .button-secondary:hover {
            background: #e9ecef;
            transform: translateY(-3px);
        }
        .footer {
            margin-top: 40px;
            color: #888;
            font-size: 12px;
            border-top: 1px solid #eee;
            padding-top: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="main-title">HSDCM - Web Integration</div>
            <div class="subtitle">API de Integração Web para o Sistema HPS</div>

            <div class="status-box">
                <div class="status-indicator">
                    <div class="status-dot status-connected"></div>
                    <span>API Online</span>
                </div>
                <div id="connection-status">Verificando conexão...</div>
            </div>
        </div>

        <div class="endpoints">
            <div class="endpoint-card">
                <div><span class="endpoint-method">GET</span> <span class="endpoint-path">/get-file?hash=&lt;hash64&gt;</span></div>
                <div class="endpoint-desc">Baixa um arquivo da rede HPS usando seu hash SHA256</div>
            </div>

            <div class="endpoint-card">
                <div><span class="endpoint-method">GET</span> <span class="endpoint-path">/search?q=&lt;query&gt;&type=&lt;type&gt;</span></div>
                <div class="endpoint-desc">Busca conteúdo na rede HPS por palavras-chave</div>
            </div>

            <div class="endpoint-card">
                <div><span class="endpoint-method">GET</span> <span class="endpoint-path">/resolve-dns?domain=&lt;domain&gt;</span></div>
                <div class="endpoint-desc">Resolve um domínio DNS da rede HPS para obter o hash de conteúdo</div>
            </div>

            <div class="endpoint-card">
                <div><span class="endpoint-method">GET</span> <span class="endpoint-path">/file-info?hash=&lt;hash64&gt;</span></div>
                <div class="endpoint-desc">Obtém informações sobre um arquivo (título, autor, reputação, etc.)</div>
            </div>

            <div class="endpoint-card">
                <div><span class="endpoint-method">GET</span> <span class="endpoint-path">/health</span></div>
                <div class="endpoint-desc">Verifica o status da API e da conexão com a rede HPS</div>
            </div>
        </div>

        <div class="button-container">
            <button class="button button-primary" onclick="testHealth()">Testar Conexão</button>
            <button class="button button-secondary" onclick="window.open('http://localhost:18238/health', '_blank')">Status da API</button>
            <button class="button button-secondary" onclick="showAbout()">Sobre o HSDCM</button>
        </div>

        <div class="footer">
            HSDCM Web Integration v1.0 • Sistema descentralizado HPS • """ + str(datetime.now().year) + """<br>
            Todas as requisições requerem permissão explícita do usuário via diálogos de segurança
        </div>
    </div>

    <script>
        function testHealth() {
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    alert(`Status da API: ${data.status}\\nConectado: ${data.connected ? 'Sim' : 'Não'}\\nUsuário: ${data.user}\\nServidor: ${data.server}`);
                })
                .catch(error => {
                    alert('Erro ao testar conexão: ' + error.message);
                });
        }

        function showAbout() {
            alert('HSDCM - HPS Surface and Desktop Compatibility Module\\n\\n' +
                  'Este é o módulo de integração web do sistema HPS.\\n' +
                  'Fornece uma API REST local para aplicações web\\n' +
                  'acessarem conteúdo da rede descentralizada HPS.\\n\\n' +
                  'Todas as ações requerem confirmação explícita do usuário\\n' +
                  'via diálogos de segurança que mostram hash, assinatura\\n' +
                  'e informações do autor antes de cada operação.');
        }

        // Atualiza status de conexão
        function updateConnectionStatus() {
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    const statusEl = document.getElementById('connection-status');
                    if (data.connected) {
                        statusEl.innerHTML = `Conectado a ${data.server} como ${data.user}`;
                    } else {
                        statusEl.innerHTML = 'Desconectado da rede HPS';
                    }
                })
                .catch(() => {
                    document.getElementById('connection-status').innerHTML = 'Erro ao verificar conexão';
                });
        }

        // Atualiza a cada 30 segundos
        updateConnectionStatus();
        setInterval(updateConnectionStatus, 30000);
    </script>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        logger.info(f"HSDCM-WI: {format % args}")

    def send_error(self, code, message=None, explain=None):
        self.wi_instance.send_error_page(self, code, f"Erro {code}", message or "", explain or "")

    def send_response(self, code, message=None):
        try:
            super().send_response(code, message)
        except (BrokenPipeError, ConnectionError):
            pass

class HSDCM_DU:
    def __init__(self, client, main_app):
        self.client = client
        self.main_app = main_app

    def show_download_interface(self):
        dialog = DownloadDialog(self.main_app.root, self.client, self.main_app)
        dialog.window.transient(self.main_app.root)
        dialog.window.grab_set()

class DownloadDialog:
    def __init__(self, parent, client, main_app):
        self.client = client
        self.main_app = main_app
        self.window = tk.Toplevel(parent)
        self.window.title("HSDCM-DU - Downloader Utility")
        self.window.geometry("850x650")

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="HSDCM-DU - Downloader Utility", font=("Arial", 18, "bold")).pack(pady=15)

        download_frame = ttk.Frame(main_frame)
        download_frame.pack(fill=tk.X, pady=15)

        ttk.Label(download_frame, text="Hash do conteúdo ou Domínio DNS:", font=("Arial", 11)).pack(anchor=tk.W)
        self.hash_var = tk.StringVar()
        hash_entry = ttk.Entry(download_frame, textvariable=self.hash_var, font=("Arial", 12))
        hash_entry.pack(fill=tk.X, pady=8)
        ttk.Label(download_frame, text="(Digite um hash de 64 caracteres ou um domínio DNS)", font=("Arial", 9), foreground="gray").pack(anchor=tk.W)

        ttk.Label(download_frame, text="Pasta de destino:", font=("Arial", 11)).pack(anchor=tk.W, pady=(12,0))
        dest_frame = ttk.Frame(download_frame)
        dest_frame.pack(fill=tk.X, pady=8)

        self.dest_var = tk.StringVar(value=os.path.expanduser("~"))
        dest_entry = ttk.Entry(dest_frame, textvariable=self.dest_var, font=("Arial", 11))
        dest_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,12))
        ttk.Button(dest_frame, text="Selecionar", command=self.select_destination).pack(side=tk.RIGHT)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Download", command=self.start_download, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Cancelar", command=self.window.destroy, width=18).pack(side=tk.LEFT, padx=10)

        self.status_var = tk.StringVar(value="Pronto para download")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Arial", 11))
        status_label.pack(pady=12)

        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.pack(fill=tk.X, pady=12)

        self.details_text = scrolledtext.ScrolledText(main_frame, height=12, font=("Arial", 10))
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=15)
        self.details_text.config(state=tk.DISABLED)

    def select_destination(self):
        folder = filedialog.askdirectory(initialdir=self.dest_var.get())
        if folder:
            self.dest_var.set(folder)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def start_download(self):
        identifier = self.hash_var.get().strip()
        dest_folder = self.dest_var.get().strip()

        if not identifier:
            messagebox.showwarning("Aviso", "Digite um hash ou domínio válido")
            return

        if not dest_folder or not os.path.exists(dest_folder):
            messagebox.showwarning("Aviso", "Selecione uma pasta de destino válida")
            return

        # Verifica se é hash (64 caracteres hex) ou domínio
        if re.match(r'^[a-fA-F0-9]{64}$', identifier):
            self.download_by_hash(identifier, dest_folder)
        else:
            self.download_by_domain(identifier, dest_folder)

    def download_by_hash(self, content_hash, dest_folder):
        content_info = self.client.get_content_info(content_hash)
        if content_info:
            dialog = SecurityDialog(self.window, content_info, "download")
            if not dialog.wait_for_choice() or not dialog.user_choice:
                self.log_message("Download cancelado pelo usuário")
                return

        if not self.client.current_user:
            def login_and_download():
                dialog = FastLoginDialog(self.window, self.client,
                                   f"Download do arquivo: {content_hash}")
                if dialog.wait_for_login():
                    self.do_download(content_hash, dest_folder)
                else:
                    self.log_message("Login falhou ou foi cancelado")

            threading.Thread(target=login_and_download, daemon=True).start()
        else:
            self.do_download(content_hash, dest_folder)

    def download_by_domain(self, domain, dest_folder):
        def resolve_and_download():
            if not self.client.current_user:
                def login_and_resolve():
                    dialog = FastLoginDialog(self.window, self.client,
                                       f"Resolução DNS: {domain}")
                    if dialog.wait_for_login():
                        self.resolve_domain(domain, dest_folder)
                    else:
                        self.log_message("Login falhou ou foi cancelado")

                threading.Thread(target=login_and_resolve, daemon=True).start()
            else:
                self.resolve_domain(domain, dest_folder)

        threading.Thread(target=resolve_and_download, daemon=True).start()

    def resolve_domain(self, domain, dest_folder):
        self.status_var.set("Resolvendo domínio DNS...")
        self.progress['value'] = 10
        self.log_message(f"Resolvendo domínio: {domain}")

        dns_event = threading.Event()
        dns_result = [None]

        def dns_callback(data):
            if data.get('domain') == domain:
                dns_result[0] = data
                dns_event.set()

        with self.client.callback_lock:
            self.client.response_callbacks[domain] = dns_callback

        try:
            request_task = asyncio.run_coroutine_threadsafe(
                self.client.resolve_dns(domain),
                self.client.loop
            )
            request_success = request_task.result(timeout=5)

            if request_success and dns_event.wait(timeout=15):
                data = dns_result[0]
                if data and 'error' not in data:
                    content_hash = data.get('content_hash')
                    self.progress['value'] = 30
                    self.log_message(f"Domínio resolvido para hash: {content_hash}")
                    self.download_by_hash(content_hash, dest_folder)
                else:
                    error = data.get('error', 'Erro desconhecido') if data else 'Timeout'
                    self.log_message(f"Erro na resolução DNS: {error}")
                    messagebox.showerror("Erro", f"Falha na resolução DNS: {error}")
            else:
                self.log_message("Timeout na resolução DNS")
                messagebox.showerror("Erro", "Timeout na resolução DNS")

        except asyncio.TimeoutError:
            self.log_message("Timeout ao iniciar resolução DNS")
            messagebox.showerror("Erro", "Timeout ao iniciar resolução DNS")
        except Exception as e:
            self.log_message(f"Erro na resolução DNS: {e}")
            messagebox.showerror("Erro", f"Erro na resolução DNS: {e}")
        finally:
            with self.client.callback_lock:
                if domain in self.client.response_callbacks:
                    del self.client.response_callbacks[domain]

    def do_download(self, content_hash, dest_folder):
        try:
            self.status_var.set("Verificando cache local...")
            self.progress['value'] = 40
            self.log_message(f"Iniciando download: {content_hash}")

            file_path = self.client.get_content_file_path(content_hash)

            if file_path and os.path.exists(file_path):
                self.progress['value'] = 80
                self.log_message("Arquivo encontrado no cache local")
                self.finalize_download(file_path, content_hash, dest_folder)
            else:
                self.progress['value'] = 50
                self.log_message("Solicitando conteúdo da rede...")

                def download_thread():
                    try:
                        def wait_for_cache(max_wait=60):
                            deadline = time.time() + max_wait
                            while time.time() < deadline:
                                file_path = self.client.get_content_file_path(content_hash)
                                if file_path and os.path.exists(file_path):
                                    self.window.after(0, lambda: self.progress.set(80))
                                    self.window.after(0, lambda: self.log_message("Conteúdo recebido (cache)"))
                                    self.window.after(0, lambda: self.finalize_download(file_path, content_hash, dest_folder))
                                    return True
                                time.sleep(2)
                            return False

                        download_event = threading.Event()
                        download_success = [False]

                        def content_callback(data):
                            if data.get('content_hash') == content_hash:
                                if 'error' not in data:
                                    download_success[0] = True
                                download_event.set()

                        with self.client.callback_lock:
                            self.client.response_callbacks[content_hash] = content_callback

                        request_task = asyncio.run_coroutine_threadsafe(
                            self.client.request_content(content_hash),
                            self.client.loop
                        )
                        request_success = request_task.result(timeout=10)

                        if request_success and download_event.wait(timeout=15):
                            if download_success[0]:
                                file_path = self.client.get_content_file_path(content_hash)
                                if file_path and os.path.exists(file_path):
                                    self.window.after(0, lambda: self.progress.set(80))
                                    self.window.after(0, lambda: self.log_message("Conteúdo recebido da rede"))
                                    self.window.after(0, lambda: self.finalize_download(file_path, content_hash, dest_folder))
                                else:
                                    if not wait_for_cache():
                                        self.window.after(0, lambda: self.log_message("Erro: Arquivo não encontrado após download"))
                                        self.window.after(0, lambda: messagebox.showerror("Erro", "Falha ao baixar arquivo"))
                            else:
                                if not wait_for_cache():
                                    self.window.after(0, lambda: self.log_message("Erro: Conteúdo não disponível"))
                                    self.window.after(0, lambda: messagebox.showerror("Erro", "Conteúdo não disponível"))
                        else:
                            if not wait_for_cache():
                                self.window.after(0, lambda: self.log_message("Erro: Timeout ao baixar arquivo"))
                                self.window.after(0, lambda: messagebox.showerror("Erro", "Timeout ao baixar arquivo"))

                    except asyncio.TimeoutError:
                        if not wait_for_cache():
                            self.window.after(0, lambda: self.log_message("Erro: Timeout ao solicitar conteúdo"))
                            self.window.after(0, lambda: messagebox.showerror("Erro", "Timeout ao solicitar conteúdo"))
                    except Exception as e:
                        self.window.after(0, lambda: self.log_message(f"Erro: {e}"))
                        self.window.after(0, lambda: messagebox.showerror("Erro", f"Erro no download: {e}"))
                    finally:
                        with self.client.callback_lock:
                            if content_hash in self.client.response_callbacks:
                                del self.client.response_callbacks[content_hash]

                threading.Thread(target=download_thread, daemon=True).start()

        except Exception as e:
            self.log_message(f"Erro no download: {e}")
            messagebox.showerror("Erro", f"Falha no download: {e}")

    def finalize_download(self, file_path, content_hash, dest_folder):
        try:
            self.progress['value'] = 90
            self.log_message("Processando arquivo...")

            with open(file_path, 'rb') as f:
                content_with_header = f.read()

            content = self.client.extract_content_from_header(content_with_header)

            # Usa o título do arquivo se disponível, senão usa o hash
            file_info = self.client.get_content_info(content_hash)
            if file_info and file_info.get('title'):
                filename = f"{file_info['title']}_{content_hash[:8]}"
            else:
                filename = content_hash

            dest_file = os.path.join(dest_folder, filename)
            with open(dest_file, 'wb') as f:
                f.write(content)

            self.progress['value'] = 100
            self.status_var.set("Download concluído!")
            self.log_message(f"Arquivo salvo em: {dest_file}")
            messagebox.showinfo("Sucesso", f"Download concluído!\nArquivo salvo em: {dest_file}")

        except Exception as e:
            self.log_message(f"Erro ao processar arquivo: {e}")
            messagebox.showerror("Erro", f"Falha ao processar arquivo: {e}")

class HSDCM_PU:
    def __init__(self, client, main_app):
        self.client = client
        self.main_app = main_app
        self.server = None
        self.port = 8081
        self.running = False
        self.active_connections = {}
        self._content_handlers = {}
        self.permission_queue = queue.Queue()
        self.permission_processor_running = False
        self.permission_processor_thread = None
        self.permission_processor_lock = threading.Lock()
        self.current_permission_dialog = None

        self.start_permission_processor()

    def start_permission_processor(self):
        if self.permission_processor_running:
            return

        self.permission_processor_running = True

        def process_permissions():
            while self.permission_processor_running:
                try:
                    request = self.permission_queue.get(timeout=1)
                    if request is None:
                        continue

                    processed = False
                    while not processed and self.permission_processor_running:
                        with self.permission_processor_lock:
                            if self.current_permission_dialog is None:
                                self.current_permission_dialog = request
                                processed = True
                        time.sleep(0.1)

                    if processed and self.current_permission_dialog:
                        self.show_permission_dialog(request)

                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Erro no processador de permissões: {e}")
                    time.sleep(1)

        self.permission_processor_thread = threading.Thread(target=process_permissions, daemon=True)
        self.permission_processor_thread.start()

    def show_permission_dialog(self, request):
        try:
            if request.content_info:
                dialog = SecurityDialog(
                    None,
                    request.content_info,
                    "proxy_access",
                    client=self.client
                )

                if dialog.wait_for_choice():
                    request.allowed = dialog.user_choice
                else:
                    request.allowed = False
            else:
                response = tk.messagebox.askyesno(
                    "HSDCM-PU - Permissão Requerida",
                    f"Uma requisição proxy está tentando acessar:\n{request.description}\n\nPermitir esta ação?"
                )
                request.allowed = response

            request.event.set()
        except Exception as e:
            logger.error(f"Erro no diálogo de permissão: {e}")
            request.allowed = False
            request.event.set()
        finally:
            with self.permission_processor_lock:
                self.current_permission_dialog = None

    def start_proxy(self):
        if self.running:
            return

        class HSDCMProxyHandler(BaseHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                self.pu_instance = kwargs.pop('pu_instance')
                super().__init__(*args, **kwargs)

            def do_GET(self):
                try:
                    host = self.headers.get('Host', '')

                    domain = host.split(':')[0] if ':' in host else host

                    # Página about.hsdcm
                    if domain == 'about.hsdcm':
                        self.serve_about_page()
                        return

                    if self.is_hash_domain(domain):
                        content_hash = domain.split('.')[0]
                        self.pu_instance.handle_proxy_request(content_hash, self)
                    else:
                        self.pu_instance.handle_domain_proxy_request(domain, self)
                except Exception as e:
                    logger.error(f"Erro no handler PU: {e}")
                    try:
                        self.pu_instance.send_error_page(self, 500, f"Erro interno: {e}",
                                                      "Ocorreu um erro interno no proxy.",
                                                      "Tente novamente mais tarde.")
                    except:
                        pass

            def serve_about_page(self):
                html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HSDCM - Sobre o Sistema</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 90%;
            max-width: 1000px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .main-title {
            color: #333;
            font-size: 36px;
            margin-bottom: 10px;
            font-weight: bold;
        }
        .subtitle {
            color: #666;
            font-size: 20px;
            margin-bottom: 30px;
        }
        .section {
            margin: 30px 0;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 15px;
            border-left: 5px solid #667eea;
        }
        .section-title {
            color: #333;
            font-size: 22px;
            margin-bottom: 15px;
            font-weight: 600;
        }
        .section-content {
            color: #555;
            line-height: 1.6;
            font-size: 15px;
        }
        .feature-list {
            list-style: none;
            padding: 0;
        }
        .feature-list li {
            padding: 10px 0;
            border-bottom: 1px solid #eee;
            display: flex;
            align-items: center;
        }
        .feature-list li:before {
            content: "✓";
            color: #2ecc71;
            font-weight: bold;
            margin-right: 10px;
            font-size: 18px;
        }
        .glossary {
            background: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .glossary-term {
            color: #3498db;
            font-weight: bold;
        }
        .button-container {
            text-align: center;
            margin-top: 40px;
        }
        .button {
            padding: 12px 30px;
            border: none;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            margin: 0 10px;
        }
        .button-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .button-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .button-secondary {
            background: #f8f9fa;
            color: #333;
            border: 2px solid #ddd;
        }
        .button-secondary:hover {
            background: #e9ecef;
            transform: translateY(-3px);
        }
        .footer {
            margin-top: 40px;
            color: #888;
            font-size: 12px;
            border-top: 1px solid #eee;
            padding-top: 20px;
            text-align: center;
        }
        .credit-box {
            background: linear-gradient(135deg, #fdfcfb 0%, #e2d1c3 100%);
            border: 2px solid #e0e0e0;
            border-radius: 15px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="main-title">HSDCM - HPS Surface and Desktop Compatibility Module</div>
            <div class="subtitle">Sistema de Integração Descentralizado para Rede HPS</div>
        </div>

        <div class="section">
            <div class="section-title">📚 O que é o HSDCM?</div>
            <div class="section-content">
                O HSDCM é um módulo de compatibilidade que integra a rede descentralizada HPS com sistemas desktop e web.
                Ele permite acesso seguro e controlado a conteúdo da rede HPS através de múltiplas interfaces:
            </div>
            <ul class="feature-list">
                <li><strong>DI</strong> (Desktop Integration): Integração com sistema de arquivos local</li>
                <li><strong>WI</strong> (Web Integration): API REST para aplicações web</li>
                <li><strong>DU</strong> (Downloader Utility): Interface gráfica para downloads</li>
                <li><strong>PU</strong> (Proxy Utility): Proxy local para acesso via navegador</li>
            </ul>
        </div>

        <div class="section">
            <div class="section-title">🔑 Nomenclaturas e Conceitos</div>
            <div class="section-content">
                <div class="glossary">
                    <p><span class="glossary-term">HPS</span>: Rede Peer-to-Peer descentralizada com criptografia e prova de trabalho.</p>
                    <p><span class="glossary-term">Hash SHA256</span>: Identificador único de 64 caracteres para cada conteúdo.</p>
                    <p><span class="glossary-term">DNS HPS</span>: Sistema de nomes descentralizado que mapeia domínios para hashes.</p>
                    <p><span class="glossary-term">PoW</span> (Proof of Work): Prova de trabalho para prevenir abuso.</p>
                    <p><span class="glossary-term">Assinatura Digital</span>: Verificação de autenticidade e autoria.</p>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">⚡ Como Usar o Proxy</div>
            <div class="section-content">
                <p>O proxy HSDCM permite acessar conteúdo HPS diretamente pelo navegador:</p>
                <ul class="feature-list">
                    <li><strong>Por Hash</strong>: Acesse http://&lt;hash64&gt;.com</li>
                    <li><strong>Por Domínio</strong>: Acesse http://&lt;dominio&gt;.com (se registrado na rede HPS)</li>
                    <li><strong>Página About</strong>: Você está aqui! http://about.hsdcm</li>
                </ul>
                <p>Cada acesso requer confirmação do usuário via diálogos de segurança.</p>
            </div>
        </div>

        <div class="credit-box">
            <div class="section-title">👨‍💻 Créditos e Informações</div>
            <div class="section-content">
                <p><strong>Sistema HSDCM</strong> - Versão 1.0</p>
                <p>Desenvolvido para a rede HPS (HPS Network)</p>
                <p>Arquitetura descentralizada • Criptografia de ponta a ponta • Controle total do usuário</p>
            </div>
        </div>

        <div class="button-container">
            <button class="button button-primary" onclick="window.location.href='https://github.com/op3ny'">Github (Thais)</button>
            <button class="button button-secondary" onclick="window.location.href='https://github.com/Hsyst/hsdcm'">Github (Projeto)</button>
        </div>

        <div class="footer">
            HSDCM Proxy Utility v1.0 • Sistema descentralizado HPS • """ + str(datetime.now().year) + """<br>
            Todas as ações requerem permissão explícita do usuário • Privacidade e segurança em primeiro lugar
        </div>
    </div>
</body>
</html>"""

                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(html.encode('utf-8'))))
                self.end_headers()
                self.wfile.write(html.encode('utf-8'))

            def do_CONNECT(self):
                self.pu_instance.send_error_page(self, 501, "Método CONNECT não suportado",
                                               "O proxy HSDCM não suporta o método CONNECT.",
                                               "Use requisições HTTP/HTTPS diretas.")

            def is_hash_domain(self, domain):
                if domain.endswith('.com'):
                    hash_part = domain.split('.')[0]
                    if len(hash_part) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_part):
                        return True
                return False

            def log_message(self, format, *args):
                logger.info(f"HSDCM-PU: {format % args}")

        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            pass

        def run_server():
            handler = lambda *args, **kwargs: HSDCMProxyHandler(*args, pu_instance=self, **kwargs)
            self.server = ThreadedHTTPServer(('localhost', self.port), handler)
            self.running = True
            logger.info(f"HSDCM-PU Proxy rodando em http://localhost:{self.port}")
            try:
                self.server.serve_forever()
            except Exception as e:
                logger.error(f"Erro no servidor PU: {e}")
            finally:
                self.running = False

        threading.Thread(target=run_server, daemon=True).start()

    def stop_proxy(self):
        if self.server:
            self.server.shutdown()
            self.server = None
            self.running = False
            logger.info("HSDCM-PU Proxy parado")

    def stop_permission_processor(self):
        self.permission_processor_running = False
        if self.permission_processor_thread:
            self.permission_processor_thread.join(timeout=5)

    def ask_permission(self, description, content_info=None):
        request = PermissionRequest(description, content_info)
        self.permission_queue.put(request)
        request.event.wait(timeout=30)
        if request.allowed is None:
            return False
        return request.allowed

    def request_login(self, description):
        login_event = threading.Event()
        login_success = [False]

        def show_dialog():
            try:
                dialog = FastLoginDialog(None, self.client, description)
                login_success[0] = dialog.wait_for_login()
                login_event.set()
            except Exception as e:
                logger.error(f"Erro no diálogo de login: {e}")
                login_event.set()

        threading.Thread(target=show_dialog, daemon=True).start()

        login_event.wait(timeout=60)
        return login_success[0]

    def send_error_page(self, handler, code, title, message, suggestion=""):
        try:
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HSDCM - {title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            width: 80%;
            max-width: 800px;
            text-align: center;
        }}
        .header {{
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
            font-weight: bold;
        }}
        .subheader {{
            color: #666;
            font-size: 18px;
            margin-bottom: 30px;
        }}
        .error-box {{
            background: linear-gradient(135deg, #fdfcfb 0%, #e2d1c3 100%);
            border: 2px solid #e0e0e0;
            border-radius: 15px;
            padding: 30px;
            margin: 30px 0;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        .error-title {{
            color: #e74c3c;
            font-size: 24px;
            margin-bottom: 15px;
            font-weight: bold;
        }}
        .error-message {{
            color: #555;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .suggestion {{
            color: #3498db;
            font-size: 14px;
            font-style: italic;
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 4px solid #3498db;
        }}
        .button-container {{
            margin-top: 30px;
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
        }}
        .button {{
            padding: 12px 30px;
            border: none;
            border-radius: 50px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }}
        .button-primary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .button-primary:hover {{
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }}
        .button-secondary {{
            background: #f8f9fa;
            color: #333;
            border: 2px solid #ddd;
        }}
        .button-secondary:hover {{
            background: #e9ecef;
            transform: translateY(-3px);
        }}
        .code {{
            font-family: 'Courier New', monospace;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 14px;
        }}
        .footer {{
            margin-top: 40px;
            color: #888;
            font-size: 12px;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }}
        .domain-info {{
            background: #f1c40f;
            color: #2c3e50;
            padding: 10px;
            border-radius: 10px;
            margin: 15px 0;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">HSDCM - HPS Surface and Desktop Compatibility Module</div>
        <div class="subheader">Proxy Utility - Portal de Erros</div>

        <div class="error-box">
            <div class="error-title">⚠️ {title}</div>
            <div class="error-message">{message}</div>

            <div class="code">
                Código do Erro: {code}<br>
                Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                Proxy: localhost:{self.port}
            </div>

            {f'<div class="suggestion">💡 Sugestão: {suggestion}</div>' if suggestion else ''}

            <div class="domain-info">
                ℹ️ Este é um proxy HSDCM para acessar conteúdo da rede HPS via navegador
            </div>
        </div>

        <div class="button-container">
            <button class="button button-primary" onclick="window.location.href='http://about.hsdcm'">Sobre o HSDCM</button>
            <button class="button button-secondary" onclick="window.location.reload()">Tentar Novamente</button>
            {f'<button class="button button-primary" onclick="github()">GitHub</button>' if code == 403 else ''}
            <button class="button button-secondary" onclick="window.location.href=\'/\'">Voltar</button>
        </div>

        <div class="footer">
            HSDCM Proxy Utility • Sistema descentralizado HPS • {datetime.now().year}<br>
            Acesse http://about.hsdcm para mais informações sobre o sistema
            Made by Thais (https://github.com/op3ny)
        </div>
    </div>

    <script>
        function github() {{
            alert('Github: https://github.com/Hsyst/hsdcm \\n\\n' +
                  'Feito pela Thais (https://github.com/op3ny)');
        }}
    </script>
</body>
</html>"""

            handler.send_response(code)
            handler.send_header('Content-Type', 'text/html; charset=utf-8')
            handler.send_header('Content-Length', str(len(html.encode('utf-8'))))
            handler.end_headers()
            handler.wfile.write(html.encode('utf-8'))
        except:
            pass

    def handle_domain_proxy_request(self, domain, http_handler):
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = http_handler

        cached_hash = self.client.get_dns_resolution(domain)
        if cached_hash:
            self.handle_proxy_request_with_hash(cached_hash, http_handler, connection_id, domain)
            return

        if not self.ask_permission(f"Resolver domínio DNS: {domain}"):
            self.fail_proxy_request(connection_id, "Ação não permitida pelo usuário", domain)
            self.client.db.log_security_action(
                "proxy_dns_denied",
                domain=domain,
                result="denied"
            )
            return

        if not self.client.current_user:
            if not self.request_login(f"Resolver domínio DNS: {domain}"):
                self.fail_proxy_request(connection_id, "Login falhou ou foi cancelado", domain)
                self.client.db.log_security_action(
                    "proxy_dns_failed",
                    domain=domain,
                    result="login_failed"
                )
                return

        self.do_domain_resolution(domain, http_handler, connection_id)

    def do_domain_resolution(self, domain, http_handler, connection_id):
        dns_event = threading.Event()
        dns_result = [None]

        def dns_callback(data):
            if data.get('domain') == domain:
                dns_result[0] = data
                dns_event.set()

        with self.client.callback_lock:
            self.client.response_callbacks[domain] = dns_callback

        try:
            request_task = asyncio.run_coroutine_threadsafe(
                self.client.resolve_dns(domain),
                self.client.loop
            )
            request_success = request_task.result(timeout=5)

            if not request_success:
                self.send_error_page(http_handler, 500, "Falha ao resolver domínio",
                                   f"Não foi possível resolver o domínio '{domain}'.",
                                   "Verifique sua conexão com a rede HPS.")
                self.client.db.log_security_action(
                    "proxy_dns_error",
                    domain=domain,
                    result="error",
                    details="Falha ao iniciar resolução"
                )
                return

            if dns_event.wait(timeout=15):
                data = dns_result[0]
                if data and 'error' not in data:
                    content_hash = data.get('content_hash')
                    if content_hash:
                        self.handle_proxy_request_with_hash(content_hash, http_handler, connection_id, domain)
                    else:
                        self.send_error_page(http_handler, 404, "Domínio não encontrado",
                                           f"O domínio '{domain}' não foi encontrado na rede HPS.",
                                           "Verifique se o domínio está registrado corretamente.")
                        self.client.db.log_security_action(
                            "proxy_dns_not_found",
                            domain=domain,
                            result="not_found"
                        )
                else:
                    error_msg = data.get('error', 'Nenhum resultado encontrado') if data else 'Timeout'
                    self.send_error_page(http_handler, 404, "Falha na resolução DNS",
                                       f"Falha ao resolver o domínio '{domain}': {error_msg}",
                                       "Tente novamente em alguns instantes.")
                    self.client.db.log_security_action(
                        "proxy_dns_not_found",
                        domain=domain,
                        result="not_found",
                        details=f"Erro: {error_msg}"
                    )
            else:
                self.send_error_page(http_handler, 408, "Timeout na resolução DNS",
                                   f"O tempo para resolver o domínio '{domain}' expirou.",
                                   "Tente novamente com uma conexão mais estável.")
                self.client.db.log_security_action(
                    "proxy_dns_timeout",
                    domain=domain,
                    result="timeout"
                )
        except asyncio.TimeoutError:
            self.send_error_page(http_handler, 408, "Timeout ao resolver domínio",
                               f"Não foi possível resolver o domínio '{domain}' devido a timeout.",
                               "Verifique sua conexão com a rede HPS.")
            self.client.db.log_security_action(
                "proxy_dns_timeout",
                domain=domain,
                result="timeout"
            )
        except Exception as e:
            logger.error(f"Erro na resolução DNS: {e}")
            self.send_error_page(http_handler, 500, f"Erro interno: {e}",
                               f"Ocorreu um erro ao resolver o domínio '{domain}'.",
                               "Tente novamente mais tarde.")
            self.client.db.log_security_action(
                "proxy_dns_error",
                domain=domain,
                result="error",
                details=f"Erro: {e}"
            )
        finally:
            with self.client.callback_lock:
                if domain in self.client.response_callbacks:
                    del self.client.response_callbacks[domain]

    def handle_proxy_request(self, content_hash, http_handler):
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = http_handler
        self.handle_proxy_request_with_hash(content_hash, http_handler, connection_id, None)

    def handle_proxy_request_with_hash(self, content_hash, http_handler, connection_id, domain=None):
        content_info = self.client.get_content_info(content_hash)

        description = f"Acesso via proxy ao conteúdo: {content_hash}"
        if domain:
            description = f"Acesso via proxy ao domínio: {domain} -> {content_hash}"

        if not self.ask_permission(description, content_info):
            self.fail_proxy_request(connection_id, "Ação não permitida pelo usuário", domain)
            action_type = "proxy_dns_access" if domain else "proxy_access"
            self.client.db.log_security_action(
                f"{action_type}_denied",
                content_hash=content_hash,
                domain=domain,
                result="denied"
            )
            return

        if not self.client.current_user:
            if not self.request_login(description):
                self.fail_proxy_request(connection_id, "Login falhou ou foi cancelado", domain)
                action_type = "proxy_dns_access" if domain else "proxy_access"
                self.client.db.log_security_action(
                    f"{action_type}_failed",
                    content_hash=content_hash,
                    domain=domain,
                    result="login_failed"
                )
                return

        self.do_proxy_serve(content_hash, http_handler, connection_id, domain)

    def fail_proxy_request(self, connection_id, error_message, domain=None):
        if connection_id in self.active_connections:
            try:
                handler = self.active_connections[connection_id]
                self.send_error_page(handler, 403, "Ação não permitida", error_message,
                                   "Permita o acesso através do diálogo de segurança.")
            except:
                pass
            finally:
                del self.active_connections[connection_id]

    def do_proxy_serve(self, content_hash, http_handler, connection_id, domain=None):
        try:
            if not self.client.connected or not self.client.current_user:
                self.send_error_page(http_handler, 403, "Cliente não conectado ou não autenticado",
                                   "É necessário estar conectado e autenticado na rede HPS.",
                                   "Conecte-se a um servidor HPS e faça login.")
                action_type = "proxy_dns_access" if domain else "proxy_access"
                self.client.db.log_security_action(
                    f"{action_type}_failed",
                    content_hash=content_hash,
                    domain=domain,
                    result="not_connected"
                )
                return

            file_path = self.client.get_content_file_path(content_hash)

            if file_path and os.path.exists(file_path):
                self._serve_content_from_file(content_hash, file_path, http_handler, connection_id, domain)
            else:
                self._download_and_serve_content(content_hash, http_handler, connection_id, domain)

        except Exception as e:
            logger.error(f"Erro no proxy: {e}")
            try:
                self.send_error_page(http_handler, 500, f"Erro interno: {e}",
                                   "Ocorreu um erro durante o processamento da requisição.",
                                   "Tente novamente mais tarde.")
                action_type = "proxy_dns_access" if domain else "proxy_access"
                self.client.db.log_security_action(
                    f"{action_type}_error",
                    content_hash=content_hash,
                    domain=domain,
                    result="error",
                    details=f"Erro: {e}"
                )
            except:
                pass
        finally:
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]

    def _serve_content_from_file(self, content_hash, file_path, http_handler, connection_id, domain=None):
        try:
            with open(file_path, 'rb') as f:
                content_with_header = f.read()

            content = self.client.extract_content_from_header(content_with_header)

            mime_type = 'text/html'
            try:
                file_info = self.client.get_content_info(content_hash)
                if file_info and file_info['mime_type']:
                    mime_type = file_info['mime_type']
            except:
                pass

            http_handler.send_response(200)
            http_handler.send_header('Content-Type', mime_type)
            http_handler.send_header('Content-Length', str(len(content)))
            if domain:
                http_handler.send_header('X-HSDCM-Domain', domain)
            http_handler.send_header('X-HSDCM-Hash', content_hash)
            http_handler.end_headers()
            http_handler.wfile.write(content)

            logger.info(f"Conteúdo servido via proxy: {content_hash} (domínio: {domain})")
            action_type = "proxy_dns_access" if domain else "proxy_access"
            self.client.db.log_security_action(
                f"{action_type}_served",
                content_hash=content_hash,
                domain=domain,
                result="served"
            )
        except BrokenPipeError:
            logger.warning("Cliente fechou a conexão durante o envio do conteúdo")
            action_type = "proxy_dns_access" if domain else "proxy_access"
            self.client.db.log_security_action(
                f"{action_type}_connection_lost",
                content_hash=content_hash,
                domain=domain,
                result="connection_lost"
            )
        except Exception as e:
            logger.error(f"Erro ao servir conteúdo do arquivo: {e}")
            self.send_error_page(http_handler, 500, f"Erro interno: {e}",
                               "Ocorreu um erro ao servir o conteúdo.",
                               "Tente baixar novamente.")
            action_type = "proxy_dns_access" if domain else "proxy_access"
            self.client.db.log_security_action(
                f"{action_type}_error",
                content_hash=content_hash,
                domain=domain,
                result="error",
                details=f"Erro ao servir: {e}"
            )

    def _download_and_serve_content(self, content_hash, http_handler, connection_id, domain=None):
        if content_hash in self._content_handlers:
            self.send_loading_page(http_handler, content_hash, domain, in_progress=True)
            action_type = "proxy_dns_access" if domain else "proxy_access"
            self.client.db.log_security_action(
                f"{action_type}_busy",
                content_hash=content_hash,
                domain=domain,
                result="busy"
            )
            return

        self._content_handlers[content_hash] = {
            "started_at": time.time(),
            "domain": domain
        }
        self.send_loading_page(http_handler, content_hash, domain, in_progress=False)

        content_received = threading.Event()
        download_success = [False]

        def content_handler(data):
            if data.get('content_hash') == content_hash:
                if 'error' not in data:
                    download_success[0] = True
                content_received.set()

        with self.client.callback_lock:
            self.client.response_callbacks[content_hash] = content_handler

        def download_thread():
            try:
                request_task = asyncio.run_coroutine_threadsafe(
                    self.client.request_content(content_hash),
                    self.client.loop
                )
                request_success = request_task.result(timeout=10)

                if request_success and content_received.wait(timeout=60) and download_success[0]:
                    logger.info(f"Download proxy concluído: {content_hash}")
                else:
                    logger.info(f"Download proxy pendente/timeout: {content_hash}")

            except asyncio.TimeoutError:
                logger.info(f"Timeout ao solicitar conteúdo no proxy: {content_hash}")
            except Exception as e:
                logger.error(f"Erro ao baixar conteúdo no proxy: {e}")
            finally:
                if content_hash in self._content_handlers:
                    del self._content_handlers[content_hash]

                with self.client.callback_lock:
                    if content_hash in self.client.response_callbacks:
                        del self.client.response_callbacks[content_hash]

        threading.Thread(target=download_thread, daemon=True).start()

    def send_loading_page(self, http_handler, content_hash, domain=None, in_progress=False):
        try:
            title = "Baixando conteúdo..." if in_progress else "Iniciando download..."
            detail = f"Domínio: {domain}" if domain else f"Hash: {content_hash}"
            html = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f7f7f7; color: #222; }}
    .wrap {{ max-width: 720px; margin: 60px auto; background: #fff; padding: 24px; border-radius: 10px; box-shadow: 0 4px 16px rgba(0,0,0,0.08); }}
    .status {{ font-size: 18px; margin-bottom: 8px; }}
    .detail {{ color: #555; margin-bottom: 16px; }}
    .hint {{ color: #777; font-size: 14px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="status">{title}</div>
    <div class="detail">{detail}</div>
    <div class="hint">Esta página irá atualizar automaticamente a cada 2 segundos.</div>
  </div>
  <script>
    setTimeout(function() {{
      window.location.reload();
    }}, 2000);
  </script>
</body>
</html>"""

            http_handler.send_response(200)
            http_handler.send_header('Content-Type', 'text/html; charset=utf-8')
            http_handler.send_header('Cache-Control', 'no-store')
            http_handler.send_header('Content-Length', str(len(html.encode('utf-8'))))
            if domain:
                http_handler.send_header('X-HSDCM-Domain', domain)
            http_handler.send_header('X-HSDCM-Hash', content_hash)
            http_handler.end_headers()
            http_handler.wfile.write(html.encode('utf-8'))
        except Exception as e:
            logger.error(f"Erro ao enviar página de loading: {e}")

class SystemTrayIcon:
    def __init__(self, main_app):
        self.main_app = main_app
        self.icon = None

        if platform.system() == "Windows":
            self.setup_windows_tray()
        elif platform.system() == "Darwin":
            self.setup_mac_tray()
        else:
            self.setup_linux_tray()

    def setup_windows_tray(self):
        try:
            import pystray
            from PIL import Image, ImageDraw

            image = Image.new('RGB', (64, 64), color='white')
            draw = ImageDraw.Draw(image)
            draw.rectangle([16, 16, 48, 48], fill='blue')

            menu = pystray.Menu(
                pystray.MenuItem("Abrir HSDCM", self.show_main_window),
                pystray.MenuItem("Downloader Utility", self.show_downloader),
                pystray.MenuItem("Sair", self.exit_app)
            )

            self.icon = pystray.Icon("HSDCM", image, "HSDCM", menu)

            def run_icon():
                self.icon.run()

            threading.Thread(target=run_icon, daemon=True).start()
        except ImportError:
            logger.warning("pystray não instalado - system tray não disponível")

    def setup_mac_tray(self):
        logger.info("System tray não suportado no macOS")

    def setup_linux_tray(self):
        logger.info("System tray não suportado no Linux")

    def show_main_window(self):
        if self.main_app and self.main_app.root:
            self.main_app.root.deiconify()
            self.main_app.root.lift()
            self.main_app.root.focus_force()

    def show_downloader(self):
        if self.main_app:
            self.main_app.du.show_download_interface()

    def exit_app(self):
        if self.main_app:
            self.main_app.quit_app()

class HSDCMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HSDCM - HPS Surface and Desktop Compatibility Module")
        self.root.geometry("1100x950")
        self.root.minsize(900, 700)

        self.client = HPSClient()
        self.di = HSDCM_DI(self.client, self)
        self.wi = HSDCM_WI(self.client, self)
        self.du = HSDCM_DU(self.client, self)
        self.pu = HSDCM_PU(self.client, self)

        self.tray_icon = SystemTrayIcon(self)

        self.setup_ui()
        self.load_settings()

        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)
        self.start_services()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        ttk.Label(main_frame, text="HSDCM - HPS Surface and Desktop Compatibility Module",
                 font=("Arial", 18, "bold")).grid(row=0, column=0, columnspan=3, pady=20)

        nav_frame = ttk.Frame(main_frame)
        nav_frame.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.W), padx=(0, 20))

        self.nav_buttons = {
            "di": ttk.Button(nav_frame, text="Desktop Integration", command=self.show_di, width=22),
            "wi": ttk.Button(nav_frame, text="Web Integration", command=self.show_wi, width=22),
            "du": ttk.Button(nav_frame, text="Downloader Utility", command=self.show_du, width=22),
            "pu": ttk.Button(nav_frame, text="Proxy Utility", command=self.show_pu, width=22),
            "logs": ttk.Button(nav_frame, text="Logs do Sistema", command=self.show_logs, width=22),
            "settings": ttk.Button(nav_frame, text="Configurações", command=self.show_settings, width=22),
        }

        for button in self.nav_buttons.values():
            button.pack(fill=tk.X, pady=6)

        self.main_area = ttk.Frame(main_frame)
        self.main_area.grid(row=1, column=1, sticky=(tk.N, tk.E, tk.S, tk.W))
        self.main_area.columnconfigure(0, weight=1)
        self.main_area.rowconfigure(0, weight=1)

        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=15)

        self.status_var = tk.StringVar(value="Desconectado")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, font=("Arial", 10))
        status_label.pack(side=tk.LEFT)

        self.user_var = tk.StringVar(value="Não logado")
        ttk.Label(status_frame, textvariable=self.user_var, font=("Arial", 10)).pack(side=tk.RIGHT)

        self.setup_di_ui()
        self.setup_wi_ui()
        self.setup_du_ui()
        self.setup_pu_ui()
        self.setup_settings_ui()
        self.setup_logs_ui()

        self.show_di()

        log_handler = TextHandler(self.log_text)
        log_handler.setLevel(logging.INFO)
        logger.addHandler(log_handler)

    def start_services(self):
        self.di.start_monitoring()
        self.wi.start_api()
        self.pu.start_proxy()

    def setup_di_ui(self):
        self.di_frame = ttk.Frame(self.main_area)

        ttk.Label(self.di_frame, text="HSDCM-DI - Desktop Integration", font=("Arial", 16, "bold")).pack(pady=20)

        info_text = f"""HSDCM-DI (Desktop Integration) fornece integração completa do HPS com o sistema de arquivos local.

Funcionalidades:
• Disco Virtual: Uma pasta monitorada que funciona como armazenamento em nuvem HPS
• Download por Hash: Crie arquivos .download para baixar conteúdo da rede (com confirmação)
• Download por DNS: Crie arquivos .dns.download para resolver domínios e baixar conteúdo
• Diálogos de Segurança: Todas as ações mostram informações de segurança antes de prosseguir
• Verificação de Assinatura: Verifica automaticamente a autenticidade dos arquivos

Como usar:
1. A pasta do disco virtual está localizada em:
   {self.di.virtual_disk_path}

2. Para download por hash: Crie um arquivo <HASH64>.download na pasta
3. Para download por DNS: Crie um arquivo <DOMINIO>.dns.download na pasta
4. Todas as ações requerem confirmação e login se necessário
5. Diálogos de segurança mostram hash, assinatura e informações do autor"""

        info_label = ttk.Label(self.di_frame, text=info_text, justify=tk.LEFT, wraplength=750, font=("Arial", 10))
        info_label.pack(pady=20, padx=20, fill=tk.X)

        button_frame = ttk.Frame(self.di_frame)
        button_frame.pack(pady=25)

        ttk.Button(button_frame, text="Abrir Pasta", command=self.open_di_folder, width=20).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Testar Download", command=self.test_di_download, width=20).pack(side=tk.LEFT, padx=10)

        self.di_status = ttk.Label(self.di_frame, text="Monitoramento: Ativo", font=("Arial", 10))
        self.di_status.pack(pady=15)

    def setup_wi_ui(self):
        self.wi_frame = ttk.Frame(self.main_area)

        ttk.Label(self.wi_frame, text="HSDCM-WI - Web Integration", font=("Arial", 16, "bold")).pack(pady=20)

        info_text = """HSDCM-WI (Web Integration) fornece uma API local para integração com aplicações web.

Funcionalidades:
• API REST: Serviço local na porta 18238
• Autenticação Segura: Popups de confirmação e diálogos de segurança para todas as ações
• Download via Web: Sites podem solicitar download de arquivos HPS
• Controle de Permissões: Usuário decide permitir ou negar cada ação
• Diálogos de Segurança: Mostra hash, assinatura e informações do autor antes de cada download
• Páginas de Erro Customizadas: Erros bonitos e amigáveis com sugestões de solução

Endpoints disponíveis:
• GET /get-file?hash=<HASH64> - Baixa um arquivo da rede HPS
• GET /resolve-dns?domain=<domain> - Resolve um domínio DNS
• GET /file-info?hash=<hash64> - Obtém informações sobre um arquivo
• GET /health - Verifica status da API e conexão

Como usar:
1. Configure seu site para fazer requisições para http://localhost:18238
2. Para cada ação, um popup solicitará sua confirmação e login se necessário
3. Diálogos de segurança mostram informações detalhadas antes de cada download
4. Em caso de erro, páginas bonitas explicam o problema e sugerem soluções"""

        info_label = ttk.Label(self.wi_frame, text=info_text, justify=tk.LEFT, wraplength=750, font=("Arial", 10))
        info_label.pack(pady=20, padx=20, fill=tk.X)

        button_frame = ttk.Frame(self.wi_frame)
        button_frame.pack(pady=25)

        ttk.Button(button_frame, text="Testar Conexão", command=self.test_wi, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Abrir API Web", command=self.open_wi_browser, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Documentação", command=self.show_wi_docs, width=18).pack(side=tk.LEFT, padx=10)

        self.wi_status = ttk.Label(self.wi_frame, text="API: Rodando na porta 18238", font=("Arial", 10))
        self.wi_status.pack(pady=15)

    def setup_du_ui(self):
        self.du_frame = ttk.Frame(self.main_area)

        ttk.Label(self.du_frame, text="HSDCM-DU - Downloader Utility", font=("Arial", 16, "bold")).pack(pady=20)

        info_text = """HSDCM-DU (Downloader Utility) fornece uma interface simplificada para download de arquivos HPS.

Funcionalidades:
• Interface Gráfica: Download fácil sem usar o disco virtual
• Suporte a Hash e DNS: Baixe por hash SHA256 ou por domínio DNS
• Seleção de Destino: Escolha onde salvar os arquivos
• Status Detalhado: Acompanhamento do progresso do download
• Diálogos de Segurança: Mostra hash, assinatura e informações do autor antes de cada download
• Verificação de Assinatura: Verifica automaticamente a autenticidade dos arquivos

Como usar:
1. Use o botão abaixo para abrir a interface de download
2. Digite o hash (64 caracteres) ou domínio DNS desejado
3. Selecione a pasta de destino
4. Um diálogo de segurança mostrará as informações do arquivo
5. Clique em Download e aguarde a conclusão"""

        info_label = ttk.Label(self.du_frame, text=info_text, justify=tk.LEFT, wraplength=750, font=("Arial", 10))
        info_label.pack(pady=20, padx=20, fill=tk.X)

        button_frame = ttk.Frame(self.du_frame)
        button_frame.pack(pady=25)

        ttk.Button(button_frame, text="Abrir Downloader", command=self.open_du, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Exemplos", command=self.show_du_examples, width=18).pack(side=tk.LEFT, padx=10)

        self.du_status = ttk.Label(self.du_frame, text="Pronto para uso", font=("Arial", 10))
        self.du_status.pack(pady=15)

    def setup_pu_ui(self):
        self.pu_frame = ttk.Frame(self.main_area)

        ttk.Label(self.pu_frame, text="HSDCM-PU - Proxy Utility", font=("Arial", 16, "bold")).pack(pady=20)

        info_text = """HSDCM-PU (Proxy Utility) fornece um proxy local para acesso web a conteúdo HPS.

Funcionalidades:
• Proxy Local: Serviço na porta 8081
• Domínios por Hash: Acesse conteúdo usando <hash64>.com
• Domínios DDNS: Acesse conteúdo usando domínios registrados na rede HPS
• Página About: Acesse http://about.hsdcm para informações sobre o sistema
• Renderização Web: Conteúdo HTML é renderizado no navegador
• Segurança: Popups de confirmação e diálogos de segurança para cada acesso
• Diálogos de Segurança: Mostra hash, assinatura e informações do autor antes de servir conteúdo
• Páginas de Erro Customizadas: Erros bonitos com botões de ação (login, retry, etc.)

Como usar:
1. Configure seu navegador para usar localhost:8081 como proxy
2. Acesse conteúdo usando URLs como: http://<hash64>.com
3. Ou acesse domínios DDNS: http://<dominio>.com
4. Para cada acesso, um diálogo de segurança solicitará confirmação e login
5. Acesse http://about.hsdcm para informações sobre o sistema"""

        info_label = ttk.Label(self.pu_frame, text=info_text, justify=tk.LEFT, wraplength=750, font=("Arial", 10))
        info_label.pack(pady=20, padx=20, fill=tk.X)

        button_frame = ttk.Frame(self.pu_frame)
        button_frame.pack(pady=25)

        ttk.Button(button_frame, text="Testar Proxy", command=self.test_pu, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Abrir About", command=self.open_pu_about, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Configurar Proxy", command=self.configure_proxy, width=18).pack(side=tk.LEFT, padx=10)

        self.pu_status = ttk.Label(self.pu_frame, text="Proxy: Rodando na porta 8081", font=("Arial", 10))
        self.pu_status.pack(pady=15)

    def setup_settings_ui(self):
        self.settings_frame = ttk.Frame(self.main_area)

        ttk.Label(self.settings_frame, text="Configurações HSDCM", font=("Arial", 16, "bold")).pack(pady=20)

        settings_form = ttk.Frame(self.settings_frame)
        settings_form.pack(fill=tk.X, pady=20, padx=25)

        ttk.Label(settings_form, text="Inicialização Automática:", font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=10)
        self.auto_start_var = tk.BooleanVar()
        ttk.Checkbutton(settings_form, variable=self.auto_start_var).grid(row=0, column=1, sticky=tk.W, pady=10)

        ttk.Label(settings_form, text="Iniciar com Sistema:", font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=10)
        self.start_with_system_var = tk.BooleanVar()
        ttk.Checkbutton(settings_form, variable=self.start_with_system_var).grid(row=1, column=1, sticky=tk.W, pady=10)

        ttk.Label(settings_form, text="Servidor Padrão:", font=("Arial", 11)).grid(row=2, column=0, sticky=tk.W, pady=10)
        self.default_server_var = tk.StringVar(value="server1.hps.hsyst.xyz")
        ttk.Entry(settings_form, textvariable=self.default_server_var, font=("Arial", 10)).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=10, padx=(15, 0))

        ttk.Label(settings_form, text="Porta API Web:", font=("Arial", 11)).grid(row=3, column=0, sticky=tk.W, pady=10)
        self.api_port_var = tk.StringVar(value="18238")
        ttk.Entry(settings_form, textvariable=self.api_port_var, font=("Arial", 10)).grid(row=3, column=1, sticky=(tk.W, tk.E), pady=10, padx=(15, 0))

        ttk.Label(settings_form, text="Porta Proxy:", font=("Arial", 11)).grid(row=4, column=0, sticky=tk.W, pady=10)
        self.proxy_port_var = tk.StringVar(value="8081")
        ttk.Entry(settings_form, textvariable=self.proxy_port_var, font=("Arial", 10)).grid(row=4, column=1, sticky=(tk.W, tk.E), pady=10, padx=(15, 0))

        settings_form.columnconfigure(1, weight=1)

        button_frame = ttk.Frame(self.settings_frame)
        button_frame.pack(pady=25)

        ttk.Button(button_frame, text="Salvar Configurações", command=self.save_settings, width=20).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Restaurar Padrões", command=self.restore_defaults, width=20).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Login HPS", command=self.show_login, width=20).pack(side=tk.LEFT, padx=10)

    def setup_logs_ui(self):
        self.log_frame = ttk.Frame(self.main_area)

        ttk.Label(self.log_frame, text="Logs do Sistema HSDCM", font=("Arial", 16, "bold")).pack(pady=20)

        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=35, font=("Courier", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.log_text.config(state=tk.DISABLED)

        button_frame = ttk.Frame(self.log_frame)
        button_frame.pack(pady=15)
        ttk.Button(button_frame, text="Limpar Logs", command=self.clear_logs, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Copiar Logs", command=self.copy_logs, width=18).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Salvar Logs", command=self.save_logs, width=18).pack(side=tk.LEFT, padx=10)

    def show_di(self):
        self.show_frame(self.di_frame)
        self.update_nav_buttons("di")

    def show_wi(self):
        self.show_frame(self.wi_frame)
        self.update_nav_buttons("wi")

    def show_du(self):
        self.show_frame(self.du_frame)
        self.update_nav_buttons("du")

    def show_pu(self):
        self.show_frame(self.pu_frame)
        self.update_nav_buttons("pu")

    def show_logs(self):
        self.show_frame(self.log_frame)
        self.update_nav_buttons("logs")

    def show_settings(self):
        self.show_frame(self.settings_frame)
        self.update_nav_buttons("settings")

    def show_frame(self, frame):
        for widget in self.main_area.winfo_children():
            widget.pack_forget()
        frame.pack(fill=tk.BOTH, expand=True)

    def update_nav_buttons(self, active_button):
        for name, button in self.nav_buttons.items():
            if name == active_button:
                button.config(style="Accent.TButton")
            else:
                button.config(style="TButton")

    def open_di_folder(self):
        if platform.system() == "Windows":
            os.startfile(self.di.virtual_disk_path)
        elif platform.system() == "Darwin":
            subprocess.run(["open", self.di.virtual_disk_path])
        else:
            subprocess.run(["xdg-open", self.di.virtual_disk_path])

    def test_di_download(self):
        test_file = os.path.join(self.di.virtual_disk_path, "TEST.download")
        try:
            with open(test_file, 'w') as f:
                f.write("Arquivo de teste para download via HSDCM-DI")
            messagebox.showinfo("Teste DI", f"Arquivo de teste criado: {test_file}\n\nO sistema monitorará este arquivo e solicitará download quando detectado.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao criar arquivo de teste: {e}")

    def test_wi(self):
        try:
            port = int(self.api_port_var.get())
            response = requests.get(f"http://localhost:{port}/health", timeout=2)
            if response.status_code == 200:
                data = response.json()
                status = f"API respondendo: {data['status']}\n"
                status += f"Conectado: {'Sim' if data['connected'] else 'Não'}\n"
                status += f"Usuário: {data['user']}\n"
                status += f"Servidor: {data['server']}"
                messagebox.showinfo("Teste WI - Sucesso", status)
            else:
                messagebox.showinfo("Teste WI", f"API com erro: {response.status_code}")
        except requests.exceptions.ConnectionError:
            messagebox.showinfo("Teste WI", "API não está respondendo. Certifique-se de que o serviço está rodando.")
        except Exception as e:
            messagebox.showinfo("Teste WI", f"Erro no teste: {e}")

    def open_wi_browser(self):
        port = int(self.api_port_var.get())
        webbrowser.open(f"http://localhost:{port}")

    def show_wi_docs(self):
        docs = """Documentação da API HSDCM-WI:

Endpoints disponíveis:
1. GET /get-file?hash=<HASH64>
   - Baixa um arquivo da rede HPS
   - Requer: Hash SHA256 de 64 caracteres
   - Retorna: Arquivo binário

2. GET /resolve-dns?domain=<domain>
   - Resolve um domínio DNS da rede HPS
   - Requer: Nome de domínio
   - Retorna: JSON com hash do conteúdo

3. GET /file-info?hash=<hash64>
   - Obtém informações sobre um arquivo
   - Requer: Hash SHA256 de 64 caracteres
   - Retorna: JSON com metadados

4. GET /health
   - Verifica status da API
   - Retorna: JSON com status e informações

Segurança:
- Todas as requisições requerem permissão do usuário
- Diálogos de segurança mostram informações detalhadas
- Login é solicitado quando necessário
- Assinaturas digitais são verificadas"""

        messagebox.showinfo("Documentação WI", docs)

    def open_du(self):
        self.du.show_download_interface()

    def show_du_examples(self):
        examples = """Exemplos de uso do HSDCM-DU:

1. Download por Hash:
   - Hash: abc123def456abc123def456abc123def456abc123def456abc123def45612
   - (Use um hash real da rede HPS)

2. Download por DNS:
   - Domínio: exemplo.hps
   - (Use um domínio registrado na rede HPS)

Passos:
1. Abra o Downloader Utility
2. Digite o hash ou domínio
3. Selecione a pasta de destino
4. Confirme no diálogo de segurança
5. Aguarde o download

Observações:
- Hashes devem ter 64 caracteres hexadecimais
- Domínios devem estar registrados na rede HPS
- Todos os downloads requerem confirmação
- Arquivos são verificados por assinatura digital"""

        messagebox.showinfo("Exemplos DU", examples)

    def test_pu(self):
        try:
            port = int(self.proxy_port_var.get())
            # Testa a página about
            response = requests.get(f"http://localhost:{port}",
                                  headers={'Host': 'about.hsdcm'},
                                  timeout=2)
            if response.status_code == 200:
                messagebox.showinfo("Teste PU - Sucesso", f"Proxy respondendo na porta {port}\nPágina about.hsdcm carregada com sucesso!")
            else:
                messagebox.showinfo("Teste PU", f"Proxy respondendo: {response.status_code}")
        except requests.exceptions.ConnectionError:
            messagebox.showinfo("Teste PU", "Proxy não está respondendo. Certifique-se de que o serviço está rodando.")
        except Exception as e:
            messagebox.showinfo("Teste PU", f"Erro no teste: {e}")

    def open_pu_about(self):
        port = int(self.proxy_port_var.get())
        webbrowser.open(f"http://localhost:{port}")

    def configure_proxy(self):
        config = """Configuração do Proxy HSDCM-PU:

Para usar o proxy HSDCM no seu navegador:

1. No Windows:
   - Configurações → Rede e Internet → Proxy
   - Configurar proxy manualmente
   - Servidor: localhost
   - Porta: 8081 (ou a porta configurada)

2. No Firefox:
   - Configurações → Rede → Configurações de conexão
   - Configuração manual de proxy
   - Proxy HTTP: localhost, Porta: 8081

3. No Chrome/Edge:
   - Configurações → Sistema → Abrir configurações de proxy
   - Siga as instruções do Windows

Após configurar:
- Acesse conteúdo via: http://<hash64>.com
- Ou: http://<dominio>.com
- Página about: http://about.hsdcm

Observações:
- O proxy só funciona para requisições HTTP (não HTTPS)
- Cada acesso requer confirmação do usuário
- É necessário estar logado na rede HPS"""

        messagebox.showinfo("Configurar Proxy", config)

    def show_login(self):
        dialog = FastLoginDialog(self.root, self.client, "Login no HSDCM")
        if dialog.wait_for_login():
            self.update_user_status()

    def update_user_status(self):
        if self.client.current_user:
            self.user_var.set(f"Usuário: {self.client.current_user}")
            if self.client.current_server:
                self.status_var.set(f"Conectado a {self.client.current_server}")
            else:
                self.status_var.set("Conectado")
        else:
            self.user_var.set("Não logado")
            self.status_var.set("Desconectado")

    def clear_logs(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def copy_logs(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get(1.0, tk.END))
        messagebox.showinfo("Copiado", "Logs copiados para área de transferência")

    def save_logs(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("Salvo", f"Logs salvos em {file_path}")

    def load_settings(self):
        try:
            rows = self.client.db.fetch_all('SELECT key, value FROM hsdcm_settings')
            for row in rows:
                key, value = row
                if key == 'auto_start':
                    self.auto_start_var.set(value == '1')
                elif key == 'start_with_system':
                    self.start_with_system_var.set(value == '1')
                elif key == 'default_server':
                    self.default_server_var.set(value)
                elif key == 'api_port':
                    self.api_port_var.set(value)
                elif key == 'proxy_port':
                    self.proxy_port_var.set(value)
        except:
            pass

    def save_settings(self):
        try:
            settings = {
                'auto_start': '1' if self.auto_start_var.get() else '0',
                'start_with_system': '1' if self.start_with_system_var.get() else '0',
                'default_server': self.default_server_var.get(),
                'api_port': self.api_port_var.get(),
                'proxy_port': self.proxy_port_var.get()
            }

            for key, value in settings.items():
                self.client.db.execute_query('''
                    INSERT OR REPLACE INTO hsdcm_settings (key, value)
                    VALUES (?, ?)
                ''', (key, value))

            messagebox.showinfo("Sucesso", "Configurações salvas!\nAlgumas alterações podem requerer reinicialização.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar configurações: {e}")

    def restore_defaults(self):
        self.auto_start_var.set(False)
        self.start_with_system_var.set(False)
        self.default_server_var.set("server1.hps.hsyst.xyz")
        self.api_port_var.set("18238")
        self.proxy_port_var.set("8081")
        messagebox.showinfo("Sucesso", "Configurações restauradas para os padrões!")

    def hide_window(self):
        self.root.withdraw()

    def quit_app(self):
        self.di.stop_monitoring()
        self.wi.stop_api()
        self.wi.stop_permission_processor()
        self.pu.stop_proxy()
        self.pu.stop_permission_processor()

        if hasattr(self.tray_icon, 'icon') and self.tray_icon.icon:
            self.tray_icon.icon.stop()

        self.root.quit()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = HSDCMApp(root)
    root.mainloop()
