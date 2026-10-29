#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LIMMA v2.0 - Linux Integrated Management & Monitoring Analyzer
Geliştirilmiş sürüm: tüm menü boşlukları kapatıldı, pipe/shell komut hataları
düzeltildi, 41-45 arası adli analiz fonksiyonları eklendi, colorama
opsiyonel hale getirildi, threading/timeout desteği iyileştirildi.
"""

import os
import sys
import re
import json
import shlex
import shutil
import logging
import hashlib
import platform
import subprocess
import threading
import functools
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Union, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colorama opsiyonel - yoksa renksiz çalış
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    class _NoColor:
        def __getattr__(self, item):
            return ""
    Fore = Style = Back = _NoColor()

# Loglama yapılandırması
def setup_logging():
    logging.basicConfig(
        filename="system_control.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class LinuxSystemControl:
    """LIMMA - Linux Sistem Yönetimi ve Güvenlik Analizi Aracı"""

    TOOL_ALIASES = {
        "clamav": "clamscan",
        "wireshark-cli": "tshark",
    }

    def __init__(self):
        self.required_tools = {
            "Güvenlik Tarama": ["openvas", "nikto", "sqlmap", "xsser"],
            "Şifre Kırma": ["john", "hashcat", "hydra"],
            "Adli Analiz": ["autopsy", "volatility", "binwalk"],
            "Ağ Analizi": ["wireshark", "tcpdump", "nmap", "aircrack-ng"],
            "Zararlı Yazılım Analizi": ["clamav", "rkhunter", "yara"],
            "Tersine Mühendislik": ["radare2", "ghidra"],
            "Framework": ["metasploit-framework", "burpsuite"],
            "Diğer": [
                "steghide", "stegdetect", "tensorflow", "mythril",
                "prowler", "cuckoo", "filebeat", "osquery", "lynis",
            ],
        }
        self.package_managers = {
            "apt": ["apt-get", "install", "-y"],
            "yum": ["yum", "install", "-y"],
            "dnf": ["dnf", "install", "-y"],
            "pacman": ["pacman", "-S", "--noconfirm"],
            "zypper": ["zypper", "install", "-y"],
        }
        self.temp_files = []
        setup_logging()

        # Mutex ve kilitler
        self.command_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.config_lock = threading.Lock()

        self.max_threads = 4
        self.executor = ThreadPoolExecutor(max_workers=self.max_threads)

    # ------------------------------------------------------------------
    # Çekirdek yardımcı metodlar
    # ------------------------------------------------------------------
    def run_command(self, command: str, sudo: bool = False,
                    timeout: Optional[int] = None,
                    quiet: bool = False,
                    cwd: Optional[str] = None) -> Optional[str]:
        """Thread-safe komut çalıştırma.

        Pipe (|), &&, ||, >, <, ;, *, {, } içeren komutlar otomatik olarak
        shell üzerinden çalıştırılır (shlex.split bunları bozardı).
        """
        with self.command_lock:
            shell_ops = ("|", "&&", "||", ">", "<", ";", "*", "{", "}")
            use_shell = any(op in command for op in shell_ops)

            try:
                if use_shell:
                    cmd = ["sh", "-c", command]
                else:
                    cmd = shlex.split(command)
                if sudo:
                    cmd = ["sudo"] + (["sh", "-c", command] if use_shell else cmd)

                logging.info(f"Çalıştırılan komut: {' '.join(cmd) if not use_shell else command}")

                # Interaktif komutlar ekranda açılır
                if any(t in command for t in ("htop", "nano", "vim", "less", "man ", "testdisk", "autopsy", "wireshark ")):
                    process = subprocess.Popen(cmd, cwd=cwd)
                    process.wait()
                    return None

                result = subprocess.run(
                    cmd, shell=False, text=True, capture_output=True,
                    timeout=timeout, cwd=cwd,
                )

                if result.returncode == 0:
                    if result.stdout and not quiet:
                        print(result.stdout)
                    return result.stdout

                logging.error(f"Komut hatası (rc={result.returncode}): {result.stderr.strip()}")
                if not quiet:
                    print(f"{Fore.RED}Hata: {result.stderr.strip()}{Style.RESET_ALL}")
                return None

            except subprocess.TimeoutExpired:
                logging.error(f"Komut zaman aşımı ({timeout}s): {command}")
                if not quiet:
                    print(f"{Fore.RED}Komut zaman aşımına uğradı ({timeout}s): {command}{Style.RESET_ALL}")
                return None
            except (subprocess.SubprocessError, OSError, ValueError) as e:
                logging.error(f"Komut çalıştırma hatası: {str(e)}")
                if not quiet:
                    print(f"{Fore.RED}Hata: {str(e)}{Style.RESET_ALL}")
                return None

    def safe_file_operation(self, file_path: Union[str, Path],
                            mode: str = "r") -> Optional[str]:
        """Thread-safe dosya okuma/yazma"""
        with self.file_lock:
            try:
                file_path = Path(file_path)
                with open(file_path, mode, encoding="utf-8", errors="replace") as f:
                    return f.read() if "r" in mode else None
            except (IOError, PermissionError, OSError) as e:
                logging.error(f"Dosya işlem hatası ({file_path}): {str(e)}")
                print(f"{Fore.RED}Dosya işlem hatası: {str(e)}{Style.RESET_ALL}")
                return None

    def get_package_manager(self) -> Optional[str]:
        """Sistemdeki paket yöneticisini tespit et"""
        try:
            for pm in ("apt", "dnf", "yum", "zypper", "pacman"):
                if shutil.which(pm):
                    return pm
            print(f"{Fore.RED}Desteklenen paket yöneticisi bulunamadı.{Style.RESET_ALL}")
            return None
        except Exception as e:
            logging.error(f"Paket yöneticisi tespiti hatası: {str(e)}")
            return None

    def install_package(self, package_name: str) -> bool:
        """Paketi otomatik olarak yükle"""
        try:
            pkg_manager = self.get_package_manager()
            if not pkg_manager:
                return False
            print(f"{Fore.YELLOW}{package_name} yükleniyor...{Style.RESET_ALL}")
            cmd = self.package_managers[pkg_manager] + [package_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Fore.GREEN}{package_name} başarıyla yüklendi.{Style.RESET_ALL}")
                return True
            print(f"{Fore.RED}{package_name} yüklenemedi: {result.stderr.strip()}{Style.RESET_ALL}")
            return False
        except Exception as e:
            logging.error(f"Paket yükleme hatası: {str(e)}")
            return False

    @classmethod
    def check_platform(cls) -> None:
        """Platform kontrolü - sadece Linux"""
        if platform.system() != "Linux":
            print(f"{Fore.RED}Bu program yalnızca Linux sistemlerde çalışır.{Style.RESET_ALL}")
            sys.exit(1)

    def check_tool(self, tool_name: str) -> bool:
        """Araç kontrolü ve otomatik kurulumu (alias çözümlemeli)"""
        binary = self.TOOL_ALIASES.get(tool_name, tool_name)
        if not shutil.which(binary):
            print(f"{Fore.YELLOW}{tool_name} kurulu değil.{Style.RESET_ALL}")
            if input(f"{tool_name} otomatik olarak kurulsun mu? (e/h): ").lower() == "e":
                return self.install_package(tool_name)
            return False
        return True

    @staticmethod
    def error_handler(func):
        """Hata yönetimi dekoratörü"""
        @functools.wraps(func)
        def wrapper(instance, *args, **kwargs):
            try:
                return func(instance, *args, **kwargs)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}İşlem kullanıcı tarafından iptal edildi.{Style.RESET_ALL}")
                return None
            except Exception as e:
                logging.error(f"{func.__name__} hatası: {str(e)}")
                print(f"{Fore.RED}{func.__name__} çalıştırılırken hata: {str(e)}{Style.RESET_ALL}")
                return None
        return wrapper

    def cleanup(self) -> None:
        """Geçici kaynakları temizle"""
        try:
            for temp_file in self.temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except OSError:
                    pass
            self.run_command("pkill -f 'nc -l' 2>/dev/null; pkill -f netcat 2>/dev/null",
                             sudo=True, quiet=True)
        except Exception as e:
            logging.error(f"Temizlik hatası: {str(e)}")

    def _all_tools_flat(self) -> List[str]:
        """Tüm araçları düz liste halinde döndürür (kategori anahtarlarını HARİÇ)"""
        tools: List[str] = []
        for category_tools in self.required_tools.values():
            tools.extend(category_tools)
        return tools

    def check_security_tools(self) -> None:
        """Eksik güvenlik araçlarını tespit edip kurulum menüsü sunar"""
        print(f"{Fore.CYAN}Güvenlik Araçları Kontrolü{Style.RESET_ALL}")
        if input("Araç kontrolü yapılsın mı? (E/h): ").lower() == "h":
            return

        flat_tools = self._all_tools_flat()
        with self.executor:
            futures = {self.executor.submit(shutil.which, t): t for t in flat_tools}
            installed = set()
            for fut in as_completed(futures):
                if fut.result():
                    installed.add(futures[fut])

        missing_by_category = {
            cat: [t for t in tools if t not in installed]
            for cat, tools in self.required_tools.items()
        }
        missing_by_category = {k: v for k, v in missing_by_category.items() if v}

        if not missing_by_category:
            print(f"{Fore.GREEN}Tüm güvenlik araçları hazır.{Style.RESET_ALL}")
            return

        while True:
            print(f"\n{Fore.YELLOW}Eksik Araçlar (Kategorilere Göre):{Style.RESET_ALL}")
            categories = list(missing_by_category.keys())
            for i, category in enumerate(categories, 1):
                print(f"{i}. {category} ({len(missing_by_category[category])} araç)")
            print(f"0. {Fore.CYAN}Ana Menüye Dön{Style.RESET_ALL}")

            try:
                choice = input(f"\n{Fore.YELLOW}Kategori seçin (0-{len(categories)}): {Style.RESET_ALL}")
                if choice == "0":
                    break
                category_idx = int(choice) - 1
                if not (0 <= category_idx < len(categories)):
                    print(f"{Fore.RED}Geçersiz kategori seçimi!{Style.RESET_ALL}")
                    continue

                selected_category = categories[category_idx]
                missing_tools = missing_by_category[selected_category]

                while True:
                    print(f"\n{Fore.CYAN}{selected_category} kategorisindeki eksik araçlar:{Style.RESET_ALL}")
                    for i, tool in enumerate(missing_tools, 1):
                        print(f"{i}. {tool}")
                    print("\nKurulum seçenekleri:")
                    print("1. Paket yöneticisi ile kur")
                    print("2. Snap kullanarak kur")
                    print("3. Flatpak kullanarak kur")
                    print("4. Git repositoryden kur")
                    print("5. İndirme linki girerek kur")
                    print("0. Geri dön")

                    tool_choice = input(f"\n{Fore.YELLOW}Araç seçin (1-{len(missing_tools)}) veya 0: {Style.RESET_ALL}")
                    if tool_choice == "0":
                        break
                    tool_idx = int(tool_choice) - 1
                    if not (0 <= tool_idx < len(missing_tools)):
                        print(f"{Fore.RED}Geçersiz araç seçimi!{Style.RESET_ALL}")
                        continue

                    tool_to_install = missing_tools[tool_idx]
                    install_choice = input("Kurulum yöntemi seçin (1-5): ")

                    if install_choice == "1":
                        ok = self.install_package(tool_to_install)
                    elif install_choice == "2":
                        ok = bool(self.run_command(f"snap install {tool_to_install}", sudo=True))
                    elif install_choice == "3":
                        ok = bool(self.run_command(f"flatpak install -y {tool_to_install}", sudo=True))
                    elif install_choice == "4":
                        repo_url = input("Git repository URL'si: ")
                        ok = bool(self.run_command(f"git clone {repo_url} /tmp/{tool_to_install} && cd /tmp/{tool_to_install} && make install", sudo=True))
                    elif install_choice == "5":
                        download_url = input("İndirme linki: ")
                        ok = bool(self.run_command(f"cd /tmp && wget {download_url} && dpkg -i ./*.deb 2>/dev/null || true", sudo=True))
                    else:
                        print(f"{Fore.RED}Geçersiz kurulum seçimi!{Style.RESET_ALL}")
                        continue

                    if ok:
                        print(f"{Fore.GREEN}{tool_to_install} başarıyla yüklendi.{Style.RESET_ALL}")
                        missing_tools.remove(tool_to_install)
                        if not missing_tools:
                            del missing_by_category[selected_category]
                            break
                    else:
                        print(f"{Fore.RED}{tool_to_install} yüklenemedi!{Style.RESET_ALL}")

            except ValueError:
                print(f"{Fore.RED}Lütfen geçerli bir sayı girin!{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Araç kontrol menüsünden çıkılıyor...{Style.RESET_ALL}")
                break

            if not missing_by_category:
                print(f"\n{Fore.GREEN}Tüm araçlar kuruldu!{Style.RESET_ALL}")
                break

    # ------------------------------------------------------------------
    # Temel Sistem Yönetimi (1-10)
    # ------------------------------------------------------------------
    def check_disk_space(self):
        """1. Disk alanı kontrolü"""
        print(f"\n{Fore.CYAN}Disk Kullanım Bilgileri:{Style.RESET_ALL}")
        self.run_command("df -h --output=source,size,used,avail,pcent,target")
        print(f"\n{Fore.CYAN}İnode Kullanımı:{Style.RESET_ALL}")
        self.run_command("df -i")
        print(f"\n{Fore.CYAN}En Büyük Dizinler:{Style.RESET_ALL}")
        self.run_command("du -xhd1 / 2>/dev/null | sort -rh | head -10", sudo=True, timeout=120)

    def check_ram_usage(self):
        """2. RAM kullanımı kontrolü"""
        print(f"\n{Fore.CYAN}Bellek Kullanım Bilgileri:{Style.RESET_ALL}")
        self.run_command("free -h")
        print(f"\n{Fore.CYAN}Detaylı Bellek İstatistikleri:{Style.RESET_ALL}")
        self.run_command("vmstat 1 3", timeout=15)

    def list_processes(self):
        """3. Aktif işlemleri listele"""
        print(f"\n{Fore.CYAN}En Çok CPU Kullanan Süreçler:{Style.RESET_ALL}")
        self.run_command("ps aux --sort=-%cpu | head -11")
        print(f"\n{Fore.CYAN}En Çok Bellek Kullanan Süreçler:{Style.RESET_ALL}")
        self.run_command("ps aux --sort=-%mem | head -11")

    def network_interfaces(self):
        """4. Ağ arayüzlerini görüntüle"""
        print(f"\n{Fore.CYAN}Ağ Arayüzleri:{Style.RESET_ALL}")
        self.run_command("ip -c addr show 2>/dev/null || ip addr show")
        print(f"\n{Fore.CYAN}Yönlendirme Tablosu:{Style.RESET_ALL}")
        self.run_command("ip route")

    def check_open_ports(self):
        """5. Açık portları kontrol et"""
        print(f"\n{Fore.CYAN}Açık Portlar ve Bağlantılar:{Style.RESET_ALL}")
        self.run_command("ss -tuln")
        print(f"\n{Fore.CYAN}Aktif Bağlantılar:{Style.RESET_ALL}")
        self.run_command("ss -tupn", sudo=True)

    def system_info(self):
        """6. Sistem bilgilerini görüntüle"""
        print(f"\n{Fore.CYAN}Sistem Bilgileri:{Style.RESET_ALL}")
        self.run_command("uname -a")
        print(f"\n{Fore.CYAN}İşletim Sistemi Bilgisi:{Style.RESET_ALL}")
        self.run_command("cat /etc/os-release")
        print(f"\n{Fore.CYAN}Çekirdek ve Çalışma Süresi:{Style.RESET_ALL}")
        self.run_command("uptime")

    def list_users(self):
        """7. Kullanıcıları listele"""
        print(f"\n{Fore.CYAN}Normal Kullanıcılar (UID>=1000):{Style.RESET_ALL}")
        self.run_command("awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd")
        print(f"\n{Fore.CYAN}Sudo Yetkisi Olan Kullanıcılar:{Style.RESET_ALL}")
        self.run_command("getent group sudo 2>/dev/null | cut -d: -f4 || getent group wheel | cut -d: -f4")
        print(f"\n{Fore.CYAN}Son Giriş Yapanlar:{Style.RESET_ALL}")
        self.run_command("last -n 10 -F | head -10")

    def check_services(self):
        """8. Servisleri kontrol et"""
        print(f"\n{Fore.CYAN}Çalışan Servisler:{Style.RESET_ALL}")
        self.run_command("systemctl list-units --type=service --state=running --no-pager | head -30")
        print(f"\n{Fore.CYAN}Başarısız Servisler:{Style.RESET_ALL}")
        self.run_command("systemctl --failed --no-pager")

    def check_logs(self):
        """9. Sistem loglarını görüntüle"""
        print(f"\n{Fore.CYAN}Son Sistem Logları:{Style.RESET_ALL}")
        self.run_command("journalctl -n 30 --no-pager", sudo=True)
        print(f"\n{Fore.CYAN}Hata Logları:{Style.RESET_ALL}")
        self.run_command("journalctl -p err..alert -n 20 --no-pager", sudo=True)

    def check_updates(self):
        """10. Sistem güncellemelerini kontrol et (dağıtıma göre)"""
        pm = self.get_package_manager()
        if pm == "apt":
            self.run_command("apt update", sudo=True, timeout=300)
            self.run_command("apt list --upgradable 2>/dev/null | head -30")
        elif pm == "pacman":
            self.run_command("pacman -Sy --noconfirm", sudo=True, timeout=300)
            self.run_command("pacman -Qu")
        else:  # yum/dnf/zypper
            self.run_command(f"{pm} check-update", timeout=300)
        if input("\nGüncellemeler şimdi kurulsun mu? (e/h): ").lower() == "e":
            if pm == "apt":
                self.run_command("apt upgrade -y", sudo=True, timeout=3600)
            elif pm == "pacman":
                self.run_command("pacman -Syu --noconfirm", sudo=True, timeout=3600)
            else:
                self.run_command(f"{pm} upgrade -y", sudo=True, timeout=3600)

    # ------------------------------------------------------------------
    # Güvenlik Taramaları (11-20)
    # ------------------------------------------------------------------
    def vulnerability_scan(self):
        """11. Zafiyet taraması (OpenVAS/GVM)"""
        if not self.check_tool("openvas") and not shutil.which("gvm"):
            print(f"{Fore.RED}OpenVAS/GVM bulunamadı.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Zafiyet Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Hızlı Tarama\n2. Kapsamlı Tarama\n3. Özel Tarama")
        scan_type = input("\nTarama türünü seçin (1-3): ")
        target = input("Hedef IP/Domain: ")
        omp_user = input("GVM kullanıcı adı [admin]: ") or "admin"
        omp_pass = input("GVM parolası: ")

        output_dir = f"vulnerability_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        profiles = {"1": "daba56c8-73ec-11df-a475-00202664cea6",  # Fast
                    "2": "698f691e-7489-11df-9d8c-00202664cea6",  # Full and deep
                    "3": "698f691e-7489-11df-9d8c-00202664cea6"}
        port_range = ""
        if scan_type == "3":
            port_range = input("Port aralığı (örn: 1-1000) [tümü]: ")

        report_file = f"{output_dir}/scan_report.xml"
        cmd = (f"omp -u {omp_user} -w {omp_pass} -X "
               f"'<create_task><name>limma_scan</name>"
               f"<target><hosts>{target}</hosts>"
               f"{'<port_range>' + port_range + '</port_range>' if port_range else ''}"
               f"</target>"
               f"<config id=\"{profiles.get(scan_type, profiles['1'])}\"/></create_task>'")
        result = self.run_command(cmd, sudo=True, timeout=120)
        if result:
            print(f"{Fore.GREEN}Görev oluşturuldu. Sonuçlar {output_dir} altında takip edilebilir.{Style.RESET_ALL}")

    def malware_scan(self):
        """12. Zararlı yazılım taraması (ClamAV)"""
        if not self.check_tool("clamav"):
            return

        print(f"\n{Fore.CYAN}Zararlı Yazılım Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Hızlı Tarama (/home)\n2. Kapsamlı Tarama (/)\n3. Belirli Dizin Tarama\n4. Sadece Rapor (temizleme yok)")
        scan_type = input("\nTarama türünü seçin (1-4): ")

        output_dir = f"malware_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        log_file = f"{output_dir}/scan_log.txt"

        remove_flag = "" if scan_type == "4" else "--remove"
        targets = {"1": "/home", "2": "/", "4": "/home"}
        if scan_type == "3":
            target = input("Taranacak dizin: ")
        else:
            target = targets.get(scan_type, "/home")

        command = f"clamscan -r {remove_flag} --max-filesize=4000M --max-scansize=4000M {target}"
        exclude_dir = input("\nHariç tutulacak dizinler (virgülle, boş=tümü): ")
        if exclude_dir:
            for d in exclude_dir.split(","):
                command += f" --exclude-dir='{d.strip()}'"
        command += f" --log={log_file}"

        print(f"\n{Fore.YELLOW}Tarama başlatılıyor (bu işlem uzun sürebilir)...{Style.RESET_ALL}")
        self.run_command(command, sudo=True, timeout=7200)

        if os.path.exists(log_file):
            print(f"\n{Fore.GREEN}Tarama tamamlandı. Sonuçlar {output_dir} dizinine kaydedildi.{Style.RESET_ALL}")
            content = self.safe_file_operation(log_file)
            if content:
                infected = [ln for ln in content.splitlines() if "FOUND" in ln]
                print(f"\n{Fore.CYAN}=== ÖZET ==={Style.RESET_ALL}")
                for ln in content.splitlines():
                    if any(k in ln for k in ("Scanned files", "Infected files", "Total errors")):
                        print(ln)
                if infected:
                    print(f"\n{Fore.RED}Bulaşan dosyalar:{Style.RESET_ALL}")
                    print("\n".join(infected[:50]))
                # E-posta bildirimi (tarama SONRASI)
                if input("\nSonuçlar e-posta ile gönderilsin mi? (e/h): ").lower() == "e":
                    email = input("E-posta adresi: ")
                    self.run_command(f"echo 'Tarama sonuçları ektedir.' | mail -s 'Zararlı Yazılım Tarama Raporu' -a {log_file} {email}", timeout=60)
        else:
            print(f"{Fore.RED}Tarama log dosyası oluşturulamadı.{Style.RESET_ALL}")

    def rootkit_scan(self):
        """13. Rootkit taraması"""
        if not self.check_tool("rkhunter"):
            return

        print(f"\n{Fore.CYAN}Rootkit Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Hızlı Tarama\n2. Kapsamlı Tarama\n3. Özel Tarama\n4. Sistem Dosyaları Kontrolü")
        scan_type = input("\nTarama türünü seçin (1-4): ")

        output_dir = f"rootkit_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        log_file = f"{output_dir}/rkhunter_log.txt"

        if input("\nRootkit veritabanı güncellensin mi? (e/h): ").lower() == "e":
            self.run_command("rkhunter --update", sudo=True, timeout=300)

        scan_options = {"1": "--check --skip-keypress",
                        "2": "--check --thorough --skip-keypress",
                        "3": "--check --skip-keypress",
                        "4": "--propupd"}
        custom_options = ""
        if scan_type == "3":
            for label, opt in (("Ağ arayüzleri", "--check-network"),
                               ("Açık portlar", "--check-ports"),
                               ("Bilinen rootkitler", "--check-rootkits")):
                if input(f"{label} kontrol edilsin mi? (e/h): ").lower() == "e":
                    custom_options += f" {opt}"

        self.run_command(f"rkhunter {scan_options.get(scan_type, scan_options['1'])} {custom_options} --logfile {log_file}",
                         sudo=True, timeout=3600)

        if os.path.exists(log_file):
            print(f"\n{Fore.GREEN}Tarama tamamlandı: {log_file}{Style.RESET_ALL}")
            if input("\nSonuçlar görüntülensin mi? (e/h): ").lower() == "e":
                content = self.safe_file_operation(log_file)
                if content:
                    warnings = [ln for ln in content.splitlines() if "Warning" in ln]
                    print(f"\n{Fore.CYAN}Uyarılar ({len(warnings)}):{Style.RESET_ALL}")
                    print("\n".join(warnings[:30]) if warnings else "Uyarı yok ✓")
        else:
            print(f"{Fore.RED}Log dosyası oluşturulamadı.{Style.RESET_ALL}")

    def port_scan(self):
        """14. Port taraması (nmap)"""
        if not self.check_tool("nmap"):
            return

        target = input("Hedef IP/Domain: ")
        print(f"\n{Fore.CYAN}Tarama Türleri:{Style.RESET_ALL}")
        print("1. Hızlı TCP SYN (-sS -sV)\n2. TCP Connect (-sT -sV)\n3. UDP (-sU)\n4. Kapsamlı (-sS -sV -sC -O)\n5. Gizli (-sS -T2)")
        scan_type = input("Tarama türünü seçin (1-5): ")
        port_range = input("Port aralığı (örn: 1-1000) [Enter=1000 yaygın]: ") or "1-1000"

        scan_options = {"1": "-sS -sV", "2": "-sT -sV", "3": "-sU --top-ports 100",
                        "4": "-sS -sV -sC -O", "5": "-sS -T2"}
        command = f"nmap {scan_options.get(scan_type, '-sS -sV')} -p{port_range} {target}"

        if scan_type not in ("4",) and input("OS tespiti eklensin mi? (e/h): ").lower() == "e":
            command += " -O"

        output_file = f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        if input("Sonuçlar dosyaya kaydedilsin mi? (E/h): ").lower() != "h":
            command += f" -oN {output_file}"

        print(f"\n{Fore.YELLOW}Tarama başlatılıyor... (sudo gerekebilir){Style.RESET_ALL}")
        result = self.run_command(command, sudo=True, timeout=1800)
        if result and output_file and os.path.exists(output_file):
            print(f"\n{Fore.GREEN}Sonuçlar {output_file} dosyasına kaydedildi.{Style.RESET_ALL}")

    def web_scan(self):
        """15. Web uygulama taraması (Nikto)"""
        if not self.check_tool("nikto"):
            return

        target = input("\nHedef URL (örn: http://example.com): ")
        print(f"\n{Fore.CYAN}Tarama Türleri:{Style.RESET_ALL}")
        print("1. Hızlı Tarama\n2. Kapsamlı Tarama\n3. SSL/TLS Taraması\n4. Özel Tarama")
        scan_type = input("Tarama türünü seçin (1-4): ")

        output_dir = f"web_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        tuning = {"1": "", "2": "-Tuning x", "3": "-ssl", "4": ""}
        if scan_type == "4":
            port = input("Port [80]: ") or "80"
            timeout = input("Zaman aşımı (sn) [30]: ") or "30"
            extra = f"-p {port} -Pause {timeout}"
        else:
            extra = ""

        report_file = f"{output_dir}/scan_report.txt"
        cmd = f"nikto -h {target} {tuning.get(scan_type, '')} {extra} -output {report_file}"
        print(f"\n{Fore.YELLOW}Tarama başlatılıyor...{Style.RESET_ALL}")
        self.run_command(cmd, timeout=3600)

        if os.path.exists(report_file):
            print(f"\n{Fore.GREEN}Tarama tamamlandı: {report_file}{Style.RESET_ALL}")
            if input("Sonuçlar görüntülensin mi? (e/h): ").lower() == "e":
                content = self.safe_file_operation(report_file)
                if content:
                    print(content[:4000])

    def ssl_scan(self):
        """16. SSL/TLS Analizi"""
        if not self.check_tool("sslscan") and not shutil.which("testssl.sh") and not shutil.which("testssl"):
            print(f"{Fore.RED}sslscan veya testssl bulunamadı.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}SSL/TLS Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel SSL Tarama\n2. Detaylı Sertifika Analizi\n3. Güvenlik Açığı Taraması\n4. Protokol Testi")
        choice = input("\nSeçiminiz (1-4): ")
        target = input("Hedef domain: ")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"ssl_scan_{timestamp}.txt"

        if shutil.which("sslscan"):
            commands = {"1": f"sslscan --no-colour {target}",
                        "2": f"sslscan --no-colour --show-certificate {target}",
                        "3": f"sslscan --no-colour --no-fallback --no-renegotiation {target}",
                        "4": f"sslscan --no-colour --ssl2 --ssl3 --tlsall {target}"}
            cmd = commands.get(choice, commands["1"])
        else:
            cmd = f"testssl --logfile {output_file} {target}"

        print(f"\n{Fore.YELLOW}Analiz başlatılıyor...{Style.RESET_ALL}")
        result = self.run_command(cmd, timeout=600)
        if result and shutil.which("sslscan"):
            with open(output_file, "w") as f:
                f.write(result)
            print(f"\n{Fore.GREEN}Sonuçlar {output_file} dosyasına kaydedildi.{Style.RESET_ALL}")
            # Kritik bulguları vurgula
            issues = [ln for ln in result.splitlines() if any(k in ln.lower() for k in ("failed", "vulnerable", "weak", "sslv2", "sslv3"))]
            if issues:
                print(f"\n{Fore.RED}Kritik Bulgular:{Style.RESET_ALL}")
                print("\n".join(issues[:20]))

    def wifi_scan(self):
        """17. Kablosuz Ağ Taraması"""
        if not self.check_tool("aircrack-ng"):
            return

        print(f"\n{Fore.CYAN}Kablosuz Ağ Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Ağ Keşfi\n2. Handshake Yakalama\n3. Deauth Tespiti\n4. Hidden SSID Tespiti")
        choice = input("\nSeçiminiz (1-4): ")
        interface = input("Kablosuz arayüz (örn: wlan0mon): ")

        if choice == "1":
            self.run_command(f"airodump-ng {interface}", sudo=True)
        elif choice == "2":
            bssid = input("Hedef BSSID: ")
            channel = input("Kanal: ")
            self.run_command(f"airodump-ng -c {channel} --bssid {bssid} -w capture {interface}", sudo=True)
        elif choice == "3":
            self.run_command(f"airodump-ng --showack {interface}", sudo=True)
        elif choice == "4":
            self.run_command(f"airodump-ng --manufacturer --uptime {interface}", sudo=True)

    def packet_capture(self):
        """18. Paket Yakalama"""
        if not self.check_tool("tcpdump"):
            return

        print(f"\n{Fore.CYAN}Paket Yakalama Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel Yakalama\n2. HTTP/HTTPS Trafiği\n3. DNS Trafiği\n4. Belirli IP")
        choice = input("\nSeçiminiz (1-4): ")
        interface = input("Ağ arayüzü [tümü]: ")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        iface_arg = f"-i {interface}" if interface else "-i any"

        filters = {"1": "", "2": "port 80 or port 443", "3": "port 53"}
        if choice == "4":
            filters["4"] = f"host {input('Hedef IP: ')}"
        filter_str = filters.get(choice, "")

        output_file = f"capture_{timestamp}.pcap"
        print(f"\n{Fore.YELLOW}Yakalama başlatıldı - durdurmak için Ctrl+C{Style.RESET_ALL}")
        self.run_command(f"tcpdump {iface_arg} -w {output_file} {filter_str}", sudo=True)
        print(f"\n{Fore.GREEN}Kayıt: {output_file}{Style.RESET_ALL}")

        if os.path.exists(output_file) and input("Wireshark ile açılsın mı? (e/h): ").lower() == "e":
            self.run_command(f"wireshark {output_file}")

    def arp_scan(self):
        """19. ARP Taraması"""
        if not self.check_tool("arp-scan"):
            return

        print(f"\n{Fore.CYAN}ARP Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Yerel Ağ Taraması\n2. Belirli IP Aralığı\n3. Üretici Filtreleme")
        choice = input("\nSeçiminiz (1-3): ")
        output_file = f"arp_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        if choice == "1":
            self.run_command(f"arp-scan --localnet --plain > {output_file}", sudo=True)
        elif choice == "2":
            ip_range = input("IP aralığı (örn: 192.168.1.0/24): ")
            self.run_command(f"arp-scan {ip_range} --plain > {output_file}", sudo=True)
        elif choice == "3":
            vendor = input("Üretici adı: ")
            self.run_command(f"arp-scan --localnet --plain | grep -i '{vendor}' > {output_file}", sudo=True)

        if os.path.exists(output_file):
            content = self.safe_file_operation(output_file)
            if content:
                print(f"\n{Fore.GREEN}Bulunan cihazlar:{Style.RESET_ALL}")
                print(content[:2000])

    def dns_enum(self):
        """20. DNS Bilgi Toplama"""
        print(f"\n{Fore.CYAN}DNS Bilgi Toplama Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel DNS Kayıtları (dig)\n2. Zone Transfer Denemesi\n3. Alt Alan Adı Keşfi (dnsenum)")
        choice = input("\nSeçiminiz (1-3): ")
        domain = input("Hedef domain: ")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"dns_enum_{timestamp}.txt"

        if choice == "1":
            self.run_command(f"dig {domain} ANY +noall +answer; dig {domain} MX +short; dig {domain} NS +short > {output_file}")
        elif choice == "2":
            ns = self.run_command(f"dig {domain} NS +short", quiet=True)
            if ns:
                for server in ns.splitlines():
                    server = server.strip().rstrip(".")
                    if server:
                        print(f"\n{Fore.YELLOW}{server} üzerinde zone transfer deneniyor...{Style.RESET_ALL}")
                        self.run_command(f"dig @{server} {domain} AXFR >> {output_file}")
        elif choice == "3":
            if self.check_tool("dnsenum"):
                self.run_command(f"dnsenum --noreverse -o dns_enum_{timestamp}.xml {domain}", timeout=1800)

        if os.path.exists(output_file):
            content = self.safe_file_operation(output_file)
            if content:
                print(f"\n{Fore.GREEN}=== Sonuçlar ==={Style.RESET_ALL}")
                print(content[:3000])

    # ------------------------------------------------------------------
    # Ağ ve Sistem Güvenliği (21-35)
    # ------------------------------------------------------------------
    def mitm_detection(self):
        """21. MITM Saldırı Tespiti"""
        print(f"\n{Fore.CYAN}MITM Saldırı Tespit Seçenekleri:{Style.RESET_ALL}")
        print("1. ARP Tablosu Kontrolü\n2. SSL/TLS Sertifika Kontrolü\n3. DNS Yanıt Kontrolü\n4. Aktif ARP İzleme (arpwatch)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"mitm_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            print(f"\n{Fore.YELLOW}ARP tablosu kontrol ediliyor...{Style.RESET_ALL}")
            self.run_command(f"ip neigh show > {output_dir}/arp_table.txt")
            print(f"\n{Fore.CYAN}(incomplete) girişler:{Style.RESET_ALL}")
            self.run_command("ip neigh show | grep -i 'failed\|incomplete' || echo 'Bulunamadı ✓'")
            print(f"\n{Fore.CYAN}Aynı MAC'e sahip birden fazla IP:{Style.RESET_ALL}")
            self.run_command("ip neigh show | awk '{print $5}' | sort | uniq -d | grep -v '^$' || echo 'Çakışma yok ✓'")

        elif choice == "2":
            target = input("Hedef domain/IP: ")
            output_file = f"{output_dir}/ssl_scan.txt"
            if shutil.which("sslscan"):
                self.run_command(f"sslscan --no-colour --show-certificate {target} > {output_file}", timeout=300)
                if os.path.exists(output_file):
                    content = self.safe_file_operation(output_file)
                    if content:
                        issues = [ln for ln in content.splitlines() if any(k in ln.lower() for k in ("self-signed", "expired", "invalid", "failed"))]
                        print(f"\n{Fore.RED if issues else Fore.GREEN}{'Şüpheli bulgular:' if issues else 'Sertifika sorunu görünmüyor ✓'}{Style.RESET_ALL}")
                        if issues:
                            print("\n".join(issues[:15]))

        elif choice == "3":
            domain = input("Kontrol edilecek domain: ")
            print(f"\n{Fore.YELLOW}DNS yanıtları karşılaştırılıyor...{Style.RESET_ALL}")
            for server, label in (("8.8.8.8", "Google"), ("1.1.1.1", "Cloudflare")):
                result = self.run_command(f"dig @{server} {domain} +short", quiet=True, timeout=15)
                print(f"{label}: {result.strip() if result else 'yanıt yok'}")
            print(f"\n{Fore.CYAN}Yerel çözümleme:{Style.RESET_ALL}")
            self.run_command(f"dig {domain} +short")

        elif choice == "4":
            if self.check_tool("arpwatch"):
                interface = input("Ağ arayüzü [tümü]: ")
                duration = int(input("İzleme süresi (dakika) [5]: ") or "5")
                log_file = f"{output_dir}/arpwatch.log"
                print(f"\n{Fore.YELLOW}ARP izleme {duration} dk boyunca çalışacak...{Style.RESET_ALL}")
                iface_arg = f"-i {interface}" if interface else ""
                process = subprocess.Popen(["sudo", "arpwatch", *shlex.split(iface_arg), "-f", log_file],
                                           stderr=subprocess.DEVNULL)
                try:
                    time.sleep(duration * 60)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}İzleme erken durduruldu.{Style.RESET_ALL}")
                process.terminate()
                if os.path.exists(log_file):
                    content = self.safe_file_operation(log_file)
                    if content:
                        changes = [ln for ln in content.splitlines() if "changed" in ln]
                        print(f"\n{Fore.RED if changes else Fore.GREEN}{len(changes)} MAC değişikliği tespit edildi{Style.RESET_ALL}")
                        if changes:
                            print("\n".join(changes[:20]))

        # Özet rapor
        with open(f"{output_dir}/summary.txt", "w") as f:
            f.write(f"=== MITM Tespit Özeti ===\nTarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nSeçim: {choice}\n")
        print(f"\n{Fore.GREEN}Sonuçlar {output_dir} dizinine kaydedildi.{Style.RESET_ALL}")

    def firewall_check(self):
        """22. Güvenlik Duvarı Kontrolü"""
        print(f"\n{Fore.CYAN}Güvenlik Duvarı Kontrol Seçenekleri:{Style.RESET_ALL}")
        print("1. UFW Durumu\n2. Aktif Kurallar (iptables/nftables)\n3. Açık Portlar\n4. Yapılandırma Denetimi")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"firewall_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            self.run_command("ufw status verbose 2>/dev/null || echo 'UFW kurulu değil'", sudo=True)
            if shutil.which("firewall-cmd"):
                self.run_command("firewall-cmd --state && firewall-cmd --list-all", sudo=True)

        elif choice == "2":
            self.run_command(f"iptables -L -n -v --line-numbers > {output_dir}/iptables_rules.txt 2>/dev/null; nft list ruleset > {output_dir}/nftables_rules.txt 2>/dev/null", sudo=True)
            content = self.safe_file_operation(f"{output_dir}/iptables_rules.txt")
            if content:
                print(content[:3000])

        elif choice == "3":
            self.run_command(f"ss -tulpn > {output_dir}/open_ports.txt", sudo=True)
            content = self.safe_file_operation(f"{output_dir}/open_ports.txt")
            if content:
                print(content[:3000])

        elif choice == "4":
            recommendations = []
            if shutil.which("ufw"):
                status = self.run_command("ufw status", quiet=True, sudo=True) or ""
                if "inactive" in status:
                    recommendations.append("- UFW etkin değil: 'sudo ufw enable'")
                if "deny (incoming)" not in status.lower():
                    recommendations.append("- Varsayılan gelen politika 'deny' olmalı")
            else:
                recommendations.append("- UFW kurulu değil")
            if os.path.exists("/etc/default/ufw"):
                ipv6 = self.run_command("grep IPV6 /etc/default/ufw", quiet=True)
                if ipv6 and "yes" not in ipv6:
                    recommendations.append("- IPv6 desteği kapalı")
            if not recommendations:
                recommendations.append("- Temel kontroller başarılı ✓")
            print(f"\n{Fore.CYAN}Denetim Sonucu:{Style.RESET_ALL}")
            for rec in recommendations:
                print(rec)
            with open(f"{output_dir}/recommendations.txt", "w") as f:
                f.write("\n".join(recommendations))

        print(f"\n{Fore.GREEN}Sonuçlar {output_dir} dizinine kaydedildi.{Style.RESET_ALL}")

    def network_monitor(self):
        """23. Ağ İzleme"""
        print(f"\n{Fore.CYAN}Ağ İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Süreç Bazlı Kullanım (nethogs)\n2. Gerçek Zamanlı Trafik (iftop)\n3. Ağ İstatistikleri\n4. Paket Yakalama")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"network_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if self.check_tool("nethogs"):
                interface = input("Ağ arayüzü [tümü]: ")
                duration = input("Süre (sn) [30]: ") or "30"
                output_file = f"{output_dir}/process_traffic.log"
                self.run_command(f"nethogs -t -c {duration} {interface} > {output_file}", sudo=True, timeout=int(duration) + 30)
                if os.path.exists(output_file):
                    print(f"\n{Fore.GREEN}Kayıt: {output_file}{Style.RESET_ALL}")

        elif choice == "2":
            if self.check_tool("iftop"):
                interface = input("Ağ arayüzü [tümü]: ")
                cmd = f"iftop -P {('-i ' + interface) if interface else ''}"
                self.run_command(cmd, sudo=True)

        elif choice == "3":
            stats_file = f"{output_dir}/network_stats.txt"
            with open(stats_file, "w") as f:
                f.write("=== Ağ İstatistikleri ===\n\n")
            self.run_command(f"ss -s >> {stats_file}; netstat -s 2>/dev/null >> {stats_file}")
            content = self.safe_file_operation(stats_file)
            if content:
                print(content[:2000])

        elif choice == "4":
            self.packet_capture()  # 18 numaralı fonksiyonu yeniden kullan

    def bandwidth_monitor(self):
        """24. Bant Genişliği İzleme"""
        print(f"\n{Fore.CYAN}Bant Genişliği İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Gerçek Zamanlı Kullanım (iftop)\n2. Arayüz İstatistikleri\n3. Hız Testi\n4. Uzun Süreli İzleme (CSV)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"bandwidth_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if self.check_tool("iftop"):
                interface = input("Ağ arayüzü [tümü]: ")
                self.run_command(f"iftop -B {('-i ' + interface) if interface else ''}", sudo=True)

        elif choice == "2":
            interface = input("Arayüz [eth0]: ") or "eth0"
            self.run_command(f"cat /sys/class/net/{interface}/statistics/rx_bytes; cat /sys/class/net/{interface}/statistics/tx_bytes")
            self.run_command(f"ethtool {interface} 2>/dev/null | grep -i speed")

        elif choice == "3":
            if self.check_tool("speedtest-cli"):
                result_file = f"{output_dir}/speedtest.json"
                self.run_command(f"speedtest-cli --json --timeout 60 > {result_file}", timeout=120)
                if os.path.exists(result_file):
                    try:
                        data = json.loads(self.safe_file_operation(result_file) or "{}")
                        print(f"\n{Fore.CYAN}Test Sonuçları:{Style.RESET_ALL}")
                        print(f"İndirme: {data.get('download', 0) / 1e6:.2f} Mbps")
                        print(f"Yükleme: {data.get('upload', 0) / 1e6:.2f} Mbps")
                        print(f"Ping: {data.get('ping', 0):.1f} ms")
                    except (json.JSONDecodeError, TypeError):
                        print(f"{Fore.RED}Test sonucu okunamadı.{Style.RESET_ALL}")

        elif choice == "4":
            interface = input("Arayüz [eth0]: ") or "eth0"
            duration = float(input("Süre (dk) [10]: ") or "10")
            interval = float(input("Aralık (sn) [30]: ") or "30")
            if not os.path.exists(f"/sys/class/net/{interface}"):
                print(f"{Fore.RED}Arayüz bulunamadı: {interface}{Style.RESET_ALL}")
                return
            log_file = f"{output_dir}/bandwidth.csv"
            with open(log_file, "w") as f:
                f.write("timestamp,rx_bytes,tx_bytes\n")
            end_time = time.time() + duration * 60
            print(f"{Fore.YELLOW}İzleme başladı - Ctrl+C ile durdurabilirsiniz{Style.RESET_ALL}")
            try:
                while time.time() < end_time:
                    rx = self.run_command(f"cat /sys/class/net/{interface}/statistics/rx_bytes", quiet=True)
                    tx = self.run_command(f"cat /sys/class/net/{interface}/statistics/tx_bytes", quiet=True)
                    with open(log_file, "a") as f:
                        f.write(f"{datetime.now()},{rx.strip() if rx else 0},{tx.strip() if tx else 0}\n")
                    time.sleep(interval)
            except KeyboardInterrupt:
                pass
            print(f"\n{Fore.GREEN}Kayıt: {log_file}{Style.RESET_ALL}")

    def connection_monitor(self):
        """25. Bağlantı İzleme"""
        print(f"\n{Fore.CYAN}Bağlantı İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Aktif Bağlantılar\n2. Dinleme Portları\n3. Bağlantı İstatistikleri\n4. Bağlantı Takibi (log)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"connection_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            self.run_command("ss -tupn", sudo=True)

        elif choice == "2":
            self.run_command("ss -tulpn", sudo=True)
            # Bilinen olmayan portları vurgula
            result = self.run_command("ss -tuln | awk 'NR>1 {print $5}' | awk -F: '{print $NF}' | sort -un", quiet=True)
            if result:
                known = set()
                try:
                    with open("/etc/services") as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 2 and not line.startswith("#"):
                                known.add(parts[1].split("/")[0])
                except IOError:
                    pass
                unknown = [p for p in result.split() if p not in known]
                if unknown:
                    print(f"\n{Fore.YELLOW}İncelenmesi önerilen portlar: {', '.join(unknown[:20])}{Style.RESET_ALL}")

        elif choice == "3":
            self.run_command("ss -s")
            self.run_command("cat /proc/net/netstat 2>/dev/null | head -4")

        elif choice == "4":
            duration = float(input("Süre (dk) [5]: ") or "5")
            interval = float(input("Aralık (sn) [10]: ") or "10")
            log_file = f"{output_dir}/connections.log"
            end_time = time.time() + duration * 60
            try:
                while time.time() < end_time:
                    with open(log_file, "a") as f:
                        f.write(f"=== {datetime.now().strftime('%H:%M:%S')} ===\n")
                    self.run_command(f"ss -tupn >> {log_file}", sudo=True, quiet=True)
                    time.sleep(interval)
            except KeyboardInterrupt:
                pass
            print(f"\n{Fore.GREEN}Kayıt: {log_file}{Style.RESET_ALL}")

    def file_integrity(self):
        """26. Dosya Bütünlük Kontrolü"""
        print(f"\n{Fore.CYAN}Dosya Bütünlük Kontrolü Seçenekleri:{Style.RESET_ALL}")
        print("1. AIDE Tam Kontrol\n2. Belirli Dizin Kontrolü\n3. İzleme Döngüsü\n4. Veritabanı Güncelleme")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"integrity_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if not self.check_tool("aide"):
            return

        if choice == "1":
            self.run_command(f"aide --check > {output_dir}/full_check.log", sudo=True, timeout=3600)
            if os.path.exists(f"{output_dir}/full_check.log"):
                content = self.safe_file_operation(f"{output_dir}/full_check.log")
                if content:
                    changed = [ln for ln in content.splitlines() if "changed" in ln.lower()]
                    print(f"\n{Fore.CYAN}{len(changed)} değişiklik tespit edildi.{Style.RESET_ALL}")
        elif choice == "2":
            path = input("Kontrol edilecek dizin: ")
            self.run_command(f"aide --check > {output_dir}/dir_check.log 2>&1", sudo=True, timeout=1800)
        elif choice == "3":
            duration = float(input("Süre (saat) [1]: ") or "1")
            interval = float(input("Aralık (dk) [30]: ") or "30")
            end_time = time.time() + duration * 3600
            try:
                while time.time() < end_time:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    self.run_command(f"aide --check > {output_dir}/check_{ts}.log 2>&1", sudo=True, timeout=1800, quiet=True)
                    time.sleep(interval * 60)
            except KeyboardInterrupt:
                pass
        elif choice == "4":
            self.run_command("aide --update", sudo=True, timeout=3600)
            self.run_command("cp -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null", sudo=True)

    def process_monitor(self):
        """27. Süreç İzleme"""
        print(f"\n{Fore.CYAN}Süreç İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Gerçek Zamanlı (htop)\n2. Kaynak Kullanım Analizi\n3. Şüpheli Süreç Tespiti\n4. Belirli PID İzleme")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"process_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if shutil.which("htop"):
                self.run_command("htop")
            else:
                self.run_command("top", timeout=None)

        elif choice == "2":
            duration = float(input("Süre (dk) [5]: ") or "5")
            interval = float(input("Aralık (sn) [5]: ") or "5")
            csv_file = f"{output_dir}/resource_usage.csv"
            with open(csv_file, "w") as f:
                f.write("timestamp,pid,user,cpu,mem,command\n")
            end_time = time.time() + duration * 60
            try:
                while time.time() < end_time:
                    ts = datetime.now().strftime("%H:%M:%S")
                    result = self.run_command("ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head -11", quiet=True)
                    if result:
                        with open(csv_file, "a") as f:
                            for line in result.splitlines()[1:]:
                                parts = line.split(None, 4)
                                if len(parts) == 5:
                                    f.write(f"{ts},{','.join(parts)}\n")
                    time.sleep(interval)
            except KeyboardInterrupt:
                pass
            print(f"\n{Fore.GREEN}Kayıt: {csv_file}{Style.RESET_ALL}")

        elif choice == "3":
            patterns = ["kworker", "cryptominer", "miner", "backdoor", "reverse", "ncat", "nc -e"]
            found_any = False
            for pattern in patterns:
                result = self.run_command(f"ps aux | grep -i '{pattern}' | grep -v grep", quiet=True)
                if result and result.strip():
                    found_any = True
                    print(f"\n{Fore.RED}[!] '{pattern}' eşleşmesi:{Style.RESET_ALL}")
                    print(result[:1000])
                    with open(f"{output_dir}/suspicious_processes.log", "a") as f:
                        f.write(f"=== {pattern} ===\n{result}\n")
            if not found_any:
                print(f"\n{Fore.GREEN}Şüpheli süreç bulunamadı ✓{Style.RESET_ALL}")

        elif choice == "4":
            pid = input("PID: ")
            if not pid.isdigit() or not os.path.exists(f"/proc/{pid}"):
                print(f"{Fore.RED}Geçersiz PID veya süreç sonlanmış.{Style.RESET_ALL}")
                return
            duration = float(input("Süre (dk) [5]: ") or "5")
            log_file = f"{output_dir}/pid_{pid}.log"
            end_time = time.time() + duration * 60
            try:
                while time.time() < end_time and os.path.exists(f"/proc/{pid}"):
                    with open(log_file, "a") as f:
                        f.write(f"{datetime.now().strftime('%H:%M:%S')}: ")
                    self.run_command(f"ps -p {pid} -o pcpu,pmem,rss,etime --no-headers >> {log_file}", quiet=True)
                    time.sleep(2)
            except KeyboardInterrupt:
                pass
            print(f"\n{Fore.GREEN}Kayıt: {log_file}{Style.RESET_ALL}")

    def user_audit(self):
        """28. Kullanıcı Denetimi"""
        print(f"\n{Fore.CYAN}Kullanıcı Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Oturum Geçmişi\n2. Kullanıcı Aktiviteleri (audit)\n3. Yetki Değişiklikleri\n4. Parola Politikası")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"user_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            self.run_command(f"last -F | head -30 > {output_dir}/login_history.log")
            self.run_command(f"lastb -F | head -30 > {output_dir}/failed_logins.log 2>/dev/null", sudo=True)
            content = self.safe_file_operation(f"{output_dir}/login_history.log")
            if content:
                print(content[:2000])

        elif choice == "2":
            user = input("Kullanıcı adı [tümü]: ")
            if user and shutil.which("ausearch"):
                self.run_command(f"ausearch -ua {user} -i 2>/dev/null | tail -50 > {output_dir}/user_activities.log", sudo=True, timeout=120)
            elif shutil.which("aureport"):
                self.run_command(f"aureport --user -i 2>/dev/null | tail -50 > {output_dir}/all_activities.log", sudo=True, timeout=120)
            else:
                print(f"{Fore.YELLOW}auditd araçları kurulu değil; wtmp kayıtları gösteriliyor.{Style.RESET_ALL}")
                self.run_command(f"last -F | head -30 > {output_dir}/activities.log")

        elif choice == "3":
            self.run_command(f"grep -h 'USER_ACCT\|USER_ROLE' /var/log/auth.log 2>/dev/null | tail -50 > {output_dir}/permission_changes.log", sudo=True)
            self.run_command(f"tail -100 /var/log/auth.log 2>/dev/null | grep -i 'sudo\|su\[' > {output_dir}/privilege_events.log", sudo=True)
            content = self.safe_file_operation(f"{output_dir}/privilege_events.log")
            if content:
                print(content[:2000])

        elif choice == "4":
            if os.path.exists("/etc/security/pwquality.conf"):
                self.run_command(f"cat /etc/security/pwquality.conf > {output_dir}/password_policy.txt")
            self.run_command(f"grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs >> {output_dir}/password_policy.txt 2>/dev/null")
            content = self.safe_file_operation(f"{output_dir}/password_policy.txt")
            if content:
                print(content[:2000])

    def login_monitor(self):
        """29. Giriş İzleme"""
        print(f"\n{Fore.CYAN}Giriş İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Son Girişler\n2. Başarısız Girişler\n3. SSH Giriş Kayıtları\n4. Gerçek Zamanlı Takip (polling)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"login_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            limit = input("Kayıt sayısı [20]: ") or "20"
            self.run_command(f"last -n {limit} -F | head -{limit}")

        elif choice == "2":
            self.run_command(f"lastb -F | head -30", sudo=True)
            self.run_command("lastb | awk '{print $3}' | sort | uniq -c | sort -nr | head -10", sudo=True)

        elif choice == "3":
            for logfile in ("/var/log/auth.log", "/var/log/secure"):
                if os.path.exists(logfile):
                    self.run_command(f"grep 'sshd' {logfile} | tail -50 > {output_dir}/ssh_logins.log", sudo=True)
                    content = self.safe_file_operation(f"{output_dir}/ssh_logins.log")
                    if content:
                        print(content[:2500])
                    break

        elif choice == "4":
            duration = float(input("Süre (dk) [5]: ") or "5")
            log_file = f"{output_dir}/realtime_logins.log"
            src = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
            if not os.path.exists(src):
                print(f"{Fore.RED}Auth log bulunamadı.{Style.RESET_ALL}")
                return
            end_time = time.time() + duration * 60
            try:
                print(f"{Fore.YELLOW}Takip başladı ({src}) - Ctrl+C ile durdurun{Style.RESET_ALL}")
                while time.time() < end_time:
                    result = self.run_command(f"tail -5 {src}", quiet=True, sudo=True)
                    if result:
                        with open(log_file, "a") as f:
                            f.write(result)
                    time.sleep(5)
            except KeyboardInterrupt:
                pass
            print(f"\n{Fore.GREEN}Kayıt: {log_file}{Style.RESET_ALL}")

    def service_audit(self):
        """30. Servis Denetimi"""
        print(f"\n{Fore.CYAN}Servis Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Çalışan Servisler\n2. Başarısız Servisler\n3. Otomatik Başlayanlar\n4. Yüzey Azaltma Önerileri")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"service_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            self.run_command(f"systemctl list-units --type=service --state=running --no-pager > {output_dir}/running.txt")
            content = self.safe_file_operation(f"{output_dir}/running.txt")
            if content:
                print(content[:2500])

        elif choice == "2":
            self.run_command("systemctl --failed --no-pager")

        elif choice == "3":
            self.run_command("systemctl list-unit-files --type=service --state=enabled --no-pager | head -40")

        elif choice == "4":
            # Yaygın riskli servisleri kontrol et
            risky = ["telnet", "ftp", "rsh", "rlogin", "nfs-server", "smbd"]
            for svc in risky:
                result = self.run_command(f"systemctl is-active {svc} 2>/dev/null", quiet=True)
                if result and "active" in result:
                    print(f"{Fore.RED}[!] Riskli servis aktif: {svc} - 'sudo systemctl disable --now {svc}' önerilir{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}Denetim tamamlandı.{Style.RESET_ALL}")

    def password_audit(self):
        """31. Parola Güvenlik Denetimi"""
        print(f"\n{Fore.CYAN}Parola Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Hash Analizi (john)\n2. Zayıf Parola Tespiti\n3. Parola Politikası\n4. Parola Yaşlandırma Durumu")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"password_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice in ("1", "2"):
            if not self.check_tool("john"):
                return
            # unshadow ile birleştir (john'un ham shadow'u okuyamaması için)
            combined = f"{output_dir}/unshadowed.txt"
            if shutil.which("unshadow"):
                self.run_command(f"unshadow /etc/passwd /etc/shadow > {combined} 2>/dev/null", sudo=True)
            else:
                self.run_command(f"cat /etc/shadow > {combined}", sudo=True)
            if choice == "1":
                self.run_command(f"john --show {combined} > {output_dir}/cracked.txt 2>/dev/null", sudo=True, timeout=600)
            else:
                self.run_command(f"john --single --show {combined} > {output_dir}/cracked.txt 2>/dev/null", sudo=True, timeout=600)
            content = self.safe_file_operation(f"{output_dir}/cracked.txt")
            if content:
                lines = [ln for ln in content.splitlines() if ":" in ln and "password hash" not in ln]
                print(f"\n{Fore.RED if lines else Fore.GREEN}{len(lines)} parola çözüldü{Style.RESET_ALL}")
                if lines:
                    print("\n".join(ln.split(":")[0] for ln in lines[:20]))

        elif choice == "3":
            if os.path.exists("/etc/pam.d/common-password"):
                self.run_command(f"cat /etc/pam.d/common-password > {output_dir}/policy.txt")
            self.run_command(f"grep -E 'PASS_|pam_pwquality|pam_cracklib' /etc/login.defs /etc/pam.d/* 2>/dev/null >> {output_dir}/policy.txt")
            content = self.safe_file_operation(f"{output_dir}/policy.txt")
            if content:
                print(content[:2000])

        elif choice == "4":
            users = self.run_command("awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd", quiet=True)
            if users:
                for user in users.splitlines()[:15]:
                    self.run_command(f"chage -l {user}")

    def file_permission_check(self):
        """32. Dosya İzin Kontrolü"""
        print(f"\n{Fore.CYAN}Dosya İzin Kontrolü Seçenekleri:{Style.RESET_ALL}")
        print("1. SUID Dosyaları\n2. SUID+SGID Dosyaları\n3. Dizin İzin Denetimi\n4. Dosya Sahipliği")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"permission_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            path = input("Dizin [/]: ") or "/"
            print(f"{Fore.YELLOW}Taranıyor (uzun sürebilir)...{Style.RESET_ALL}")
            self.run_command(f"find {path} -xdev -type f -perm -4000 > {output_dir}/suid_files.txt 2>/dev/null", sudo=True, timeout=600)
            count = self.run_command(f"wc -l < {output_dir}/suid_files.txt", quiet=True)
            print(f"\n{Fore.GREEN}SUID dosya sayısı: {count.strip() if count else '0'} -> {output_dir}/suid_files.txt{Style.RESET_ALL}")

        elif choice == "2":
            self.run_command(f"find / -xdev -type f \( -perm -4000 -o -perm -2000 \) > {output_dir}/suid_sgid.txt 2>/dev/null", sudo=True, timeout=600)

        elif choice == "3":
            path = input("Dizin: ")
            self.run_command(f"ls -la {path} > {output_dir}/audit.txt")
            self.run_command(f"find {path} -perm -002 > {output_dir}/world_writable.txt 2>/dev/null")
            print(f"{Fore.GREEN}Sonuçlar: {output_dir}{Style.RESET_ALL}")

        elif choice == "4":
            path = input("Dizin: ")
            user = input("Kullanıcı [tümü]: ")
            cmd = f"find {path} -user {user}" if user else f"find {path} -ls"
            self.run_command(f"{cmd} > {output_dir}/ownership.txt 2>/dev/null", sudo=True, timeout=300)

    def system_hardening(self):
        """33. Sistem Sertleştirme"""
        print(f"\n{Fore.CYAN}Sistem Sertleştirme Seçenekleri:{Style.RESET_ALL}")
        print("1. Lynis Denetimi\n2. Öneriler\n3. Temel Otomatik Sertleştirme\n4. Güvenlik Raporu")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"system_hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if self.check_tool("lynis"):
                self.run_command(f"lynis audit system > {output_dir}/lynis.txt", sudo=True, timeout=1800)
                content = self.safe_file_operation(f"{output_dir}/lynis.txt")
                if content:
                    warnings = [ln for ln in content.splitlines() if "Warning" in ln or "Suggestion" in ln]
                    print(f"\n{Fore.CYAN}{len(warnings)} uyarı/öneri - detay: {output_dir}/lynis.txt{Style.RESET_ALL}")

        elif choice == "2":
            recommendations = [
                "1. Gereksiz servisleri kapatın: systemctl disable --now <servis>",
                "2. SSH parola girişini kapatın: PasswordAuthentication no",
                "3. Otomatik güvenlik güncellemelerini etkinleştirin",
                "4. UFW/firewalld ile varsayılan deny politikası uygulayın",
                "5. /tmp'yi noexec,nodev,nosuid ile bağlayın",
                "6. ASLR etkinliğini doğrulayın: cat /proc/sys/kernel/randomize_va_space (2 olmalı)",
                "7. Çekirdek paramatreleri: sysctl -a | grep -i 'icmp\|ip_forward'",
            ]
            for rec in recommendations:
                print(rec)
            with open(f"{output_dir}/recommendations.txt", "w") as f:
                f.write("\n".join(recommendations))

        elif choice == "3":
            print(f"{Fore.YELLOW}Temel sertleştirme adımları uygulanıyor...{Style.RESET_ALL}")
            steps = [
                ("systemctl disable --now telnet.socket 2>/dev/null", "telnet kapatma"),
                ("systemctl enable --now ufw 2>/dev/null || systemctl enable --now firewalld 2>/dev/null", "güvenlik duvarı"),
                ("sysctl -w kernel.randomize_va_space=2", "ASLR"),
                ("sysctl -w net.ipv4.conf.all.rp_filter=1", "IP spoof koruması"),
                ("chmod 600 /etc/shadow", "shadow izinleri"),
            ]
            for cmd, desc in steps:
                print(f"  -> {desc}...", end=" ")
                self.run_command(cmd, sudo=True, quiet=True)
                print("tamam")

        elif choice == "4":
            report = f"{output_dir}/report.txt"
            with open(report, "w") as f:
                f.write("=== Sistem Güvenlik Raporu ===\n\n")
            self.run_command(f"echo 'SELinux/AppArmor:' >> {report}; (sestatus 2>/dev/null || aa-status 2>/dev/null || echo 'yok') >> {report}", sudo=True)
            self.run_command(f"echo '\nASLR:' >> {report}; cat /proc/sys/kernel/randomize_va_space >> {report}")
            self.run_command(f"echo '\nAçık portlar:' >> {report}; ss -tuln >> {report}")
            content = self.safe_file_operation(report)
            if content:
                print(content[:2500])

    def backup_check(self):
        """34. Yedekleme Kontrolü"""
        print(f"\n{Fore.CYAN}Yedekleme Kontrol Seçenekleri:{Style.RESET_ALL}")
        print("1. Son Yedekler\n2. Yedek Dizin Doluluk\n3. Bütünlük Kontrolü (md5)\n4. Rapor")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"backup_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        backup_root = input("Yedek dizini [/backup]: ") or "/backup"
        if not os.path.exists(backup_root):
            print(f"{Fore.RED}Dizin bulunamadı: {backup_root}{Style.RESET_ALL}")
            return

        if choice == "1":
            days = input("Kaç gün [7]: ") or "7"
            self.run_command(f"find {backup_root} -type f -mtime -{days} -exec ls -lh {{}} \;")

        elif choice == "2":
            self.run_command(f"du -sh {backup_root}; df -h {backup_root}")

        elif choice == "3":
            print(f"{Fore.YELLOW}MD5 toplamları hesaplanıyor (uzun sürebilir)...{Style.RESET_ALL}")
            with open(f"{output_dir}/checksums.md5", "w") as f:
                pass
            self.run_command(f"find {backup_root} -type f -exec md5sum {{}} \; >> {output_dir}/checksums.md5", timeout=3600)
            print(f"{Fore.GREEN}Kayıt: {output_dir}/checksums.md5{Style.RESET_ALL}")

        elif choice == "4":
            with open(f"{output_dir}/report.txt", "w") as f:
                f.write(f"=== Yedekleme Raporu ===\nTarih: {datetime.now()}\n\n")
            self.run_command(f"echo 'Dosya sayısı:' >> {output_dir}/report.txt; find {backup_root} -type f | wc -l >> {output_dir}/report.txt")
            self.run_command(f"echo 'Toplam boyut:' >> {output_dir}/report.txt; du -sh {backup_root} >> {output_dir}/report.txt")
            self.run_command(f"echo 'Son 5 dosya:' >> {output_dir}/report.txt; find {backup_root} -type f -exec ls -lt {{}} + | head -5 >> {output_dir}/report.txt", timeout=300)
            content = self.safe_file_operation(f"{output_dir}/report.txt")
            if content:
                print(content)

    def encryption_check(self):
        """35. Disk Şifreleme Kontrolü"""
        print(f"\n{Fore.CYAN}Disk Şifreleme Kontrol Seçenekleri:{Style.RESET_ALL}")
        print("1. Şifreli Bölümler\n2. LUKS Detayları\n3. Swap Şifreleme\n4. Rapor")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"encryption_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            self.run_command(f"lsblk -f > {output_dir}/partitions.txt")
            self.run_command(f"lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,MODEL | grep -i 'crypt\|luks'")
            content = self.safe_file_operation(f"{output_dir}/partitions.txt")
            if content:
                print(content[:2000])

        elif choice == "2":
            self.run_command(f"dmsetup ls --target crypt > {output_dir}/crypt_devices.txt 2>/dev/null", sudo=True)
            for dev in self.run_command("dmsetup ls --target crypt | awk '{print $1}'", quiet=True, sudo=True).splitlines():
                dev = dev.strip()
                if dev:
                    print(f"\n{Fore.CYAN}=== {dev} ==={Style.RESET_ALL}")
                    self.run_command(f"cryptsetup status /dev/mapper/{dev}", sudo=True)

        elif choice == "3":
            result = self.run_command("swapon --show", quiet=True)
            if result and "crypt" not in result and "/dev/mapper" not in result:
                print(f"{Fore.RED}[!] Swap şifreli görünmüyor - /etc/crypttab ile şifreli swap önerilir{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}Swap cihazları:{Style.RESET_ALL}\n{result}")

        elif choice == "4":
            with open(f"{output_dir}/report.txt", "w") as f:
                f.write("=== Disk Şifreleme Raporu ===\n\n")
            self.run_command(f"lsblk -f >> {output_dir}/report.txt")
            self.run_command(f"dmsetup table >> {output_dir}/report.txt 2>/dev/null", sudo=True)
            content = self.safe_file_operation(f"{output_dir}/report.txt")
            if content:
                print(content[:2500])

    # ------------------------------------------------------------------
    # Adli Analiz (36-45)
    # ------------------------------------------------------------------
    def memory_analysis(self):
        """36. Bellek Analizi (Volatility)"""
        if not self.check_tool("volatility"):
            return
        image = input("Bellek imajı yolu: ")
        if not os.path.exists(image):
            print(f"{Fore.RED}İmaj bulunamadı: {image}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Bellek Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Süreç Listesi\n2. Ağ Bağlantıları\n3. DLL Listesi\n4. Şüpheli Süreçler (malfind)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"memory_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        plugins = {"1": "pslist", "2": "netscan", "3": "dlllist", "4": "malfind"}
        plugin = plugins.get(choice, "pslist")
        self.run_command(f"volatility -f {image} {plugin} > {output_dir}/{plugin}.txt", sudo=True, timeout=3600)

        out_file = f"{output_dir}/{plugin}.txt"
        if os.path.exists(out_file):
            content = self.safe_file_operation(out_file)
            if content:
                print(f"\n{Fore.GREEN}{len(content.splitlines())} satır -> {out_file}{Style.RESET_ALL}")
                if choice == "4" and content.strip():
                    print(f"{Fore.RED}malfind çıktısı mevcut - şüpheli kod bölümleri incelenmeli{Style.RESET_ALL}")

    def disk_analysis(self):
        """37. Disk Analizi"""
        print(f"\n{Fore.CYAN}Disk Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Autopsy (GUI)\n2. TestDisk (kurtarma)\n3. Dosya Sistemi Listesi (fls)\n4. Bütünlük (hashdeep)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"disk_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("autopsy"):
            disk = input("Analiz edilecek imaj/disk: ")
            self.run_command(f"autopsy", sudo=True)  # autopsy web arayüzünde çalışır
        elif choice == "2" and self.check_tool("testdisk"):
            disk = input("Kurtarma yapılacak disk: ")
            self.run_command(f"testdisk {disk}", sudo=True)
        elif choice == "3" and self.check_tool("fls"):
            image = input("İmaj dosyası: ")
            self.run_command(f"fls -r {image} > {output_dir}/metadata.txt 2>/dev/null", sudo=True, timeout=3600)
            content = self.safe_file_operation(f"{output_dir}/metadata.txt")
            if content:
                print(content[:2000])
        elif choice == "4" and self.check_tool("hashdeep"):
            path = input("Kontrol edilecek dizin: ")
            self.run_command(f"hashdeep -r {path} > {output_dir}/integrity.txt", timeout=3600)

    def log_analysis(self):
        """38. Log Analizi"""
        print(f"\n{Fore.CYAN}Log Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Sistem Logları (journal)\n2. Güvenlik Logları\n3. Hata İçeren Uygulama Logları\n4. Belirli Dosya Analizi")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            self.run_command(f"journalctl -p err..alert --since '24 hours ago' --no-pager > {output_dir}/system_errors.log", sudo=True, timeout=300)
            content = self.safe_file_operation(f"{output_dir}/system_errors.log")
            if content:
                print(f"{Fore.CYAN}Son 24 saat hata logları:{Style.RESET_ALL}")
                print(content[:2500])

        elif choice == "2":
            for src in ("/var/log/auth.log", "/var/log/secure"):
                if os.path.exists(src):
                    self.run_command(f"grep -iE 'fail|error|invalid|break' {src} | tail -50 > {output_dir}/security.log", sudo=True)
                    content = self.safe_file_operation(f"{output_dir}/security.log")
                    if content:
                        print(content[:2500])
                    break

        elif choice == "3":
            self.run_command(f"grep -rliE 'error|fatal' /var/log --include='*.log' 2>/dev/null | head -20 > {output_dir}/error_logs.txt", sudo=True, timeout=300)
            content = self.safe_file_operation(f"{output_dir}/error_logs.txt")
            if content:
                print(f"{Fore.CYAN}Hata içeren log dosyaları:{Style.RESET_ALL}\n{content}")

        elif choice == "4":
            path = input("Log dosyası: ")
            if not os.path.exists(path):
                print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
                return
            content = self.safe_file_operation(path)
            if content:
                lines = content.splitlines()
                print(f"Toplam {len(lines)} satır")
                for pattern in ("error", "failed", "warning", "critical"):
                    count = sum(1 for ln in lines if pattern in ln.lower())
                    print(f"  {pattern}: {count}")
                print(f"\n{Fore.CYAN}Son 30 satır:{Style.RESET_ALL}")
                print("\n".join(lines[-30:]))

    def file_carving(self):
        """39. Dosya Kurtarma (foremost)"""
        if not self.check_tool("foremost"):
            return
        image = input("İmaj/disk yolu: ")
        if not os.path.exists(image):
            print(f"{Fore.RED}Dosya bulunamadı: {image}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Kurtarma Seçenekleri:{Style.RESET_ALL}")
        print("1. Tüm türler\n2. Belirli türler\n3. Derin tarama")
        choice = input("\nSeçiminiz (1-3): ")
        output_dir = f"file_carving_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "2":
            types = input("Türler (jpg,pdf,doc,zip): ")
            cmd = f"foremost -t {types} -i {image} -o {output_dir}/out"
        elif choice == "3":
            cmd = f"foremost -d -v -i {image} -o {output_dir}/out"
        else:
            cmd = f"foremost -i {image} -o {output_dir}/out"

        print(f"\n{Fore.YELLOW}Kurtarma başlatılıyor (uzun sürebilir)...{Style.RESET_ALL}")
        self.run_command(cmd, sudo=True, timeout=7200)

        if os.path.exists(f"{output_dir}/out"):
            count = self.run_command(f"find {output_dir}/out -type f | wc -l", quiet=True)
            print(f"\n{Fore.GREEN}Kurtarılan dosya sayısı: {count.strip() if count else '0'} -> {output_dir}/out{Style.RESET_ALL}")

    def timeline_analysis(self):
        """40. Zaman Çizelgesi Analizi"""
        print(f"\n{Fore.CYAN}Zaman Çizelgesi Seçenekleri:{Style.RESET_ALL}")
        print("1. mactime (bodyfile)\n2. Son değişen dosyalar\n3. audit olayları\n4. Bash geçmişi zamanı")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("mactime"):
            bodyfile = input("Bodyfile yolu [/tmp/body.txt]: ") or "/tmp/body.txt"
            if not os.path.exists(bodyfile):
                print(f"{Fore.YELLOW}Bodyfile bulunamadı. Önce fls ile oluşturun (37. Disk Analizi > fls).{Style.RESET_ALL}")
                return
            self.run_command(f"mactime -b {bodyfile} -d -y > {output_dir}/timeline.csv", timeout=1800)
            content = self.safe_file_operation(f"{output_dir}/timeline.csv")
            if content:
                print(content[:2500])

        elif choice == "2":
            path = input("Dizin [/]: ") or "/"
            days = input("Kaç gün [1]: ") or "1"
            self.run_command(f"find {path} -xdev -mtime -{days} -exec ls -lt {{}} + 2>/dev/null | head -50")

        elif choice == "3" and shutil.which("ausearch"):
            start = (datetime.now() - timedelta(days=1)).strftime("%m/%d/%Y %H:%M:%S")
            self.run_command(f"ausearch -ts {start} -i 2>/dev/null | tail -60", sudo=True, timeout=300)

        elif choice == "4":
            for hist in ("/root/.bash_history", os.path.expanduser("~/.bash_history")):
                if os.path.exists(hist):
                    print(f"\n{Fore.CYAN}=== {hist} ==={Style.RESET_ALL}")
                    content = self.safe_file_operation(hist)
                    if content:
                        print("\n".join(content.splitlines()[-40:]))
                    break

    def network_forensics(self):
        """41. Ağ Adli Analizi (pcap)"""
        if not self.check_tool("wireshark") and not shutil.which("tshark"):
            print(f"{Fore.RED}tshark/wireshark bulunamadı.{Style.RESET_ALL}")
            return

        pcap = input("Pcap dosyası yolu: ")
        if not os.path.exists(pcap):
            print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Protokol hiyerarşisi\n2. HTTP istekleri\n3. DNS sorguları\n4. Şüpheli trafik (beaconing, ARP)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"net_forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if shutil.which("tshark"):
            cmds = {
                "1": f"tshark -r {pcap} -q -z io,phs > {output_dir}/protocols.txt",
                "2": f"tshark -r {pcap} -Y http.request -T fields -e frame.time -e http.host -e http.request.uri > {output_dir}/http.txt",
                "3": f"tshark -r {pcap} -Y 'dns.flags.response == 0' -T fields -e frame.time -e dns.qry.name > {output_dir}/dns.txt",
                "4": f"tshark -r {pcap} -Y 'arp.duplicate-address-detected || tcp.analysis.retransmission' > {output_dir}/suspicious.txt",
            }
            self.run_command(cmds.get(choice, cmds["1"]), timeout=900)
        else:
            self.run_command(f"wireshark {pcap}")

        for fname in ("protocols.txt", "http.txt", "dns.txt", "suspicious.txt"):
            path = f"{output_dir}/{fname}"
            if os.path.exists(path):
                content = self.safe_file_operation(path)
                if content:
                    print(f"\n{Fore.CYAN}=== {fname} ==={Style.RESET_ALL}")
                    print(content[:2000])
        print(f"\n{Fore.GREEN}Sonuçlar: {output_dir}{Style.RESET_ALL}")

    def usb_forensics(self):
        """42. USB Aygıt Geçmişi Analizi"""
        print(f"\n{Fore.CYAN}USB Aygıt Geçmişi{Style.RESET_ALL}")
        output_dir = f"usb_forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        print(f"\n{Fore.YELLOW}Geçerli bağlı USB aygıtlar:{Style.RESET_ALL}")
        self.run_command("lsusb")
        self.run_command(f"lsusb -v > {output_dir}/usb_verbose.txt 2>/dev/null", timeout=120)

        print(f"\n{Fore.YELLOW}Sistem günlüklerinde USB geçmişi (son 200 eşleşme):{Style.RESET_ALL}")
        for log in ("/var/log/syslog", "/var/log/messages", "/var/log/kern.log"):
            if os.path.exists(log):
                self.run_command(f"grep -iE 'usb|sd[a-z]' {log} 2>/dev/null | tail -200 > {output_dir}/usb_history.log", sudo=True, timeout=300)
                break
        content = self.safe_file_operation(f"{output_dir}/usb_history.log")
        if content:
            print(content[:3000])
        else:
            print(f"{Fore.YELLOW}Geçmiş kaydı bulunamadı.{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}Sonuçlar: {output_dir}{Style.RESET_ALL}")

    def cron_forensics(self):
        """43. Zamanlanmış Görev Analizi"""
        print(f"\n{Fore.CYAN}Zamanlanmış Görev Analizi{Style.RESET_ALL}")
        output_dir = f"cron_forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        self.run_command(f"crontab -l > {output_dir}/root_cron.txt 2>/dev/null", sudo=True)
        self.run_command(f"ls -la /etc/cron* /var/spool/cron 2>/dev/null > {output_dir}/cron_files.txt")
        self.run_command(f"cat /etc/crontab /etc/cron.d/* 2>/dev/null > {output_dir}/cron_entries.txt")
        self.run_command("echo '--- Kullanıcı crontabları ---' >> {0}/cron_entries.txt".format(output_dir), quiet=True)
        self.run_command(f"for u in $(cut -d: -f1 /etc/passwd); do echo \"== $u ==\"; crontab -u $u -l 2>/dev/null; done >> {output_dir}/cron_entries.txt")
        self.run_command(f"systemctl list-timers --all --no-pager > {output_dir}/systemd_timers.txt")

        for fname in ("root_cron.txt", "cron_entries.txt", "systemd_timers.txt"):
            path = f"{output_dir}/{fname}"
            if os.path.exists(path):
                content = self.safe_file_operation(path)
                if content and content.strip():
                    print(f"\n{Fore.CYAN}=== {fname} ==={Style.RESET_ALL}")
                    print(content[:2000])
        # Şüpheli kalıplar
        print(f"\n{Fore.YELLOW}Şüpheli cron kalıpları (curl|wget|base64|/tmp):{Style.RESET_ALL}")
        self.run_command(f"grep -rEn 'curl|wget|base64|/tmp/|/dev/shm' {output_dir}/cron_entries.txt 2>/dev/null || echo 'Bulunamadı ✓'")

    def shell_history_analysis(self):
        """44. Kabuk Geçmişi Adli Analizi"""
        print(f"\n{Fore.CYAN}Kabuk Geçmişi Analizi{Style.RESET_ALL}")
        output_dir = f"shell_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        suspicious_patterns = {
            "reverse_shell": r"nc -e|bash -i|sh -i|/dev/tcp/|python -c 'import socket'",
            "credential_access": r"cat /etc/shadow|cat /etc/passwd|history -c",
            "download_execute": r"curl .*\| (sh|bash)|wget .*\| (sh|bash)",
            "privesc": r"chmod \+s|setuid|sudo -l",
        }

        histories = []
        users = self.run_command("cut -d: -f1,6 /etc/passwd", quiet=True)
        if users:
            for line in users.splitlines()[:30]:
                parts = line.split(":")
                if len(parts) == 2:
                    for hist_name in (".bash_history", ".zsh_history", ".history"):
                        p = os.path.join(parts[1], hist_name)
                        if os.path.exists(p):
                            histories.append((parts[0], p))
        # Mevcut kullanıcı da dahil
        me = os.path.expanduser("~/.bash_history")
        if os.path.exists(me) and all(p != me for _, p in histories):
            histories.append((os.environ.get("USER", "current"), me))

        if not histories:
            print(f"{Fore.YELLOW}Geçmiş dosyası bulunamadı.{Style.RESET_ALL}")
            return

        for user, path in histories:
            content = self.safe_file_operation(path)
            if not content:
                continue
            print(f"\n{Fore.CYAN}=== {user}: {path} ({len(content.splitlines())} komut) ==={Style.RESET_ALL}")
            for label, pattern in suspicious_patterns.items():
                matches = [ln for ln in content.splitlines() if re.search(pattern, ln)]
                if matches:
                    print(f"{Fore.RED}[!] {label}:{Style.RESET_ALL}")
                    for m in matches[:10]:
                        print(f"    {m[:150]}")
            with open(f"{output_dir}/{user}_history.txt", "w") as f:
                f.write(content)

        print(f"\n{Fore.GREEN}Kopyalar: {output_dir}{Style.RESET_ALL}")

    def open_files_analysis(self):
        """45. Açık Dosyalar ve Silinmiş Açık Dosyalar"""
        print(f"\n{Fore.CYAN}Açık Dosyalar Analizi (lsof){Style.RESET_ALL}")
        output_dir = f"open_files_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        print(f"\n{Fore.YELLOW}Silinmiş ama hâlâ açık dosyalar:{Style.RESET_ALL}")
        self.run_command(f"lsof +L1 > {output_dir}/deleted_open.txt", sudo=True, timeout=120)
        content = self.safe_file_operation(f"{output_dir}/deleted_open.txt")
        if content:
            lines = content.splitlines()
            print(f"{len(lines) - 1} kayıt")
            print("\n".join(lines[:25]))

        print(f"\n{Fore.YELLOW}Süreçlerin açık soketleri:{Style.RESET_ALL}")
        self.run_command(f"lsof -i -P > {output_dir}/sockets.txt", sudo=True, timeout=120)
        content = self.safe_file_operation(f"{output_dir}/sockets.txt")
        if content:
            print(content[:2000])

        print(f"\n{Fore.YELLOW}/tmp ve /dev/shm içinde çalışan süreçler:{Style.RESET_ALL}")
        self.run_command(f"lsof +D /tmp 2>/dev/null | head -30; lsof +D /dev/shm 2>/dev/null | head -30")
        print(f"\n{Fore.GREEN}Sonuçlar: {output_dir}{Style.RESET_ALL}")

    # ------------------------------------------------------------------
    # Sızma Testi (46-55)
    # ------------------------------------------------------------------
    def password_cracking(self):
        """46. Parola Kırma (hashcat)"""
        if not self.check_tool("hashcat"):
            return

        print(f"\n{Fore.CYAN}Parola Kırma Seçenekleri:{Style.RESET_ALL}")
        print("1. Wordlist\n2. Brute Force\n3. Wordlist + Kurallar\n4. Kombinasyon")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"password_crack_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        hash_file = input("Hash dosyası: ")
        if not os.path.exists(hash_file):
            print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
            return

        # Hash türü tespiti
        first_hash = self.safe_file_operation(hash_file)
        sample = first_hash.splitlines()[0].strip() if first_hash and first_hash.splitlines() else ""
        if shutil.which("hashid") and sample:
            ids = self.run_command(f"hashid '{sample}'", quiet=True, timeout=15)
            if ids:
                print(f"\n{Fore.YELLOW}Olası hash türleri:{Style.RESET_ALL}\n{ids[:600]}")
        hash_mode = input("\nHash modu (-m) [0=MD5]: ") or "0"

        out_file = f"{output_dir}/cracked.txt"
        if choice == "1":
            wordlist = input("Wordlist [/usr/share/wordlists/rockyou.txt]: ") or "/usr/share/wordlists/rockyou.txt"
            if not os.path.exists(wordlist):
                print(f"{Fore.RED}Wordlist bulunamadı: {wordlist}{Style.RESET_ALL}")
                return
            cmd = f"hashcat -m {hash_mode} {hash_file} {wordlist} -o {out_file}"
        elif choice == "2":
            charset = input("Karakter seti [?a]: ") or "?a"
            min_len = input("Min uzunluk [1]: ") or "1"
            max_len = input("Max uzunluk [6]: ") or "6"
            cmd = f"hashcat -m {hash_mode} -a 3 {hash_file} {charset} -i --increment-min={min_len} --increment-max={max_len} -o {out_file}"
        elif choice == "3":
            wordlist = input("Wordlist: ")
            rules = input("Kurallar [best64]: ") or "best64"
            rule_path = f"/usr/share/hashcat/rules/{rules}.rule"
            if not os.path.exists(rule_path):
                rule_path = rules  # kullanıcı tam yol vermiş olabilir
            cmd = f"hashcat -m {hash_mode} {hash_file} {wordlist} -r {rule_path} -o {out_file}"
        elif choice == "4":
            w1 = input("Wordlist 1: ")
            w2 = input("Wordlist 2: ")
            cmd = f"hashcat -m {hash_mode} -a 1 {hash_file} {w1} {w2} -o {out_file}"
        else:
            print(f"{Fore.RED}Geçersiz seçim.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}Kırma başlatılıyor... (dur: 's', durum: Enter){Style.RESET_ALL}")
        self.run_command(cmd, timeout=7200)

        if os.path.exists(out_file):
            content = self.safe_file_operation(out_file)
            if content and content.strip():
                print(f"\n{Fore.GREEN}Kırılan parolalar:{Style.RESET_ALL}")
                print(content[:2000])
            else:
                print(f"\n{Fore.YELLOW}Bu oturumda parola kırılamadı.{Style.RESET_ALL}")
            self.run_command(f"hashcat -m {hash_mode} {hash_file} --show", timeout=120)

    def exploit_search(self):
        """47. Exploit Arama (searchsploit)"""
        if not self.check_tool("searchsploit"):
            return

        print(f"\n{Fore.CYAN}Exploit Arama Seçenekleri:{Style.RESET_ALL}")
        print("1. Anahtar kelime\n2. CVE numarası\n3. Başlıkta ara\n4. Detaylı arama")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"exploit_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            kw = input("Anahtar kelime: ")
            cmd = f"searchsploit {kw} -w -t"
        elif choice == "2":
            cve = input("CVE (örn: CVE-2021-44228): ")
            cmd = f"searchsploit --cve {cve}"
        elif choice == "3":
            kw = input("Başlık: ")
            cmd = f"searchsploit {kw} -t"
        elif choice == "4":
            kw = input("Anahtar kelime: ")
            author = input("Yazar [boş=tümü]: ")
            cmd = f"searchsploit {kw}"
            if author:
                cmd += f" --author={author}"
        else:
            print(f"{Fore.RED}Geçersiz seçim.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}Aranıyor...{Style.RESET_ALL}")
        result = self.run_command(f"{cmd} | tee {output_dir}/exploits.txt", timeout=120)
        if result:
            print(f"\n{Fore.GREEN}Sonuçlar: {output_dir}/exploits.txt{Style.RESET_ALL}")

    def web_fuzzing(self):
        """48. Web Fuzzing (wfuzz)"""
        if not self.check_tool("wfuzz"):
            return

        print(f"\n{Fore.CYAN}Web Fuzzing Seçenekleri:{Style.RESET_ALL}")
        print("1. Dizin taraması\n2. Parametre fuzzing\n3. Virtual host keşfi\n4. Özel (metod/header)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"web_fuzzing_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        url = input("Hedef URL (örn: http://target): ")

        if choice == "1":
            wordlist = input("Wordlist [/usr/share/wordlists/dirb/common.txt]: ") or "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                print(f"{Fore.RED}Wordlist bulunamadı.{Style.RESET_ALL}")
                return
            cmd = f"wfuzz -c -z file,{wordlist} --hc 404,403 -u {url}/FUZZ -f {output_dir}/dirs.txt"
        elif choice == "2":
            param = input("Parametre adı (örn: id): ")
            wordlist = input("Wordlist: ")
            cmd = f"wfuzz -c -z file,{wordlist} -d '{param}=FUZZ' {url} -f {output_dir}/params.txt"
        elif choice == "3":
            domain = input("Ana domain: ")
            wordlist = input("Subdomain wordlist: ")
            cmd = f"wfuzz -c -w {wordlist} -H 'Host: FUZZ.{domain}' {url} -f {output_dir}/vhosts.txt"
        elif choice == "4":
            method = input("Metod [GET]: ") or "GET"
            headers = input("Header'lar (Key:Value, virgüllü) [boş]: ")
            cmd = f"wfuzz -c -X {method} -z file,/usr/share/wordlists/dirb/common.txt -u {url}/FUZZ"
            if headers:
                for h in headers.split(","):
                    cmd += f" -H '{h.strip()}'"
            cmd += f" -f {output_dir}/custom.txt"
        else:
            print(f"{Fore.RED}Geçersiz seçim.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}Fuzzing başlatılıyor... (Ctrl+C ile durdurun){Style.RESET_ALL}")
        self.run_command(cmd, timeout=3600)

        for f in os.listdir(output_dir):
            path = os.path.join(output_dir, f)
            content = self.safe_file_operation(path)
            if content and content.strip():
                print(f"\n{Fore.CYAN}=== {f} ==={Style.RESET_ALL}")
                print(content[:1500])

    def sql_injection(self):
        """49. SQL Injection Taraması (sqlmap)"""
        if not self.check_tool("sqlmap"):
            return

        print(f"\n{Fore.CYAN}SQL Injection Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel tarama\n2. Veritabanı keşfi\n3. Derin tarama (risk 3)\n4. Özel tarama")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"sqlmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        url = input("Hedef URL (parametreli): ")
        base_cmd = f"sqlmap -u '{url}' --batch --random-agent"

        if choice == "1":
            cmd = base_cmd
        elif choice == "2":
            print(" 1. Veritabanları  2. Tablolar  3. Sütunlar  4. Dump")
            sub = input("Seçim: ")
            if sub == "1":
                cmd = f"{base_cmd} --dbs"
            elif sub == "2":
                db = input("DB adı: ")
                cmd = f"{base_cmd} -D {db} --tables"
            elif sub == "3":
                db = input("DB adı: ")
                tbl = input("Tablo: ")
                cmd = f"{base_cmd} -D {db} -T {tbl} --columns"
            elif sub == "4":
                db = input("DB adı: ")
                tbl = input("Tablo: ")
                cmd = f"{base_cmd} -D {db} -T {tbl} --dump"
            else:
                print(f"{Fore.RED}Geçersiz.{Style.RESET_ALL}")
                return
        elif choice == "3":
            cmd = f"{base_cmd} --risk=3 --level=5 --threads=4"
        elif choice == "4":
            risk = input("Risk (1-3) [1]: ") or "1"
            level = input("Level (1-5) [1]: ") or "1"
            dbms = input("DBMS (boş=otomatik): ")
            cmd = f"{base_cmd} --risk={risk} --level={level}"
            if dbms:
                cmd += f" --dbms={dbms}"
        else:
            print(f"{Fore.RED}Geçersiz.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}Tarama başlatılıyor... (uzun sürebilir){Style.RESET_ALL}")
        self.run_command(f"{cmd} --output-dir={output_dir}", timeout=10800)
        print(f"\n{Fore.GREEN}Çıktılar: {output_dir}{Style.RESET_ALL}")

    def xss_scan(self):
        """50. XSS Taraması (xsser)"""
        if not self.check_tool("xsser"):
            return

        print(f"\n{Fore.CYAN}XSS Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Hızlı tarama\n2. Detaylı tarama\n3. DOM XSS\n4. Özel payload")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"xss_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        url = input("Hedef URL: ")
        if choice == "1":
            cmd = f"xsser --url '{url}' --auto -v"
        elif choice == "2":
            cmd = f"xsser --url '{url}' --auto --Cw --Str --reverse-check -v"
        elif choice == "3":
            cmd = f"xsser --url '{url}' --DOM --auto -v"
        elif choice == "4":
            payload_file = input("Payload dosyası: ")
            if not os.path.exists(payload_file):
                print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
                return
            method = input("Metod (GET/POST) [GET]: ") or "GET"
            cmd = f"xsser --url '{url}' -s {payload_file} --{method.lower()}"
        else:
            print(f"{Fore.RED}Geçersiz.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}Tarama başlatılıyor...{Style.RESET_ALL}")
        self.run_command(f"{cmd} > {output_dir}/results.txt 2>&1", timeout=3600)

        out_file = f"{output_dir}/results.txt"
        if os.path.exists(out_file):
            content = self.safe_file_operation(out_file)
            if content:
                found = content.lower().count("xss found") + content.count("[+]")
                print(f"\n{Fore.RED if found else Fore.GREEN}XSS bulgusu: {found}{Style.RESET_ALL}")
                print(content[:2500])

    def binary_analysis(self):
        """51. İkili Dosya Analizi (r2)"""
        if not self.check_tool("radare2"):
            return

        file = input("Dosya yolu: ")
        if not os.path.exists(file):
            print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel (fonksiyonlar/imports)\n2. Derin (disassembly/xrefs)\n3. Güvenlik (ROP/checksec)\n4. Özel r2 komutu")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"binary_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        self.run_command(f"file {file}")
        if shutil.which("checksec"):
            self.run_command(f"checksec --file={file}")

        if choice == "1":
            cmds = [f"r2 -A -q -c afl {file}", f"r2 -A -q -c ii {file}", f"r2 -A -q -c iz {file}"]
        elif choice == "2":
            cmds = [f"r2 -A -q -c 'aa; pdf @ main' {file}", f"r2 -A -q -c axt {file}", f"r2 -A -q -c izq {file}"]
        elif choice == "3":
            cmds = [f"r2 -A -q -c i {file}", f"r2 -A -q -c '/R/' {file}"]
        elif choice == "4":
            r2_cmd = input("r2 komutu: ")
            cmds = [f"r2 -A -q -c '{r2_cmd}' {file}"]
        else:
            print(f"{Fore.RED}Geçersiz.{Style.RESET_ALL}")
            return

        for i, cmd in enumerate(cmds):
            print(f"\n{Fore.CYAN}=== [{i+1}/{len(cmds)}] ==={Style.RESET_ALL}")
            self.run_command(cmd, timeout=600)
        print(f"\n{Fore.GREEN}Tamamlandı: {output_dir}{Style.RESET_ALL}")

    def malware_analysis(self):
        """52. Zararlı Yazılım Analizi (statik + sandbox)"""
        print(f"\n{Fore.CYAN}Zararlı Yazılım Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Statik (strings/objdump)\n2. Dinamik (strace)\n3. Ağ izleme\n4. YARA tarama")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        file = input("Dosya yolu: ")
        if not os.path.exists(file):
            print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
            return

        self.run_command(f"file {file}; sha256sum {file}; md5sum {file}")

        if choice == "1":
            self.run_command(f"strings -n 6 {file} > {output_dir}/strings.txt", timeout=300)
            content = self.safe_file_operation(f"{output_dir}/strings.txt")
            if content:
                suspicious = [ln for ln in content.splitlines() if re.search(r"http[s]?://|cmd\.exe|/bin/sh|exec|socket", ln, re.I)]
                print(f"\n{Fore.CYAN}{len(content.splitlines())} string, {len(suspicious)} şüpheli:{Style.RESET_ALL}")
                for ln in suspicious[:30]:
                    print(f"  {ln[:140]}")
        elif choice == "2":
            if self.check_tool("strace"):
                self.run_command(f"timeout 30 strace -f -o {output_dir}/syscalls.txt ./{file} 2>/dev/null || true", timeout=60)
                content = self.safe_file_operation(f"{output_dir}/syscalls.txt")
                if content:
                    print(content[:1500])
        elif choice == "3":
            print(f"{Fore.YELLOW}Ağ trafiği izleniyor (30sn) - hedef başlatılmadıysa manuel çalıştırın{Style.RESET_ALL}")
            interface = input("Arayüz [any]: ") or "any"
            self.run_command(f"timeout 30 tcpdump -i {interface} -w {output_dir}/network.pcap", sudo=True, timeout=40)
            print(f"{Fore.GREEN}Kayıt: {output_dir}/network.pcap{Style.RESET_ALL}")
        elif choice == "4":
            if self.check_tool("yara"):
                rules = input("Kural dizini [boş=öntanımlı yok]: ")
                if rules and os.path.exists(rules):
                    self.run_command(f"yara -r {rules} {file}", timeout=600)
                else:
                    print(f"{Fore.YELLOW}Kural dizini verilmedi.{Style.RESET_ALL}")

    def threat_hunting(self):
        """53. Tehdit Avcılığı (YARA)"""
        print(f"\n{Fore.CYAN}Tehdit Avcılığı Seçenekleri:{Style.RESET_ALL}")
        print("1. YARA tarama\n2. IOC dosya hash taraması\n3. Şüpheli süreç\n4. Recent değişiklikler")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"threat_hunting_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if not self.check_tool("yara"):
                return
            target = input("Taranacak dizin: ")
            rule_file = input("Kural dosyası/dizini: ")
            if not os.path.exists(rule_file):
                print(f"{Fore.RED}Kural bulunamadı.{Style.RESET_ALL}")
                return
            self.run_command(f"yara -r {rule_file} {target} > {output_dir}/yara_results.txt", timeout=3600)
            content = self.safe_file_operation(f"{output_dir}/yara_results.txt")
            if content and content.strip():
                print(f"\n{Fore.RED}Eşleşmeler:{Style.RESET_ALL}\n{content[:2000]}")
            else:
                print(f"\n{Fore.GREEN}Eşleşme yok ✓{Style.RESET_ALL}")

        elif choice == "2":
            target = input("Dizin: ")
            self.run_command(f"find {target} -type f -exec sha256sum {{}} \; > {output_dir}/hashes.txt 2>/dev/null", timeout=3600)
            print(f"{Fore.GREEN}Hash listesi: {output_dir}/hashes.txt{Style.RESET_ALL}")

        elif choice == "3":
            result = self.run_command("ps aux | grep -iE 'miner|crypto|xmrig|kworker/[0-9]*:[0-9]|backdoor' | grep -v grep", quiet=True)
            if result and result.strip():
                print(f"{Fore.RED}Şüpheli süreçler:{Style.RESET_ALL}\n{result}")
            else:
                print(f"{Fore.GREEN}Şüpheli süreç yok ✓{Style.RESET_ALL}")

        elif choice == "4":
            path = input("Dizin [/etc /usr/bin]: ") or "/etc"
            self.run_command(f"find {path} -xdev -type f -mtime -2 -exec ls -l {{}} \; 2>/dev/null | head -40", sudo=True, timeout=600)

    def osint_gathering(self):
        """54. OSINT Bilgi Toplama"""
        print(f"\n{Fore.CYAN}OSINT Seçenekleri:{Style.RESET_ALL}")
        print("1. E-posta (theHarvester)\n2. Subdomain (subfinder)\n3. Teknoloji tespiti (whatweb)\n4. Sosyal medya (sherlock)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"osint_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("theharvester"):
            domain = input("Domain: ")
            limit = input("Limit [500]: ") or "500"
            self.run_command(f"theharvester -d {domain} -l {limit} -b all > {output_dir}/emails.txt", timeout=1800)
        elif choice == "2" and self.check_tool("subfinder"):
            domain = input("Domain: ")
            self.run_command(f"subfinder -d {domain} -o {output_dir}/subdomains.txt", timeout=1800)
        elif choice == "3" and self.check_tool("whatweb"):
            target = input("URL: ")
            self.run_command(f"whatweb -v {target} > {output_dir}/tech.txt", timeout=600)
        elif choice == "4" and self.check_tool("sherlock"):
            username = input("Kullanıcı adı: ")
            self.run_command(f"sherlock {username} --output {output_dir}/social.txt", timeout=1800)
        else:
            if choice in ("1", "2", "3", "4"):
                pass  # check_tool hata mesajı verdi
            else:
                print(f"{Fore.RED}Geçersiz seçim.{Style.RESET_ALL}")
            return

        for f in os.listdir(output_dir):
            content = self.safe_file_operation(f"{output_dir}/{f}")
            if content and content.strip():
                print(f"\n{Fore.CYAN}=== {f} ==={Style.RESET_ALL}")
                print(content[:2000])

    def reverse_engineering(self):
        """55. Tersine Mühendislik"""
        print(f"\n{Fore.CYAN}Tersine Mühendislik Seçenekleri:{Style.RESET_ALL}")
        print("1. Statik (strings/objdump)\n2. Dinamik (ltrace/strace)\n3. r2 ile\n4. Ghidra (GUI)")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"reverse_eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        target = input("Dosya yolu: ")
        if not os.path.exists(target):
            print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
            return
        self.run_command(f"file {target}")

        if choice == "1":
            self.run_command(f"strings -n 5 {target} | head -100")
            self.run_command(f"objdump -d {target} > {output_dir}/disasm.txt 2>/dev/null", timeout=600)
            print(f"{Fore.GREEN}Disassembly: {output_dir}/disasm.txt{Style.RESET_ALL}")
        elif choice == "2":
            if shutil.which("ltrace"):
                self.run_command(f"timeout 20 ltrace ./{target} 2>&1 | head -60", timeout=30)
            if shutil.which("strace"):
                self.run_command(f"timeout 20 strace ./{target} 2>&1 | head -60", timeout=30)
        elif choice == "3" and self.check_tool("radare2"):
            self.run_command(f"r2 -A -q -c 'afl; iz' {target}", timeout=300)
        elif choice == "4" and self.check_tool("ghidra"):
            self.run_command("ghidraRun", timeout=None)
        else:
            if choice not in ("1", "2"):
                print(f"{Fore.RED}Araç bulunamadı veya geçersiz seçim.{Style.RESET_ALL}")

    # ------------------------------------------------------------------
    # İleri Seviye Güvenlik (56-64)
    # ------------------------------------------------------------------
    def steganography(self):
        """56. Steganografi Analizi"""
        print(f"\n{Fore.CYAN}Steganografi Seçenekleri:{Style.RESET_ALL}")
        print("1. steghide çıkarma\n2. Metadata (exiftool)\n3. LSB analizi\n4. Stegdetect")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"stego_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        file = input("Dosya yolu: ")
        if not os.path.exists(file):
            print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
            return

        if choice == "1" and self.check_tool("steghide"):
            passphrase = input("Parola (boş=denemesiz): ")
            cmd = f"cd {output_dir} && steghide extract -sf {file} -f"
            if passphrase:
                cmd += f" -p '{passphrase}'"
            self.run_command(cmd)
        elif choice == "2" and self.check_tool("exiftool"):
            self.run_command(f"exiftool {file} | tee {output_dir}/metadata.txt")
        elif choice == "3":
            if shutil.which("zsteg"):  # PNG/BMP LSB
                self.run_command(f"zsteg {file}")
            elif shutil.which("stegolsb"):
                self.run_command(f"stegolsb steglsb -r -i {file} -o {output_dir}/lsb_out 2>/dev/null")
            else:
                print(f"{Fore.RED}zsteg/stegolsb bulunamadı.{Style.RESET_ALL}")
        elif choice == "4" and self.check_tool("stegdetect"):
            self.run_command(f"stegdetect {file}")

    def crypto_analysis(self):
        """57. Kriptografik Analiz"""
        print(f"\n{Fore.CYAN}Kriptografik Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Dosya hash'leri\n2. SSL/TLS bağlantı analizi\n3. Binwalk imza taraması\n4. Entropi analizi")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"crypto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            file = input("Dosya: ")
            if not os.path.exists(file):
                print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
                return
            for algo in ("md5sum", "sha1sum", "sha256sum", "sha512sum"):
                self.run_command(f"{algo} {file}")
        elif choice == "2":
            host = input("Host: ")
            port = input("Port [443]: ") or "443"
            self.run_command(f"echo | openssl s_client -connect {host}:{port} -showcerts 2>/dev/null | openssl x509 -noout -text | head -40", timeout=60)
        elif choice == "3" and self.check_tool("binwalk"):
            file = input("Dosya: ")
            self.run_command(f"binwalk {file} | tee {output_dir}/signatures.txt", timeout=600)
        elif choice == "4":
            file = input("Dosya: ")
            if not os.path.exists(file):
                print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
                return
            result = self.run_command(f"openssl rand 2>/dev/null; file {file}", quiet=True)
            # Basit entropi hesabı
            try:
                with open(file, "rb") as f:
                    data = f.read(1_000_000)
                if data:
                    from collections import Counter
                    import math
                    counts = Counter(data)
                    total = len(data)
                    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
                    print(f"{Fore.CYAN}Entropi (ilk 1MB): {entropy:.4f} bits/byte{Style.RESET_ALL}")
                    print(f"8.0'e yakın = şifreli/sıkıştırılmış, <6 = düz metin olabilir")
            except OSError as e:
                print(f"{Fore.RED}{e}{Style.RESET_ALL}")
        else:
            if choice in ("1", "2", "3", "4"):
                pass
            else:
                print(f"{Fore.RED}Geçersiz seçim.{Style.RESET_ALL}")

    def container_security(self):
        """58. Konteyner Güvenliği"""
        print(f"\n{Fore.CYAN}Konteyner Güvenlik Seçenekleri:{Style.RESET_ALL}")
        print("1. İmaj tarama (trivy)\n2. Docker daemon bilgisi\n3. Kapsül izolasyon durumu\n4. Kubernetes denetimi")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"container_security_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if not shutil.which("docker"):
            print(f"{Fore.RED}Docker bulunamadı.{Style.RESET_ALL}")
            return

        if choice == "1":
            if self.check_tool("trivy"):
                images = self.run_command("docker images --format '{{.Repository}}:{{.Tag}}'", quiet=True)
                if images:
                    for image in images.splitlines()[:10]:
                        if "<none>" not in image:
                            print(f"\n{Fore.CYAN}=== {image} ==={Style.RESET_ALL}")
                            self.run_command(f"trivy image --severity HIGH,CRITICAL {image} 2>/dev/null | head -30", timeout=900)
        elif choice == "2":
            self.run_command("docker info --format 'ServerVersion: {{.ServerVersion}}  Driver: {{.Driver}}  Security: {{json .SecurityOptions}}'")
            self.run_command(f"docker ps --format 'table {{{{.Names}}}}\t{{{{.Image}}}}\t{{{{.Ports}}}}'")
        elif choice == "3":
            self.run_command("aa-status 2>/dev/null || echo 'AppArmor yok'")
            self.run_command("docker info 2>/dev/null | grep -iE 'security|userns'")
        elif choice == "4":
            if shutil.which("kubectl"):
                self.run_command("kubectl get pods --all-namespaces -o wide 2>/dev/null | head -20")
                self.run_command("kubectl get networkpolicies --all-namespaces 2>/dev/null")
            else:
                print(f"{Fore.RED}kubectl bulunamadı.{Style.RESET_ALL}")

    def compliance_check(self):
        """59. Uyumluluk Kontrolü"""
        print(f"\n{Fore.CYAN}Uyumluluk Seçenekleri:{Style.RESET_ALL}")
        print("1. CIS (lynis/oscap)\n2. Parola politikası denetimi\n3. Açık port/CIS servis kontrolü\n4. Özet rapor")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if shutil.which("lynis"):
                self.run_command(f"lynis audit system --quick > {output_dir}/cis.txt", sudo=True, timeout=1800)
                content = self.safe_file_operation(f"{output_dir}/cis.txt")
                if content:
                    score = [ln for ln in content.splitlines() if "hardening index" in ln.lower()]
                    print(f"\n{Fore.CYAN}{score[0] if score else 'Skor satırı bulunamadı'}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}lynis bulunamadı.{Style.RESET_ALL}")
        elif choice == "2":
            self.run_command("grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs")
            if os.path.exists("/etc/security/pwquality.conf"):
                self.run_command("grep -vE '^#|^$' /etc/security/pwquality.conf")
        elif choice == "3":
            self.run_command("ss -tulpn", sudo=True)
            self.run_command("systemctl list-unit-files --state=enabled --type=service | grep -E 'telnet|ftp|rsh|nfs' || echo 'Riskli servis yok ✓'")
        elif choice == "4":
            with open(f"{output_dir}/summary.txt", "w") as f:
                f.write(f"=== Uyumluluk Özeti ===\nTarih: {datetime.now()}\n\n")
            self.run_command(f"echo 'OS:' >> {output_dir}/summary.txt; grep PRETTY_NAME /etc/os-release >> {output_dir}/summary.txt")
            self.run_command(f"echo '\nKernel:' >> {output_dir}/summary.txt; uname -r >> {output_dir}/summary.txt")
            self.run_command(f"echo '\nAçık portlar:' >> {output_dir}/summary.txt; ss -tuln >> {output_dir}/summary.txt")
            self.run_command(f"echo '\nParola politikası:' >> {output_dir}/summary.txt; grep PASS_MAX_DAYS /etc/login.defs >> {output_dir}/summary.txt")
            content = self.safe_file_operation(f"{output_dir}/summary.txt")
            if content:
                print(content)

    def security_audit(self):
        """60. Güvenlik Denetimi"""
        print(f"\n{Fore.CYAN}Güvenlik Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Lynis tam denetim\n2. Ağ denetimi\n3. Kullanıcı/yetki denetimi\n4. SSH yapılandırma denetimi")
        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if self.check_tool("lynis"):
                self.run_command(f"lynis audit system > {output_dir}/lynis_full.txt", sudo=True, timeout=3600)
                content = self.safe_file_operation(f"{output_dir}/lynis_full.txt")
                if content:
                    for ln in content.splitlines():
                        if "hardening index" in ln.lower() or "warning" in ln.lower()[:40]:
                            print(ln)
        elif choice == "2":
            self.run_command(f"nmap -sV --top-ports 100 localhost -oN {output_dir}/ports.txt 2>/dev/null", sudo=True, timeout=600)
            content = self.safe_file_operation(f"{output_dir}/ports.txt")
            if content:
                print(content[:2000])
        elif choice == "3":
            self.run_command("awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd")
            self.run_command("getent group sudo 2>/dev/null | cut -d: -f4 || getent group wheel | cut -d: -f4")
            self.run_command("grep -E 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null", sudo=True)
        elif choice == "4":
            if os.path.exists("/etc/ssh/sshd_config"):
                self.run_command("sshd -T 2>/dev/null | grep -E 'permitrootlogin|passwordauthentication|permitemptypasswords|maxauth|port '")
                self.run_command(f"sshd -T > {output_dir}/sshd_effective.txt 2>/dev/null")

    def system_performance(self):
        """61. Sistem Performans Analizi"""
        print(f"\n{Fore.CYAN}Performans Seçenekleri:{Style.RESET_ALL}")
        print("1. CPU\n2. Bellek\n3. Disk I/O\n4. Ağ\n5. Yük ortalaması")
        choice = input("\nSeçiminiz (1-5): ")

        options = {
            "1": "mpstat 1 3 2>/dev/null || vmstat 1 3",
            "2": "free -h && vmstat 1 3",
            "3": "iostat -xz 1 3 2>/dev/null || cat /proc/diskstats | head -10",
            "4": "sar -n DEV 1 3 2>/dev/null || ss -s",
            "5": "uptime && cat /proc/loadavg",
        }
        cmd = options.get(choice)
        if cmd:
            self.run_command(cmd, timeout=30)

    def system_backup(self):
        """62. Sistem Yedekleme"""
        print(f"\n{Fore.CYAN}Yedekleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Tam sistem (tar)\n2. Seçili dizin\n3. Yedek listesi\n4. Geri yükleme")
        choice = input("\nSeçiminiz (1-4): ")

        backup_dir = input("Yedek dizini [/backup]: ") or "/backup"
        self.run_command(f"mkdir -p {backup_dir}", sudo=True)
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")

        if choice == "1":
            output = f"{backup_dir}/system_backup_{date_str}.tar.gz"
            print(f"{Fore.YELLOW}Tam sistem yedeği alınıyor (uzun sürebilir)...{Style.RESET_ALL}")
            self.run_command(
                f"tar --one-file-system -czpf {output} --exclude=/proc --exclude=/tmp --exclude={backup_dir} --exclude=/mnt --exclude=/dev --exclude=/sys --exclude=/run --exclude=/media --exclude=/var/cache/apt /",
                sudo=True, timeout=10800)
            print(f"{Fore.GREEN}Yedek: {output}{Style.RESET_ALL}")
        elif choice == "2":
            path = input("Dizin: ")
            if not os.path.exists(path):
                print(f"{Fore.RED}Dizin bulunamadı.{Style.RESET_ALL}")
                return
            output = f"{backup_dir}/{os.path.basename(path.rstrip('/'))}_{date_str}.tar.gz"
            self.run_command(f"tar -czpf {output} -C {os.path.dirname(path.rstrip('/')) or '/'} {os.path.basename(path.rstrip('/'))}", timeout=3600)
            print(f"{Fore.GREEN}Yedek: {output}{Style.RESET_ALL}")
        elif choice == "3":
            self.run_command(f"ls -lh {backup_dir}")
        elif choice == "4":
            self.run_command(f"ls -lh {backup_dir}")
            backup_file = input("Yedek dosyası (tam yol): ")
            restore_path = input("Hedef dizin: ")
            if not os.path.exists(backup_file):
                print(f"{Fore.RED}Dosya bulunamadı.{Style.RESET_ALL}")
                return
            self.run_command(f"mkdir -p {restore_path} && tar -xzpf {backup_file} -C {restore_path}", sudo=True, timeout=7200)
            print(f"{Fore.GREEN}Geri yükleme tamamlandı.{Style.RESET_ALL}")

    def system_cleanup(self):
        """63. Sistem Temizliği"""
        print(f"\n{Fore.CYAN}Temizlik Seçenekleri:{Style.RESET_ALL}")
        print("1. Önbellek\n2. Gereksiz paketler\n3. Eski loglar\n4. Geçici dosyalar\n5. Disk kullanım analizi")
        choice = input("\nSeçiminiz (1-5): ")

        commands = {
            "1": ["sync", "apt-get clean 2>/dev/null || true", "rm -rf ~/.cache/* 2>/dev/null || true"],
            "2": ["apt-get autoremove -y 2>/dev/null || true", "apt-get autoclean 2>/dev/null || true"],
            "3": ["journalctl --vacuum-time=7d 2>/dev/null || true",
                  "find /var/log -type f -name '*.gz' -mtime +7 -delete 2>/dev/null || true"],
            "4": ["find /tmp -type f -atime +7 -delete 2>/dev/null || true"],
            "5": ["du -xhd1 / 2>/dev/null | sort -rh | head -15", "df -h"],
        }
        for cmd in commands.get(choice, []):
            self.run_command(cmd, sudo=True, timeout=900)

    def show_installed_tools(self):
        """64. Kurulu araçları göster"""
        print(f"\n{Fore.CYAN}Sistemde Kurulu Olan Araçlar:{Style.RESET_ALL}")

        flat = self._all_tools_flat()

        def check(tool):
            path = shutil.which(self.TOOL_ALIASES.get(tool, tool))
            version = ""
            if path:
                try:
                    result = subprocess.run([path, "--version"], capture_output=True,
                                            text=True, stderr=subprocess.STDOUT, timeout=3)
                    version = (result.stdout or result.stderr or "").splitlines()[0][:60]
                except Exception:
                    version = "sürüm alınamadı"
            return tool, path, version

        installed, missing = [], []
        with ThreadPoolExecutor(max_workers=8) as ex:
            for tool, path, version in ex.map(check, flat):
                (installed if path else missing).append((tool, version))

        print(f"\nToplam: {len(flat)} | Kurulu: {Fore.GREEN}{len(installed)}{Style.RESET_ALL} | Eksik: {Fore.RED}{len(missing)}{Style.RESET_ALL}")
        if installed:
            print(f"\n{Fore.GREEN}Kurulu Araçlar:{Style.RESET_ALL}")
            for tool, version in installed:
                print(f"  ✓ {tool:<24} {version}")
        if missing:
            print(f"\n{Fore.RED}Eksik Araçlar:{Style.RESET_ALL}")
            for tool, _ in missing:
                print(f"  ✗ {tool}")
            if input(f"\n{Fore.YELLOW}Eksik araçları kurmak ister misiniz? (e/h): {Style.RESET_ALL}").lower() == "e":
                for tool, _ in missing:
                    print(f"\n{Fore.CYAN}Yükleniyor: {tool}{Style.RESET_ALL}")
                    self.install_package(tool)

    # ------------------------------------------------------------------
    # Ana döngü
    # ------------------------------------------------------------------
    def main(self) -> int:
        """Ana program döngüsü"""
        self.check_platform()
        os.system("clear" if os.name == "posix" else "cls")
        self.check_security_tools()

        options = {
            0: ("Çıkış", None),
            # Temel Sistem Yönetimi (1-10)
            1: ("Disk Alanı Kontrolü", self.check_disk_space),
            2: ("RAM Kullanımı", self.check_ram_usage),
            3: ("Aktif İşlemler", self.list_processes),
            4: ("Ağ Arayüzleri", self.network_interfaces),
            5: ("Açık Portlar", self.check_open_ports),
            6: ("Sistem Bilgileri", self.system_info),
            7: ("Kullanıcı Listesi", self.list_users),
            8: ("Servis Kontrolü", self.check_services),
            9: ("Sistem Logları", self.check_logs),
            10: ("Güncelleme Kontrolü", self.check_updates),
            # Güvenlik Taramaları (11-20)
            11: ("Zafiyet Taraması", self.vulnerability_scan),
            12: ("Zararlı Yazılım Taraması", self.malware_scan),
            13: ("Rootkit Taraması", self.rootkit_scan),
            14: ("Port Taraması", self.port_scan),
            15: ("Web Uygulama Taraması", self.web_scan),
            16: ("SSL/TLS Analizi", self.ssl_scan),
            17: ("Kablosuz Ağ Taraması", self.wifi_scan),
            18: ("Paket Yakalama", self.packet_capture),
            19: ("ARP Taraması", self.arp_scan),
            20: ("DNS Bilgi Toplama", self.dns_enum),
            # Ağ ve Sistem Güvenliği (21-35)
            21: ("MITM Saldırı Tespiti", self.mitm_detection),
            22: ("Güvenlik Duvarı Kontrolü", self.firewall_check),
            23: ("Ağ İzleme", self.network_monitor),
            24: ("Bant Genişliği İzleme", self.bandwidth_monitor),
            25: ("Bağlantı İzleme", self.connection_monitor),
            26: ("Dosya Bütünlük Kontrolü", self.file_integrity),
            27: ("Süreç İzleme", self.process_monitor),
            28: ("Kullanıcı Denetimi", self.user_audit),
            29: ("Giriş İzleme", self.login_monitor),
            30: ("Servis Denetimi", self.service_audit),
            31: ("Parola Güvenlik Denetimi", self.password_audit),
            32: ("Dosya İzin Kontrolü", self.file_permission_check),
            33: ("Sistem Sertleştirme", self.system_hardening),
            34: ("Yedekleme Kontrolü", self.backup_check),
            35: ("Disk Şifreleme Kontrolü", self.encryption_check),
            # Adli Analiz (36-45)
            36: ("Bellek Analizi", self.memory_analysis),
            37: ("Disk Analizi", self.disk_analysis),
            38: ("Log Analizi", self.log_analysis),
            39: ("Dosya Kurtarma", self.file_carving),
            40: ("Zaman Çizelgesi Analizi", self.timeline_analysis),
            41: ("Ağ Adli Analizi (pcap)", self.network_forensics),
            42: ("USB Aygıt Geçmişi", self.usb_forensics),
            43: ("Zamanlanmış Görev Analizi", self.cron_forensics),
            44: ("Kabuk Geçmişi Analizi", self.shell_history_analysis),
            45: ("Açık/Silinmiş Dosyalar", self.open_files_analysis),
            # Sızma Testi (46-55)
            46: ("Parola Kırma", self.password_cracking),
            47: ("Exploit Arama", self.exploit_search),
            48: ("Web Fuzzing", self.web_fuzzing),
            49: ("SQL Injection Taraması", self.sql_injection),
            50: ("XSS Taraması", self.xss_scan),
            51: ("İkili Dosya Analizi", self.binary_analysis),
            52: ("Zararlı Yazılım Analizi", self.malware_analysis),
            53: ("Tehdit Avcılığı", self.threat_hunting),
            54: ("OSINT Bilgi Toplama", self.osint_gathering),
            55: ("Tersine Mühendislik", self.reverse_engineering),
            # İleri Seviye (56-64)
            56: ("Steganografi Analizi", self.steganography),
            57: ("Kriptografik Analiz", self.crypto_analysis),
            58: ("Konteyner Güvenliği", self.container_security),
            59: ("Uyumluluk Kontrolü", self.compliance_check),
            60: ("Güvenlik Denetimi", self.security_audit),
            61: ("Sistem Performans Analizi", self.system_performance),
            62: ("Sistem Yedekleme", self.system_backup),
            63: ("Sistem Temizliği", self.system_cleanup),
            64: ("Kurulu Araçları Göster", self.show_installed_tools),
        }

        while True:
            print(f"{Fore.CYAN}")
            print("""
██╗     ██╗███╗   ███╗███╗   ███╗ █████╗
██║     ██║████╗ ████║████╗ ████║██╔══██╗
██║     ██║██╔████╔██║██╔████╔██║███████║
██║     ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║
███████╗██║██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
            """)
            print(f"{Style.RESET_ALL}")

            print(f"{Fore.YELLOW}Kategoriler:{Style.RESET_ALL}")
            print("  1-10 : Temel Sistem Yönetimi")
            print(" 11-20 : Güvenlik Taramaları")
            print(" 21-35 : Ağ ve Sistem Güvenliği")
            print(" 36-45 : Adli Analiz")
            print(" 46-55 : Sızma Testi")
            print(" 56-64 : İleri Seviye Güvenlik\n")

            for key in sorted(options.keys()):
                name, _ = options[key]
                if key == 0:
                    print(f"{Fore.RED}  0. {name}{Style.RESET_ALL}")
                    continue
                if 1 <= key <= 10:
                    c = Fore.GREEN
                elif key <= 20:
                    c = Fore.YELLOW
                elif key <= 35:
                    c = Fore.BLUE
                elif key <= 45:
                    c = Fore.MAGENTA
                elif key <= 55:
                    c = Fore.RED
                else:
                    c = Fore.CYAN
                print(f"{c}{key:>3}. {name}{Style.RESET_ALL}")

            try:
                choice = int(input(f"\n{Fore.YELLOW}Seçiminiz (0-64): {Style.RESET_ALL}"))
                if choice == 0:
                    print(f"{Fore.GREEN}Çıkış yapılıyor...{Style.RESET_ALL}")
                    return 0
                if choice in options:
                    name, func = options[choice]
                    print(f"\n{Fore.CYAN}=== {name} ==={Style.RESET_ALL}")
                    if func is not None:
                        func()
                    input(f"\n{Fore.CYAN}Devam etmek için Enter'a basın...{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Geçersiz seçim! 0-64 arası bir sayı girin.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Lütfen geçerli bir sayı girin.{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Program kapatılıyor...{Style.RESET_ALL}")
                return 0


# Tüm genel metodlara hata-yönetimi dekoratörü uygula
for _mname in list(vars(LinuxSystemControl)):
    if _mname.startswith("_") or _mname in ("main", "check_platform"):
        continue
    _m = vars(LinuxSystemControl)[_mname]
    if callable(_m):
        setattr(LinuxSystemControl, _mname, LinuxSystemControl.error_handler(_m))


if __name__ == "__main__":
    exit_code = 0
    try:
        system_control = LinuxSystemControl()
        exit_code = system_control.main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program kapatıldı.{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Program başlatma hatası: {str(e)}")
        print(f"{Back.RED}Program başlatılamadı: {str(e)}{Style.RESET_ALL}")
        exit_code = 1
    finally:
        try:
            system_control.cleanup()
            system_control.executor.shutdown(wait=False)
        except Exception:
            pass
        print(f"{Fore.GREEN}Program sonlandırıldı.{Style.RESET_ALL}")
    sys.exit(exit_code)
