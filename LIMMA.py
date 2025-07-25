#!/usr/bin/env python3

# Gerekli modüllerin import edilmesi
import os
import sys
import logging
import subprocess
import hashlib
import shutil
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Union, Callable
from colorama import init, Fore, Style, Back
import platform
import time
import threading
import functools
from concurrent.futures import ThreadPoolExecutor

# Colorama başlatma ve loglama yapılandırması
init(autoreset=True)  # autoreset=True eklendi


# Loglama yapılandırması
def setup_logging():
    logging.basicConfig(
        filename="system_control.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


class LinuxSystemControl:
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
                "steghide",
                "stegdetect",
                "tensorflow",
                "mythril",
                "prowler",
                "cuckoo",
                "filebeat",
                "osquery",
                "lynis",
            ],
        }
        self.package_managers = {
            "apt": "apt-get install -y",
            "yum": "yum install -y",
            "dnf": "dnf install -y",
            "pacman": "pacman -S --noconfirm",
        }
        self.temp_files = []
        setup_logging()

        # Mutex ve kilitleri ekle
        self.command_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.config_lock = threading.Lock()

        # Varsayılan yapılandırma
        self.max_threads = 4

        # Thread havuzu
        self.executor = ThreadPoolExecutor(max_workers=self.max_threads)

    def run_command(self, command: str, sudo: bool = False) -> Optional[str]:
        """Thread-safe komut çalıştırma"""
        with self.command_lock:
            try:
                import shlex

                if isinstance(command, str):
                    cmd = shlex.split(command)
                if sudo:
                    cmd.insert(0, "sudo")

                logging.info(f"Çalıştırılan komut: {' '.join(cmd)}")

                # Interaktif komutlar için özel işleme
                if any(tool in command for tool in ["htop", "nano", "vim", "less"]):
                    process = subprocess.Popen(cmd)
                    process.wait()
                    return None

                # Normal komut çıktısı
                result = subprocess.run(
                    cmd, shell=False, text=True, capture_output=True, check=False
                )

                if result.returncode == 0:
                    if result.stdout:
                        # Renkli çıktı için ANSI kodlarını koru
                        print(result.stdout)
                    return result.stdout

                logging.error(f"Komut hatası: {result.stderr}")
                print(f"{Fore.RED}Hata: {result.stderr}{Style.RESET_ALL}")
                return None

            except subprocess.SubprocessError as e:
                logging.error(f"Subprocess hatası: {str(e)}")
                return None

    def safe_file_operation(
        self, file_path: Union[str, Path], mode: str = "r"
    ) -> Optional[str]:
        """Thread-safe dosya işlemleri"""
        with self.file_lock:
            try:
                file_path = Path(file_path)
                with open(file_path, mode) as f:
                    return f.read() if mode == "r" else None
            except (IOError, PermissionError) as e:
                logging.error(f"Dosya işlem hatası: {str(e)}")
                print(f"{Fore.RED}Dosya işlem hatası: {str(e)}{Style.RESET_ALL}")
                return None

    def get_package_manager(self):
        """Sistemdeki paket yöneticisini tespit et"""
        try:
            if shutil.which("apt"):
                return "apt"
            elif shutil.which("yum"):
                return "yum"
            elif shutil.which("dnf"):
                return "dnf"
            elif shutil.which("pacman"):
                return "pacman"
            else:
                print(
                    f"{Fore.RED}Desteklenen paket yöneticisi bulunamadı.{Style.RESET_ALL}"
                )
                return None
        except Exception as e:
            logging.error(f"Paket yöneticisi tespiti hatası: {str(e)}")
            return None

    def install_package(self, package_name):
        """Paketi otomatik olarak yükle"""
        try:
            pkg_manager = self.get_package_manager()
            if pkg_manager:
                print(f"{Fore.YELLOW}{package_name} yükleniyor...{Style.RESET_ALL}")
                cmd = f"{self.package_managers[pkg_manager]} {package_name}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                if result.returncode == 0:
                    print(
                        f"{Fore.GREEN}{package_name} başarıyla yüklendi.{Style.RESET_ALL}"
                    )
                    return True
                else:
                    print(
                        f"{Fore.RED}{package_name} yüklenemedi: {result.stderr}{Style.RESET_ALL}"
                    )
            return False
        except Exception as e:
            logging.error(f"Paket yükleme hatası: {str(e)}")
            return False

    @classmethod
    def check_platform(cls):
        """Platform kontrolü"""
        if platform.system() != "Linux":
            print(
                f"{Fore.RED}Bu program yalnızca Linux sistemlerde çalışır.{Style.RESET_ALL}"
            )
            sys.exit(1)

    def check_tool(self, tool_name: str) -> bool:
        """Araç kontrolü ve otomatik kurulumu"""
        if not shutil.which(tool_name):
            print(f"{Fore.YELLOW}{tool_name} kurulu değil.{Style.RESET_ALL}")
            if (
                input(f"{tool_name} otomatik olarak kurulsun mu? (e/h): ").lower()
                == "e"
            ):
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
            except Exception as e:
                logging.error(f"{func.__name__} hatası: {str(e)}")
                print(
                    f"{Fore.RED}{func.__name__} çalıştırılırken hata: {str(e)}{Style.RESET_ALL}"
                )
                return None

        return wrapper

    def cleanup(self):
        """Kaynakları temizle"""
        try:
            # Geçici dosyaları temizle
            for temp_file in self.temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)

            # Açık kalan bağlantıları kontrol et ve kapat
            try:
                # ps komutunu düzelt
                processes = self.run_command(
                    "ps aux | grep -i 'nc\\|netcat' | grep -v 'grep'"
                )
                if processes:
                    for line in processes.splitlines():
                        parts = line.split()
                        if len(parts) > 1:
                            try:
                                pid = int(parts[1])  # PID'nin sayı olduğundan emin ol
                                self.run_command(f"kill {pid}", sudo=True)
                            except (ValueError, IndexError):
                                continue
            except Exception as e:
                logging.error(f"Süreç temizleme hatası: {str(e)}")

        except Exception as e:
            logging.error(f"Temizlik hatası: {str(e)}")

    def check_security_tools(self):
        """Tüm güvenlik araçlarının kontrolü"""
        print(f"{Fore.CYAN}Güvenlik Araçları Kontrol Menüsü{Style.RESET_ALL}")

        # Eksik araçları kategorilere göre belirle
        missing_by_category = {}
        for category, tools in self.required_tools.items():
            missing = [tool for tool in tools if not shutil.which(tool)]
            if missing:
                missing_by_category[category] = missing

        if not missing_by_category:
            print(f"{Fore.GREEN}Tüm güvenlik araçları hazır.{Style.RESET_ALL}")
            return

        while True:
            print(f"\n{Fore.YELLOW}Eksik Araçlar (Kategorilere Göre):{Style.RESET_ALL}")
            categories = list(missing_by_category.keys())

            # Kategorileri listele
            for i, category in enumerate(categories, 1):
                missing_tools = missing_by_category[category]
                print(f"{i}. {category} ({len(missing_tools)} araç)")

            print(f"0. {Fore.CYAN}Ana Menüye Dön{Style.RESET_ALL}")

            try:
                choice = input(
                    f"\n{Fore.YELLOW}Kategori seçin (0-{len(categories)}): {Style.RESET_ALL}"
                )
                if choice == "0":
                    break

                category_idx = int(choice) - 1
                if 0 <= category_idx < len(categories):
                    selected_category = categories[category_idx]
                    missing_tools = missing_by_category[selected_category]

                    while True:
                        print(
                            f"\n{Fore.CYAN}{selected_category} kategorisindeki eksik araçlar:{Style.RESET_ALL}"
                        )
                        for i, tool in enumerate(missing_tools, 1):
                            print(f"{i}. {tool}")

                        print("\nKurulum seçenekleri:")
                        print("1. APT kullanarak kur")
                        print("2. Snap kullanarak kur")
                        print("3. Flatpak kullanarak kur")
                        print("4. Git repositoryden kur")
                        print("5. İndirme linki girerek kur")
                        print("0. Geri dön")

                        tool_choice = input(
                            f"\n{Fore.YELLOW}Yüklenecek aracı seçin (1-{len(missing_tools)}) veya 0 ile geri dönün: {Style.RESET_ALL}"
                        )
                        if tool_choice == "0":
                            break

                        tool_idx = int(tool_choice) - 1
                        if 0 <= tool_idx < len(missing_tools):
                            tool_to_install = missing_tools[tool_idx]

                            install_choice = input("\nKurulum yöntemi seçin (1-5): ")

                            if install_choice == "1":
                                cmd = f"apt-get install -y {tool_to_install}"
                            elif install_choice == "2":
                                cmd = f"snap install {tool_to_install}"
                            elif install_choice == "3":
                                cmd = f"flatpak install -y {tool_to_install}"
                            elif install_choice == "4":
                                repo_url = input("Git repository URL'si: ")
                                cmd = f"git clone {repo_url} && cd {tool_to_install} && make install"
                            elif install_choice == "5":
                                download_url = input("İndirme linki: ")
                                cmd = f"wget {download_url} && dpkg -i {tool_to_install}*.deb"
                            else:
                                print(
                                    f"{Fore.RED}Geçersiz kurulum seçimi!{Style.RESET_ALL}"
                                )
                                continue

                            print(
                                f"\n{Fore.YELLOW}{tool_to_install} kuruluyor...{Style.RESET_ALL}"
                            )
                            if self.run_command(cmd, sudo=True):
                                print(
                                    f"{Fore.GREEN}{tool_to_install} başarıyla yüklendi.{Style.RESET_ALL}"
                                )
                                missing_tools.remove(tool_to_install)
                                if not missing_tools:
                                    del missing_by_category[selected_category]
                                    break
                            else:
                                print(
                                    f"{Fore.RED}{tool_to_install} yüklenemedi!{Style.RESET_ALL}"
                                )
                        else:
                            print(f"{Fore.RED}Geçersiz araç seçimi!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Geçersiz kategori seçimi!{Style.RESET_ALL}")

            except ValueError:
                print(f"{Fore.RED}Lütfen geçerli bir sayı girin!{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(
                    f"\n{Fore.YELLOW}Araç kontrol menüsünden çıkılıyor...{Style.RESET_ALL}"
                )
                break

            if not missing_by_category:
                print(f"\n{Fore.GREEN}Tüm araçlar kuruldu!{Style.RESET_ALL}")
                break

            print(f"\n{Fore.CYAN}Devam etmek için Enter'a basın...{Style.RESET_ALL}")
            input()

    # Temel Sistem Fonksiyonları (1-10)
    # basit fonksiyonlar ile temel işlemler için hazırlanmıştır.
    def check_disk_space(self):
        """1. Disk alanı kontrolü"""
        try:
            print(f"\n{Fore.CYAN}Disk Kullanım Bilgileri:{Style.RESET_ALL}")
            # Disk kullanımı
            self.run_command("df -h --output=source,size,used,avail,pcent,target")
            # İnode kullanımı
            print(f"\n{Fore.CYAN}İnode Kullanımı:{Style.RESET_ALL}")
            self.run_command("df -i")
        except Exception as e:
            print(f"{Fore.RED}Disk kontrolü sırasında hata: {str(e)}{Style.RESET_ALL}")

    def check_ram_usage(self):
        """2. RAM kullanımı kontrolü"""
        try:
            print(f"\n{Fore.CYAN}Bellek Kullanım Bilgileri:{Style.RESET_ALL}")
            self.run_command("free -h")
            print(f"\n{Fore.CYAN}Detaylı Bellek İstatistikleri:{Style.RESET_ALL}")
            self.run_command("vmstat 1 5")
        except Exception as e:
            print(f"{Fore.RED}RAM kontrolü sırasında hata: {str(e)}{Style.RESET_ALL}")

    def list_processes(self):
        """3. Aktif işlemleri listele"""
        try:
            print(f"\n{Fore.CYAN}En Çok Kaynak Kullanan Süreçler:{Style.RESET_ALL}")
            # ps komutunu düzelt
            self.run_command("ps aux --sort=-%cpu,-%mem | head -11")
        except Exception as e:
            print(f"{Fore.RED}Süreç listesi alınırken hata: {str(e)}{Style.RESET_ALL}")

    def network_interfaces(self):
        """4. Ağ arayüzlerini görüntüle"""
        try:
            print(f"\n{Fore.CYAN}Ağ Arayüzleri:{Style.RESET_ALL}")
            self.run_command("ip -c addr show")
            print(f"\n{Fore.CYAN}Ağ İstatistikleri:{Style.RESET_ALL}")
            self.run_command("netstat -i")
        except Exception as e:
            print(
                f"{Fore.RED}Ağ arayüzleri kontrolünde hata: {str(e)}{Style.RESET_ALL}"
            )

    def check_open_ports(self):
        """5. Açık portları kontrol et"""
        try:
            print(f"\n{Fore.CYAN}Açık Portlar ve Bağlantılar:{Style.RESET_ALL}")
            self.run_command("ss -tuln")
            print(f"\n{Fore.CYAN}Aktif Bağlantılar:{Style.RESET_ALL}")
            self.run_command("netstat -tunap", sudo=True)
        except Exception as e:
            print(f"{Fore.RED}Port kontrolünde hata: {str(e)}{Style.RESET_ALL}")

    def system_info(self):
        """6. Sistem bilgilerini görüntüle"""
        try:
            print(f"\n{Fore.CYAN}Sistem Bilgileri:{Style.RESET_ALL}")
            self.run_command("uname -a")
            print(f"\n{Fore.CYAN}İşletim Sistemi Bilgisi:{Style.RESET_ALL}")
            self.run_command("cat /etc/os-release")
            print(f"\n{Fore.CYAN}Donanım Bilgileri:{Style.RESET_ALL}")
            self.run_command("lscpu")
        except Exception as e:
            print(f"{Fore.RED}Sistem bilgisi alınırken hata: {str(e)}{Style.RESET_ALL}")

    def list_users(self):
        """7. Kullanıcıları listele"""
        try:
            print(f"\n{Fore.CYAN}Sistem Kullanıcıları:{Style.RESET_ALL}")
            self.run_command("awk -F: '$3 >= 1000 {print $1}' /etc/passwd")
            print(f"\n{Fore.CYAN}Sudo Yetkisi Olan Kullanıcılar:{Style.RESET_ALL}")
            self.run_command("getent group sudo | cut -d: -f4")
        except Exception as e:
            print(
                f"{Fore.RED}Kullanıcı listesi alınırken hata: {str(e)}{Style.RESET_ALL}"
            )

    def check_services(self):
        """8. Servisleri kontrol et"""
        try:
            print(f"\n{Fore.CYAN}Çalışan Servisler:{Style.RESET_ALL}")
            self.run_command("systemctl list-units --type=service --state=running")
            print(f"\n{Fore.CYAN}Başarısız Servisler:{Style.RESET_ALL}")
            self.run_command("systemctl --failed")
        except Exception as e:
            print(f"{Fore.RED}Servis kontrolünde hata: {str(e)}{Style.RESET_ALL}")

    def check_logs(self):
        """9. Sistem loglarını görüntüle"""
        try:
            print(f"\n{Fore.CYAN}Son Sistem Logları:{Style.RESET_ALL}")
            self.run_command("journalctl -n 50 --no-pager")
            print(f"\n{Fore.CYAN}Hata Logları:{Style.RESET_ALL}")
            self.run_command("journalctl -p err..alert -n 20 --no-pager")
        except Exception as e:
            print(f"{Fore.RED}Log kontrolünde hata: {str(e)}{Style.RESET_ALL}")

    def check_updates(self):
        """10. Sistem güncellemelerini kontrol et"""
        try:
            print(f"\n{Fore.CYAN}Paket Listesi Güncelleniyor...{Style.RESET_ALL}")
            self.run_command("apt update", sudo=True)
            print(f"\n{Fore.CYAN}Yüklenebilir Güncellemeler:{Style.RESET_ALL}")
            self.run_command("apt list --upgradable", sudo=True)
        except Exception as e:
            print(f"{Fore.RED}Güncelleme kontrolünde hata: {str(e)}{Style.RESET_ALL}")

    # Güvenlik Tarama Fonksiyonları (11-20)
    def vulnerability_scan(self):
        """11. Zafiyet taraması"""
        if self.check_tool("openvas"):
            print(f"\n{Fore.CYAN}Zafiyet Tarama Seçenekleri:{Style.RESET_ALL}")
            print("1. Hızlı Tarama")
            print("2. Kapsamlı Tarama")
            print("3. Özel Tarama")
            print("4. Sürekli İzleme")

            scan_type = input("\nTarama türünü seçin (1-4): ")
            target = input("Hedef IP/Domain: ")

            # Tarama çıktısı için dizin oluştur
            output_dir = (
                f"vulnerability_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            os.makedirs(output_dir, exist_ok=True)

            # Tarama seçenekleri
            scan_options = {
                "1": "--scan-config fast_scan",
                "2": "--scan-config full_and_deep",
                "3": "--scan-config custom",
                "4": "--scan-config continuous",
            }

            # Özel tarama seçenekleri
            if scan_type == "3":
                print("\nÖzel Tarama Seçenekleri:")
                port_range = input("Port aralığı (örn: 1-1000): ")
                intensity = input("Tarama yoğunluğu (1-5): ")
                timeout = input("Zaman aşımı (dakika): ")
                custom_options = (
                    f"--ports {port_range} --intensity {intensity} --timeout {timeout}"
                )
            else:
                custom_options = ""

            # E-posta bildirimi
            email_notification = input(
                "\nTarama sonuçları e-posta ile gönderilsin mi? (e/h): "
            ).lower()
            if email_notification == "e":
                email = input("E-posta adresi: ")
                notification_cmd = f"--notify-email {email}"
            else:
                notification_cmd = ""

            # Zamanlanmış tarama
            scheduled_scan = input(
                "\nTarama zamanlanmış olarak çalışsın mı? (e/h): "
            ).lower()
            if scheduled_scan == "e":
                schedule_time = input("Tarama zamanı (Format: YYYY-MM-DD HH:MM): ")
                schedule_cmd = f"--schedule '{schedule_time}'"
            else:
                schedule_cmd = ""

            # HTML rapor oluşturma
            html_report = input("\nHTML rapor oluşturulsun mu? (e/h): ").lower()
            report_format = "--format html" if html_report == "e" else "--format txt"

            # Komut oluşturma
            base_cmd = f"openvas-start && omp -u admin -w admin"
            scan_cmd = f"{scan_options.get(scan_type, '--scan-config fast_scan')}"
            target_cmd = f"-T {target}"
            output_cmd = f"--output-file {output_dir}/scan_report"

            full_cmd = f"{base_cmd} {scan_cmd} {target_cmd} {custom_options} {notification_cmd} {schedule_cmd} {report_format} {output_cmd}"

            print(f"\n{Fore.YELLOW}Tarama başlatılıyor...{Style.RESET_ALL}")
            result = self.run_command(full_cmd, sudo=True)

            if result:
                print(
                    f"\n{Fore.GREEN}Tarama tamamlandı. Sonuçlar {output_dir} dizinine kaydedildi.{Style.RESET_ALL}"
                )

                # Sonuçları görüntüleme
                if input("\nSonuçlar görüntülensin mi? (e/h): ").lower() == "e":
                    self.run_command(f"cat {output_dir}/scan_report")

            return result

    def malware_scan(self):
        """12. Zararlı yazılım taraması"""
        if self.check_tool("clamav"):
            print(f"\n{Fore.CYAN}Zararlı Yazılım Tarama Seçenekleri:{Style.RESET_ALL}")
            print("1. Hızlı Tarama")
            print("2. Kapsamlı Tarama")
            print("3. Belirli Dizin Tarama")
            print("4. Sürekli İzleme")

            scan_type = input("\nTarama türünü seçin (1-4): ")

            # Tarama çıktısı için dizin oluştur
            output_dir = f"malware_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(output_dir, exist_ok=True)

            # Tarama seçenekleri
            scan_options = {
                "1": "-r --remove --max-filesize=4000M --max-scansize=4000M /home",
                "2": "-r --remove --detect-pua --scan-mail --max-filesize=4000M --max-scansize=4000M /",
                "3": "-r --remove",
                "4": "-r --remove --follow-dir-symlinks=2 --follow-file-symlinks=2",
            }

            # Özel dizin tarama
            if scan_type == "3":
                path = input("Taranacak dizin: ")
                command = f"clamscan {scan_options[scan_type]} {path}"
            else:
                command = f"clamscan {scan_options.get(scan_type, scan_options['1'])}"

            # Ek seçenekler
            exclude_dir = input(
                "\nHariç tutulacak dizinler (virgülle ayırın) [Enter=Yok]: "
            )
            if exclude_dir:
                for dir in exclude_dir.split(","):
                    command += f" --exclude-dir='{dir.strip()}'"

            # Rapor seçenekleri
            command += f" --log={output_dir}/scan_log.txt"

            # Tarama limitleri
            print("\nTarama Limitleri:")
            max_file_size = input("Maksimum dosya boyutu (MB) [Enter=4000]: ") or "4000"
            max_scan_size = (
                input("Maksimum tarama boyutu (MB) [Enter=4000]: ") or "4000"
            )
            command += (
                f" --max-filesize={max_file_size}M --max-scansize={max_scan_size}M"
            )

            # Otomatik temizleme
            if (
                input(
                    "\nBulunan zararlı yazılımlar otomatik temizlensin mi? (e/h): "
                ).lower()
                == "e"
            ):
                command += " --remove"

            # E-posta bildirimi
            email_notification = input(
                "\nTarama sonuçları e-posta ile gönderilsin mi? (e/h): "
            ).lower()
            if email_notification == "e":
                email = input("E-posta adresi: ")
                self.run_command(
                    f"echo 'Tarama sonuçları ektedir.' | mail -s 'Zararlı Yazılım Tarama Raporu' -a {output_dir}/scan_log.txt {email}"
                )

            print(f"\n{Fore.YELLOW}Tarama başlatılıyor...{Style.RESET_ALL}")
            result = self.run_command(command, sudo=True)

            if result:
                print(
                    f"\n{Fore.GREEN}Tarama tamamlandı. Sonuçlar {output_dir} dizinine kaydedildi.{Style.RESET_ALL}"
                )

                # İstatistikleri göster
                with open(f"{output_dir}/scan_log.txt", "r") as f:
                    log_content = f.read()
                    print(f"\n{Fore.CYAN}Tarama İstatistikleri:{Style.RESET_ALL}")
                    print(log_content)

            return result

    def rootkit_scan(self):
        """13. Rootkit taraması"""
        if self.check_tool("rkhunter"):
            print(f"\n{Fore.CYAN}Rootkit Tarama Seçenekleri:{Style.RESET_ALL}")
            print("1. Hızlı Tarama")
            print("2. Kapsamlı Tarama")
            print("3. Özel Tarama")
            print("4. Sistem Dosyaları Kontrolü")

            scan_type = input("\nTarama türünü seçin (1-4): ")

            # Tarama çıktısı için dizin oluştur
            output_dir = f"rootkit_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(output_dir, exist_ok=True)

            # Tarama seçenekleri
            scan_options = {
                "1": "--check --skip-keypress",
                "2": "--check --thorough --skip-keypress",
                "3": "--check --skip-keypress --enable additional-tests",
                "4": "--propupd",
            }

            # Özel tarama seçenekleri
            if scan_type == "3":
                print("\nÖzel Tarama Seçenekleri:")
                check_network = (
                    input("Ağ arayüzlerini kontrol et (e/h): ").lower() == "e"
                )
                check_ports = input("Açık portları kontrol et (e/h): ").lower() == "e"
                check_rootkits = (
                    input("Bilinen rootkitleri kontrol et (e/h): ").lower() == "e"
                )
                check_files = (
                    input("Şüpheli dosyaları kontrol et (e/h): ").lower() == "e"
                )

                custom_options = ""
                if check_network:
                    custom_options += " --check-network"
                if check_ports:
                    custom_options += " --check-ports"
                if check_rootkits:
                    custom_options += " --check-rootkits"
                if check_files:
                    custom_options += " --check-files"
            else:
                custom_options = ""

            # Günlük dosyası oluşturma
            log_file = f"{output_dir}/rkhunter_log.txt"
            command = f"rkhunter {scan_options.get(scan_type, '--check')} {custom_options} --logfile {log_file}"

            # Otomatik güncelleme
            if input("\nRootkit veritabanı güncellensin mi? (e/h): ").lower() == "e":
                print(f"\n{Fore.YELLOW}Veritabanı güncelleniyor...{Style.RESET_ALL}")
                self.run_command("rkhunter --update", sudo=True)

            print(f"\n{Fore.YELLOW}Tarama başlatılıyor...{Style.RESET_ALL}")
            result = self.run_command(command, sudo=True)

            if result:
                print(
                    f"\n{Fore.GREEN}Tarama tamamlandı. Sonuçlar {log_file} dosyasına kaydedildi.{Style.RESET_ALL}"
                )

                # Sonuçları görüntüleme
                if input("\nSonuçlar görüntülensin mi? (e/h): ").lower() == "e":
                    with open(log_file, "r") as f:
                        log_content = f.read()
                        print(f"\n{Fore.CYAN}Tarama Sonuçları:{Style.RESET_ALL}")
                        print(log_content)

                # Özet rapor oluşturma
                summary_file = f"{output_dir}/summary.txt"
                self.run_command(f"rkhunter --summary > {summary_file}", sudo=True)

                # E-posta bildirimi
                if (
                    input("\nSonuçlar e-posta ile gönderilsin mi? (e/h): ").lower()
                    == "e"
                ):
                    email = input("E-posta adresi: ")
                    self.run_command(
                        f"echo 'Rootkit tarama sonuçları ektedir.' | mail -s 'Rootkit Tarama Raporu' -a {log_file} {email}"
                    )

            return result

    def port_scan(self):
        """14. Port taraması"""
        if self.check_tool("nmap"):
            target = input("Hedef IP: ")

            # Tarama türü seçimi
            print(f"\n{Fore.CYAN}Tarama Türleri:{Style.RESET_ALL}")
            print("1. Hızlı TCP SYN taraması (-sS)")
            print("2. TCP Connect taraması (-sT)")
            print("3. UDP taraması (-sU)")
            print("4. Kapsamlı tarama (-sS -sV -sC)")
            print("5. Gizli tarama (-sS -T2)")

            scan_type = input("Tarama türünü seçin (1-5): ")
            scan_options = {
                "1": "-sS -sV",
                "2": "-sT -sV",
                "3": "-sU",
                "4": "-sS -sV -sC",
                "5": "-sS -T2",
            }

            # Port aralığı
            port_range = input("Port aralığı (örn: 1-1000) [Enter=Tümü]: ") or "1-65535"

            # Çıktı dosyası
            save_output = input(
                "Sonuçları dosyaya kaydetmek ister misiniz? (e/h): "
            ).lower()
            output_file = (
                f"nmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                if save_output == "e"
                else None
            )

            # Komut oluşturma
            command = f"nmap {scan_options.get(scan_type, '-sS -sV')} -p{port_range}"

            # Ek seçenekler
            if input("Servis sürüm tespiti eklensin mi? (e/h): ").lower() == "e":
                command += " -sV"
            if input("İşletim sistemi tespiti eklensin mi? (e/h): ").lower() == "e":
                command += " -O"

            # Hedef ve çıktı dosyası ekleme
            command += f" {target}"
            if output_file:
                command += f" -oN {output_file}"

            print(f"\n{Fore.YELLOW}Tarama başlatılıyor...{Style.RESET_ALL}")
            result = self.run_command(command, sudo=True)

            if result and output_file:
                print(
                    f"\n{Fore.GREEN}Sonuçlar {output_file} dosyasına kaydedildi.{Style.RESET_ALL}"
                )

            return result

    def web_scan(self):
        """15. Web uygulama taraması"""
        if self.check_tool("nikto"):
            print(f"\n{Fore.CYAN}Web Uygulama Tarama Seçenekleri:{Style.RESET_ALL}")
            print("1. Hızlı Tarama")
            print("2. Kapsamlı Tarama")
            print("3. SSL/TLS Taraması")
            print("4. XSS Taraması")
            print("5. SQL Injection Taraması")
            print("6. Özel Tarama")

            # Tarama çıktısı için dizin oluştur
            output_dir = f"web_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(output_dir, exist_ok=True)

            target = input("\nHedef URL: ")
            scan_type = input("Tarama türünü seçin (1-6): ")

            # Temel tarama seçenekleri
            scan_options = {
                "1": "-h",
                "2": "-h -Tuning x",
                "3": "-h -ssl",
                "4": "-h -Tuning 4",
                "5": "-h -Tuning 9",
                "6": "-h",
            }

            # Özel tarama seçenekleri
            if scan_type == "6":
                print("\nÖzel Tarama Seçenekleri:")
                port = input("Port numarası [80]: ") or "80"
                timeout = input("Zaman aşımı (saniye) [30]: ") or "30"
                intensity = input("Tarama yoğunluğu (1-5) [3]: ") or "3"
                dbcheck = (
                    input("Veritabanı kontrolü yapılsın mı? (e/h): ").lower() == "e"
                )

                custom_options = f"-p {port} -Pause {timeout} -T {intensity}"
                if dbcheck:
                    custom_options += " -dbcheck"
            else:
                custom_options = ""

            # Raporlama seçenekleri
            print("\nRaporlama Seçenekleri:")
            formats = []
            if input("HTML rapor oluşturulsun mu? (e/h): ").lower() == "e":
                formats.append("html")
            if input("XML rapor oluşturulsun mu? (e/h): ").lower() == "e":
                formats.append("xml")
            if input("CSV rapor oluşturulsun mu? (e/h): ").lower() == "e":
                formats.append("csv")

            # Proxy seçenekleri
            use_proxy = input("\nProxy kullanılsın mı? (e/h): ").lower() == "e"
            if use_proxy:
                proxy = input("Proxy adresi (örn: http://proxy:8080): ")
                proxy_cmd = f"-useproxy {proxy}"
            else:
                proxy_cmd = ""

            # Kimlik doğrulama
            use_auth = input("\nKimlik doğrulama gerekli mi? (e/h): ").lower() == "e"
            if use_auth:
                auth_user = input("Kullanıcı adı: ")
                auth_pass = input("Parola: ")
                auth_cmd = f"-id {auth_user}:{auth_pass}"
            else:
                auth_cmd = ""

            # Tarama komutunu oluştur
            base_cmd = f"nikto {scan_options.get(scan_type, '-h')} {custom_options}"
            format_cmd = " ".join([f"-Format {fmt}" for fmt in formats])
            output_cmd = " ".join(
                [f"-output {output_dir}/scan_report.{fmt}" for fmt in formats]
            )

            full_cmd = f"{base_cmd} {format_cmd} {output_cmd} {proxy_cmd} {auth_cmd} -h {target}"

            # Taramayı başlat
            print(f"\n{Fore.YELLOW}Tarama başlatılıyor...{Style.RESET_ALL}")
            result = self.run_command(full_cmd, sudo=True)

            if result:
                print(
                    f"\n{Fore.GREEN}Tarama tamamlandı. Sonuçlar {output_dir} dizinine kaydedildi.{Style.RESET_ALL}"
                )

                # E-posta bildirimi
                if (
                    input("\nSonuçlar e-posta ile gönderilsin mi? (e/h): ").lower()
                    == "e"
                ):
                    email = input("E-posta adresi: ")
                    for fmt in formats:
                        report_file = f"{output_dir}/scan_report.{fmt}"
                        if os.path.exists(report_file):
                            self.run_command(
                                f"echo 'Web tarama sonuçları ektedir.' | mail -s 'Web Tarama Raporu' -a {report_file} {email}"
                            )

                # Sonuçları görüntüleme
                if input("\nSonuçlar görüntülensin mi? (e/h): ").lower() == "e":
                    for fmt in formats:
                        report_file = f"{output_dir}/scan_report.{fmt}"
                        if os.path.exists(report_file):
                            with open(report_file, "r") as f:
                                print(
                                    f"\n{Fore.CYAN}=== {fmt.upper()} Raporu ==={Style.RESET_ALL}"
                                )
                                print(f.read())

            return result

    # Ağ Güvenliği Fonksiyonları (16-25)
    def ssl_scan(self):
        """16. SSL/TLS Analizi"""
        if self.check_tool("sslscan"):
            print(f"\n{Fore.CYAN}SSL/TLS Analiz Seçenekleri:{Style.RESET_ALL}")
            print("1. Temel SSL Tarama")
            print("2. Detaylı Sertifika Analizi")
            print("3. Güvenlik Açığı Taraması")
            print("4. Protokol Testi")

            choice = input("\nSeçiminiz (1-4): ")
            target = input("Hedef domain: ")

            commands = {
                "1": f"sslscan {target}",
                "2": f"sslscan --show-certificate {target}",
                "3": f"sslscan --no-fallback --no-renegotiation {target}",
                "4": f"sslscan --ssl2 --ssl3 --tlsall {target}",
            }

            if choice in commands:
                self.run_command(commands[choice])

            # Sonuçları kaydet
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ssl_scan_{timestamp}.txt"
            self.run_command(f"sslscan {target} > {output_file}")
            print(
                f"\n{Fore.GREEN}Sonuçlar {output_file} dosyasına kaydedildi.{Style.RESET_ALL}"
            )

    def wifi_scan(self):
        """17. Kablosuz Ağ Taraması"""
        if self.check_tool("aircrack-ng"):
            print(f"\n{Fore.CYAN}Kablosuz Ağ Tarama Seçenekleri:{Style.RESET_ALL}")
            print("1. Ağ Keşfi")
            print("2. WEP/WPA Handshake Yakalama")
            print("3. Deauth Saldırısı Tespiti")
            print("4. Hidden SSID Tespiti")

            choice = input("\nSeçiminiz (1-4): ")
            interface = input("Kablosuz arayüz: ")

            if choice == "1":
                self.run_command(f"airodump-ng {interface}", sudo=True)
            elif choice == "2":
                bssid = input("Hedef BSSID: ")
                channel = input("Kanal: ")
                self.run_command(
                    f"airodump-ng -c {channel} --bssid {bssid} -w capture {interface}",
                    sudo=True,
                )
            elif choice == "3":
                self.run_command(f"airodump-ng -c 1 --showack {interface}", sudo=True)
            elif choice == "4":
                self.run_command(
                    f"airodump-ng --manufacturer --uptime {interface}", sudo=True
                )

    def packet_capture(self):
        """18. Paket Yakalama"""
        if self.check_tool("tcpdump"):
            print(f"\n{Fore.CYAN}Paket Yakalama Seçenekleri:{Style.RESET_ALL}")
            print("1. Temel Paket Yakalama")
            print("2. HTTP Trafiği İzleme")
            print("3. DNS Trafiği İzleme")
            print("4. Belirli IP İzleme")

            choice = input("\nSeçiminiz (1-4): ")
            interface = input("Ağ arayüzü: ")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            filters = {
                "1": f"-i {interface} -w capture_{timestamp}.pcap",
                "2": f"-i {interface} -w http_{timestamp}.pcap port 80 or port 443",
                "3": f"-i {interface} -w dns_{timestamp}.pcap port 53",
                "4": f"-i {interface} -w ip_{timestamp}.pcap host {input('Hedef IP: ')}",
            }

            if choice in filters:
                self.run_command(f"tcpdump {filters[choice]}", sudo=True)

            # Wireshark ile analiz seçeneği
            if input("\nWireshark ile analiz edilsin mi? (e/h): ").lower() == "e":
                self.run_command(f"wireshark capture_{timestamp}.pcap")

    def arp_scan(self):
        """19. ARP Taraması"""
        if self.check_tool("arp-scan"):
            print(f"\n{Fore.CYAN}ARP Tarama Seçenekleri:{Style.RESET_ALL}")
            print("1. Yerel Ağ Taraması")
            print("2. Belirli IP Aralığı Taraması")
            print("3. MAC Adresi Filtreleme")
            print("4. Üretici Filtreleme")

            choice = input("\nSeçiminiz (1-4): ")
            output_file = f"arp_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

            if choice == "1":
                self.run_command(
                    f"arp-scan --localnet --output={output_file}", sudo=True
                )
            elif choice == "2":
                ip_range = input("IP aralığı (örn: 192.168.1.0/24): ")
                self.run_command(
                    f"arp-scan {ip_range} --output={output_file}", sudo=True
                )
            elif choice == "3":
                mac = input("MAC adresi: ")
                self.run_command(
                    f"arp-scan --localnet --macfile={mac} --output={output_file}",
                    sudo=True,
                )
            elif choice == "4":
                vendor = input("Üretici adı: ")
                self.run_command(
                    f"arp-scan --localnet | grep -i {vendor} > {output_file}", sudo=True
                )

    def dns_enum(self):
        """20. DNS Bilgi Toplama"""
        if self.check_tool("dnsenum"):
            print(f"\n{Fore.CYAN}DNS Bilgi Toplama Seçenekleri:{Style.RESET_ALL}")
            print("1. Temel DNS Taraması")
            print("2. Alt Alan Adı Keşfi")
            print("3. Zone Transfer Testi")
            print("4. Google Araması")

            choice = input("\nSeçiminiz (1-4): ")
            domain = input("Hedef domain: ")
            output_file = f"dns_enum_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"

            commands = {
                "1": f"dnsenum --noreverse -o {output_file} {domain}",
                "2": f"dnsenum --dnsserver 8.8.8.8 -f /usr/share/wordlists/dnsenum.txt -o {output_file} {domain}",
                "3": f"dnsenum --threads 10 -t -o {output_file} {domain}",
                "4": f"dnsenum --google -o {output_file} {domain}",
            }

            if choice in commands:
                self.run_command(commands[choice])

            # Sonuçları analiz et
            if os.path.exists(output_file):
                print(
                    f"\n{Fore.GREEN}Analiz sonuçları {output_file} dosyasına kaydedildi.{Style.RESET_ALL}"
                )

    def mitm_detection(self):
        """21. MITM Saldırı Tespiti"""
        print(f"\n{Fore.CYAN}MITM Saldırı Tespit Seçenekleri:{Style.RESET_ALL}")
        print("1. ARP İzleme (arpwatch)")
        print("2. SSL/TLS Sertifika Kontrolü")
        print("3. DNS Spoofing Tespiti")
        print("4. Paket Analizi")
        print("5. ARP Tablosu Kontrolü")

        choice = input("\nSeçiminiz (1-5): ")
        output_dir = f"mitm_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            if self.check_tool("arpwatch"):
                interface = input("Ağ arayüzü [eth0]: ") or "eth0"
                duration = input("İzleme süresi (dakika) [60]: ") or "60"
                log_file = f"{output_dir}/arpwatch.log"

                print(f"\n{Fore.YELLOW}ARP izleme başlatılıyor...{Style.RESET_ALL}")
                self.run_command(f"arpwatch -i {interface} -f {log_file}", sudo=True)
                time.sleep(int(duration) * 60)

                # ARP değişikliklerini analiz et
                self.run_command(f"cat {log_file} | grep 'changed'")

        elif choice == "2":
            if self.check_tool("sslscan"):
                target = input("Hedef domain/IP: ")
                output_file = f"{output_dir}/ssl_scan.txt"

                print(
                    f"\n{Fore.YELLOW}SSL/TLS sertifikaları kontrol ediliyor...{Style.RESET_ALL}"
                )
                self.run_command(
                    f"sslscan --show-certificate --no-colour {target} > {output_file}"
                )

                # Şüpheli sertifikaları kontrol et
                self.run_command(
                    f"cat {output_file} | grep -i 'invalid\\|expired\\|self-signed'"
                )

        elif choice == "3":
            if self.check_tool("dnstracer"):
                domain = input("Kontrol edilecek domain: ")
                output_file = f"{output_dir}/dns_trace.txt"

                print(
                    f"\n{Fore.YELLOW}DNS yönlendirmeleri kontrol ediliyor...{Style.RESET_ALL}"
                )
                self.run_command(f"dnstracer -v -o {output_file} {domain}")

                # DNS yanıtlarını analiz et
                self.run_command(f"cat {output_file} | grep 'ANSWER'")

        elif choice == "4":
            if self.check_tool("tcpdump"):
                interface = input("Ağ arayüzü [eth0]: ") or "eth0"
                duration = input("Yakalama süresi (saniye) [30]: ") or "30"
                output_file = f"{output_dir}/packet_capture.pcap"

                print(f"\n{Fore.YELLOW}Paket yakalama başlatılıyor...{Style.RESET_ALL}")
                self.run_command(
                    f"tcpdump -i {interface} -w {output_file} -v 'arp or (tcp and port 443)' -G {duration} -W 1",
                    sudo=True,
                )

                # Yakalanan paketleri analiz et
                if self.check_tool("wireshark-cli"):
                    self.run_command(
                        f"tshark -r {output_file} -Y 'arp.duplicate-address-detected or ssl.alert.desc == 51'"
                    )

        elif choice == "5":
            print(f"\n{Fore.YELLOW}ARP tablosu kontrol ediliyor...{Style.RESET_ALL}")
            # Mevcut ARP tablosunu kaydet
            self.run_command(f"arp -a > {output_dir}/arp_table.txt")

            # Şüpheli ARP girişlerini kontrol et
            print(f"\n{Fore.CYAN}Şüpheli ARP Girişleri:{Style.RESET_ALL}")
            self.run_command("arp -a | grep -i '(incomplete)'")

            # MAC adresi çakışmalarını kontrol et
            print(f"\n{Fore.CYAN}MAC Adresi Çakışmaları:{Style.RESET_ALL}")
            self.run_command("arp -a | cut -d' ' -f4 | sort | uniq -d")

        # Sonuçları raporla
        print(
            f"\n{Fore.GREEN}Tespit sonuçları {output_dir} dizinine kaydedildi.{Style.RESET_ALL}"
        )

        # E-posta bildirimi
        if input("\nSonuçlar e-posta ile gönderilsin mi? (e/h): ").lower() == "e":
            email = input("E-posta adresi: ")
            self.run_command(
                f"tar -czf {output_dir}.tar.gz {output_dir} && echo 'MITM tespit sonuçları ekte.' | mail -s 'MITM Tespit Raporu' -a {output_dir}.tar.gz {email}"
            )

        # Özet rapor
        with open(f"{output_dir}/summary.txt", "w") as f:
            f.write("=== MITM Tespit Özeti ===\n")
            f.write(f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Seçilen Kontrol: {choice}\n")
            f.write("Kontrol Sonuçları:\n")
            # Tespit edilen tehditleri ekle
            if os.path.exists(f"{output_dir}/arp_table.txt"):
                f.write("- ARP tablosu analizi tamamlandı\n")
            if os.path.exists(f"{output_dir}/ssl_scan.txt"):
                f.write("- SSL/TLS kontrolleri tamamlandı\n")
            if os.path.exists(f"{output_dir}/dns_trace.txt"):
                f.write("- DNS kontrolleri tamamlandı\n")
            if os.path.exists(f"{output_dir}/packet_capture.pcap"):
                f.write("- Paket analizi tamamlandı\n")

    def firewall_check(self):
        """22. Güvenlik Duvarı Kontrolü"""
        print(f"\n{Fore.CYAN}Güvenlik Duvarı Kontrol Seçenekleri:{Style.RESET_ALL}")
        print("1. UFW Durum Kontrolü")
        print("2. Aktif Kurallar")
        print("3. Uygulama Profilleri")
        print("4. Güvenlik Duvarı Logları")
        print("5. Güvenlik Duvarı Yapılandırma Kontrolü")

        choice = input("\nSeçiminiz (1-5): ")
        output_dir = f"firewall_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            print(f"\n{Fore.YELLOW}UFW Durum Kontrolü:{Style.RESET_ALL}")
            self.run_command("ufw status verbose", sudo=True)
            self.run_command("ufw status numbered", sudo=True)

            # Servis durumunu kontrol et
            self.run_command("systemctl status ufw", sudo=True)

        elif choice == "2":
            print(f"\n{Fore.YELLOW}Aktif Güvenlik Duvarı Kuralları:{Style.RESET_ALL}")
            # UFW kuralları
            self.run_command(f"ufw show raw > {output_dir}/ufw_rules.txt", sudo=True)

            # IPTables kuralları
            self.run_command(
                f"iptables -L -n -v --line-numbers > {output_dir}/iptables_rules.txt",
                sudo=True,
            )

            # Açık portları kontrol et
            self.run_command(f"netstat -tulpn > {output_dir}/open_ports.txt", sudo=True)

            print(
                f"\n{Fore.GREEN}Sonuçlar {output_dir} dizinine kaydedildi.{Style.RESET_ALL}"
            )

        elif choice == "3":
            print(f"\n{Fore.YELLOW}Uygulama Profilleri:{Style.RESET_ALL}")
            # Mevcut profilleri listele
            self.run_command("ufw app list", sudo=True)

            # Detaylı profil bilgisi
            app = input("\nDetaylı bilgi için uygulama adı (veya Enter ile geç): ")
            if app:
                self.run_command(f"ufw app info {app}", sudo=True)

        elif choice == "4":
            print(f"\n{Fore.YELLOW}Güvenlik Duvarı Logları:{Style.RESET_ALL}")
            # Son logları görüntüle
            self.run_command(
                f"grep UFW /var/log/kern.log | tail -n 50 > {output_dir}/ufw_recent_logs.txt",
                sudo=True,
            )

            # Reddedilen paketleri analiz et
            self.run_command(
                f"grep 'UFW BLOCK' /var/log/kern.log | awk '{{print $12}}' | sort | uniq -c | sort -nr > {output_dir}/blocked_ips.txt",
                sudo=True,
            )

            print(
                f"\n{Fore.GREEN}Log analizi {output_dir} dizinine kaydedildi.{Style.RESET_ALL}"
            )

        elif choice == "5":
            print(
                f"\n{Fore.YELLOW}Güvenlik Duvarı Yapılandırma Kontrolü:{Style.RESET_ALL}"
            )
            # Yapılandırma dosyalarını kontrol et
            config_files = [
                "/etc/default/ufw",
                "/etc/ufw/before.rules",
                "/etc/ufw/after.rules",
                "/etc/ufw/user.rules",
            ]

            for config in config_files:
                if os.path.exists(config):
                    print(f"\nKontrol ediliyor: {config}")
                    self.run_command(
                        f"cat {config} > {output_dir}/$(basename {config})", sudo=True
                    )

            # Güvenlik önerilerini kontrol et
            recommendations = []

            # Default policy kontrolü
            default_policy = self.run_command(
                "ufw status verbose | grep Default:", sudo=True
            )
            if "deny" not in str(default_policy).lower():
                recommendations.append("- Varsayılan 'deny' politikası önerilir")

            # IPv6 kontrolü
            ipv6_status = self.run_command("grep IPV6 /etc/default/ufw", sudo=True)
            if "IPV6=yes" not in str(ipv6_status):
                recommendations.append("- IPv6 desteği etkin değil")

            # Önerileri kaydet
            if recommendations:
                with open(f"{output_dir}/security_recommendations.txt", "w") as f:
                    f.write("Güvenlik Duvarı Önerileri:\n")
                    f.write("\n".join(recommendations))
                print(
                    f"\n{Fore.YELLOW}Güvenlik önerileri {output_dir}/security_recommendations.txt dosyasına kaydedildi.{Style.RESET_ALL}"
                )

        # Sonuç raporu oluştur
        print(f"\n{Fore.CYAN}Güvenlik Duvarı Kontrol Özeti:{Style.RESET_ALL}")
        print(f"- Kontrol tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"- Kontrol türü: {choice}")
        print(f"- Sonuçlar: {output_dir} dizininde")

        # E-posta bildirimi
        if input("\nSonuçlar e-posta ile gönderilsin mi? (e/h): ").lower() == "e":
            email = input("E-posta adresi: ")
            self.run_command(
                f"tar -czf {output_dir}.tar.gz {output_dir} && echo 'Güvenlik duvarı kontrol sonuçları ekte.' | mail -s 'Güvenlik Duvarı Kontrol Raporu' -a {output_dir}.tar.gz {email}"
            )

    def network_monitor(self):
        """23. Ağ İzleme"""
        print(f"\n{Fore.CYAN}Ağ İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Süreç Bazlı Ağ Kullanımı")
        print("2. Gerçek Zamanlı Trafik Analizi")
        print("3. Ağ İstatistikleri")
        print("4. Paket İzleme")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"network_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("nethogs"):
            interface = input("Ağ arayüzü [eth0]: ") or "eth0"
            duration = input("İzleme süresi (saniye) [60]: ") or "60"
            output_file = f"{output_dir}/process_traffic.log"

            print(
                f"\n{Fore.YELLOW}Süreç bazlı ağ kullanımı izleniyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"nethogs -t {duration} {interface} > {output_file}", sudo=True
            )

            # İstatistikleri göster
            print(f"\n{Fore.CYAN}En Çok Trafik Kullanan Süreçler:{Style.RESET_ALL}")
            self.run_command(f"sort -nrk 2 {output_file} | head -n 10")

        elif choice == "2" and self.check_tool("iftop"):
            interface = input("Ağ arayüzü [eth0]: ") or "eth0"
            filters = input("Trafik filtresi (örn: port 80) [tümü]: ")
            cmd = f"iftop -i {interface} -P"
            if filters:
                cmd += f" -f '{filters}'"
            self.run_command(cmd, sudo=True)

        elif choice == "3":
            print(f"\n{Fore.YELLOW}Ağ istatistikleri toplanıyor...{Style.RESET_ALL}")
            stats_file = f"{output_dir}/network_stats.txt"

            with open(stats_file, "w") as f:
                f.write("=== Ağ İstatistikleri ===\n\n")

                # TCP bağlantı istatistikleri
                f.write("TCP Bağlantıları:\n")
                self.run_command("netstat -st >> " + stats_file)

                # UDP istatistikleri
                f.write("\nUDP İstatistikleri:\n")
                self.run_command("netstat -su >> " + stats_file)

                # ICMP istatistikleri
                f.write("\nICMP İstatistikleri:\n")
                self.run_command("netstat -s --icmp >> " + stats_file)

            print(
                f"\n{Fore.GREEN}İstatistikler {stats_file} dosyasına kaydedildi.{Style.RESET_ALL}"
            )

        elif choice == "4" and self.check_tool("tcpdump"):
            interface = input("Ağ arayüzü [eth0]: ") or "eth0"
            capture_file = f"{output_dir}/packet_capture.pcap"

            print("\nPaket Yakalama Seçenekleri:")
            print("1. HTTP/HTTPS Trafiği")
            print("2. DNS Sorguları")
            print("3. TCP Bağlantıları")
            print("4. Özel Filtre")

            filter_choice = input("Seçiminiz (1-4): ")
            filters = {
                "1": "port 80 or port 443",
                "2": "port 53",
                "3": "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0",
                "4": input("Filtreyi girin: "),
            }

            filter_str = filters.get(filter_choice, "")
            command = f"tcpdump -i {interface} -w {capture_file} {filter_str}"

            print(
                f"\n{Fore.YELLOW}Paketler yakalanıyor... (Ctrl+C ile durdurun){Style.RESET_ALL}"
            )
            self.run_command(command, sudo=True)

    def bandwidth_monitor(self):
        """24. Bant Genişliği İzleme"""
        print(f"\n{Fore.CYAN}Bant Genişliği İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Gerçek Zamanlı Bant Genişliği Kullanımı")
        print("2. Arayüz Bazlı İstatistikler")
        print("3. Bağlantı Hızı Testi")
        print("4. Uzun Süreli İzleme")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"bandwidth_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("iftop"):
            interface = input("Ağ arayüzü [eth0]: ") or "eth0"
            options = []

            if input("Port numaralarını göster? (e/h): ").lower() == "e":
                options.append("-P")
            if input("DNS çözümlemesi yapılsın mı? (e/h): ").lower() == "h":
                options.append("-n")
            if input("Toplam bant genişliği gösterilsin mi? (e/h): ").lower() == "e":
                options.append("-B")

            cmd = f"iftop -i {interface} {' '.join(options)}"
            self.run_command(cmd, sudo=True)

        elif choice == "2":
            interface = input("Ağ arayüzü [eth0]: ") or "eth0"
            duration = input("İzleme süresi (saniye) [300]: ") or "300"
            stats_file = f"{output_dir}/interface_stats.log"

            print(
                f"\n{Fore.YELLOW}Arayüz istatistikleri toplanıyor...{Style.RESET_ALL}"
            )
            self.run_command(f"sar -n DEV {duration} 1 > {stats_file}")

            print(
                f"\n{Fore.GREEN}İstatistikler {stats_file} dosyasına kaydedildi.{Style.RESET_ALL}"
            )

        elif choice == "3" and self.check_tool("speedtest-cli"):
            print(f"\n{Fore.YELLOW}Bağlantı hızı testi yapılıyor...{Style.RESET_ALL}")
            result_file = f"{output_dir}/speedtest_result.json"
            self.run_command(f"speedtest-cli --json > {result_file}")

            # Sonuçları göster
            if os.path.exists(result_file):
                with open(result_file, "r") as f:
                    data = json.loads(f.read())
                    print(f"\n{Fore.CYAN}Test Sonuçları:{Style.RESET_ALL}")
                    print(f"İndirme Hızı: {data['download'] / 1_000_000:.2f} Mbps")
                    print(f"Yükleme Hızı: {data['upload'] / 1_000_000:.2f} Mbps")
                    print(f"Ping: {data['ping']:.2f} ms")

        elif choice == "4":
            interface = input("Ağ arayüzü [eth0]: ") or "eth0"
            duration = input("İzleme süresi (saat) [24]: ") or "24"
            interval = input("Örnekleme aralığı (dakika) [5]: ") or "5"

            log_file = f"{output_dir}/bandwidth_log.csv"
            print(f"\n{Fore.YELLOW}Uzun süreli izleme başlatılıyor...{Style.RESET_ALL}")

            # CSV başlığını oluştur
            with open(log_file, "w") as f:
                f.write("timestamp,rx_bytes,tx_bytes\n")

            # İzleme döngüsü
            end_time = time.time() + (float(duration) * 3600)
            while time.time() < end_time:
                rx_result = self.run_command(
                    f"cat /sys/class/net/{interface}/statistics/rx_bytes"
                )
                tx_result = self.run_command(
                    f"cat /sys/class/net/{interface}/statistics/tx_bytes"
                )

                rx_bytes = int(rx_result.strip()) if rx_result else 0
                tx_bytes = int(tx_result.strip()) if tx_result else 0

                with open(log_file, "a") as f:
                    f.write(f"{datetime.now()},{rx_bytes},{tx_bytes}\n")

                time.sleep(float(interval) * 60)

    def connection_monitor(self):
        """25. Bağlantı İzleme"""
        print(f"\n{Fore.CYAN}Bağlantı İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Aktif Bağlantılar")
        print("2. Dinleme Portları")
        print("3. Bağlantı İstatistikleri")
        print("4. Bağlantı Takibi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"connection_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            print(f"\n{Fore.YELLOW}Aktif bağlantılar listeleniyor...{Style.RESET_ALL}")
            output_file = f"{output_dir}/active_connections.txt"

            # Detaylı bağlantı bilgilerini topla
            self.run_command("netstat -tupn > " + output_file, sudo=True)
            self.run_command("ss -tupn >> " + output_file, sudo=True)

            # Şüpheli bağlantıları kontrol et
            suspicious = self.run_command(
                "netstat -tupn | grep -i 'syn_sent\\|established'", sudo=True
            )
            if suspicious:
                print(
                    f"\n{Fore.RED}Şüpheli Bağlantılar Tespit Edildi:{Style.RESET_ALL}"
                )
                print(suspicious)

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}Dinleme portları kontrol ediliyor...{Style.RESET_ALL}"
            )
            output_file = f"{output_dir}/listening_ports.txt"

            self.run_command("netstat -tlpn > " + output_file, sudo=True)
            self.run_command("lsof -i -P -n >> " + output_file, sudo=True)

            # Bilinen portları karşılaştır
            with open("/etc/services", "r") as f:
                known_ports = {
                    line.split()[1].split("/")[0]
                    for line in f
                    if line.strip() and not line.startswith("#")
                }

            unknown_ports = set()
            cmd_result = self.run_command("netstat -tlpn | awk '{print $4}'")
            if cmd_result:
                for line in cmd_result.split("\n"):
                    if line and ":" in line:
                        port = line.split(":")[-1]
                        if port not in known_ports:
                            unknown_ports.add(port)

            if unknown_ports:
                print(f"\n{Fore.RED}Bilinmeyen Portlar:{Style.RESET_ALL}")
                print("\n".join(unknown_ports))

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Bağlantı istatistikleri toplanıyor...{Style.RESET_ALL}"
            )
            output_file = f"{output_dir}/connection_stats.txt"

            self.run_command("netstat -s > " + output_file)
            self.run_command("ss -s >> " + output_file)

            # İstatistikleri analiz et
            tcp_stats = self.run_command(
                "netstat -st | grep -i 'failed\\|reset\\|timeout'"
            )
            if tcp_stats:
                print(f"\n{Fore.RED}Dikkat Çeken TCP İstatistikleri:{Style.RESET_ALL}")
                print(tcp_stats)

        elif choice == "4":
            print(f"\n{Fore.YELLOW}Bağlantı takibi başlatılıyor...{Style.RESET_ALL}")
            duration = input("Takip süresi (dakika) [30]: ") or "30"
            interval = input("Kontrol aralığı (saniye) [5]: ") or "5"

            log_file = f"{output_dir}/connection_tracking.log"
            end_time = time.time() + (float(duration) * 60)

            while time.time() < end_time:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                connections = self.run_command("netstat -tupn", sudo=True)

                with open(log_file, "a") as f:
                    f.write(f"\n=== {timestamp} ===\n")
                    if connections:
                        f.write(f"{connections}\n")
                    else:
                        f.write("No connections found\n")

                time.sleep(float(interval))

            print(
                f"\n{Fore.GREEN}Bağlantı takibi tamamlandı. Sonuçlar {log_file} dosyasına kaydedildi.{Style.RESET_ALL}"
            )

    # Sistem Güvenliği Fonksiyonları (26-35)
    def file_integrity(self):
        """26. Dosya Bütünlük Kontrolü"""
        print(f"\n{Fore.CYAN}Dosya Bütünlük Kontrolü Seçenekleri:{Style.RESET_ALL}")
        print("1. AIDE İle Tam Sistem Kontrolü")
        print("2. Belirli Dizin Kontrolü")
        print("3. Gerçek Zamanlı İzleme")
        print("4. Rapor Oluşturma")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"integrity_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("aide"):
            if choice == "1":
                print(
                    f"\n{Fore.YELLOW}Tam sistem kontrolü başlatılıyor...{Style.RESET_ALL}"
                )
                self.run_command(
                    f"aide --check > {output_dir}/full_check.log", sudo=True
                )

            elif choice == "2":
                path = input("Kontrol edilecek dizin: ")
                print(f"\n{Fore.YELLOW}Dizin kontrolü başlatılıyor...{Style.RESET_ALL}")
                self.run_command(
                    f"aide --check --config-check -r {path} > {output_dir}/dir_check.log",
                    sudo=True,
                )

            elif choice == "3":
                duration = input("İzleme süresi (saat) [24]: ") or "24"
                interval = input("Kontrol aralığı (dakika) [30]: ") or "30"

                end_time = time.time() + (float(duration) * 3600)
                while time.time() < end_time:
                    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    self.run_command(
                        f"aide --check > {output_dir}/check_{timestamp}.log", sudo=True
                    )
                    time.sleep(float(interval) * 60)

            elif choice == "4":
                print(f"\n{Fore.YELLOW}Rapor oluşturuluyor...{Style.RESET_ALL}")
                self.run_command(
                    f"aide --update > {output_dir}/aide_update.log", sudo=True
                )

    def process_monitor(self):
        """27. Süreç İzleme"""
        print(f"\n{Fore.CYAN}Süreç İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Gerçek Zamanlı Süreç İzleme (htop)")
        print("2. Kaynak Kullanımı Analizi")
        print("3. Şüpheli Süreç Tespiti")
        print("4. Süreç Performans İzleme")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"process_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("htop"):
            self.run_command("htop")

        elif choice == "2":
            duration = input("İzleme süresi (dakika) [60]: ") or "60"
            interval = input("Örnekleme aralığı (saniye) [5]: ") or "5"

            print(
                f"\n{Fore.YELLOW}Kaynak kullanımı analizi başlatılıyor...{Style.RESET_ALL}"
            )
            end_time = time.time() + (float(duration) * 60)

            with open(f"{output_dir}/resource_usage.csv", "w") as f:
                f.write("timestamp,pid,process,cpu,memory,disk_read,disk_write\n")

                while time.time() < end_time:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    ps_output = self.run_command("ps aux --sort=-%cpu | head -11")

                    if ps_output:
                        for line in ps_output.splitlines()[1:]:
                            f.write(f"{timestamp},{line.split()}\n")
                    else:
                        f.write(f"{timestamp},No output from ps command\n")

                    time.sleep(float(interval))

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Şüpheli süreçler kontrol ediliyor...{Style.RESET_ALL}"
            )
            suspicious_patterns = [
                "kworker",
                "cryptominer",
                "backdoor",
                "reverse_shell",
                "netcat",
                "ncat",
            ]

            for pattern in suspicious_patterns:
                result = self.run_command(f"ps aux | grep -i {pattern}")
                if result:
                    with open(f"{output_dir}/suspicious_processes.log", "a") as f:
                        f.write(f"\n=== {pattern} ===\n{result}\n")

        elif choice == "4":
            pid = input("İzlenecek süreç PID: ")
            duration = input("İzleme süresi (dakika) [30]: ") or "30"

            print(f"\n{Fore.YELLOW}Süreç performansı izleniyor...{Style.RESET_ALL}")
            end_time = time.time() + (float(duration) * 60)

            with open(f"{output_dir}/process_performance.log", "w") as f:
                while time.time() < end_time:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    stats = self.run_command(f"ps -p {pid} -o %cpu,%mem,vsz,rss")
                    f.write(f"{timestamp}: {stats}\n")
                    time.sleep(1)

    def user_audit(self):
        """28. Kullanıcı Denetimi"""
        print(f"\n{Fore.CYAN}Kullanıcı Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Oturum Açma Geçmişi")
        print("2. Kullanıcı Aktiviteleri")
        print("3. Yetki Değişiklikleri")
        print("4. Parola Politikası Kontrolü")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"user_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            print(f"\n{Fore.YELLOW}Oturum açma geçmişi inceleniyor...{Style.RESET_ALL}")
            self.run_command(f"last > {output_dir}/login_history.log")
            self.run_command(f"lastb > {output_dir}/failed_logins.log", sudo=True)

        elif choice == "2":
            user = input("Kullanıcı adı [tümü]: ")
            if user:
                self.run_command(
                    f"ausearch -ua {user} > {output_dir}/user_activities.log", sudo=True
                )
            else:
                self.run_command(
                    f"aureport --user > {output_dir}/all_user_activities.log", sudo=True
                )

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Yetki değişiklikleri kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"ausearch -m USER_ACCT -m USER_ROLE_CHANGE > {output_dir}/permission_changes.log",
                sudo=True,
            )

        elif choice == "4":
            print(
                f"\n{Fore.YELLOW}Parola politikası kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"cat /etc/security/pwquality.conf > {output_dir}/password_policy.txt"
            )
            self.run_command(f"cat /etc/login.defs >> {output_dir}/password_policy.txt")

    def login_monitor(self):
        """29. Giriş İzleme"""
        print(f"\n{Fore.CYAN}Giriş İzleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Son Giriş Denemeleri")
        print("2. Başarısız Giriş Analizi")
        print("3. SSH Giriş İzleme")
        print("4. Gerçek Zamanlı Giriş Takibi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"login_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            limit = input("Gösterilecek kayıt sayısı [20]: ") or "20"
            self.run_command(f"last -n {limit} > {output_dir}/recent_logins.log")

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}Başarısız girişler analiz ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(f"lastb > {output_dir}/failed_logins.log", sudo=True)

            # IP bazlı analiz
            self.run_command(
                "lastb | awk '{print $3}' | sort | uniq -c | sort -nr > "
                + f"{output_dir}/failed_login_ips.txt",
                sudo=True,
            )

        elif choice == "3":
            print(f"\n{Fore.YELLOW}SSH giriş kayıtları inceleniyor...{Style.RESET_ALL}")
            self.run_command(
                f"grep 'sshd' /var/log/auth.log > {output_dir}/ssh_logins.log",
                sudo=True,
            )

        elif choice == "4":
            duration = input("İzleme süresi (dakika) [30]: ") or "30"
            print(
                f"\n{Fore.YELLOW}Gerçek zamanlı giriş takibi başlatılıyor...{Style.RESET_ALL}"
            )

            end_time = time.time() + (float(duration) * 60)
            while time.time() < end_time:
                self.run_command(
                    f"tail -f /var/log/auth.log > {output_dir}/realtime_logins.log",
                    sudo=True,
                )
                time.sleep(1)

    def service_audit(self):
        """30. Servis Denetimi"""
        print(f"\n{Fore.CYAN}Servis Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Çalışan Servisler")
        print("2. Servis Durumu Analizi")
        print("3. Otomatik Başlayan Servisler")
        print("4. Servis Güvenlik Denetimi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"service_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            print(f"\n{Fore.YELLOW}Çalışan servisler listeleniyor...{Style.RESET_ALL}")
            self.run_command(
                f"systemctl list-units --type=service --state=running > {output_dir}/running_services.txt"
            )

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}Servis durumları analiz ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"systemctl list-units --type=service --all > {output_dir}/all_services.txt"
            )

            # Başarısız servisleri analiz et
            self.run_command(
                "systemctl --failed --type=service > "
                + f"{output_dir}/failed_services.txt"
            )

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Otomatik başlayan servisler kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"systemctl list-unit-files --type=service | grep enabled > {output_dir}/enabled_services.txt"
            )

        elif choice == "4":
            print(
                f"\n{Fore.YELLOW}Servis güvenlik denetimi yapılıyor...{Style.RESET_ALL}"
            )
            cmd_output = self.run_command(
                "systemctl list-units --type=service --state=running | awk '{print $1}'"
            )
            services = cmd_output.splitlines() if cmd_output else []

            with open(f"{output_dir}/service_security_audit.txt", "w") as f:
                for service in services:
                    if service.endswith(".service"):
                        f.write(f"\n=== {service} ===\n")
                        # Servis yapılandırmasını kontrol et
                        cmd_output = self.run_command(f"systemctl show {service}")
                        f.write(f"{cmd_output if cmd_output else 'No output'}\n")
                        # Servis dosya izinlerini kontrol et
                        service_path = self.run_command(
                            f"systemctl show {service} -p FragmentPath"
                        )
                        if service_path:
                            cmd_result = self.run_command(
                                f"ls -l {service_path.split('=')[1]}"
                            )
                            f.write(f"{cmd_result if cmd_result else 'No output'}\n")

    def password_audit(self):
        """31. Parola Güvenlik Denetimi"""
        print(f"\n{Fore.CYAN}Parola Güvenlik Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Parola Karması Analizi")
        print("2. Zayıf Parola Tespiti")
        print("3. Parola Politikası Kontrolü")
        print("4. Kullanıcı Parola Durumu")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"password_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("john"):
            print(
                f"\n{Fore.YELLOW}Parola karmaları analiz ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"john --show /etc/shadow > {output_dir}/password_hashes.txt", sudo=True
            )

        elif choice == "2":
            print(f"\n{Fore.YELLOW}Zayıf parolalar tespit ediliyor...{Style.RESET_ALL}")
            if self.check_tool("john"):
                self.run_command(
                    f"john --single /etc/shadow > {output_dir}/weak_passwords.txt",
                    sudo=True,
                )

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Parola politikası kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"cat /etc/pam.d/common-password > {output_dir}/password_policy.txt"
            )
            self.run_command(
                f"cat /etc/security/pwquality.conf >> {output_dir}/password_policy.txt"
            )

        elif choice == "4":
            print(
                f"\n{Fore.YELLOW}Kullanıcı parola durumları kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"chage -l $(cut -d: -f1 /etc/passwd) > {output_dir}/password_status.txt",
                sudo=True,
            )

    def file_permission_check(self):
        """32. Dosya İzin Kontrolü"""
        print(f"\n{Fore.CYAN}Dosya İzin Kontrolü Seçenekleri:{Style.RESET_ALL}")
        print("1. Yüksek İzinli Dosyalar")
        print("2. SUID/SGID Dosyaları")
        print("3. İzin Denetimi")
        print("4. Dosya Sahipliği Kontrolü")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"permission_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            path = input("Kontrol edilecek dizin [/]: ") or "/"
            print(f"\n{Fore.YELLOW}Yüksek izinli dosyalar aranıyor...{Style.RESET_ALL}")
            self.run_command(
                f"find {path} -type f -perm /4000 > {output_dir}/high_perm_files.txt"
            )

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}SUID/SGID dosyaları kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"find / -type f -perm /6000 > {output_dir}/suid_sgid_files.txt"
            )

        elif choice == "3":
            path = input("Kontrol edilecek dizin: ")
            recursive = input("Alt dizinler dahil edilsin mi? (e/h): ").lower() == "e"

            cmd = f"ls -la {'-R' if recursive else ''} {path} > {output_dir}/permission_audit.txt"
            self.run_command(cmd)

        elif choice == "4":
            print(
                f"\n{Fore.YELLOW}Dosya sahipliği kontrol ediliyor...{Style.RESET_ALL}"
            )
            path = input("Kontrol edilecek dizin: ")
            user = input("Kontrol edilecek kullanıcı [tümü]: ")

            if user:
                cmd = f"find {path} -user {user}"
            else:
                cmd = f"find {path} -ls"

            self.run_command(f"{cmd} > {output_dir}/ownership_check.txt")

    def system_hardening(self):
        """33. Sistem Sertleştirme"""
        print(f"\n{Fore.CYAN}Sistem Sertleştirme Seçenekleri:{Style.RESET_ALL}")
        print("1. Güvenlik Denetimi")
        print("2. Sertleştirme Önerileri")
        print("3. Otomatik Sertleştirme")
        print("4. Güvenlik Raporu")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"system_hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("lynis"):
            print(f"\n{Fore.YELLOW}Güvenlik denetimi başlatılıyor...{Style.RESET_ALL}")
            self.run_command(
                f"lynis audit system > {output_dir}/security_audit.txt", sudo=True
            )

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}Sertleştirme önerileri hazırlanıyor...{Style.RESET_ALL}"
            )
            recommendations = [
                "Gereksiz servisleri devre dışı bırakın",
                "Güçlü parola politikası uygulayın",
                "Düzenli güvenlik güncellemeleri yapın",
                "Güvenlik duvarı kurallarını sıkılaştırın",
            ]

            with open(f"{output_dir}/hardening_recommendations.txt", "w") as f:
                for i, rec in enumerate(recommendations, 1):
                    f.write(f"{i}. {rec}\n")

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Otomatik sertleştirme başlatılıyor...{Style.RESET_ALL}"
            )
            # Temel güvenlik önlemleri
            commands = [
                "systemctl disable telnet",
                "systemctl enable firewalld",
                "sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config",
            ]

            for cmd in commands:
                self.run_command(cmd, sudo=True)

        elif choice == "4":
            print(f"\n{Fore.YELLOW}Güvenlik raporu oluşturuluyor...{Style.RESET_ALL}")
            with open(f"{output_dir}/security_report.txt", "w") as f:
                f.write("=== Sistem Güvenlik Raporu ===\n\n")

                # SELinux durumu
                f.write("SELinux Durumu:\n")
                result = self.run_command("sestatus")
                f.write(f"{result if result else 'Command failed'}\n\n")

                # Güvenlik duvarı durumu
                f.write("Güvenlik Duvarı Durumu:\n")
                cmd_result = self.run_command("firewall-cmd --list-all")
                f.write(f"{cmd_result if cmd_result else 'Command failed'}\n\n")

                # Açık portlar
                f.write("Açık Portlar:\n")
                cmd_result = self.run_command("ss -tuln")
                f.write(f"{cmd_result if cmd_result else ''}\n\n")

    def backup_check(self):
        """34. Yedekleme Kontrolü"""
        print(f"\n{Fore.CYAN}Yedekleme Kontrol Seçenekleri:{Style.RESET_ALL}")
        print("1. Son Yedeklemeleri Kontrol Et")
        print("2. Yedekleme Durumu")
        print("3. Yedek Bütünlük Kontrolü")
        print("4. Yedekleme Raporu")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"backup_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            days = input("Kaç günlük yedekler kontrol edilsin [7]: ") or "7"
            print(
                f"\n{Fore.YELLOW}Son yedeklemeler kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(
                f"find /backup -type f -mtime -{days} > {output_dir}/recent_backups.txt"
            )

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}Yedekleme durumu kontrol ediliyor...{Style.RESET_ALL}"
            )
            # Yedekleme servislerinin durumu
            self.run_command(
                f"systemctl status *backup* > {output_dir}/backup_services.txt"
            )

            # Disk kullanımı
            self.run_command(f"df -h /backup > {output_dir}/backup_disk_usage.txt")

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Yedek bütünlüğü kontrol ediliyor...{Style.RESET_ALL}"
            )
            backup_dir = input("Yedek dizini: ")

            # MD5 sağlama toplamlarını kontrol et
            with open(f"{output_dir}/backup_integrity.txt", "w") as f:
                for root, _, files in os.walk(backup_dir):
                    for file in files:
                        filepath = os.path.join(root, file)
                        md5sum = self.run_command(f"md5sum {filepath}")
                        f.write(f"{md5sum}\n")

        elif choice == "4":
            print(f"\n{Fore.YELLOW}Yedekleme raporu oluşturuluyor...{Style.RESET_ALL}")
            with open(f"{output_dir}/backup_report.txt", "w") as f:
                f.write("=== Yedekleme Raporu ===\n\n")

                # Son yedekleme zamanı
                f.write("Son Yedeklemeler:\n")
                cmd_result = self.run_command("find /backup -type f -mtime -7 -ls")
                f.write(f"{cmd_result if cmd_result else 'No output'}\n\n")

                # Yedekleme politikası
                f.write("Yedekleme Politikası:\n")
                if os.path.exists("/etc/backup.conf"):
                    cmd_output = self.run_command("cat /etc/backup.conf")
                    f.write(
                        f"{cmd_output if cmd_output else 'No backup configuration found'}\n\n"
                    )

                # Yedekleme alanı kullanımı
                f.write("Yedekleme Alanı Kullanımı:\n")
                cmd_output = self.run_command("du -sh /backup/*")
                f.write(f"{cmd_output if cmd_output else 'No backup data available'}\n")

    def encryption_check(self):
        """35. Disk Şifreleme Kontrolü"""
        print(f"\n{Fore.CYAN}Disk Şifreleme Kontrol Seçenekleri:{Style.RESET_ALL}")
        print("1. Şifreli Disk Bölümleri")
        print("2. LUKS Durumu")
        print("3. Şifreleme Politikası")
        print("4. Şifreleme Raporu")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"encryption_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            print(
                f"\n{Fore.YELLOW}Şifreli disk bölümleri kontrol ediliyor...{Style.RESET_ALL}"
            )
            self.run_command(f"lsblk -f > {output_dir}/encrypted_partitions.txt")

            # LUKS başlıklarını kontrol et
            self.run_command(
                f"cryptsetup luksDump /dev/sda* > {output_dir}/luks_headers.txt 2>/dev/null",
                sudo=True,
            )

        elif choice == "2":
            print(f"\n{Fore.YELLOW}LUKS durumu kontrol ediliyor...{Style.RESET_ALL}")
            # Aktif LUKS bağlantıları
            self.run_command(
                f"dmsetup ls --target crypt > {output_dir}/active_luks.txt", sudo=True
            )

            # LUKS versiyonları
            self.run_command(
                f"cryptsetup luksDump /dev/mapper/* > {output_dir}/luks_versions.txt 2>/dev/null",
                sudo=True,
            )

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Şifreleme politikası kontrol ediliyor...{Style.RESET_ALL}"
            )
            policies = {
                "GRUB_ENABLE_CRYPTODISK": "/etc/default/grub",
                "ENCRYPT_METHOD": "/etc/login.defs",
                "UMASK": "/etc/login.defs",
            }

            with open(f"{output_dir}/encryption_policies.txt", "w") as f:
                for policy, file in policies.items():
                    f.write(f"\n=== {policy} ===\n")
                    result = self.run_command(f"grep {policy} {file}")
                    f.write(f"{result if result else 'No results found'}\n")

        elif choice == "4":
            print(f"\n{Fore.YELLOW}Şifreleme raporu oluşturuluyor...{Style.RESET_ALL}")
            with open(f"{output_dir}/encryption_report.txt", "w") as f:
                f.write("=== Disk Şifreleme Raporu ===\n\n")

                # Disk bölümleri
                f.write("Disk Bölümleri:\n")
                cmd_result = self.run_command("lsblk -f")
                f.write(f"{cmd_result if cmd_result else 'Command failed'}\n\n")

                # LUKS başlıkları
                f.write("LUKS Başlıkları:\n")
                cmd_result = self.run_command(
                    "cryptsetup luksDump /dev/sda* 2>/dev/null", sudo=True
                )
                f.write(f"{cmd_result if cmd_result else 'No output'}\n\n")

                # Şifreleme algoritmaları
                f.write("Kullanılan Şifreleme Algoritmaları:\n")
                cmd_result = self.run_command("dmsetup table")
                f.write(f"{cmd_result if cmd_result else 'No output available'}\n")

    # Adli Analiz Fonksiyonları (36-45)
    def memory_analysis(self):
        """36. Bellek Analizi"""
        print(f"\n{Fore.CYAN}Bellek Analizi Seçenekleri:{Style.RESET_ALL}")
        print("1. Süreç Listesi")
        print("2. Ağ Bağlantıları")
        print("3. Yüklü DLL'ler")
        print("4. Şüpheli Süreçler")

        choice = input("\nSeçiminiz (1-4): ")
        if self.check_tool("volatility"):
            image = input("Bellek imajı yolu: ")
            output_dir = f"memory_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(output_dir, exist_ok=True)

            commands = {
                "1": f"volatility -f {image} pslist > {output_dir}/pslist.txt",
                "2": f"volatility -f {image} netscan > {output_dir}/netscan.txt",
                "3": f"volatility -f {image} dlllist > {output_dir}/dlllist.txt",
                "4": f"volatility -f {image} malfind > {output_dir}/malfind.txt",
            }

            if choice in commands:
                self.run_command(commands[choice], sudo=True)

                # Sonuçları analiz et
                if choice == "4":
                    with open(f"{output_dir}/malfind.txt", "r") as f:
                        if "suspicious" in f.read():
                            print(
                                f"{Fore.RED}Şüpheli aktivite tespit edildi!{Style.RESET_ALL}"
                            )

    def disk_analysis(self):
        """37. Disk Analizi"""
        print(f"\n{Fore.CYAN}Disk Analizi Seçenekleri:{Style.RESET_ALL}")
        print("1. Dosya Sistemi Analizi")
        print("2. Silinmiş Dosya Kurtarma")
        print("3. Metadata Analizi")
        print("4. Bütünlük Kontrolü")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"disk_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("autopsy"):
            disk = input("Analiz edilecek disk (/dev/sdX): ")
            self.run_command(f"autopsy -d {disk} -o {output_dir}", sudo=True)
        elif choice == "2" and self.check_tool("testdisk"):
            disk = input("Kurtarma yapılacak disk: ")
            self.run_command(f"testdisk {disk}", sudo=True)
        elif choice == "3" and self.check_tool("fls"):
            image = input("İmaj dosyası: ")
            self.run_command(f"fls -r {image} > {output_dir}/metadata.txt", sudo=True)
        elif choice == "4" and self.check_tool("hashdeep"):
            path = input("Kontrol edilecek dizin: ")
            self.run_command(f"hashdeep -r {path} > {output_dir}/integrity.txt")

    def log_analysis(self):
        """38. Log Analizi"""
        print(f"\n{Fore.CYAN}Log Analizi Seçenekleri:{Style.RESET_ALL}")
        print("1. Sistem Logları")
        print("2. Güvenlik Logları")
        print("3. Uygulama Logları")
        print("4. Özel Log Analizi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        time_range = (
            input("Zaman aralığı (örn: '1 hour ago', 'yesterday'): ") or "today"
        )

        commands = {
            "1": f"journalctl --since '{time_range}' > {output_dir}/system_logs.txt",
            "2": f"grep -i 'fail\\|error\\|warn\\|invalid' /var/log/auth.log > {output_dir}/security_logs.txt",
            "3": f"find /var/log -type f -exec grep -l 'error' {{}} \\; > {output_dir}/app_logs.txt",
            "4": input("Log dosyası yolu: "),
        }

        if choice in commands:
            self.run_command(commands[choice], sudo=True)

            # Log analizi yap
            with open(f"{output_dir}/analysis_report.txt", "w") as f:
                f.write("=== Log Analiz Raporu ===\n")
                f.write(f"Tarih: {datetime.now()}\n")
                f.write(f"Analiz Edilen Dosya: {commands[choice]}\n\n")

                # Önemli olayları tespit et
                patterns = ["error", "failed", "warning", "critical"]
                for pattern in patterns:
                    result = self.run_command(
                        f"grep -i {pattern} {commands[choice]} | wc -l"
                    )
                    f.write(f"{pattern.title()} Sayısı: {result}\n")

    def file_carving(self):
        """39. Dosya Kurtarma"""
        print(f"\n{Fore.CYAN}Dosya Kurtarma Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel Dosya Kurtarma")
        print("2. Detaylı Dosya Analizi")
        print("3. Özel Format Kurtarma")
        print("4. Derin Tarama")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"file_carving_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("foremost"):
            image = input("İmaj dosyası yolu: ")

            commands = {
                "1": f"foremost -i {image} -o {output_dir}/basic",
                "2": f"foremost -i {image} -v -o {output_dir}/detailed",
                "3": (
                    lambda: self.run_command(
                        f"foremost -t {input('Kurtarılacak dosya türleri (jpg,pdf,doc): ')} "
                        f"-i {image} -o {output_dir}/custom"
                    )
                ),
                "4": f"foremost -i {image} -d -v -o {output_dir}/deep",
            }

            if choice in commands:
                print(f"\n{Fore.YELLOW}Dosya kurtarma başlatılıyor...{Style.RESET_ALL}")
                cmd = commands[choice]
                if callable(cmd):
                    cmd()
                else:
                    self.run_command(cmd)

                # Sonuçları analiz et
                recovered_files = self.run_command(f"find {output_dir} -type f | wc -l")
                print(
                    f"\n{Fore.GREEN}Kurtarılan Dosya Sayısı: {recovered_files}{Style.RESET_ALL}"
                )

                # İstatistik raporu oluştur
                with open(f"{output_dir}/recovery_report.txt", "w") as f:
                    f.write("=== Dosya Kurtarma Raporu ===\n")
                    f.write(f"Tarih: {datetime.now()}\n")
                    f.write(f"Kaynak İmaj: {image}\n")
                    f.write(f"Kurtarılan Dosya Sayısı: {recovered_files}\n\n")

                    # Dosya türlerine göre istatistik
                    f.write("Dosya Türü Dağılımı:\n")
                    for ext in ["jpg", "pdf", "doc", "txt", "zip"]:
                        count = self.run_command(
                            f"find {output_dir} -name '*.{ext}' | wc -l"
                        )
                        f.write(f"{ext.upper()}: {count} dosya\n")

    def timeline_analysis(self):
        """40. Zaman Çizelgesi Analizi"""
        print(f"\n{Fore.CYAN}Zaman Çizelgesi Analizi Seçenekleri:{Style.RESET_ALL}")
        print("1. Sistem Aktivite Analizi")
        print("2. Kullanıcı Aktivite Analizi")
        print("3. Dosya Sistemi Değişiklikleri")
        print("4. Güvenlik Olayları Analizi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"timeline_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("mactime"):
            # Tarih aralığı belirleme
            start_date = input("Başlangıç tarihi (YYYY-MM-DD) [1 ay önce]: ") or (
                datetime.now() - timedelta(days=30)
            ).strftime("%Y-%m-%d")
            end_date = input(
                "Bitiş tarihi (YYYY-MM-DD) [bugün]: "
            ) or datetime.now().strftime("%Y-%m-%d")

            commands = {
                "1": f"mactime -b /tmp/body.txt -d -y -z UTC {start_date} {end_date} > {output_dir}/system_timeline.csv",
                "2": f"mactime -b /tmp/body.txt -d -u {start_date} {end_date} > {output_dir}/user_timeline.csv",
                "3": f"find / -type f -printf '%T@ %p\n' | sort -n > {output_dir}/filesystem_changes.txt",
                "4": f"ausearch --start {start_date} --end {end_date} --raw > {output_dir}/security_events.txt",
            }

            if choice in commands:
                print(
                    f"\n{Fore.YELLOW}Zaman çizelgesi oluşturuluyor...{Style.RESET_ALL}"
                )
                self.run_command(commands[choice], sudo=True)

                # Analiz raporu oluştur
                with open(f"{output_dir}/timeline_report.txt", "w") as f:
                    f.write("=== Zaman Çizelgesi Analiz Raporu ===\n")
                    f.write(f"Tarih Aralığı: {start_date} - {end_date}\n\n")

                    # Olay istatistikleri
                    if choice in ["1", "2"]:
                        timeline_file = f"{output_dir}/{'system' if choice == '1' else 'user'}_timeline.csv"
                        if os.path.exists(timeline_file):
                            cmd_result = self.run_command(f"wc -l {timeline_file}")
                            total_events = cmd_result.split()[0] if cmd_result else "0"
                            f.write(f"Toplam Olay Sayısı: {total_events}\n")

                            # Saat bazlı aktivite dağılımı
                            f.write("\nSaat Bazlı Aktivite Dağılımı:\n")
                            self.run_command(
                                f"awk -F',' '{{print $1}}' {timeline_file} | "
                                + "awk -F':' '{print $1}' | sort | uniq -c >> "
                                + f"{output_dir}/timeline_report.txt"
                            )

                # Görselleştirme (opsiyonel)
                if (
                    input("\nZaman çizelgesi görselleştirilsin mi? (e/h): ").lower()
                    == "e"
                ):
                    if self.check_tool("gnuplot"):
                        self.run_command(
                            f'gnuplot -e \'set terminal png; set output "{output_dir}/timeline.png"; '
                            + f'plot "{output_dir}/timeline.csv" using 1:2 with lines\''
                        )

                print(
                    f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
                )

    # Sızma Testi Fonksiyonları (46-55)
    def password_cracking(self):
        """46. Parola Kırma"""
        print(f"\n{Fore.CYAN}Parola Kırma Seçenekleri:{Style.RESET_ALL}")
        print("1. Hash Kırma")
        print("2. Brute Force Saldırısı")
        print("3. Wordlist ile Deneme")
        print("4. Kombinasyon Saldırısı")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"password_crack_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if not self.check_tool("hashcat"):
            print(
                f"{Fore.RED}Hashcat yüklü değil veya PATH değişkeninde değil.{Style.RESET_ALL}"
            )
            return

        hash_file = input("Hash dosyası: ")

        # Hash türünü otomatik tespit
        hash_type = self.run_command(f"hashid {hash_file}") or "Tespit edilemedi"
        print(
            f"\n{Fore.YELLOW}Tespit Edilen Hash Türleri:{Style.RESET_ALL}\n{hash_type}"
        )

        hash_mode = input("Hash modu (-m) [0]: ") or "0"

        cmd: str | None = None  # Başlangıçta tanımsızlığı önle

        if choice == "1":
            wordlist = (
                input("Wordlist dosyası [rockyou.txt]: ")
                or "/usr/share/wordlists/rockyou.txt"
            )
            cmd = f"hashcat -m {hash_mode} {hash_file} {wordlist} -o {output_dir}/cracked.txt"

        elif choice == "2":
            charset = input("Karakter seti [?a]: ") or "?a"
            min_len = input("Minimum uzunluk [1]: ") or "1"
            max_len = input("Maximum uzunluk [8]: ") or "8"
            cmd = f"hashcat -m {hash_mode} -a 3 {hash_file} {charset*int(max_len)} -i --increment-min={min_len} -o {output_dir}/cracked.txt"

        elif choice == "3":
            wordlist = input("Özel wordlist dosyası: ")
            rules = input("Kural dosyası [best64.rule]: ") or "best64.rule"
            cmd = f"hashcat -m {hash_mode} {hash_file} {wordlist} -r /usr/share/hashcat/rules/{rules} -o {output_dir}/cracked.txt"

        elif choice == "4":
            wordlist1 = input("İlk wordlist: ")
            wordlist2 = input("İkinci wordlist: ")
            cmd = f"hashcat -m {hash_mode} {hash_file} -a 1 {wordlist1} {wordlist2} -o {output_dir}/cracked.txt"

        else:
            print(f"{Fore.RED}Geçersiz seçim yaptınız!{Style.RESET_ALL}")
            return  # cmd tanımlı olmazsa aşağıya inmesini engelle

        # Parola kırma komutunu çalıştır
        print(f"\n{Fore.YELLOW}Parola kırma başlatılıyor...{Style.RESET_ALL}")
        self.run_command(cmd)

        # Sonuçları kontrol et ve yazdır
        cracked_path = f"{output_dir}/cracked.txt"
        if os.path.exists(cracked_path):
            with open(cracked_path, "r") as f:
                cracked = f.read()
                print(f"\n{Fore.GREEN}Kırılan Parolalar:{Style.RESET_ALL}\n{cracked}")
        else:
            print(
                f"{Fore.RED}Hiçbir parola kırılamadı ya da çıktı dosyası oluşturulmadı.{Style.RESET_ALL}"
            )

    def exploit_search(self):
        """47. Exploit Arama"""
        print(f"\n{Fore.CYAN}Exploit Arama Seçenekleri:{Style.RESET_ALL}")
        print("1. Anahtar Kelime ile Arama")
        print("2. CVE Numarası ile Arama")
        print("3. Platform Bazlı Arama")
        print("4. Detaylı Arama")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"exploit_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("searchsploit"):
            cmd = None  # Initialize cmd with None
            if choice == "1":
                keyword = input("Anahtar kelime: ")
                cmd = f"searchsploit {keyword} -w -t"

            elif choice == "2":
                cve = input("CVE numarası (örn: CVE-2021-44228): ")
                cmd = f"searchsploit {cve} -w --cve"

            elif choice == "3":
                print("\nPlatformlar:")
                print("1. Windows")
                print("2. Linux")
                print("3. Android")
                print("4. macOS")
                platform = input("Platform seçin (1-4): ")
                platform_map = {
                    "1": "windows",
                    "2": "linux",
                    "3": "android",
                    "4": "osx",
                }
                cmd = f"searchsploit -p {platform_map.get(platform, 'windows')}"

            elif choice == "4":
                keyword = input("Anahtar kelime: ")
                author = input("Yazar (opsiyonel): ")
                platform = input("Platform (opsiyonel): ")
                type = input("Exploit türü (opsiyonel): ")

                cmd = f"searchsploit {keyword}"
                if author:
                    cmd += f" --author {author}"
                if platform:
                    cmd += f" -p {platform}"
                if type:
                    cmd += f" -t {type}"

            if not cmd:
                print(
                    f"{Fore.RED}Geçersiz seçim. İşlem iptal ediliyor.{Style.RESET_ALL}"
                )
                return

            # Sonuçları kaydet
            print(f"\n{Fore.YELLOW}Exploit aranıyor...{Style.RESET_ALL}")
            result = self.run_command(f"{cmd} | tee {output_dir}/exploits.txt")

            # Detaylı rapor oluştur
            with open(f"{output_dir}/exploit_report.txt", "w") as f:
                f.write("=== Exploit Arama Raporu ===\n")
                f.write(f"Tarih: {datetime.now()}\n")
                f.write(f"Arama Parametreleri: {cmd}\n\n")
                f.write("Bulunan Exploitler:\n")
                f.write(result if result else "No results found")

    def web_fuzzing(self):
        """48. Web Fuzzing"""
        print(f"\n{Fore.CYAN}Web Fuzzing Seçenekleri:{Style.RESET_ALL}")
        print("1. Dizin/Dosya Taraması")
        print("2. Parameter Fuzzing")
        print("3. Virtual Host Keşfi")
        print("4. Custom Fuzzing")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"web_fuzzing_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("wfuzz"):
            url = input("Hedef URL: ")
            cmd = None  # Ensure cmd is always defined as None

            if choice == "1":
                wordlist = (
                    input("Wordlist [common.txt]: ")
                    or "/usr/share/wfuzz/wordlist/general/common.txt"
                )
                extensions = input("Dosya uzantıları (örn: php,txt,html): ")
                threads = input("Thread sayısı [10]: ") or "10"

                cmd = f"wfuzz -c -z file,{wordlist} --hc 404"
                if extensions:
                    cmd += (
                        f" -z file,{wordlist} -z list,{extensions} -u {url}/FUZZ.FUZ2Z"
                    )
                else:
                    cmd += f" -u {url}/FUZZ"
                cmd += f" -t {threads} -f {output_dir}/fuzzing_results.txt"

            elif choice == "2":
                param = input("Parametre adı: ")
                wordlist = input("Wordlist: ")
                cmd = f"wfuzz -c -z file,{wordlist} -d '{param}=FUZZ' {url} -f {output_dir}/param_fuzzing.txt"

            elif choice == "3":
                wordlist = input("Subdomain wordlist: ")
                cmd = f"wfuzz -c -w {wordlist} -H 'Host: FUZZ.{url}' {url} -f {output_dir}/vhost_fuzzing.txt"

            elif choice == "4":
                method = input("HTTP Metodu [GET]: ") or "GET"
                headers = input("HTTP Başlıkları (Key:Value,Key:Value): ")
                cookies = input("Cookies: ")

                cmd = f"wfuzz -c -X {method}"
                if headers:
                    for header in headers.split(","):
                        cmd += f" -H '{header}'"
                if cookies:
                    cmd += f" -b '{cookies}'"

            if cmd is not None:
                print(f"\n{Fore.YELLOW}Fuzzing başlatılıyor...{Style.RESET_ALL}")
                self.run_command(cmd)
            else:
                print(
                    f"{Fore.RED}Geçersiz seçim. Komut oluşturulamadı.{Style.RESET_ALL}"
                )

            # Sonuçları analiz et
            if os.path.exists(f"{output_dir}/fuzzing_results.txt"):
                with open(f"{output_dir}/fuzzing_analysis.txt", "w") as f:
                    f.write("=== Fuzzing Analiz Raporu ===\n")
                    f.write(f"Tarih: {datetime.now()}\n")
                    f.write(f"Hedef URL: {url}\n\n")

                    # İstatistikler
                    results = self.run_command(f"cat {output_dir}/fuzzing_results.txt")
                    response_codes = {}
                    if results:
                        for line in results.splitlines():
                            if "Code:" in line:
                                code = line.split("Code:")[1].strip().split()[0]
                                response_codes[code] = response_codes.get(code, 0) + 1

                    f.write("HTTP Yanıt Kodları:\n")
                    for code, count in response_codes.items():
                        f.write(f"- {code}: {count} adet\n")

    def sql_injection(self):
        """49. SQL Injection Taraması"""
        print(f"\n{Fore.CYAN}SQL Injection Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel Tarama")
        print("2. Detaylı Veritabanı Keşfi")
        print("3. Otomatik Exploit")
        print("4. Custom Tarama")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"sqlmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("sqlmap"):
            url = input("Hedef URL: ")
            cmd = None  # Initialize cmd with None

            if choice == "1":
                cmd = f"sqlmap -u {url} --batch --random-agent"

            elif choice == "2":
                print("\nVeri Çıkarma Seçenekleri:")
                print("1. Veritabanları")
                print("2. Tablolar")
                print("3. Sütunlar")
                print("4. Dump")

                data_choice = input("Seçiminiz (1-4): ")
                cmd = f"sqlmap -u {url} --random-agent"

                if data_choice == "1":
                    cmd += " --dbs"
                elif data_choice == "2":
                    db = input("Veritabanı adı: ")
                    cmd += f" -D {db} --tables"
                elif data_choice == "3":
                    db = input("Veritabanı adı: ")
                    table = input("Tablo adı: ")
                    cmd += f" -D {db} -T {table} --columns"
                elif data_choice == "4":
                    db = input("Veritabanı adı: ")
                    table = input("Tablo adı: ")
                    cmd += f" -D {db} -T {table} --dump"

            elif choice == "3":
                cmd = f"sqlmap -u {url} --batch --random-agent --risk=3 --level=5 --all"

            elif choice == "4":
                risk = input("Risk seviyesi (1-3) [1]: ") or "1"
                level = input("Level (1-5) [1]: ") or "1"
                dbms = input("DBMS (mysql,postgresql,mssql,oracle) [all]: ") or "all"
                threads = input("Thread sayısı [1]: ") or "1"

                cmd = f"sqlmap -u {url} --risk={risk} --level={level}"
                if dbms != "all":
                    cmd += f" --dbms={dbms}"
                cmd += f" --threads={threads} --random-agent"

            if cmd:
                print(
                    f"\n{Fore.YELLOW}SQL Injection taraması başlatılıyor...{Style.RESET_ALL}"
                )
                self.run_command(f"{cmd} -v 3 --output-dir={output_dir}")
            else:
                print(
                    f"{Fore.RED}Geçersiz seçim. Komut oluşturulamadı.{Style.RESET_ALL}"
                )

            # Sonuçları analiz et
            log_file = f"{output_dir}/log"
            if os.path.exists(log_file):
                with open(f"{output_dir}/analysis_report.txt", "w") as f:
                    f.write("=== SQL Injection Analiz Raporu ===\n")
                    f.write(f"Tarih: {datetime.now()}\n")
                    f.write(f"Hedef URL: {url}\n\n")

                    # Tespit edilen payloadları listele
                    f.write("Tespit Edilen Payloadlar:\n")
                    self.run_command(f"grep 'Parameter:' {log_file}")

    def xss_scan(self):
        """50. XSS Taraması"""
        print(f"\n{Fore.CYAN}XSS Tarama Seçenekleri:{Style.RESET_ALL}")
        print("1. Hızlı Tarama")
        print("2. Detaylı Tarama")
        print("3. DOM XSS Taraması")
        print("4. Custom Payload Taraması")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"xss_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("xsser"):
            url = input("Hedef URL: ")
            cmd = ""  # Ensure cmd is always defined

            if choice == "1":
                cmd = f"xsser --url {url} --auto --Fp -v"

            elif choice == "2":
                cmd = (
                    f"xsser --url {url} --auto --Fp --Cw --Str --DOM -v --reverse-check"
                )

            elif choice == "3":
                cmd = f"xsser --url {url} --DOM --auto -v --sleep=1"

            elif choice == "4":
                payload_file = input("Payload dosyası: ")
                method = input("HTTP Metodu (GET/POST) [GET]: ") or "GET"
                headers = input("HTTP Başlıkları (Key:Value,Key:Value): ")

                cmd = f"xsser --url {url} -s {payload_file} --{method.lower()}"
                if headers:
                    for header in headers.split(","):
                        cmd += f" --header='{header}'"

            if cmd:
                print(f"\n{Fore.YELLOW}XSS taraması başlatılıyor...{Style.RESET_ALL}")
                self.run_command(f"{cmd} --save --output={output_dir}/xss_results.txt")
            else:
                print(
                    f"{Fore.RED}Geçersiz seçim. Komut oluşturulamadı.{Style.RESET_ALL}"
                )

            # Sonuçları analiz et
            if os.path.exists(f"{output_dir}/xss_results.txt"):
                with open(f"{output_dir}/xss_analysis.txt", "w") as f:
                    f.write("=== XSS Analiz Raporu ===\n")
                    f.write(f"Tarih: {datetime.now()}\n")
                    f.write(f"Hedef URL: {url}\n\n")

                    # Tespit edilen XSS'leri say
                    results = self.run_command(f"cat {output_dir}/xss_results.txt")
                    if results is not None:
                        vulnerable_count = results.count("XSS FOUND!")
                    else:
                        vulnerable_count = 0
                    f.write(f"Tespit Edilen XSS Sayısı: {vulnerable_count}\n\n")

                    # Detaylı sonuçları ekle
                    f.write("Detaylı Sonuçlar:\n")
                    f.write(results if results is not None else "")

            # HTML rapor oluştur
            if input("\nHTML rapor oluşturulsun mu? (e/h): ").lower() == "e":
                self.run_command(
                    f"xsser --url {url} --xml-file={output_dir}/xss_results.xml"
                )

    # İleri Seviye Güvenlik Fonksiyonları (51-60)
    def binary_analysis(self):
        """51. İkili Dosya Analizi"""
        print(f"\n{Fore.CYAN}İkili Dosya Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Temel Analiz")
        print("2. Derinlemesine Analiz")
        print("3. Güvenlik Kontrolü")
        print("4. Özel Analiz")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"binary_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("radare2"):
            file = input("Analiz edilecek dosya: ")

            # Dosya türünü kontrol et
            file_type = self.run_command(f"file {file}")
            print(f"\n{Fore.YELLOW}Dosya Türü:{Style.RESET_ALL}\n{file_type}")

            commands = {
                "1": [
                    f"r2 -A {file} -q -c 'afl' > {output_dir}/functions.txt",  # Fonksiyonları listele
                    f"r2 -A {file} -q -c 'ii' > {output_dir}/imports.txt",  # İçe aktarmaları listele
                    f"r2 -A {file} -q -c 'is' > {output_dir}/symbols.txt",  # Sembolleri listele
                ],
                "2": [
                    f"r2 -A {file} -q -c 'aa;pdf@main' > {output_dir}/main_disasm.txt",  # Ana fonksiyon disassembly
                    f"r2 -A {file} -q -c 'axt' > {output_dir}/xrefs.txt",  # Cross referanslar
                    f"r2 -A {file} -q -c 'iz' > {output_dir}/strings.txt",  # Stringleri listele
                ],
                "3": [
                    f"r2 -A {file} -q -c 'i' > {output_dir}/info.txt",  # Dosya bilgisi
                    f"r2 -A {file} -q -c '/R' > {output_dir}/rop_gadgets.txt",  # ROP gadgetları
                    f"checksec --file={file} > {output_dir}/security.txt",  # Güvenlik özellikleri
                ],
                "4": None,  # Özel analiz için kullanıcı girişi alınacak
            }

            if choice == "4":
                print("\nÖzel Analiz Seçenekleri:")
                print("1. Belirli bir fonksiyonu analiz et")
                print("2. Belirli bir adres aralığını incele")
                print("3. Özel komut çalıştır")

                cmd = ""  # Ensure cmd is always defined
                subchoice = input("Seçiminiz (1-3): ")
                if subchoice == "1":
                    func_name = input("Fonksiyon adı: ")
                    cmd = f"r2 -A {file} -q -c 'aa;pdf@{func_name}' > {output_dir}/custom_func.txt"
                elif subchoice == "2":
                    start_addr = input("Başlangıç adresi: ")
                    end_addr = input("Bitiş adresi: ")
                    cmd = f"r2 -A {file} -q -c 'pD {end_addr}@{start_addr}' > {output_dir}/custom_range.txt"
                elif subchoice == "3":
                    r2_cmd = input("r2 komutu: ")
                    cmd = f"r2 -A {file} -q -c '{r2_cmd}' > {output_dir}/custom_cmd.txt"
                else:
                    cmd = ""
                commands["4"] = [cmd] if cmd else []

            if choice in commands:
                print(f"\n{Fore.YELLOW}Analiz başlatılıyor...{Style.RESET_ALL}")
                # Ensure commands[choice] is always a list, even if empty
                for cmd in commands.get(choice, []):
                    if cmd:  # Only run if cmd is not empty
                        self.run_command(cmd)

                # Sonuçları analiz et ve rapor oluştur
                with open(f"{output_dir}/analysis_report.txt", "w") as f:
                    f.write("=== İkili Dosya Analiz Raporu ===\n")
                    f.write(f"Tarih: {datetime.now()}\n")
                    f.write(f"Dosya: {file}\n")
                    f.write(f"Dosya Türü: {file_type}\n\n")

                    # Analiz sonuçlarını özetle
                    if os.path.exists(f"{output_dir}/functions.txt"):
                        func_count_result = self.run_command(
                            f"wc -l {output_dir}/functions.txt"
                        )
                        func_count = (
                            func_count_result.split()[0] if func_count_result else "0"
                        )
                        f.write(f"Fonksiyon Sayısı: {func_count}\n")

                    if os.path.exists(f"{output_dir}/imports.txt"):
                        import_count_result = self.run_command(
                            f"wc -l {output_dir}/imports.txt"
                        )
                        import_count = (
                            import_count_result.split()[0]
                            if import_count_result
                            else "0"
                        )
                        f.write(f"İçe Aktarma Sayısı: {import_count}\n")

                    if os.path.exists(f"{output_dir}/strings.txt"):
                        string_count_result = self.run_command(
                            f"wc -l {output_dir}/strings.txt"
                        )
                        string_count = (
                            string_count_result.split()[0]
                            if string_count_result
                            else "0"
                        )
                        f.write(f"String Sayısı: {string_count}\n")

                print(
                    f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
                )

    def malware_analysis(self):
        """52. Zararlı Yazılım Analizi"""
        print(f"\n{Fore.CYAN}Zararlı Yazılım Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Statik Analiz")
        print("2. Dinamik Analiz")
        print("3. Ağ Davranışı Analizi")
        print("4. Bellek Analizi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"malware_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if self.check_tool("cuckoo"):
            file = input("Analiz edilecek dosya: ")

            # Dosya türünü ve hash değerlerini kontrol et
            file_info = {
                "type": self.run_command(f"file {file}"),
                "md5": self.run_command(f"md5sum {file}"),
                "sha256": self.run_command(f"sha256sum {file}"),
            }

            print(f"\n{Fore.YELLOW}Dosya Bilgileri:{Style.RESET_ALL}")
            for key, value in file_info.items():
                print(f"{key.title()}: {value}")

            commands = {
                "1": [  # Statik Analiz
                    f"strings {file} > {output_dir}/strings.txt",
                    f"objdump -d {file} > {output_dir}/disassembly.txt",
                    f"ldd {file} > {output_dir}/dependencies.txt",
                ],
                "2": [  # Dinamik Analiz
                    f"cuckoo submit --timeout 300 {file}",
                    f"strace -f -o {output_dir}/syscalls.txt ./{file}",
                ],
                "3": [  # Ağ Analizi
                    f"tcpdump -i any -w {output_dir}/network.pcap",
                    f"cuckoo submit --timeout 300 --options network-routing=internet {file}",
                ],
                "4": [  # Bellek Analizi
                    f"volatility -f memory.dmp imageinfo > {output_dir}/memory_info.txt",
                    f"volatility -f memory.dmp malfind > {output_dir}/memory_scan.txt",
                ],
            }

            if choice in commands:
                print(f"\n{Fore.YELLOW}Analiz başlatılıyor...{Style.RESET_ALL}")

                # YARA kurallarını kontrol et
                if os.path.exists("/rules/malware"):
                    print("\nYARA taraması yapılıyor...")
                    self.run_command(
                        f"yara -r /rules/malware {file} > {output_dir}/yara_matches.txt"
                    )

                # Seçilen analizi çalıştır
                for cmd in commands[choice]:
                    self.run_command(cmd)

                # Detaylı rapor oluştur
                with open(f"{output_dir}/analysis_report.txt", "w") as f:
                    f.write("=== Zararlı Yazılım Analiz Raporu ===\n")
                    f.write(f"Tarih: {datetime.now()}\n")
                    f.write("\nDosya Bilgileri:\n")
                    for key, value in file_info.items():
                        f.write(f"{key.title()}: {value}\n")

                    # YARA eşleşmelerini kontrol et
                    if os.path.exists(f"{output_dir}/yara_matches.txt"):
                        f.write("\nYARA Eşleşmeleri:\n")
                        with open(f"{output_dir}/yara_matches.txt", "r") as yara_f:
                            f.write(yara_f.read())

                    # Cuckoo analiz sonuçlarını ekle
                    if choice in ["2", "3"]:
                        cuckoo_report = self.run_command("cuckoo report latest")
                        f.write("\nCuckoo Analiz Sonuçları:\n")
                        f.write(cuckoo_report if cuckoo_report is not None else "")

                # Virustotal kontrolü (opsiyonel)
                if input("\nVirustotal kontrolü yapılsın mı? (e/h): ").lower() == "e":
                    vt_api_key = input("Virustotal API anahtarı: ")
                    self.run_command(
                        f"vt-cli file {file_info['sha256']} -k {vt_api_key} > {output_dir}/virustotal.txt"
                    )

                print(
                    f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
                )

    def threat_hunting(self):
        """53. Tehdit Avcılığı"""
        print(f"\n{Fore.CYAN}Tehdit Avcılığı Seçenekleri:{Style.RESET_ALL}")
        print("1. YARA Kuralları ile Tarama")
        print("2. Şüpheli Süreç Analizi")
        print("3. IOC Taraması")
        print("4. Sistem Anomali Tespiti")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"threat_hunting_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("yara"):
            print("\nYARA Tarama Seçenekleri:")
            print("1. Öntanımlı Kurallar")
            print("2. Özel Kurallar")
            print("3. Online Kural Güncelleme")

            rule_choice = input("Seçiminiz (1-3): ")
            target_path = input("Taranacak dizin: ")

            cmd = ""  # Initialize with empty string
            if rule_choice == "1":
                cmd = f"yara -r /rules/* {target_path} > {output_dir}/yara_results.txt"
            elif rule_choice == "2":
                rule_file = input("Kural dosyası: ")
                cmd = f"yara -r {rule_file} {target_path} > {output_dir}/custom_yara_results.txt"
            elif rule_choice == "3":
                # Online YARA kurallarını güncelle
                self.run_command(
                    "git clone https://github.com/Yara-Rules/rules.git /tmp/yara-rules"
                )
                cmd = f"yara -r /tmp/yara-rules/malware/* {target_path} > {output_dir}/updated_yara_results.txt"

            if cmd:  # Only run if cmd is not empty
                self.run_command(cmd)

        elif choice == "2":
            print("\nŞüpheli Süreç Analizi yapılıyor...")
            # Şüpheli süreçleri kontrol et
            self.run_command(
                f"ps aux | grep -i 'crypto\\|miner\\|malware' > {output_dir}/suspicious_processes.txt"
            )
            self.run_command(f"lsof -i > {output_dir}/network_connections.txt")

        elif choice == "3":
            print("\nIOC Taraması yapılıyor...")
            # IOC'leri kontrol et
            self.run_command(
                f"find / -type f -exec md5sum {{}} \\; > {output_dir}/file_hashes.txt"
            )
            self.run_command(f"netstat -antup > {output_dir}/network_ioc.txt")

        elif choice == "4":
            print("\nSistem Anomali Tespiti yapılıyor...")
            # Sistem anomalilerini kontrol et
            self.run_command(f"last > {output_dir}/login_history.txt")
            self.run_command(f"find / -mtime -1 -ls > {output_dir}/recent_changes.txt")

        # Sonuçları analiz et
        print(f"\n{Fore.YELLOW}Sonuçlar analiz ediliyor...{Style.RESET_ALL}")
        with open(f"{output_dir}/analysis_report.txt", "w") as f:
            f.write("=== Tehdit Avcılığı Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n\n")

            # Tespit edilen tehditleri say
            if os.path.exists(f"{output_dir}/yara_results.txt"):
                yara_result = self.run_command(f"wc -l {output_dir}/yara_results.txt")
                yara_hits = yara_result.split()[0] if yara_result else "0"
                f.write(f"YARA Eşleşmeleri: {yara_hits}\n")

            if os.path.exists(f"{output_dir}/suspicious_processes.txt"):
                suspicious_result = self.run_command(
                    f"wc -l {output_dir}/suspicious_processes.txt"
                )
                suspicious = suspicious_result.split()[0] if suspicious_result else "0"
                f.write(f"Şüpheli Süreç Sayısı: {suspicious}\n")

        print(
            f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def osint_gathering(self):
        """54. OSINT Bilgi Toplama"""
        print(f"\n{Fore.CYAN}OSINT Bilgi Toplama Seçenekleri:{Style.RESET_ALL}")
        print("1. E-posta Adresleri")
        print("2. Alt Domainler")
        print("3. Teknoloji Tespiti")
        print("4. Sosyal Medya Taraması")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"osint_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("theharvester"):
            domain = input("Hedef domain: ")
            sources = input("Kaynaklar (google,linkedin,github) [all]: ") or "all"
            limit = input("Sonuç limiti [500]: ") or "500"

            cmd = f"theharvester -d {domain} -l {limit} -b {sources}"
            self.run_command(f"{cmd} > {output_dir}/email_results.txt")

        elif choice == "2" and self.check_tool("subfinder"):
            domain = input("Hedef domain: ")
            self.run_command(f"subfinder -d {domain} -o {output_dir}/subdomains.txt")

        elif choice == "3" and self.check_tool("whatweb"):
            target = input("Hedef URL: ")
            self.run_command(f"whatweb -v {target} > {output_dir}/tech_stack.txt")

        elif choice == "4" and self.check_tool("sherlock"):
            username = input("Kullanıcı adı: ")
            self.run_command(
                f"sherlock {username} --output {output_dir}/social_media.txt"
            )

        # Sonuçları birleştir
        print(f"\n{Fore.YELLOW}Rapor oluşturuluyor...{Style.RESET_ALL}")
        with open(f"{output_dir}/osint_report.txt", "w") as f:
            f.write("=== OSINT Bilgi Toplama Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n\n")

            # Her bir sonuç dosyasını kontrol et ve ekle
            for result_file in os.listdir(output_dir):
                if result_file != "osint_report.txt":
                    with open(f"{output_dir}/{result_file}", "r") as rf:
                        f.write(f"=== {result_file} ===\n")
                        f.write(rf.read() + "\n\n")

        print(
            f"\n{Fore.GREEN}Bilgi toplama tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def reverse_engineering(self):
        """55. Tersine Mühendislik"""
        print(f"\n{Fore.CYAN}Tersine Mühendislik Seçenekleri:{Style.RESET_ALL}")
        print("1. Ghidra ile Analiz")
        print("2. Radare2 ile Analiz")
        print("3. Statik Analiz")
        print("4. Dinamik Analiz")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"reverse_eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        target_file = input("Analiz edilecek dosya: ")

        if choice == "1" and self.check_tool("ghidra"):
            project_name = input("Proje adı: ")
            cmd = f"ghidra -import {target_file} -postScript AnalyzeHeadless.java {project_name}"
            self.run_command(cmd)

        elif choice == "2" and self.check_tool("radare2"):
            # Radare2 ile analiz
            commands = [
                f"r2 -A {target_file} -qc 'afl' > {output_dir}/functions.txt",
                f"r2 -A {target_file} -qc 'iS' > {output_dir}/sections.txt",
                f"r2 -A {target_file} -qc 'iz' > {output_dir}/strings.txt",
            ]
            for command in commands:
                self.run_command(command)

        elif choice == "3":
            # Statik analiz
            self.run_command(f"file {target_file} > {output_dir}/file_info.txt")
            self.run_command(f"strings {target_file} > {output_dir}/strings.txt")
            self.run_command(f"objdump -d {target_file} > {output_dir}/disassembly.txt")

        elif choice == "4":
            # Dinamik analiz
            self.run_command(f"ltrace ./{target_file} > {output_dir}/library_calls.txt")
            self.run_command(f"strace ./{target_file} > {output_dir}/system_calls.txt")

        # Analiz raporu oluştur
        print(f"\n{Fore.YELLOW}Analiz raporu hazırlanıyor...{Style.RESET_ALL}")
        with open(f"{output_dir}/analysis_report.txt", "w") as f:
            f.write("=== Tersine Mühendislik Analiz Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n")
            f.write(f"Dosya: {target_file}\n\n")

            # Dosya bilgilerini ekle
            file_info = self.run_command(f"file {target_file}")
            if file_info:
                f.write(f"Dosya Bilgisi:\n{file_info}\n\n")

            # Tespit edilen fonksiyonları listele
            if os.path.exists(f"{output_dir}/functions.txt"):
                f.write("Tespit Edilen Fonksiyonlar:\n")
                f.write(self.run_command(f"cat {output_dir}/functions.txt") or "")

        print(
            f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def steganography(self):
        """56. Steganografi Analizi"""
        print(f"\n{Fore.CYAN}Steganografi Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Gizli Veri Çıkarma")
        print("2. Metadata Analizi")
        print("3. LSB Analizi")
        print("4. Görüntü Analizi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"stego_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        file = input("Analiz edilecek dosya: ")

        if choice == "1" and self.check_tool("steghide"):
            passphrase = input("Parola (varsa): ")
            cmd = f"steghide extract -sf {file}"
            if passphrase:
                cmd += f" -p {passphrase}"
            self.run_command(f"{cmd} -xf {output_dir}/extracted_data")

        elif choice == "2" and self.check_tool("exiftool"):
            self.run_command(f"exiftool {file} > {output_dir}/metadata.txt")

        elif choice == "3" and self.check_tool("stegolsb"):
            cmd = f"stegolsb steglsb -r -i {file} -o {output_dir}/lsb_output"
            self.run_command(cmd)

        elif choice == "4" and self.check_tool("imagemagick"):
            # Görüntü analizi
            commands = [
                f"identify -verbose {file} > {output_dir}/image_info.txt",
                f"convert {file} -separate {output_dir}/channels.png",
                f"convert {file} -edge 1 {output_dir}/edges.png",
            ]
            for cmd in commands:
                self.run_command(cmd)

        # Analiz raporu oluştur
        print(f"\n{Fore.YELLOW}Analiz raporu hazırlanıyor...{Style.RESET_ALL}")
        with open(f"{output_dir}/stego_report.txt", "w") as f:
            f.write("=== Steganografi Analiz Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n")
            f.write(f"Dosya: {file}\n\n")

            # Dosya bilgilerini ekle
            file_info = self.run_command(f"file {file}")
            f.write(f"Dosya Türü:\n{file_info}\n\n")

            # Metadata bilgilerini ekle
            if os.path.exists(f"{output_dir}/metadata.txt"):
                f.write("Metadata Bilgileri:\n")
                with open(f"{output_dir}/metadata.txt", "r") as mf:
                    f.write(mf.read())

        print(
            f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def crypto_analysis(self):
        """57. Kriptografik Analiz"""
        print(f"\n{Fore.CYAN}Kriptografik Analiz Seçenekleri:{Style.RESET_ALL}")
        print("1. Şifreleme Durumu")
        print("2. Hash Analizi")
        print("3. SSL/TLS Analizi")
        print("4. Şifreleme Algoritma Tespiti")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"crypto_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("cryptsetup"):
            # Disk şifreleme durumu
            self.run_command(f"cryptsetup status > {output_dir}/encryption_status.txt")
            self.run_command(f"dmsetup table > {output_dir}/dm_table.txt")

        elif choice == "2":
            file = input("Analiz edilecek dosya: ")
            # Çeşitli hash değerlerini hesapla
            algorithms = ["md5", "sha1", "sha256", "sha512"]
            with open(f"{output_dir}/hash_analysis.txt", "w") as f:
                for algo in algorithms:
                    hash_value = self.run_command(f"{algo}sum {file}")
                    f.write(f"{algo.upper()}: {hash_value}\n")

        elif choice == "3" and self.check_tool("openssl"):
            host = input("Hedef host: ")
            port = input("Port [443]: ") or "443"
            self.run_command(
                f"openssl s_client -connect {host}:{port} -showcerts > {output_dir}/ssl_analysis.txt"
            )

        elif choice == "4":
            file = input("Analiz edilecek dosya: ")
            # Şifreleme algoritması tespiti
            self.run_command(f"binwalk -B {file} > {output_dir}/crypto_patterns.txt")

        # Analiz raporu oluştur
        print(
            f"\n{Fore.YELLOW}Kriptografik analiz raporu hazırlanıyor...{Style.RESET_ALL}"
        )
        with open(f"{output_dir}/crypto_report.txt", "w") as f:
            f.write("=== Kriptografik Analiz Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n\n")

            # Her bir analiz sonucunu ekle
            for result_file in os.listdir(output_dir):
                if result_file != "crypto_report.txt":
                    f.write(f"=== {result_file} ===\n")
                    with open(f"{output_dir}/{result_file}", "r") as rf:
                        f.write(rf.read() + "\n\n")

        print(
            f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def container_security(self):
        """58. Konteyner Güvenliği"""
        print(f"\n{Fore.CYAN}Konteyner Güvenlik Seçenekleri:{Style.RESET_ALL}")
        print("1. Docker Güvenlik Taraması")
        print("2. Konteyner İzolasyon Kontrolü")
        print("3. İmaj Güvenlik Analizi")
        print("4. Kubernetes Güvenlik Denetimi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"container_security_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("docker"):
            print(
                f"\n{Fore.YELLOW}Docker güvenlik taraması başlatılıyor...{Style.RESET_ALL}"
            )
            # Aktif konteynerleri tara
            self.run_command(
                f"docker scan $(docker ps -q) > {output_dir}/container_scan.txt"
            )
            # Docker daemon güvenlik kontrolü
            self.run_command(
                f"docker info --format '{{.SecurityOptions}}' > {output_dir}/security_options.txt"
            )
            # Docker compose güvenlik kontrolü
            self.run_command(
                f"docker-compose config --services > {output_dir}/compose_services.txt"
            )

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}Konteyner izolasyon kontrolü yapılıyor...{Style.RESET_ALL}"
            )
            # Namespace izolasyonu
            self.run_command(f"ls -l /proc/*/ns > {output_dir}/namespace_isolation.txt")
            # Cgroup kontrolü
            self.run_command(f"cat /proc/self/cgroup > {output_dir}/cgroup_config.txt")
            # AppArmor profilleri
            self.run_command(f"aa-status > {output_dir}/apparmor_status.txt")

        elif choice == "3" and self.check_tool("trivy"):
            print(
                f"\n{Fore.YELLOW}İmaj güvenlik analizi başlatılıyor...{Style.RESET_ALL}"
            )
            images_output = self.run_command(
                "docker images --format '{{.Repository}}:{{.Tag}}'"
            )
            images = images_output.splitlines() if images_output else []
            for image in images:
                self.run_command(
                    f"trivy image {image} > {output_dir}/image_scan_{image.replace(':', '_')}.txt"
                )

        elif choice == "4" and self.check_tool("kubeaudit"):
            print(
                f"\n{Fore.YELLOW}Kubernetes güvenlik denetimi başlatılıyor...{Style.RESET_ALL}"
            )
            # Kubernetes cluster güvenlik denetimi
            self.run_command(f"kubeaudit all > {output_dir}/kubernetes_audit.txt")
            # Pod güvenlik politikaları
            self.run_command(
                f"kubectl get psp > {output_dir}/pod_security_policies.txt"
            )
            # Network politikaları
            self.run_command(
                f"kubectl get networkpolicies --all-namespaces > {output_dir}/network_policies.txt"
            )

        # Sonuçları analiz et ve rapor oluştur
        print(f"\n{Fore.YELLOW}Güvenlik raporu oluşturuluyor...{Style.RESET_ALL}")
        with open(f"{output_dir}/security_report.txt", "w") as f:
            f.write("=== Konteyner Güvenlik Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n\n")

            # Docker versiyonu ve güvenlik özellikleri
            if self.check_tool("docker"):
                f.write("Docker Güvenlik Özellikleri:\n")
                docker_version = self.run_command("docker version")
                docker_info = self.run_command("docker info")
                if docker_version:
                    f.write(docker_version + "\n")
                if docker_info:
                    f.write(docker_info + "\n\n")

            # Güvenlik açıklarının özeti
            f.write("Tespit Edilen Güvenlik Açıkları:\n")
            for file in os.listdir(output_dir):
                if file.endswith(".txt"):
                    with open(f"{output_dir}/{file}", "r") as rf:
                        content = rf.read()
                        if "vulnerability" in content.lower():
                            f.write(f"- {file}: Güvenlik açığı tespit edildi\n")

        print(
            f"\n{Fore.GREEN}Analiz tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def compliance_check(self):
        """59. Uyumluluk Kontrolü"""
        print(f"\n{Fore.CYAN}Uyumluluk Kontrol Seçenekleri:{Style.RESET_ALL}")
        print("1. GDPR Uyumluluk Kontrolü")
        print("2. PCI DSS Kontrolü")
        print("3. ISO 27001 Kontrolü")
        print("4. CIS Benchmark Kontrolü")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"compliance_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1":
            print(
                f"\n{Fore.YELLOW}GDPR uyumluluk kontrolü başlatılıyor...{Style.RESET_ALL}"
            )
            # Kişisel veri içeren dosyaları ara
            self.run_command(
                f"find / -type f -exec grep -l -i 'password\\|email\\|phone' {{}} \\; > {output_dir}/personal_data_files.txt"
            )
            # Log retention kontrolü
            self.run_command(
                f"find /var/log -type f -mtime +365 > {output_dir}/old_logs.txt"
            )
            # Veri şifreleme kontrolü
            self.run_command(
                f"grep -r 'ssl\\|tls\\|encrypt' /etc/ > {output_dir}/encryption_config.txt"
            )

        elif choice == "2" and self.check_tool("oscap"):
            print(f"\n{Fore.YELLOW}PCI DSS kontrolü başlatılıyor...{Style.RESET_ALL}")
            # Güvenlik duvarı kontrolü
            self.run_command(f"iptables -L > {output_dir}/firewall_rules.txt")
            # Güvenlik güncellemeleri kontrolü
            self.run_command(
                f"apt list --upgradable > {output_dir}/security_updates.txt"
            )
            # Antivirüs kontrolü
            self.run_command(f"freshclam --version > {output_dir}/antivirus_status.txt")

        elif choice == "3":
            print(f"\n{Fore.YELLOW}ISO 27001 kontrolü başlatılıyor...{Style.RESET_ALL}")
            # Erişim kontrol politikaları
            self.run_command(f"cat /etc/passwd > {output_dir}/user_access.txt")
            # Yedekleme politikaları
            self.run_command(
                f"find /backup -type f -mtime -7 > {output_dir}/recent_backups.txt"
            )
            # Güvenlik politikaları
            self.run_command(
                f"find /etc/security -type f -exec cat {{}} \\; > {output_dir}/security_policies.txt"
            )

        elif choice == "4" and self.check_tool("oscap"):
            print(
                f"\n{Fore.YELLOW}CIS benchmark kontrolü başlatılıyor...{Style.RESET_ALL}"
            )
            # CIS benchmark kontrolü
            self.run_command(
                f"oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
                --results {output_dir}/cis_results.xml \
                --report {output_dir}/cis_report.html \
                /usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml"
            )

        # Uyumluluk raporu oluştur
        print(f"\n{Fore.YELLOW}Uyumluluk raporu hazırlanıyor...{Style.RESET_ALL}")
        with open(f"{output_dir}/compliance_report.txt", "w") as f:
            f.write("=== Uyumluluk Kontrol Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n\n")

            # Kontrol sonuçlarını analiz et
            f.write("Uyumluluk Durumu:\n")
            for file in os.listdir(output_dir):
                if file.endswith(".txt"):
                    with open(f"{output_dir}/{file}", "r") as rf:
                        content = rf.read()
                        f.write(f"\n=== {file} ===\n")
                        f.write(f"Dosya boyutu: {len(content)} bytes\n")
                        f.write("İlk 500 karakter:\n")
                        f.write(content[:500] + "...\n")

        print(
            f"\n{Fore.GREEN}Kontrol tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def security_audit(self):
        """60. Güvenlik Denetimi"""
        print(f"\n{Fore.CYAN}Güvenlik Denetim Seçenekleri:{Style.RESET_ALL}")
        print("1. Sistem Güvenlik Denetimi")
        print("2. Ağ Güvenlik Denetimi")
        print("3. Uygulama Güvenlik Denetimi")
        print("4. Kullanıcı Güvenlik Denetimi")

        choice = input("\nSeçiminiz (1-4): ")
        output_dir = f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)

        if choice == "1" and self.check_tool("lynis"):
            print(
                f"\n{Fore.YELLOW}Sistem güvenlik denetimi başlatılıyor...{Style.RESET_ALL}"
            )
            # Lynis ile detaylı sistem denetimi
            self.run_command(
                f"lynis audit system --pentest --verbose > {output_dir}/system_audit.txt",
                sudo=True,
            )
            # AIDE ile dosya bütünlük kontrolü
            self.run_command(
                f"aide --check > {output_dir}/integrity_check.txt", sudo=True
            )
            # Rootkit kontrolü
            self.run_command(
                f"rkhunter --check --skip-keypress > {output_dir}/rootkit_check.txt",
                sudo=True,
            )

        elif choice == "2":
            print(
                f"\n{Fore.YELLOW}Ağ güvenlik denetimi başlatılıyor...{Style.RESET_ALL}"
            )
            # Açık port taraması
            self.run_command(
                f"nmap -sS -sV localhost > {output_dir}/port_scan.txt", sudo=True
            )
            # Güvenlik duvarı kuralları
            self.run_command(
                f"iptables -L -n -v > {output_dir}/firewall_rules.txt", sudo=True
            )
            # Ağ bağlantıları
            self.run_command(f"netstat -tuln > {output_dir}/network_connections.txt")

        elif choice == "3":
            print(
                f"\n{Fore.YELLOW}Uygulama güvenlik denetimi başlatılıyor...{Style.RESET_ALL}"
            )
            # Yüklü paketlerin kontrolü
            self.run_command(f"dpkg -l > {output_dir}/installed_packages.txt")
            # Servis durumları
            self.run_command(
                f"systemctl list-units --type=service > {output_dir}/service_status.txt"
            )
            # Apache/Nginx yapılandırma kontrolü
            if self.check_tool("apache2"):
                self.run_command(
                    f"apache2ctl -t -D DUMP_VHOSTS > {output_dir}/apache_config.txt"
                )
            if self.check_tool("nginx"):
                self.run_command(f"nginx -T > {output_dir}/nginx_config.txt")

        elif choice == "4":
            print(
                f"\n{Fore.YELLOW}Kullanıcı güvenlik denetimi başlatılıyor...{Style.RESET_ALL}"
            )
            # Kullanıcı hakları
            self.run_command(
                f"for user in $(cut -d: -f1 /etc/passwd); do groups $user; done > {output_dir}/user_groups.txt"
            )
            # Sudo yapılandırması
            self.run_command(
                f"cat /etc/sudoers > {output_dir}/sudo_config.txt", sudo=True
            )
            # SSH yapılandırması
            self.run_command(f"cat /etc/ssh/sshd_config > {output_dir}/ssh_config.txt")

        # Denetim raporu oluştur
        print(f"\n{Fore.YELLOW}Denetim raporu hazırlanıyor...{Style.RESET_ALL}")
        with open(f"{output_dir}/audit_report.txt", "w") as f:
            f.write("=== Güvenlik Denetim Raporu ===\n")
            f.write(f"Tarih: {datetime.now()}\n\n")

            # Risk değerlendirmesi
            f.write("Risk Değerlendirmesi:\n")
            risk_levels = {"HIGH": [], "MEDIUM": [], "LOW": []}

            # Dosyaları analiz et ve risk seviyelerini belirle
            for file in os.listdir(output_dir):
                if file.endswith(".txt"):
                    with open(f"{output_dir}/{file}", "r") as rf:
                        content = rf.read().lower()
                        if "critical" in content or "high" in content:
                            risk_levels["HIGH"].append(file)
                        elif "warning" in content or "medium" in content:
                            risk_levels["MEDIUM"].append(file)
                        else:
                            risk_levels["LOW"].append(file)

            # Risk seviyelerini raporla
            for level, files in risk_levels.items():
                f.write(f"\n{level} Risk Level Issues:\n")
                for file in files:
                    f.write(f"- {file}\n")

        # Özet rapor göster
        print(f"\n{Fore.RED}Yüksek Riskli Bulgular: {len(risk_levels['HIGH'])}")
        print(f"{Fore.YELLOW}Orta Riskli Bulgular: {len(risk_levels['MEDIUM'])}")
        print(
            f"{Fore.GREEN}Düşük Riskli Bulgular: {len(risk_levels['LOW'])}{Style.RESET_ALL}"
        )
        print(
            f"\n{Fore.GREEN}Denetim tamamlandı. Sonuçlar {output_dir} dizininde.{Style.RESET_ALL}"
        )

    def system_performance(self):
        """61. Sistem Performans Analizi"""
        if self.check_tool("sysstat"):
            print(f"\n{Fore.CYAN}Sistem Performans Seçenekleri:{Style.RESET_ALL}")
            print("1. CPU Kullanımı")
            print("2. Bellek Kullanımı")
            print("3. Disk I/O")
            print("4. Ağ Performansı")
            print("5. Genel Sistem Yükü")

            choice = input("\nSeçiminiz (1-5): ")

            options = {
                "1": "mpstat 1 5",  # 5 saniye boyunca CPU kullanımı
                "2": "vmstat 1 5",  # 5 saniye boyunca bellek kullanımı
                "3": "iostat -x 1 5",  # Detaylı disk I/O istatistikleri
                "4": "sar -n DEV 1 5",  # Ağ arayüzü istatistikleri
                "5": "sar -u -r -d 1 5",  # Genel sistem performansı
            }

            command = options.get(choice)
            if command:
                self.run_command(command)

    def system_backup(self):
        """62. Sistem Yedekleme"""
        print(f"\n{Fore.CYAN}Yedekleme Seçenekleri:{Style.RESET_ALL}")
        print("1. Tam Sistem Yedekleme")
        print("2. Seçili Dizin Yedekleme")
        print("3. Yedek Listesi")
        print("4. Yedekten Geri Yükleme")

        choice = input("\nSeçiminiz (1-4): ")
        backup_dir = "/backup"
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")

        if choice == "1":
            output = f"{backup_dir}/system_backup_{date_str}.tar.gz"
            self.run_command(
                f"tar -czpf {output} --exclude=/proc --exclude=/tmp --exclude=/backup --exclude=/mnt --exclude=/dev --exclude=/sys --exclude=/run --exclude=/media --exclude=/var/log --exclude=/var/cache/apt/archives /",
                sudo=True,
            )

        elif choice == "2":
            path = input("Yedeklenecek dizin: ")
            output = f"{backup_dir}/{os.path.basename(path)}_{date_str}.tar.gz"
            self.run_command(f"tar -czf {output} {path}", sudo=True)

        elif choice == "3":
            self.run_command(f"ls -lh {backup_dir}")

        elif choice == "4":
            self.run_command(f"ls -lh {backup_dir}")
            backup_file = input("Geri yüklenecek yedek dosyası: ")
            restore_path = input("Geri yükleme dizini: ")
            self.run_command(f"tar -xzf {backup_file} -C {restore_path}", sudo=True)

    def system_cleanup(self):
        """63. Sistem Temizliği"""
        print(f"\n{Fore.CYAN}Temizlik Seçenekleri:{Style.RESET_ALL}")
        print("1. Önbellek Temizliği")
        print("2. Gereksiz Paketlerin Kaldırılması")
        print("3. Eski Log Dosyalarının Temizlenmesi")
        print("4. Geçici Dosyaların Temizlenmesi")
        print("5. Disk Alanı Analizi")

        choice = input("\nSeçiminiz (1-5): ")

        commands = {
            "1": [
                "sync",  # Disk önbelleğini temizle
                "echo 3 > /proc/sys/vm/drop_caches",  # Bellek önbelleğini temizle
                "apt-get clean",  # APT önbelleğini temizle
            ],
            "2": [
                "apt-get autoremove -y",  # Gereksiz paketleri kaldır
                "apt-get autoclean",  # Eski paket versiyonlarını temizle
            ],
            "3": [
                "find /var/log -type f -regex '.*\\.gz$' -delete",  # Sıkıştırılmış logları sil
                "find /var/log -type f -regex '.*\\.gz$' -delete",  # Sıkıştırılmış logları sil
            ],
            "4": [
                "rm -rf /tmp/*",  # Geçici dosyaları temizle
                "rm -rf ~/.cache/*",  # Kullanıcı önbelleğini temizle
            ],
            "5": [
                "du -sh /*",  # Kök dizindeki kullanımı göster
                "df -h",  # Disk kullanımını göster
            ],
        }

        if choice in commands:
            for cmd in commands[choice]:
                self.run_command(cmd, sudo=True)

    def show_installed_tools(self):
        """Sistemde kurulu olan araçları göster"""
        print(f"\n{Fore.CYAN}Sistemde Kurulu Olan Araçlar:{Style.RESET_ALL}")

        total_tools = len(self.required_tools)
        installed_tools = []
        missing_tools = []

        print("\nKontrol ediliyor...")

        for tool in self.required_tools:
            sys.stdout.write(
                f"\r{Fore.YELLOW}Kontrol ediliyor: {tool}{Style.RESET_ALL}"
            )
            sys.stdout.flush()

            if shutil.which(tool):
                version = ""
                try:
                    # Version bilgisini almaya çalış
                    result = subprocess.run(
                        [tool, "--version"],
                        capture_output=True,
                        text=True,
                        stderr=subprocess.STDOUT,
                        timeout=2,
                    )  # 2 saniyelik timeout
                    version = result.stdout.split("\n")[0]
                except:
                    version = "Sürüm bilgisi alınamadı"

                installed_tools.append((tool, version))
            else:
                missing_tools.append(tool)

        # Ekranı temizle
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

        # İstatistikleri göster
        print(f"\n{Fore.CYAN}Özet:{Style.RESET_ALL}")
        print(f"Toplam Araç Sayısı: {total_tools}")
        print(f"Kurulu Araç Sayısı: {len(installed_tools)}")
        print(f"Eksik Araç Sayısı: {len(missing_tools)}")

        # Kurulu araçları göster
        if installed_tools:
            print(f"\n{Fore.GREEN}Kurulu Araçlar:{Style.RESET_ALL}")
            for tool, version in installed_tools:
                truncated_version = (
                    version[:50] + "..." if len(version) > 50 else version
                )
                print(
                    f"{Fore.GREEN}✓ {tool:<20}{Style.RESET_ALL} - {truncated_version}"
                )

        # Eksik araçları göster
        if missing_tools:
            print(f"\n{Fore.RED}Kurulu Olmayan Araçlar:{Style.RESET_ALL}")
            for tool in missing_tools:
                print(f"{Fore.RED}✗ {tool}{Style.RESET_ALL}")

        # Eksik araçları kurmak ister misiniz?
        if missing_tools:
            if (
                input(
                    f"\n{Fore.YELLOW}Eksik araçları kurmak ister misiniz? (e/h): {Style.RESET_ALL}"
                ).lower()
                == "e"
            ):
                for tool in missing_tools:
                    print(f"\n{Fore.CYAN}Yükleniyor: {tool}{Style.RESET_ALL}")
                    if self.install_package(tool):
                        print(
                            f"{Fore.GREEN}{tool} başarıyla yüklendi.{Style.RESET_ALL}"
                        )
                    else:
                        print(f"{Fore.RED}{tool} yüklenemedi.{Style.RESET_ALL}")

    # Ana program başlatma
    def main(self):
        """Ana program döngüsü"""
        try:
            self.check_platform()

            # Terminal temizleme
            os.system("clear" if os.name == "posix" else "cls")

            # Araçları kontrol et ve kur
            self.check_security_tools()

            while True:
                # Banner'ı güncellemek için
                print(f"{Fore.CYAN}")
                print(
                    """
██╗     ██╗███╗   ███╗███╗   ███╗ █████╗ 
██║     ██║████╗ ████║████╗ ████║██╔══██╗
██║     ██║██╔████╔██║██╔████╔██║███████║
██║     ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║
███████╗██║██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
                """
                )
                print(f"{Style.RESET_ALL}")

                print(f"{Fore.YELLOW}Kategoriler:{Style.RESET_ALL}")
                print("1-10:  Temel Sistem Yönetimi")
                print("11-20: Güvenlik Taramaları")
                print("21-35: Ağ ve Sistem Güvenliği")
                print("36-45: Adli Analiz")
                print("46-55: Sızma Testi")
                print("56-64: İleri Seviye Güvenlik\n")

                options = {
                    # Temel Sistem Yönetimi (1-10)
                    1: ("Disk Alanı Kontrolü", self.check_disk_space),
                    2: ("RAM Kullanımı Kontrolü", self.check_ram_usage),
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
                    # İleri Seviye Güvenlik (56-64)
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

                # Seçenekleri renkli göster
                for key, (name, _) in options.items():
                    # Kategori rengini belirle
                    if 1 <= key <= 10:
                        category_color = Fore.GREEN
                    elif 11 <= key <= 20:
                        category_color = Fore.YELLOW
                    elif 21 <= key <= 35:
                        category_color = Fore.BLUE
                    elif 36 <= key <= 45:
                        category_color = Fore.MAGENTA
                    elif 46 <= key <= 64:
                        category_color = Fore.RED
                    else:
                        category_color = Fore.CYAN

                    print(f"{category_color}{key}. {name}{Style.RESET_ALL}")

                try:
                    choice = int(
                        input(f"\n{Fore.YELLOW}Seçiminiz (1-64): {Style.RESET_ALL}")
                    )
                    if choice in options:
                        name, func = options[choice]
                        print(f"\n{Fore.CYAN}=== {name} ==={Style.RESET_ALL}")
                        func()
                        input(
                            f"\n{Fore.CYAN}Devam etmek için Enter'a basın...{Style.RESET_ALL}"
                        )
                    else:
                        print(
                            f"{Fore.RED}Geçersiz seçim! Lütfen 1-64 arası bir sayı girin.{Style.RESET_ALL}"
                        )
                except ValueError:
                    print(f"{Fore.RED}Lütfen geçerli bir sayı girin.{Style.RESET_ALL}")
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Program kapatılıyor...{Style.RESET_ALL}")
                    return 0

        except Exception as e:
            logging.error(f"Program hatası: {str(e)}")
            print(f"{Fore.RED}Kritik hata: {str(e)}{Style.RESET_ALL}")
            return 1
        finally:
            self.executor.shutdown(wait=True)
            self.cleanup()
            return 0


if __name__ == "__main__":
    try:
        system_control = LinuxSystemControl()
        system_control.check_platform()  # Instance metodu olarak çağır
        system_control.main()
    except Exception as e:
        logging.error(f"Program başlatma hatası: {str(e)}")
        print(f"{Back.RED}Program başlatılamadı: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    finally:
        print(f"{Fore.GREEN}Program sonlandırıldı.{Style.RESET_ALL}")
