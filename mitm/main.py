from scapy.all import ARP, Ether, srp, sniff, conf
import socket
import struct
import os
import platform
import ctypes


# Функція для перевірки прав адміністратора
def is_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    elif platform.system() == "Linux" or platform.system() == "Darwin":  # macOS
        return os.getuid() == 0  # os.getuid() замінює os.geteuid()
    else:
        return False


# Функція для отримання IP шлюза
def get_gateway_ip():
    try:
        if platform.system() == "Windows":
            gateway = [l for l in os.popen('netstat -rn | find "0.0.0.0"')][0].split()[2]
        else:
            gateway = [l for l in os.popen('ip route | grep default')][0].split()[2]
        return gateway
    except Exception as e:
        print(f"Не вдалося отримати IP шлюза: {e}")
        return None


# Функція для сканування мережі
def scan_network(ip_range):
    print(f"Сканування мережі: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


# Функція для аналізу пакетів (виявлення MitM)
def analyze_packet(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]
        print(f"ARP пакет: {arp.op} | Джерело: {arp.psrc} ({arp.hwsrc}) | Ціль: {arp.pdst}")
        if arp.op == 2:  # ARP-відповідь
            check_arp_spoofing(arp)


# Логіка для перевірки ARP-спуфінгу
arp_table = {}


def check_arp_spoofing(arp):
    ip = arp.psrc
    mac = arp.hwsrc
    if ip in arp_table:
        if arp_table[ip] != mac:
            print(f"Попередження: Можливий ARP-спуфінг! IP {ip} має нову MAC-адресу: {mac} (було: {arp_table[ip]})")
    else:
        arp_table[ip] = mac


# Основна функція
def main():
    # Отримати IP шлюза
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        return

    print(f"IP шлюза: {gateway_ip}")

    # Визначити діапазон мережі
    ip_base = ".".join(gateway_ip.split(".")[:-1]) + ".0/24"

    # Сканувати мережу
    devices = scan_network(ip_base)
    print("Знайдені пристрої в мережі:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    # Почати перехоплення трафіку
    print("Починаю аналіз трафіку для виявлення MitM...")
    sniff(prn=analyze_packet, filter="arp", store=0)


if __name__ == "__main__":
    # Перевірка прав адміністратора
    if not is_admin():
        print("Запустіть скрипт від імені адміністратора!")
        if platform.system() == "Windows":
            print("Спосіб: Клацніть правою кнопкою миші -> 'Запустити від імені адміністратора'")
        else:
            print("Спосіб: sudo python script.py")
    else:
        main()