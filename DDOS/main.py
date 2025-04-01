import time
from scapy.all import sniff, IP, ICMP, TCP
from collections import defaultdict
import os

# Налаштування параметрів
REQUEST_LIMIT = 10  # Максимальна кількість запитів від одного IP за CHECK_INTERVAL секунд
CHECK_INTERVAL = 10  # Інтервал перевірки у секундах
LOG_FILE = "fail2ban_network_flood.log"  # Шлях до лог-файлу для Fail2Ban

# Лічильники запитів від IP
request_counter = defaultdict(list)


def log_suspicious_ip(ip):
    """Логування підозрілої IP-адреси у файл для Fail2Ban."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, "a") as log:
        log.write(f"{timestamp} - Suspicious activity from {ip}\n")
    print(f"Підозріла активність від {ip} записана в лог.")


def packet_handler(packet):
    """Обробка вхідних мережевих пакетів."""
    current_time = time.time()

    # Перевіряємо, чи є IP-шар у пакеті
    if IP in packet:
        ip_src = packet[IP].src

        # Фільтруємо ICMP або TCP-пакети (можна додати інші протоколи)
        if packet.haslayer(ICMP) or packet.haslayer(TCP):
            # Очищаємо старі записи (старші за CHECK_INTERVAL секунд)
            request_counter[ip_src] = [t for t in request_counter[ip_src] if current_time - t < CHECK_INTERVAL]
            # Додаємо новий запит
            request_counter[ip_src].append(current_time)

            # Перевіряємо ліміт запитів
            if len(request_counter[ip_src]) > REQUEST_LIMIT:
                log_suspicious_ip(ip_src)
                del request_counter[ip_src]  # Очищаємо записи після логування


def monitor_traffic():
    """Запуск моніторингу мережевого трафіку."""
    print("Запуск моніторингу трафіку...")
    # Фільтруємо ICMP і TCP-пакети, store=0 для економії пам’яті
    sniff(filter="icmp or tcp", prn=packet_handler, store=0)


if __name__ == "__main__":
    # Перевіряємо наявність лог-файлу та права доступу
    if not os.path.exists(LOG_FILE):
        print(f"Лог-файл {LOG_FILE} не існує. Створіть його та перевірте права.")
    elif not os.access(LOG_FILE, os.W_OK):
        print(f"Немає прав на запис у {LOG_FILE}. Надайте права (наприклад, chmod 666).")
    else:
        monitor_traffic()