

### Захист мережі від Ping Flood та DDoS-атак за допомогою Python і Fail2Ban

#### Вступ
Ping Flood — це тип DDoS-атаки, коли зловмисник надсилає велику кількість ICMP-запитів (ping) до цільової мережі, перевантажуючи її ресурси. У цьому матеріалі ми створимо скрипт на Python для виявлення підозрілої активності в мережі та інтегруємо його з Fail2Ban для автоматичного блокування атакуючих IP-адрес.

#### Ідея підходу
Перший ваш скрипт використовував Scapy для аналізу ICMP-пакетів і блокування IP через `iptables`. Другий підхід переніс логіку на моніторинг трафіку та запис підозрілих IP у лог-файл для Fail2Ban. Ми об'єднаємо ці ідеї:
- Використаємо Scapy для точного аналізу мережевих пакетів.
- Логуватимемо підозрілу активність у файл для Fail2Ban.
- Додамо гнучкість для моніторингу не лише ICMP, а й інших типів трафіку (наприклад, TCP).



```python
import time
from scapy.all import sniff, IP, ICMP, TCP
from collections import defaultdict
import os

# Налаштування параметрів
REQUEST_LIMIT = 10  # Максимальна кількість запитів від одного IP за CHECK_INTERVAL секунд
CHECK_INTERVAL = 10  # Інтервал перевірки у секундах
LOG_FILE = "/var/log/fail2ban_network_flood.log"  # Шлях до лог-файлу для Fail2Ban

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
```

#### Як працює скрипт?
1. **Аналіз пакетів**: Scapy відстежує ICMP (ping) і TCP-пакети, отримуючи IP-адресу відправника.
2. **Підрахунок запитів**: Для кожної IP зберігається список часових міток запитів за останні `CHECK_INTERVAL` секунд.
3. **Виявлення атаки**: Якщо кількість запитів перевищує `REQUEST_LIMIT`, IP вважається підозрілою.
4. **Логування**: Підозрілі IP записуються в лог-файл із часовою міткою.
5. **Fail2Ban**: Fail2Ban читає лог-файл і блокує IP через `iptables`.

#### Налаштування системи
Для роботи скрипта потрібно підготувати систему:

1. **Створення лог-файлу**:
   ```bash
   sudo touch /var/log/fail2ban_network_flood.log
   sudo chmod 666 /var/log/fail2ban_network_flood.log
   ```

2. **Налаштування фільтра Fail2Ban**:
   Створіть файл `/etc/fail2ban/filter.d/network-flood.conf`:
   ```ini
   [Definition]
   failregex = .*Suspicious activity from <HOST>
   ignoreregex =
   ```

3. **Додавання правила в Fail2Ban**:
   Відредагуйте `/etc/fail2ban/jail.local`:
   ```ini
   [network-flood]
   enabled = true
   filter = network-flood
   action = iptables-multiport[name=NetworkFlood, port="all", protocol="all"]
   logpath = /var/log/fail2ban_network_flood.log
   maxretry = 1
   bantime = 3600
   findtime = 10
   ```

4. **Перезапуск Fail2Ban**:
   ```bash
   sudo systemctl restart fail2ban
   ```

5. **Запуск скрипта**:
   Скрипт потрібно запускати з правами root через необхідність доступу до мережевих пакетів:
   ```bash
   sudo python3 network_protection.py
   ```

#### Переваги підходу
- **Автоматизація**: Fail2Ban самостійно блокує IP, не потребуючи ручного втручання через `iptables`.
- **Гнучкість**: Легко налаштувати пороги (`REQUEST_LIMIT`, `CHECK_INTERVAL`) та додати нові протоколи (UDP, наприклад).
- **Журналювання**: Усі підозрілі дії фіксуються в лог-файлі для подальшого аналізу.
- **Ефективність проти Ping Flood**: Скрипт добре справляється з атаками типу ICMP-флуду.

#### Недоліки
- **Обмеження по масштабах**: Не захистить від розподілених атак із великою кількістю унікальних IP.
- **Помилкові спрацьовування**: Легітимні користувачі з високою активністю можуть бути заблоковані.
- **Ресурси**: Scapy може споживати багато пам’яті при інтенсивному трафіку.

#### Покращення
1. **Додавання білого списку**: Дозвольте ігнорувати певні IP (наприклад, локальні адреси).
2. **Аналіз патернів**: Перевіряйте не лише кількість запитів, а й їхній вміст чи частоту.
3. **Інтеграція з мережевими інструментами**: Використовуйте апаратні рішення для масштабного захисту.

#### Висновок
Цей скрипт у поєднанні з Fail2Ban є ефективним рішенням для захисту локальної мережі від атак типу Ping Flood та схожих DDoS-атак. Він підходить для невеликих мереж або як основа для більш складних систем захисту. Для реального використання в критичних системах рекомендується додати професійні інструменти, такі як NGFW (Next-Generation Firewall) або хмарні сервіси.

