paranoid-tun is a Tkinter-based GUI tool for Linux that prevents packet leaks through interfaces other than the VPN tunnel. It automatically detects active interfaces, identifies the active
VPN tunnel, and drops any packets attempting to bypass it.

IMPORTANT: DNS Handling
The tool automatically detects your VPN's DNS configuration. It sends a test DNS query to 1.1.1.1 through the tunnel. If the VPN configuration allows sending and receiving DNS 
queries through it, subsequent DNS requests are automatically routed via the tunnel. If the configuration doesn't allow DNS over the tunnel, queries fall back to the physical interface.
If DNS queries are being dropped even though the script marked the tunnel DNS test as passed, there is an "allow DNS via physical iface" button. When 
enabled, this forces DNS queries to be sent through the physical interface.

Firewall Marks & Monitoring:
The tool independently searches for existing fwmark rules (packets marked by the VPN) and adds them to the exceptions. To prevent bugs, the script monitors the connection state every second; if the tunnel drops, it removes the marks from the whitelist.
The script logs dropped packets and its own actions (excluding tunnel monitoring) to the system journal.

Requirements:
Linux with nftables, iproute2, and systemd (journalctl)
Python 3 with dnspython
root privileges (required for nft and journalctl)

Usage:
sudo python3 paranoid-tun.py
Bring up your VPN first.
Click RUN — the script will find the tunnel interface, test DNS through it, determine VPN marks, and set up the firewall table.
Click give up to remove the table and restore normal network operation.

Disclaimer:

This is a personal, paranoid tool, not a polished product. Please review the nft rules before relying on them.
The default-drop policy applies to all outbound system traffic — make sure your VPN and DNS are actually working before enabling it.
Interface detection is heuristic (prefixes tun/wg/tap/ppp + the first non-loopback interface with an IPv4 address). It may require manual tweaking in multi-interface or non-standard configurations.
If you forcefully kill the script, the firewall table will remain in the kernel. To fix this, either reboot your machine, or reopen the 
tool, click RUN (the script will find and load the orphaned table), and then click give up to remove it. GOOD LUCK


РУССКАЯ ВЕРСИЯ:

paranoid-tun, GUI инструмент на tkinter для linux систем, который предотвратит утечку ваших пакетов через интерфейсы отличные от vpn туннеля.
paranoid-tun автоматически определяет используемые интерфейсы, находит использующийся vpn туннель и дропает все пакеты которые пытаются пробиться вне туннеля.

ВАЖНО: Инструмент автоматически определяет конфигурацию вашего vpn по части dns (прокидывает тестовый dns запрос на 1.1.1.1 через туннель и если конфигурация vpn позволяет отправлять и принимать dns
запросы через него, то последующие dns запросы автоматически резолвятся на туннель). Если конфигурация не позволяет отправлять в туннель dns запросы то они летят через физический интерфейс.
Если dns запросы дропаются, хотя скрипт и пометил проверку dns запросов через туннель как пройденную, существует кнопка "allow DNS via physical iface", если данная функция включена днс запросы будут
отправляется через физический интерфейс.

Инструмент самостоятельно ищет существующие правила fwmark (пакеты подписанные vpn-ом) и добавляет их в исключения. Во избежание багов скрипт каждую секунду мониторит состояние подключения и если 
туннель падает, убирает марки из белого списка

Анамнез лоигрует дропнутые пакеты и действия скрипта (за исключением мониторинга туннеля).

ТРЕБОВАНИЯ:
Linux с nftables, iproute2, systemd (journalctl)
Python 3 с dnspython
root (нужен для nft и journalctl)

ИСПОЛЬЗОВАНИЕ:
sudo python3 paranoid-tun.py
Сначала поднимите VPN.
Нажмите RUN — скрипт найдёт интерфейс туннеля, проверит DNS через него, определит метки VPN и установит таблицу фаервола.
Нажмите give up, чтобы удалить таблицу и вернуть обычную работу сети.

ДИСКЛЕЙМЕР:
Это личный параноидальный инструмент, а не отточенный продукт. Просмотрите правила nft перед тем, как полагаться на них.
Политика default-drop применяется ко всему исходящему трафику системы — убедитесь, что VPN и DNS действительно работают, прежде чем включать её.
Определение интерфейсов эвристическое (префиксы tun/wg/tap/ppp + первый не loopback интерфейс с IPv4-адресом). В многоинтерфейсных или нестандартных конфигурациях может потребоваться правка.
При принудительном убийстве скрипта таблица останется в ядре, чтобы это исправить перезагрузите станцию или снова откройте инструмент, нажмите "RUN" (на этом этапе скрипт найдет осиротевшую таблицу и
удалит ее), нажмите "give up" для удаления таблицы. УДАЧИ
