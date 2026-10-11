"""Port knowledge base: service names, risk levels and plain-language explanations."""

from __future__ import annotations

# port: (service, risk, English description, Turkish description)
# risk = how dangerous it is if reachable from an untrusted network.
PORT_INFO = {
    20: ("ftp-data", "low", "FTP data channel, used by active-mode FTP.",
         "FTP veri kanalı, aktif mod FTP'de kullanılır."),
    21: ("ftp", "high", "File Transfer Protocol. Sends passwords in plain text and often allows anonymous login. Prefer SFTP.",
         "Dosya aktarım protokolü. Parolaları düz metin gönderir, anonim giriş sık görülür. SFTP tercih et."),
    22: ("ssh", "low", "Secure Shell: remote login and file transfer. Safe with key auth, but a constant brute-force target. Disable password login.",
         "Uzak sunucu girişi ve dosya aktarımı. Anahtarla güvenlidir ama sürekli parola denemesine uğrar. Parolalı girişi kapat."),
    23: ("telnet", "high", "Telnet: remote shell with NO encryption. Credentials are visible on the network. Replace with SSH.",
         "Şifresiz uzak kabuk. Kullanıcı adı ve parola ağda açıkça görünür. SSH ile değiştir."),
    25: ("smtp", "medium", "Mail transfer (SMTP). Open relays get abused for spam; make sure relaying is restricted.",
         "E-posta aktarımı (SMTP). Açık röle spam için kötüye kullanılır; relay'in kısıtlı olduğundan emin ol."),
    53: ("dns", "low", "DNS server. Open resolvers can be abused for DDoS amplification; limit recursion.",
         "DNS sunucusu. Açık çözümleyiciler DDoS amplifikasyonunda kullanılır; recursion'ı kısıtla."),
    67: ("dhcp", "info", "DHCP: hands out IP addresses on the local network.",
         "DHCP: yerel ağda IP adresi dağıtır."),
    80: ("http", "low", "Unencrypted web server. Check what it serves and redirect to HTTPS.",
         "Şifresiz web sunucusu. Ne yayınladığına bak ve HTTPS'e yönlendir."),
    110: ("pop3", "medium", "POP3 mail retrieval. Logins are plain text unless wrapped in TLS (995).",
          "POP3 e-posta çekme. TLS (995) yoksa parola düz metin gider."),
    111: ("rpcbind", "medium", "RPC portmapper. Reveals which RPC services (e.g. NFS) run; should not be public.",
          "RPC portmapper. Hangi RPC servislerinin (ör. NFS) çalıştığını ifşa eder; internete açık olmamalı."),
    123: ("ntp", "low", "Time synchronization (NTP). Old versions can be abused for DDoS amplification.",
          "Saat senkronizasyonu (NTP). Eski sürümler DDoS amplifikasyonunda kullanılabilir."),
    135: ("msrpc", "medium", "Windows RPC endpoint mapper. Normal on Windows, but must not be reachable from the internet.",
          "Windows RPC. Windows'ta normaldir ama internetten erişilebilir olmamalı."),
    139: ("netbios-ssn", "high", "NetBIOS session service (legacy Windows file sharing). Leaks host info; block from untrusted networks.",
          "NetBIOS oturum servisi (eski Windows dosya paylaşımı). Makine bilgisi sızdırır; güvenilmeyen ağlardan engelle."),
    143: ("imap", "medium", "IMAP mail access. Logins are plain text unless TLS (993) is used.",
          "IMAP e-posta erişimi. TLS (993) yoksa parola düz metin gider."),
    161: ("snmp", "medium", "SNMP device management. Default community strings like 'public' expose a lot of information.",
          "SNMP cihaz yönetimi. 'public' gibi varsayılan community değerleri çok bilgi sızdırır."),
    389: ("ldap", "medium", "LDAP directory (e.g. Active Directory). Leaks user and group info if anonymous binds are allowed.",
          "LDAP dizin servisi (ör. Active Directory). Anonim bağlantıya izin varsa kullanıcı/grup bilgisi sızar."),
    443: ("https", "info", "Encrypted web server (HTTPS). Normal; verify certificate validity and TLS versions.",
          "Şifreli web sunucusu (HTTPS). Normaldir; sertifika ve TLS sürümlerini kontrol et."),
    445: ("smb", "high", "SMB: Windows file and printer sharing. Favorite target of ransomware and worms (EternalBlue, WannaCry). Never expose to the internet.",
          "SMB: Windows dosya ve yazıcı paylaşımı. Fidye yazılımı ve solucanların (EternalBlue, WannaCry) favori hedefi. İnternete asla açma."),
    465: ("smtps", "low", "SMTP over TLS (mail submission).",
          "TLS üzerinden SMTP (e-posta gönderimi)."),
    514: ("syslog", "medium", "Syslog log collection. No authentication, so anyone can inject fake log entries.",
          "Syslog log toplama. Kimlik doğrulama yok, herkes sahte log yazabilir."),
    587: ("submission", "low", "Mail submission (SMTP with STARTTLS/auth) used by mail clients.",
          "E-posta gönderimi (STARTTLS/kimlik doğrulamalı SMTP), mail istemcileri kullanır."),
    631: ("ipp", "low", "Printing service (IPP/CUPS). Disable it if you don't share printers.",
          "Yazıcı servisi (IPP/CUPS). Yazıcı paylaşmıyorsan kapat."),
    636: ("ldaps", "low", "LDAP over TLS.", "TLS üzerinden LDAP."),
    873: ("rsync", "medium", "rsync file sync. Misconfigured modules can expose files without a password.",
          "rsync dosya senkronizasyonu. Yanlış ayarlı modüller parolasız dosya ifşa edebilir."),
    993: ("imaps", "low", "IMAP over TLS (encrypted mail access).",
          "TLS üzerinden IMAP (şifreli e-posta erişimi)."),
    995: ("pop3s", "low", "POP3 over TLS (encrypted mail retrieval).",
          "TLS üzerinden POP3 (şifreli e-posta çekme)."),
    1080: ("socks", "medium", "SOCKS proxy. Open proxies are abused to hide attackers' traffic.",
           "SOCKS proxy. Açık proxy'ler saldırganların trafiğini gizlemek için kullanılır."),
    1433: ("mssql", "medium", "Microsoft SQL Server database. Databases should never be exposed to untrusted networks.",
           "Microsoft SQL Server veritabanı. Veritabanları güvenilmeyen ağlara açılmamalı."),
    1521: ("oracle", "medium", "Oracle database listener. Keep it off untrusted networks.",
           "Oracle veritabanı dinleyicisi. Güvenilmeyen ağlara açma."),
    1723: ("pptp", "medium", "PPTP VPN. Considered insecure; use WireGuard or OpenVPN instead.",
           "PPTP VPN. Güvensiz kabul edilir; WireGuard veya OpenVPN kullan."),
    2049: ("nfs", "high", "NFS network file system. Weak default authentication; exposed shares leak files.",
           "NFS ağ dosya sistemi. Zayıf varsayılan kimlik doğrulama; açık paylaşımlar dosya sızdırır."),
    2375: ("docker", "high", "Docker API WITHOUT TLS. Anyone who reaches it gets root-level control of the host.",
           "TLS'siz Docker API. Erişen herkes makinede root seviyesinde kontrol kazanır."),
    2376: ("docker-tls", "medium", "Docker API with TLS. Safe only with client certificates; keep it private.",
           "TLS'li Docker API. Sadece istemci sertifikasıyla güvenlidir; dışarı açma."),
    3000: ("dev-http", "low", "Common dev web server port (Node, React, Next.js, Grafana). Dev servers shouldn't be public.",
           "Yaygın geliştirme sunucusu portu (Node, React, Next.js, Grafana). Geliştirme sunucuları dışarı açılmamalı."),
    3306: ("mysql", "medium", "MySQL/MariaDB database. Databases should never be exposed to untrusted networks.",
           "MySQL/MariaDB veritabanı. Veritabanları güvenilmeyen ağlara açılmamalı."),
    3389: ("rdp", "high", "Remote Desktop. Top target for brute force and ransomware; use VPN, MFA and NLA.",
           "Uzak Masaüstü. Kaba kuvvet ve fidye yazılımlarının ana hedefi; VPN, MFA ve NLA kullan."),
    5000: ("http-alt", "low", "Alternate web port (Flask, Docker registry, UPnP...). Check what is running.",
           "Alternatif web portu (Flask, Docker registry, UPnP...). Neyin çalıştığına bak."),
    5432: ("postgresql", "medium", "PostgreSQL database. Databases should never be exposed to untrusted networks.",
           "PostgreSQL veritabanı. Veritabanları güvenilmeyen ağlara açılmamalı."),
    5601: ("kibana", "medium", "Kibana dashboard. Often exposed without authentication and leaks log data.",
           "Kibana paneli. Sık sık kimlik doğrulamasız açık kalır ve log verisi sızdırır."),
    5672: ("amqp", "medium", "RabbitMQ/AMQP message broker. Change the default 'guest' account.",
           "RabbitMQ/AMQP mesaj kuyruğu. Varsayılan 'guest' hesabını değiştir."),
    5900: ("vnc", "high", "VNC remote desktop. Weak or no encryption and often weak passwords.",
           "VNC uzak masaüstü. Şifreleme zayıf ya da yok, parolalar genelde zayıf."),
    6379: ("redis", "high", "Redis database. Often runs without a password and can lead to remote code execution when exposed.",
           "Redis veritabanı. Çoğu zaman parolasız çalışır, açıkta kalırsa uzaktan kod çalıştırmaya yol açabilir."),
    6443: ("kubernetes-api", "medium", "Kubernetes API server. Must require authentication; restrict to admins.",
           "Kubernetes API sunucusu. Kimlik doğrulama şart; sadece yöneticilere aç."),
    8000: ("http-alt", "low", "Alternate web port, often a dev server (e.g. python -m http.server, Django). Check what it serves.",
           "Alternatif web portu, genelde geliştirme sunucusu (ör. python -m http.server, Django). Ne yayınladığına bak."),
    8080: ("http-proxy", "low", "Alternate HTTP port: proxies, Tomcat, Jenkins or dev apps. Check what is behind it.",
           "Alternatif HTTP portu: proxy, Tomcat, Jenkins veya geliştirme uygulamaları. Arkasında ne olduğuna bak."),
    8443: ("https-alt", "low", "Alternate HTTPS port, often admin panels or APIs.",
           "Alternatif HTTPS portu, genelde yönetim paneli veya API."),
    8888: ("http-alt", "medium", "Alternate web port, often Jupyter Notebook, which allows code execution if unprotected.",
           "Alternatif web portu, genelde Jupyter Notebook; korumasızsa kod çalıştırılabilir."),
    9000: ("http-alt", "low", "Alternate web port (PHP-FPM, SonarQube, Portainer...). Check what is running.",
           "Alternatif web portu (PHP-FPM, SonarQube, Portainer...). Neyin çalıştığına bak."),
    9092: ("kafka", "medium", "Apache Kafka broker. Should only be reachable by trusted services.",
           "Apache Kafka broker. Sadece güvenilen servisler erişebilmeli."),
    9200: ("elasticsearch", "high", "Elasticsearch REST API. Frequently exposed without authentication, leaking entire datasets.",
           "Elasticsearch REST API. Sık sık kimlik doğrulamasız açık kalır, tüm veri setleri sızar."),
    11211: ("memcached", "high", "Memcached cache. No auth by default; exposed servers leak data and are abused for DDoS amplification.",
            "Memcached önbelleği. Varsayılanda kimlik doğrulama yok; açık sunucular veri sızdırır ve DDoS amplifikasyonunda kullanılır."),
    27017: ("mongodb", "high", "MongoDB database. Old defaults had no authentication; many data leaks came from exposed instances.",
            "MongoDB veritabanı. Eski varsayılanlarda kimlik doğrulama yoktu; birçok veri sızıntısı açık sunuculardan geldi."),
}

UNKNOWN = {
    "en": "No well-known service for this port. Find the owner with 'netstat -ano' (Windows) or 'ss -tlnp' (Linux).",
    "tr": "Bu port için bilinen bir servis yok. Sahibini bulmak için 'netstat -ano' (Windows) veya 'ss -tlnp' (Linux) kullan.",
}

SERVICES = {port: info[0] for port, info in PORT_INFO.items()}

HTTP_PORTS = {80, 3000, 5000, 5601, 8000, 8080, 8888, 9000, 9200}

TOP_PORTS = sorted(PORT_INFO)

RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def service_name(port: int) -> str:
    return SERVICES.get(port, "unknown")


def port_info(port: int, lang: str = "en") -> tuple[str, str]:
    """Return (risk, description) for a port in the requested language."""
    info = PORT_INFO.get(port)
    if info is None:
        return "info", UNKNOWN.get(lang, UNKNOWN["en"])
    return info[1], info[3] if lang == "tr" else info[2]
