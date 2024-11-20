# analytics.py
# Модуль аналитики - назначает уровень угрозы 
#
# Львов Е.С., 2024


# ПО, которое может использоваться в легитимных целях и встречается на компьютерах обычных пользователей, а также средства некоторые вероятные администрирования и программы, не имеющие явного вредоносного потенциала. Исключение - RemoteAdmin: ожидается, что штатный инструмент удалённого администрирования будет помещён в белый список в частном порядке.
low_threat = ["Spam", "Server-Telnet", "Server-FTP", "Server-Proxy", "Server-Web", "Client-IRC", "Client-P2P", "Client-SMTP", "Downloader", "Monitor", "WebToolbar", "NetTool", "Adware"]
# Программы, которые несут потенциальную угрозу системе и сети, однако их деятельность может быть перепутана с деятельностью некоторых легитимных программ со специфическим функционалом/ошибками реализации (напр. флуд может свидетельствовать о неверной работе какой-то программы)
medium_threat = ["RiskTool", "Dialer", "FraudTool", "PSWTool", "Hoax", "Flooder", "IM-Flooder", "SMS-Flooder", "Email-Flooder", "Spoofer"]
# Однозначно вредоносное ПО, за исключением того, что помещено в частном порядке в белый список.
high_threat = ["Virus", "Phishing", "HackTool", "Constructor", "RemoteAdmin", "VirTool", "DoS", "Trojan", "Exploit", "Trojan-FakeAV", "Trojan-ArcBomb", "Trojan-DDoS", "Trojan-Proxy", "Trojan-Notifier", "Trojan-Clicker", "Trojan-Downloader", "Trojan-Dropper", "Trojan-Ransom", "Trojan-Mailfinder", "Trojan-Spy", "Trojan-IM", "Trojan-SMS", "Trojan-GameThief", "Trojan-PSW", "Trojan-Banker", "Backdoor", "Rootkit", "Bootkit", "Virus", "Worm", "IRC-Worm", "IM-Worm", "P2P-Worm", "Email-Worm", "Net-Worm"]
# макросы vim рулят, вручную я бы всё это не вбил :)

def calculate_threat(malwareclass):
    threat_level = {    # очередность важна
            "high": 0,
            "medium": 0,
            "low": 0
    }

    for cl in malwareclass:
        if cl in low_threat:
            threat_level["low"] += 1
        elif cl in medium_threat:
            threat_level["medium"] += 1
        elif cl in high_threat:
            threat_level["high"] += 1

    if max(threat_level.values()) == 0:
        return None
    
    return max(threat_level)
