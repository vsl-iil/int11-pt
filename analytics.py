# analytics.py
# Модуль аналитики - назначает уровень угрозы 
#
# Львов Е.С., 2024

low_threat    = []
medium_threat = []
high_threat   = []

def calculate_threat(malwareclass):
    threat_level = {    # очередность важна
            "high": 0,
            "medium": 0,
            "low": 0
    }

    for cl in malwareclass:
        if cl in low_threat:
            threat_level["low"] += 1
        elif malwareclass in medium_threat:
            threat_level["medium"] += 1
        elif malwareclass in high_threat:
            threat_level["high"] += 1

    if max(threat_level.values()) == 0:
        return None
    
    return max(threat_level)
