# importer.py
# Модуль импорта данных
#
# Львов Е.С., 2024
import requests
import json
import os
import time
import logging
from dotenv import load_dotenv

from util import eprint

# Запросы
last100query = {
    'query': 'get_recent',
    'selector': '100'
}

load_dotenv()
virustotal_headers = {
    'accept': 'application/json',
    'x-apikey': os.getenv('VIRUSTOTAL_KEY')
}


# Сделать запрос к API MalwareBazaar
def query_bazaar():
    r = requests.post('https://mb-api.abuse.ch/api/v1/', data=last100query)
    
    if r.status_code != 200:
        logging.warning('MalwareBazaar вернул статус %d', status)
        return None

    if status := r.json()['query_status'] != 'ok':
        logging.warning('MalwareBazaar вернул код %d', r.status_code)
        return None

    return list(r.json()['data'])

# Получить доп.данные о вредоносе из MISP-базы APT ETDA по имени
def query_etda(name, jsonpath):
    etda = ""
    if not os.path.isfile('etda.json'):
        with open('etda.json', 'w', encoding='utf-8') as f:
            etda = requests.get('https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t').text
            f.write(etda)
    else:
        with open('etda.json', 'r', encoding='utf-8') as f:
            etda = f.read()

    response = json.loads(etda)['values']

    result = None
    for obj in response:
        if obj['value'] == name or 'synonyms' in obj['meta'] and name in obj['meta']['synonyms']:
            result = obj
            break

    if not result:
        logging.warning('"%s" не найдено в базе APT ETDA; дополнительная информация по категории недоступна', name)
        return []

    for field in jsonpath:
        result = result.get(field)

    return list(result)

def query_virustotal(filehash, api_fun=None, method='get'):
    time.sleep(15)  # rate-limit VT - 4 запроса/минута
    url = f'https://www.virustotal.com/api/v3/files/{filehash}'
    if api_fun is not None:
        url += '/' + api_fun

    if method == 'get':
        return requests.get(url, headers=virustotal_headers)
    elif method == 'post':
        return requests.post(url, headers=virustotal_headers)
    else:
        logging.error('query_virustotal: Метод "%s" не поддерживается', method)
        exit(-1)    # TODO заменить все exit на exception'ы?

def get_virustotal_scans(filehash):
    r = query_virustotal(filehash)

    if r.status_code == 404:
        r = query_virustotal(filehash, api_fun='analyse', method='post')
        if r.status_code != 200:
            logging.warning('Ошибка сканирования нового файла VirusTotal: %d', r.status_code)
            return None
        
        r = query_virustotal(filehash)

        if r.status_code != 200:
            logging.warning('Ошибка VirusTotal: %d', r.status_code)
            return None
    elif r.status_code == 400:
        logging.warning('Ошибка авторизации на VirusTotal: %d', r.status_code)
        return None

    # В наименованиях могут быть (и будут) повторы, поэтому set вместо списка
    result = set()
    for av in r.json()['data']['attributes']['last_analysis_results'].values():
        if av['category'] == 'malicious':
            result.add(av['result'])

    return list(result)

# Принимает тип вредоносного ПО, заданный в ETDA, и транслирует термин
# в один из терминов, определённых в документе "Описание классов ВПО"
# при помощи ручного маппинга с наиболее близкими терминами.
# Список типов, используемых ETDA, взят из кода страницы поиска:
# https://apt.etda.or.th/cgi-bin/aptsearch.cgi
def get_malware_class(etda_class):
    mapping = {
        "0-day": "Exploit",
        "ATM malware": "Trojan-Banker",
        "Auto updater": "Downloader",   # очень странный тип, имеющийся только у одного 
                                        # нежелательного ПО, обозначенного `malware` в 
                                        # APT ETDA: https://apt.etda.or.th/cgi-bin/listgroups.cgi?t=AdobeARM
        "Backdoor": "Backdoor",
        "Banking trojan": "Trojan-Banker",
        "Big Game Hunting": "Trojan",         # не столько тип малвари, сколько способ использования
        "Botnet": "Trojan-DDoS",
        #"Compression": "",              # Ещё одно странное назначение: 
                                        # https://apt.etda.or.th/cgi-bin/listgroups.cgi?t=zl4vq%2Esqt
        "Control panel": "Hacktool",
        "Credential stealer": "Trojan-PSW",
        "DDoS": "Trojan-DDoS",
        "Downloader": "Trojan-Downloader",
        "Dropper": "Trojan-Dropper",
        "Exfiltration": "Trojan",
        "ICS malware": "Trojan",              # Industrial Control System
        "Info stealer": "Trojan-PSW",
        "Keylogger": "Trojan-Spy",
        "Loader": "Trojan-Dropper",           # Технически, может быть и Downloader 
                                              # - понятие Loader довольно общее.
        "Miner": "Trojan",
        "POS malware": "Trojan-Banker",       # Point-of-sale malware - атакует платёжные 
                                              # терминалы и кассы.
        #"Poisoning": ""                      # Имеется в виду cache poisoning - помещение
                                              # в кэш ложных данных, которые затем могут 
                                              # использоваться легитимными процессами;
                                              # пр. ARP poisoning, DNS poisoning
        "Ransomware": "Trojan-Ransom",
        "Reconnaissance": "Trojan-Spy",
        "Remote command": "RemoteAdmin",
        "Rootkit": "Rootkit",
        "SWIFT malware": "Trojan-Banker",
        "Tunneling": "Trojan-Proxy",
        "Vulnerability scanner": "HackTool",
        "Wiper": "Trojan",                    # Уничтожает данные.
        "Worm": "Worm",
    }
    return mapping.get(etda_class)          # None, если тип не найден в словаре
