# import.py
# Модуль импорта данных
#
# Львов Е.С., 2024
import requests
import os
import time
from pymisp import PyMISP
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
        eprint(f'[!] MalwareBazaar вернул статус {status}')
        return None

    if status := r.json()['query_status'] != 'ok':
        eprint(f'[!] MalwareBazaar вернул код {r.status_code}')
        return None

    return list(r.json()['data'])

# Получить доп.данные о вредоносе из MISP-базы APT ETDA по имени
def query_etda(name, jsonpath):
    misp = PyMISP('https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t', '-', '')
    result = misp.search(value=name, searchall=True, pythonify=True)

    if not result:
        eprint(f'[!] "{name}" не найдено в базе APT ETDA; дополнительная информация по категории недоступна')
        return None

    for field in jsonpath:
        result = result[field]

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
        eprint(f'[!] query_virustotal: Метод "{method}" не поддерживается')
        exit(-1)    # TODO заменить все exit на exception'ы?

def get_virustotal_scans(filehash):
    r = query_virustotal(filehash)

    if r.status_code == 404:
        r = query_virustotal(filehash, api_fun='analyse', method='post')
        if r.status_code != 200:
            eprint(f'[!] Ошибка сканирования нового файла VirusTotal: {r.status_code}')
            return None
        
        r = query_virustotal(filehash)

        if r.status_code != 200:
            eprint(f'[!] Ошибка VirusTotal: {r.status_code}')
            return None
    elif r.status_code == 400:
        eprint(f'[!] Ошибка авторизации на VirusTotal: {r.status_code}')
        return None

    # В наименованиях могут быть (и будут) повторы, поэтому set вместо списка
    result = set()
    for av in r.json()['data']['attributes']['last_analysis_results'].values():
        if av['category'] == 'malicious':
            result.add(av['result'])

    return list(result)

