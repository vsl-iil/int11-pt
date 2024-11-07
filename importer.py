# import.py
# Модуль импорта данных
#
# Львов Е.С., 2024
import requests
from pymisp import ExpandedPyMISP

# Запросы
last100query = {
    'query': 'get_recent',
    'selector': '100'
}


# https://stackoverflow.com/questions/5574702/how-do-i-print-to-stderr-in-python
# Удобно для отделения ошибок от всех логов:
# python feeder.py 2>err.log
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# Сделать запрос к API MalwareBazaar
def query_bazaar():
    r = requests.post('https://mb-api.abuse.ch/api/v1/', data=last100query)
    
    if r.status_code == 200:
        if status := r.json()['query_status'] == 'ok':
	        return r.json()['data']
        else:
            eprint(f'[!] MalwareBazaar вернул статус {status}')
    else:
        eprint(f'[!] MalwareBazaar вернул код {r.status_code}')

    return None

# Получить доп.данные о классе вредоноса из MISP-базы APT ETDA по имени
def query_etda(name):
    misp = ExtendedPyMISP('https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=t', '', '')
    result = misp.search(value=name, searchall=True, pythonify=True)

    if not result:
        eprint(f'[!] "{name}" не найдено в базе APT ETDA; дополнительная информация по категории недоступна')
        return None

    return result["meta"]["type"]


