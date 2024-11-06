import sys
import json
import requests
# TODO удалить:
from pprint import pprint

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


def query_bazaar(data):
    r = requests.post('https://mb-api.abuse.ch/api/v1/', data=data)
    
    if r.status_code == 200:
        if status := r.json()['query_status'] == 'ok':
	        return r.json()['data']
        else:
            eprint(f'[!] MalwareBazaar вернул статус {status}')
    else:
        eprint(f'[!] MalwareBazaar вернул код {r.status_code}')

    return None

def main():
    feed = []

    # Получаем основные данные с MalwareBazaar (последние 100 записей)
    bazaar_list = query_bazaar(last100query)
    if not bazaar_list:
        eprint('[-] Ошибка получения данных с MalwareBazaar.')
        exit(-1)

    for bzentry in bazaar_list:
        feed_entry = dict()

        feed_entry['md5']    = bzentry['md5_hash']
        feed_entry['sha256'] = bzentry['sha256_hash']


if __name__ == '__main__':
    main()
