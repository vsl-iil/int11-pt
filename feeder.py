import sys
import json
import requests

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
        return r.json()['data']
    else:
        eprint(f'[!] MalwareBazaar вернул код {r.status_code}')
        return None

def main():
    print(query_bazaar(last100query))


if __name__ == '__main__':
    main()
