# feeder.py
# Модуль совмещения данных
# 
# Львов Е.С., 2024

import sys
import json
import importer
# TODO удалить:
from pprint import pprint

# {
#	"md5": "...",
#	"sha256": "...",
#	"malware_class": ["...", ],
#	"malware_family": ["...", ],
#	"av_detects": ["...", ],
#	"threat_level": "..."	
#}
def main():
    feed = []

    # Получаем основные данные с MalwareBazaar (последние 100 записей)
    bazaar_list = importer.query_bazaar()
    if not bazaar_list:
        eprint('[-] Ошибка получения данных с MalwareBazaar.')
        exit(-1)

    pprint(bazaar_list)

    for bzentry in bazaar_list:
        feed_entry = dict()
        name = bzentry['signature']

        feed_entry['md5']    = bzentry['md5_hash']
        feed_entry['sha256'] = bzentry['sha256_hash']
        feed_entry['malware_class'] = list(importer.query_etda(name))
        # совмещение данных из поля signature (MalwareBazaar) и данных из APT ETDA
        feed_entry['malware_family'] = name


if __name__ == '__main__':
    main()
