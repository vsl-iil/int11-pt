# feeder.py
# Модуль совмещения данных
# 
# Львов Е.С., 2024

import sys
import json

import importer
from util import eprint
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

etda_synonyms = ['meta', 'synonyms']
etda_type     = ['meta', 'type']

def main():
    feed = []

    # Получаем основные данные с MalwareBazaar (последние 100 записей)
    bazaar_list = importer.query_bazaar()
    if not bazaar_list:
        eprint('[-] Ошибка получения данных с MalwareBazaar.')
        exit(-1)

    for bzentry in bazaar_list:
        feed_entry = dict()

        feed_entry['md5']    = bzentry['md5_hash']
        feed_entry['sha256'] = bzentry['sha256_hash']
        # совмещение данных из поля signature (MalwareBazaar) и данных из APT ETDA
        #feed_entry['malware_class'] = importer.query_etda(bzentry['signature'], etda_type)
        #feed_entry['malware_family'] = [bzentry['signature']] + importer.query_etda(name, etda_synonyms)
        feed_entry['av_detects'] = importer.get_virustotal_scans(bzentry['md5_hash'])
        #feed_entry['threat_level']
        pprint(feed_entry)
        
        feed.append(feed_entry)


if __name__ == '__main__':
    main()

