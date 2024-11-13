# feeder.py
# Модуль совмещения данных
# 
# Львов Е.С., 2024

import sys
import json
import logging

import importer
from util import eprint
import analytics
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
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s')

    feed = []

    # Получаем основные данные с MalwareBazaar (последние 100 записей)
    bazaar_list = importer.query_bazaar()
    if not bazaar_list:
        logging.error('Ошибка получения данных с MalwareBazaar.')
        exit(-1)

    for bzentry in bazaar_list:
        feed_entry = dict()
        name = bzentry['signature']
        #pprint(bzentry)

        feed_entry['md5']    = bzentry['md5_hash']
        feed_entry['sha256'] = bzentry['sha256_hash']

        # совмещение данных из поля signature (MalwareBazaar) и данных из APT ETDA
        feed_entry['malware_class'] = []
        feed_entry['malware_family'] = []
        if name != None:
            for etype in importer.query_etda(name, etda_type):
                translated = importer.get_malware_class(etype)
                if not translated: # None
                    logging.warning('Неизвестный тип из ETDA: {etype}')
                else:
                    feed_entry['malware_class'].append(translated)

            feed_entry['malware_family'] = [name] + importer.query_etda(name, etda_synonyms)
        else:
            logging.warning('Отсутствует signature для %s', feed_entry['md5'])

        feed_entry['av_detects'] = importer.get_virustotal_scans(bzentry['md5_hash'])
        feed_entry['threat_level'] = analytics.calculate_threat(feed_entry['malware_class'])
        pprint(feed_entry)
        
        feed.append(feed_entry)


if __name__ == '__main__':
    main()

