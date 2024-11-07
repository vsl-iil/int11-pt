import sys

# https://stackoverflow.com/questions/5574702/how-do-i-print-to-stderr-in-python
# Удобно для отделения ошибок от всех логов:
# python feeder.py 2>err.log
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

