import json

def export_to_jsonl(filename, entry):
    with open(filename, 'a') as f:
        line = json.dumps(entry)
        f.write(line+'\n')
        #print(line)
