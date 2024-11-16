import json

def export_to_jsonl(filename, entry):
    with open(filename, 'w') as f:
        line = json.dumps(entry)
        f.write(line)
        #print(line)
