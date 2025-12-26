import json
import os

from anssi_monitor.config.config import load_config

config = load_config()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_language(lang=config["locale"]):
    path = os.path.join(BASE_DIR, f'{lang}.json')
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

if __name__ == "__main__":
    print(load_language(lang=config["locale"]))