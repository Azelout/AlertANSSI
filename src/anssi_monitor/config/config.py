import yaml
import os
from pathlib import Path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = Path(__file__).resolve().parents[3]

def load_config(file_path="./config.yaml"):
    path = os.path.join(BASE_DIR,file_path)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
    
if __name__ == "__main__":
    print(load_config())