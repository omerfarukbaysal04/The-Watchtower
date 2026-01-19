import yaml

def load_config():
    with open('config.yaml', 'r') as file:
        return yaml.safe_load(file)
    
if __name__ == "__main__":
    config = load_config()
    print(f"Tarama Sıklığı: {config['settings']['scan_interval']} saniye")
    print(f"Hedef Site: {config['targets'][0]['url']}")