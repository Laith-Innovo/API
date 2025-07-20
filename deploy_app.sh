#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration Variables ---
APP_DIR="/mnt/dietpi_userdata/innovo/www"
VENV_DIR="$APP_DIR/venv"
HA_BASE_DIR="/mnt/dietpi_userdata/homeassistant"
HA_STORAGE_DIR="$HA_BASE_DIR/.storage"
HA_KNX_DIR="$HA_BASE_DIR/knx" # The new directory from your config
# The user and group ID from your .env file
APP_UID=1000
APP_GID=1000
# The name of your main python file and the Flask app object
FLASK_APP_FILE="app"
FLASK_APP_OBJECT="app"
# Nginx configuration
NGINX_SNIPPET_DIR="/etc/nginx/snippets"
NGINX_SNIPPET_FILE="python_api_proxy.conf"
NGINX_SNIPPET_PATH="$NGINX_SNIPPET_DIR/$NGINX_SNIPPET_FILE"
NGINX_SITE_CONF="/etc/nginx/sites-available/default"
# Name for the systemd service
SERVICE_NAME="python-api"


# --- Helper Functions ---
function print_success { echo -e "\e[32mâ $1\e[0m"; }
function print_info { echo -e "\e[33mâ¹ $1\e[0m"; }
function print_error { echo -e "\e[31mâ $1\e[0m"; }

# --- Main Logic ---

# 1. Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root. Please use 'sudo ./deploy.sh'"
    exit 1
fi

print_info "Starting Full Python App Deployment..."

# 2. Check for prerequisites
if ! command -v python3 &> /dev/null; then print_error "python3 could not be found."; exit 1; fi
if ! dpkg -s python3-venv >/dev/null 2>&1; then print_error "'python3-venv' is not installed. Run 'sudo apt install python3-venv'."; exit 1; fi
if ! dpkg -s nginx >/dev/null 2>&1; then print_error "'nginx' is not installed. Run 'sudo apt install nginx'."; exit 1; fi

# 3. Create Application Directory Structure
print_info "Creating application directory structure..."
mkdir -p "$APP_DIR/public/client"
print_success "Directory structure created."

# 4. Setup Python Virtual Environment
print_info "Setting up Python virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    print_success "Virtual environment created."
else
    print_info "Virtual environment already exists."
fi

print_info "Installing/updating Python dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r /dev/stdin <<EOF
Flask
Flask-Cors
cryptography
python-dotenv
PyYAML
waitress
requests
EOF
print_success "Dependencies installed."

# 5. Create .env file
print_info "Creating .env file..."
cat > "$APP_DIR/.env" <<EOF
DEBUG=True
PORT=10111
PUBLIC_DIR=./public
CHECK_CONFIG=true
CHECK_CONFIG_API_URL=http://example.com/validate
SALT=c8a0b14e0b01a3d3e90119f16b7c77f9
IV=a34560ce9633d08e83a7b40323a119ba
UID=1000
GID=1000
EOF
print_success ".env file created."

# 6. Create initial config.json with your provided content
# ###########################################################
# ###  UPDATED SECTION: Pre-populating config.json        ###
# ###########################################################
print_info "Creating config.json with specified content..."
cat > "$APP_DIR/config.json" <<'EOF'
{"apiToken":"a34560ce9633d08e83a7b40323a119bab524bb6f8966de12f030b904d310edcb0d6ac3febe003528e0806e750894496397f5457f6b4f034cff6bbc9fdbe03e270fcfced694fbbfc6548c9a52b1a0e56392ac73b4b197ab49819eb554c0526a8fc22a41130859aff6923c2d57178bc19d58fc5b46fef3ed5d292a9aac92381b7d3ab9cfa08dc7707b36c7371117efd8be7ff0362bb2c688053bd6e5990d4b09f891c953ec5c7e41a71bcb96e05649494812c3eaa0039a703e05c2bae1520788dda9ad50280ea68487242e7c0b62d34571","directory":"/mnt/dietpi_userdata/homeassistant/knx"}
EOF
print_success "config.json created."

# 7. Create other initial data files
print_info "Creating initial data.json..."
touch "$APP_DIR/data.json"
print_success "Initial data.json created."

# 8. Create your app.py file (ensure you paste your full code here)
print_info "Creating app.py file..."
# IMPORTANT: Paste your full app.py code inside this block
cat > "$APP_DIR/app.py" <<'EOF'
# PASTE YOUR ENTIRE app.py SCRIPT CONTENT HERE
import os
import json
import yaml

import subprocess
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from dotenv import load_dotenv
from waitress import serve
from functools import lru_cache

import requests
import socket

from time import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUIRED_FILES = [
    "knx_climate.yaml",
    "knx_light.yaml",
    "knx_cover.yaml",
    "knx_weather.yaml",
    "knx_sensor.yaml",
    "knx_binary_sensor.yaml",
]

app = Flask(__name__)
CORS(app)

load_dotenv()

# Load environment variables
PORT = os.getenv('PORT', '10100')
PUBLIC_DIR = os.getenv('PUBLIC_DIR', './public')
CHECK_CONFIG = os.getenv('CHECK_CONFIG', 'true').lower() != 'false'
CHECK_CONFIG_API_URL = os.getenv('CHECK_CONFIG_API_URL')
SALT = os.getenv('SALT').encode()  # Convert to bytes
IV = bytes.fromhex(os.getenv("IV", "0"*32))  # 16 bytes for AES CBC

def assure_files_created():
    directory = None
    if os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            file = json.load(f)
            directory = file.get('directory')

    if directory:
        for file in REQUIRED_FILES:
            filename = f"{directory}/{file}"
            
            if not os.path.exists(filename):
                os.makedirs(directory, exist_ok=True)
                with open(filename, 'w') as f:
                    f.write('')
            
            # Note: Python doesn't have direct equivalents for chmod/chown with UID/GID
            # You might need platform-specific solutions here
            try:
                os.chmod(filename, 0o664)
                uid = int(os.getenv('UID', 1000))
                gid = int(os.getenv('GID', 1000))
                os.chown(filename, uid, gid)
            except:
                pass

assure_files_created()

def encrypt_message(message):
    cipher = Cipher(algorithms.AES(SALT), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad the message to be a multiple of 16 bytes
    pad_length = 16 - (len(message) % 16)
    message += chr(pad_length) * pad_length
    encrypted = encryptor.update(message.encode()) + encryptor.finalize()
    return IV.hex() + encrypted.hex()

def decrypt_message(encrypted_message):
    iv = bytes.fromhex(encrypted_message[:32])
    encrypted = bytes.fromhex(encrypted_message[32:])
    cipher = Cipher(algorithms.AES(SALT), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    # Remove padding
    pad_length = decrypted[-1]
    return decrypted[:-pad_length].decode()

@app.route('/api/v1/config', methods=['GET'])
def get_config():
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                return jsonify(json.load(f))
        return jsonify({})
    except:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/config_token', methods=['GET'])
def get_config_token():
    try:
        token = request.headers.get('token')
        if token != 'innovo':
            return jsonify({'message': 'Token is required'}), 401
            
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                file = json.load(f)
                return jsonify(file.get('apiToken', {}))
        return jsonify({})
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/config', methods=['POST'])
def post_config():
    current_config = {}
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                current_config = json.load(f)
    except:
        pass
    
    try:
        assure_files_created()
        config_json = request.json
        
        if 'apiToken' in config_json:
            config_json['apiToken'] = encrypt_message(config_json['apiToken'])
        
        with open('config.json', 'w') as f:
            json.dump({**current_config, **config_json}, f)
            
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/data', methods=['GET'])
def get_data():
    try:
        if os.path.exists('data.json'):
            with open('data.json', 'r') as f:
                return jsonify(json.load(f))
        return jsonify({})
    except:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/data', methods=['POST'])
def post_data():
    try:
        data_json = request.json
        with open('data.json', 'w') as f:
            json.dump(data_json, f)
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal server error'}), 500

async def fetch_check_config():
    #print(f"Pinging validation API: POST {CHECK_CONFIG_API_URL}")
    with open('config.json', 'r') as f:
        file = json.load(f)
        decrypted_token = decrypt_message(file['apiToken'])
    
    headers = {
        'Authorization': f'Bearer {decrypted_token}',
        'Content-Type': 'application/json'
    }
    
    # In Python, you would typically use requests library for HTTP calls
    import requests
    response = requests.post(CHECK_CONFIG_API_URL, headers=headers)
    response = response.json()
    
    if response.get('result') == 'invalid':
        return {'valid': False, 'errors': response.get('errors', [])}
    
    #print(response)
    return {'valid': True}

@app.route('/api/v1/backupFromYaml', methods=['POST'])
def backup_from_yaml():
    directory = './'
    directory_backup = 'backup'
    data_json_file = 'data.json'
    
    with open('config.json', 'r') as f:
        conf = json.load(f)
    
    if 'directory' in conf:  # Simplified path validation
        directory = conf['directory']
        directory_backup = f"{directory}/{directory_backup}"
    
    data_json_backup = f"{directory_backup}/{data_json_file}"
    merged_json = {}
    
    for file in REQUIRED_FILES:
        filename = f"{directory}/{file}"
        
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                data = f.read()
                yaml_data = yaml.safe_load(data)
                merged_json = {**merged_json, **yaml_data}
    
    #print("mergedJSON:", merged_json)
    json_data_all = json.dumps(merged_json)
    
    if not os.path.exists(directory_backup):
        os.makedirs(directory_backup, exist_ok=True)
    
    with open(data_json_backup, 'w') as f:
        f.write(json_data_all)
    
    return jsonify({'jsonDataAll': json_data_all})

@app.route('/api/v1/backup', methods=['POST'])
def backup():
    directory = './'
    directory_backup = '../../knx-backup'
    data_json_file = 'data.json'
    
    with open('config.json', 'r') as f:
        conf = json.load(f)
    
    if 'directory' in conf:  # Simplified path validation
        directory = conf['directory']
    
    if not os.path.exists(directory_backup):
        os.makedirs(directory_backup, exist_ok=True)
    
    data_json_backup = f"{directory_backup}/{data_json_file}"
    data_json_source = data_json_file
    
    # In Python, we use shutil for file operations
    import shutil
    shutil.copy2(data_json_source, data_json_backup)
    print('Yaml and Data backup done')
    
    return jsonify({})

def handle_json_item(data_json, item_type):
    print(f"handleJsonItem: {item_type}")
    new_data_json = []
    climate_json = []
    fan_json = []
    
    for json_item in data_json:
        main_type = json_item.get('mainType')
        sub_type = json_item.get('subType')
        
        if 'mainType' in json_item:
            del json_item['mainType']
        if 'subType' in json_item:
            del json_item['subType']
        
        try:
            if main_type == 'climate':
                climate_json.append(json_item)
            elif main_type == 'fan':
                fan_json.append(json_item)
            else:
                new_data_json.append(json_item)
        except Exception as e:
            print(e)
    
    if item_type == 'climate':
        new_data_json = {'climate': climate_json, 'fan': fan_json}
    elif item_type == 'binary_sensor':
        new_data_json = {'binary_sensor': new_data_json}
    elif item_type == 'sensor':
        new_data_json = {'sensor': new_data_json}
    elif item_type == 'cover':
        new_data_json = {'cover': new_data_json}
    elif item_type == 'light':
        new_data_json = {'light': new_data_json}
    elif item_type == 'weather':
        new_data_json = {'weather': new_data_json}
    
    return new_data_json

@app.route('/api/v1/restore', methods=['POST'])
def restore():
    print("restore")
    directory = './'
    directory_backup = '../../knx-backup'
    data_json_file = 'data.json'
    
    assure_files_created()
    
    with open('config.json', 'r') as f:
        conf = json.load(f)
    
    if 'directory' in conf:  # Simplified path validation
        directory = conf['directory']
    
    data_json_backup = f"{directory_backup}/{data_json_file}"
    data_json_source = data_json_file
    
    try:
        if os.path.exists(data_json_backup):
            with open(data_json_backup, 'r') as f:
                data_json = json.load(f)
            
            for file in REQUIRED_FILES:
                yaml_file = f"{directory}/{file}"
                
                if not os.path.exists(yaml_file):
                    type_name = file.replace('knx_', '').replace('.yaml', '')
                    file_data_json = data_json.get(type_name, [])
                    fixed_json = handle_json_item(file_data_json, type_name)
                    yaml_data = yaml.dump(fixed_json)
                    print("file:", file)
                    
                    with open(yaml_file, 'w') as f:
                        f.write(yaml_data)
            
            import shutil
            shutil.copy2(data_json_backup, data_json_source)
            print('Yaml and Data restored')
        
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/generate', methods=['POST'])
def generate():
    filename = request.json.get('filename')
    data = request.json.get('data')
    directory = './'
    
    try:
        assure_files_created()
        
        with open('config.json', 'r') as f:
            file = json.load(f)
        
        if 'directory' in file:  # Simplified path validation
            directory = file['directory']
            os.makedirs(directory, exist_ok=True)
        else:
            print("Path not found in config or is invalid. Using default path.")
        
        yaml_data = ""
        if data and len(data) > 0:
            yaml_data = yaml.dump(data)
        
        if CHECK_CONFIG:
            print("CHECK_CONFIG")
            with open(f"{directory}/{filename}", 'w') as f:
                f.write(yaml_data)
            
            result = fetch_check_config()
            print("valid:", result['valid'])
            
            if not result['valid']:
                print("not valid")
                with open(f"{directory}/{filename}", 'w') as f:
                    f.write("")
                # Note: Python doesn't have direct equivalents for chown with UID/GID
                return jsonify({'error': result.get('errors', 'Validation failed')}), 500
        
        return jsonify(yaml_data)
    except Exception as e:
        with open(f"{directory}/{filename}", 'w') as f:
            f.write("")
        print(e)
        return jsonify({'error': str(e)}), 500

def is_token_valid(token):
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        return encrypt_message(token) == config.get('apiToken')
    except:
        return False
    
def extract_token(token):
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1] if auth_header else None
    if token:
        return token
    else:
        return False

def get_local_ip():
    try:
        # This doesn't need to actually connect to the internet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"  # fallback to localhost
     
def extract_entry_info(entry):
    return {
        'domain': entry.get('domain'),
        'title': entry.get('title'), 
        'entry_id': entry.get('entry_id'),
        'unique_id': entry.get('unique_id'),
    }

def extract_entity_info(entity):
    result = {
        'entity_id': entity.get('entity_id'),
        'platform': entity.get('platform'), 
        'capabilities': entity.get('capabilities'), 
        'name': entity.get('name'), 
        'original_name': entity.get('original_name'), 
        'device_id': entity.get('device_id'), 
        'id': entity.get('id'), 
        'unique_id': entity.get('unique_id'), 
        'original_device_class': entity.get('original_device_class'), 
        'config_entry_id': entity.get('config_entry_id'), 
        'supported_features': entity.get('supported_features'),
        'translation_key': entity.get('translation_key'),
        'area_id': entity.get('area_id'),
    }

    swing_mode = entity.get('swing_mode')
    if swing_mode is not None:  # or just `if swing_mode:` to exclude falsy values
        result['swing_mode'] = swing_mode

    return result

@lru_cache(maxsize=3)
def load_registry_file(path):
    with open(path, 'r') as f:
        return json.load(f)
    
@app.route('/api/v1/entity', methods=['POST'])
def get_entity():
    try:
        data = request.get_json(force=True)
        platform = data.get('platform')
        entity_id = data.get('entity_id')
        original_device_class = data.get('original_device_class')
        config_entry_id = data.get('config_entry_id')
        device_id = data.get('device_id')
        key = data.get('key')
        value = data.get('value')
        areaId = data.get('area_id')
        where_clause = data.get('where_clause')

        if not any([platform, entity_id, original_device_class, config_entry_id, device_id, areaId, where_clause]):
            return jsonify({'message': 'At least one filter parameter is required'}), 400

        # Normalize to list if not already
        if platform and isinstance(platform, str):
            platform = [platform]
        if entity_id and isinstance(entity_id, str):
            entity_id = [entity_id]
        if key and isinstance(key, str):
            key = [key]
        if value and isinstance(value, str):
            value = [value]
        if areaId and isinstance(areaId, str):
            areaId = [areaId]

        # Token auth
        token = extract_token(request)
        if not token:
            return jsonify({'message': 'Token is required'}), 401

        if not is_token_valid(token):
            return jsonify({'message': 'Invalid Token.'}), 401

        registry = load_registry_file('/mnt/dietpi_userdata/homeassistant/.storage/core.entity_registry')
        entities = registry.get('data', {}).get('entities', [])

        # Get filtered entities
        try:
            filtered = get_filtered_entities(
                platform=platform,
                entity_id=entity_id,
                original_device_class=original_device_class,
                config_entry_id=config_entry_id,
                device_id=device_id,
                key=key,
                value=value,
                areaId=areaId,
                entities=entities,
                where_clause=where_clause,
                token=token
            )

            return jsonify({"entities": filtered})
        except ValueError as ve:
            return jsonify({'message': str(ve)}), 400
        except RuntimeError as re:
            return jsonify({'error': str(re)}), 500

    except Exception as e:
        print("Error in get_entity():", e)
        return jsonify({'error': 'Internal server error'}), 500

def get_filtered_entities(platform=None, entity_id=None, original_device_class=None,
                          config_entry_id=None, device_id=None, key=None, value=None,
                          entities=None, areaId=None, where_clause=None, token=None):
    if not isinstance(entities, list):
        raise ValueError("Invalid data structure in entity registry")

    def match_default_filters(entity):
        if platform:
            entity_platform = str(entity.get('platform', '')).lower()
            if not any(p.lower() == entity_platform for p in platform):
                return False
        if entity_id:
            entity_entity_id = str(entity.get('entity_id', '')).lower()
            normalized_ids = [eid.lower() + '.' if '.' not in eid else eid.lower() for eid in entity_id]
            if not any(entity_entity_id.startswith(eid_prefix) for eid_prefix in normalized_ids):
                return False
        if original_device_class and original_device_class.lower() != str(entity.get('original_device_class', '')).lower():
            return False
        if areaId:
            entity_area = str(entity.get('area_id', '')).lower()
            if isinstance(areaId, list):
                areaId_normalized = [str(a).lower() for a in areaId if isinstance(a, str)]
                if entity_area not in areaId_normalized:
                    return False
            else:
                if entity_area != str(areaId).lower():
                    return False
        if config_entry_id and config_entry_id.lower() != str(entity.get('config_entry_id', '')).lower():
            return False
        if device_id and device_id.lower() != str(entity.get('device_id', '')).lower():
            return False
        if key and value:
            found = False
            for k in key:
                entity_value = str(entity.get(k, '')).lower()
                if any(v.lower() in entity_value for v in value):
                    found = True
                    break
            if not found:
                return False
        return True

    def match_single_clause(clause, entity):
        clause_entity_id = clause.get("entity_id")
        clause_key = clause.get("key", [])
        clause_value = clause.get("value", [])

        if clause_entity_id:
            ent_id = str(entity.get('entity_id', '')).lower()
            if '.' not in clause_entity_id:
                if not ent_id.startswith(clause_entity_id.lower() + "."):
                    return False
            elif clause_entity_id.lower() != ent_id:
                return False

        if clause_key and clause_value:
            found = False
            for k in clause_key:
                val = str(entity.get(k, '')).lower()
                if any(v.lower() in val for v in clause_value):
                    found = True
                    break
            if not found:
                return False

        return True

    def matches(entity):
        if where_clause:
            return match_default_filters(entity) and any(match_single_clause(clause, entity) for clause in where_clause)
        else:
            return match_default_filters(entity)
    finalEntities = [extract_entity_info(e) for e in entities if matches(e)]
    # Get live states only once

    available_filtered_entities = []
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    ha_ip = get_local_ip()
    base_url = "https://"+ha_ip+":8123/api/states"

    for entity in finalEntities:
        eid = entity.get('entity_id')
        if not eid:
            continue

        try:
            response = requests.get(f"{base_url}/{eid}", headers=headers, verify=False)
            if response.status_code == 200:
                live = response.json()
                current_state = live.get('state')

                if current_state not in ['unavailable', 'unknown', None, '']:
                    entity['state'] = current_state
                    entity['attributes'] = live.get('attributes', {})
                    entity['available'] = True
                    available_filtered_entities.append(entity)
            else:
                print(f"Failed to fetch state for {eid}, status {response.status_code}")
        except requests.RequestException as e:
            print(f"Error fetching state for {eid}:", e)

    return available_filtered_entities  # Always return a list, even if empty"""

def extract_device_info(device):
    return {
        'config_entries': device.get('config_entries'), 
        'name': device.get('name'), 
        'name_by_user': device.get('name_by_user'),
        'id': device.get('id'),
        'model': device.get('model')
    }

@app.route('/api/v1/device', methods=['POST'])
def get_device():
    try:
        data = request.get_json(force=True)
        config_entries = data.get('config_entries')
        ids = data.get('id')
        entity = data.get('entity')
        include_entities = data.get('include_entities', False)
        entity_id = data.get('entity_id')
        key = data.get('key')
        value = data.get('value')
        areaId = data.get('area_id')
        where_clause = data.get('where_clause')

        if not config_entries and not ids and not entity and not areaId:
            return jsonify({'message': 'config_entries or id or entity is required'}), 400

        # Token auth
        token = extract_token(request)
        if not token:
            return jsonify({'message': 'Token is required'}), 401

        if not is_token_valid(token):
            return jsonify({'message': 'Invalid Token.'}), 401

        registry = load_registry_file('/mnt/dietpi_userdata/homeassistant/.storage/core.device_registry')
        devices = registry.get('data', {}).get('devices', [])

        if include_entities:
            registry = load_registry_file('/mnt/dietpi_userdata/homeassistant/.storage/core.entity_registry')
            entities = registry.get('data', {}).get('entities', [])

        # Filter entries
        try:
            #Get device by entity
            if entity:
                filtered_entities = get_filtered_entities(entity_id=entity, entities=entities, areaId=areaId, 
                                                          where_clause=where_clause, token=token)
                for entityNode in filtered_entities:
                    device_id = entityNode.get("device_id")
                    #print(f"device_id: {device_id}")
                    ids = []
                    ids.append(device_id)
                    filtered_devices = get_filtered_devices(ids=ids, devices=devices)
            else:
                filtered_devices = get_filtered_devices(config_entries, ids, devices=devices)
        except ValueError as ve:
            return jsonify({'message': str(ve)}), 400
        except RuntimeError as re:
            return jsonify({'error': str(re)}), 500
        #print(f"filtered_devices: {filtered_devices}")
        valid_devices = []

        if include_entities:
            for device in filtered_devices:
                device_id = device.get('id')
                if not device_id:
                    continue

                if entity_id:
                    entities_filtered  = get_filtered_entities(entity_id=entity_id, device_id=device_id, 
                                                               key=key, value=value, entities=entities,
                                                               where_clause=where_clause, token=token, 
                                                               areaId=areaId)
                    if entities_filtered:
                        device['entities'] = entities_filtered
                        valid_devices.append(device)  # ✅ only keep if entities found
                else:
                    entities_filtered = get_filtered_entities(device_id=device_id, key=key, value=value, 
                                                              entities=entities, where_clause=where_clause, 
                                                              token=token, areaId=areaId)
                    #print(f"entities_filtered: {entities_filtered}")
                    if entities_filtered:
                        device['entities'] = entities_filtered
                        valid_devices.append(device)  # ✅ only keep if entities found
        else:
            valid_devices = filtered_devices

        return jsonify({"devices": valid_devices})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def get_filtered_devices(config_entries=None, ids=None, devices=None):
    """Filter devices by config_entries, ids, or areaId, avoiding duplicates."""
    try:
        if not devices or not isinstance(devices, list):
            return jsonify({'message': 'Invalid data in file'}), 400

        filtered = []
        seen_ids = set()

        for device in devices:
            device_id = device.get('id')
            if not device_id or device_id in seen_ids:
                continue

            # Apply strict AND logic
            if config_entries and config_entries not in device.get('config_entries', []):
                continue
            if ids and device_id not in ids:
                continue

            filtered.append(extract_device_info(device))
            seen_ids.add(device_id)

        return filtered

    except Exception as e:
        #print(f"Error reading or processing devices file: {e}")
        return jsonify({'error': 'Failed to read device registry'}), 500

@app.route('/api/v1/entries', methods=['POST'])
def get_entries():
    try:
        data = request.get_json(force=True)
        entry_id = data.get('entry_id')
        domain = data.get('domain')
        include_devices = data.get('include_devices', False)
        include_entities = data.get('include_entities', False)
        entity_id = data.get('entity_id')
        key = data.get('key')
        value = data.get('value')
        areaId = data.get('area_id')
        where_clause = data.get('where_clause')

        if domain and isinstance(domain, str):
            domain = [domain]

        if not entry_id and not domain and not entity_id and not areaId:
            return jsonify({'message': 'entry_id or domain or entity_id or area id is required'}), 400

        # Authorization
        token = extract_token(request)
        if not token:
            return jsonify({'message': 'Token is required'}), 401

        if not is_token_valid(token):
            return jsonify({'message': 'Invalid Token.'}), 401

        registry = load_registry_file('/mnt/dietpi_userdata/homeassistant/.storage/core.config_entries')
        entries = registry.get('data', {}).get('entries', [])
        
        if include_devices or where_clause:
            registry = load_registry_file('/mnt/dietpi_userdata/homeassistant/.storage/core.device_registry')
            devices = registry.get('data', {}).get('devices', [])

        if include_entities or where_clause:
            registry = load_registry_file('/mnt/dietpi_userdata/homeassistant/.storage/core.entity_registry')
            entities = registry.get('data', {}).get('entities', [])

        # Filter entries
        try:
            #Get device by entity
            filtered_entries = []
            all_filtered_entries = get_filtered_entries(entry_id=entry_id, domain=domain, entries=entries)
            
            if not entry_id and not domain:
                matched_entities = get_filtered_entities(entity_id=entity_id, entities=entities, where_clause=where_clause, token=token, areaId=areaId)
                matched_entry_ids = set(e['config_entry_id'] for e in matched_entities)
                
                # Filter only entries that match BOTH domain and matched entities
                for entry in all_filtered_entries:
                    if entry['entry_id'] in matched_entry_ids:
                        filtered_entries.append(entry)
            else:
                #filtered_entries = get_filtered_entries(entry_id=entry_id, domain=domain, entries=entries)
                filtered_entries = all_filtered_entries
        except ValueError as ve:
            return jsonify({'message': str(ve)}), 400
        except RuntimeError as re:
            return jsonify({'error': str(re)}), 500
        
        if include_devices:
            final_entries = []

            for entry in filtered_entries:
                entry_id = entry.get('entry_id')
                #print(f"entry_id: {entry_id}")
                if not entry_id:
                    continue

                filtered_devices = get_filtered_devices(config_entries=entry_id, devices=devices)
                valid_devices = []
                #print(f"filtered_devices: {filtered_devices}")
                if include_entities:
                    for device in filtered_devices:
                        filteredEntities = []
                        device_id = device.get('id')
                        #print(f"device_id: {device_id}")
                        if not device_id:
                            continue

                        if entity_id:
                            filteredEntities = get_filtered_entities(entity_id=entity_id, device_id=device_id, value=value, 
                                                                     key=key, entities=entities, areaId=areaId,
                                                                     where_clause=where_clause, token=token)
                            if filteredEntities:
                                device['entities'] = filteredEntities
                                valid_devices.append(device)  # ✅ keep device only if entities were found
                        else:
                            filteredEntities = get_filtered_entities(device_id=device_id, key=key, value=value, 
                                                                     entities=entities, areaId=areaId, where_clause=where_clause, token=token)
                            if filteredEntities:
                                device['entities'] = filteredEntities
                                valid_devices.append(device)  # ✅ keep device only if entities were found
                else:
                    valid_devices = filtered_devices

                if valid_devices:  # ✅ only add entry if it has valid devices
                    entry['devices'] = valid_devices
                    final_entries.append(entry)

            filtered_entries = final_entries  # Use this in your response

                            
        return jsonify({"entries": filtered_entries})
    
    except Exception as e:
        #print("Error in get_entries():", e)
        return jsonify({'error': 'Internal server error'}), 500
    
def get_filtered_entries(entry_id=None, domain=None, entries=None):
    if not isinstance(entries, list):
        raise ValueError("Invalid data structure in config entries")

    filtered = []
    if not entry_id and not domain:
        for entry in entries:
            filtered.append(extract_entry_info(entry))
        return filtered
        
    for entry in entries:
        if entry_id and entry_id in entry.get('entry_id', ''):
            filtered.append(extract_entry_info(entry))
        elif domain:
            entry_domain = entry.get('domain', '')
            if any(d.lower() == entry_domain.lower() for d in domain):
                filtered.append(extract_entry_info(entry))
    
    return filtered

@app.route('/api/v1/schema', methods=['GET'])
def get_schema():
    #print("schema")
    try:
        result = subprocess.run(['curl', 'checkip.amazonaws.com'], capture_output=True, text=True)
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)
    except Exception as e:
        print("err:", e)
    
    return jsonify({})

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(os.path.join(PUBLIC_DIR, 'client', path)):
        return send_from_directory(os.path.join(PUBLIC_DIR, 'client'), path)
    else:
        return send_from_directory(os.path.join(PUBLIC_DIR, 'client'), 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)

EOF
print_success "app.py created. (Remember to paste your full code inside the script!)"


# 9. Set Permissions for App Directory
print_info "Setting ownership of $APP_DIR to $APP_UID:$APP_GID..."
chown -R "$APP_UID:$APP_GID" "$APP_DIR"
print_success "App directory permissions set."


# 10. Set Permissions for Home Assistant Directories (CRITICAL)
# ###########################################################
# ###  UPDATED SECTION: Handling write permissions for knx  ###
# ###########################################################
print_info "Setting permissions for Home Assistant access..."
if ! command -v setfacl &> /dev/null; then
    print_info "'acl' package not found. Installing..."
    apt-get update && apt-get install -y acl
    print_success "'acl' package installed."
fi

# A. Grant READ access to the .storage directory
if [ -d "$HA_STORAGE_DIR" ]; then
    print_info "Applying READ access for user $APP_UID to $HA_STORAGE_DIR"
    # -R: Recursive, -m: Modify, u:user, d:default. rX = read/execute
    setfacl -R -m u:$APP_UID:rX "$HA_STORAGE_DIR"
    setfacl -dR -m u:$APP_UID:rX "$HA_STORAGE_DIR"
    print_success "Read permissions for .storage set."
else
    print_error "Home Assistant .storage directory not found at $HA_STORAGE_DIR. This is a critical error."
    exit 1
fi

# B. Create and grant WRITE access to the knx directory
print_info "Applying WRITE access for user $APP_UID to $HA_KNX_DIR"
mkdir -p "$HA_KNX_DIR"
# rwx = read/write/execute. This allows the app to create/modify files.
setfacl -R -m u:$APP_UID:rwx "$HA_KNX_DIR"
setfacl -dR -m u:$APP_UID:rwx "$HA_KNX_DIR"
print_success "Write permissions for knx directory set."


# 11. Create systemd Service File
print_info "Creating systemd service file for '$SERVICE_NAME'..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Python Flask API Service
After=network.target

[Service]
User=$APP_UID
Group=$APP_GID
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$VENV_DIR/bin/waitress-serve --host=127.0.0.1 --port=\${PORT} $FLASK_APP_FILE:$FLASK_APP_OBJECT
Restart=always

[Install]
WantedBy=multi-user.target
EOF
print_success "Systemd service file created."

# 12. Setup Nginx
print_info "Configuring Nginx..."
mkdir -p "$NGINX_SNIPPET_DIR"
cat > "$NGINX_SNIPPET_PATH" <<EOF
# Python app (no auth) - Managed by deploy script
location /py {
    proxy_pass http://127.0.0.1:10111;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF
if ! grep -q "include $NGINX_SNIPPET_PATH;" "$NGINX_SITE_CONF"; then
    sed -i '/^\s*server\s*{/a \    include '"$NGINX_SNIPPET_PATH"';' "$NGINX_SITE_CONF"
fi
nginx -t && print_success "Nginx configuration is valid."


# 13. Reload Services
print_info "Reloading systemd and starting services..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service"
systemctl restart "$SERVICE_NAME.service"
systemctl reload nginx
print_success "Systemd reloaded and services have been restarted and enabled."

echo ""
print_success "Deployment complete!"
print_info "Check status with: sudo systemctl status $SERVICE_NAME"
print_info "View logs with:    sudo journalctl -u $SERVICE_NAME -f"