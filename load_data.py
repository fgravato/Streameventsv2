import requests
import redis
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('production.env')

# Configuration
LOOKOUT_API_URL = "https://api.lookout.com"
TOKEN_URL = f"{LOOKOUT_API_URL}/oauth2/token"
DEVICES_URL = f"{LOOKOUT_API_URL}/mra/api/v2/devices"
KEYDB_HOST = "127.0.0.1"
KEYDB_PORT = 6379

# Get the application key from environment variables
APPLICATION_KEY = os.environ.get('APPLICATION_KEY')
if not APPLICATION_KEY:
    raise ValueError("APPLICATION_KEY environment variable is not set")

# Connect to KeyDB
r = redis.StrictRedis(host=KEYDB_HOST, port=KEYDB_PORT, decode_responses=True)

# Function to obtain an access token
def get_access_token(application_key):
    headers = {
        'Authorization': f'Bearer {application_key}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'client_credentials'
    }
    response = requests.post(TOKEN_URL, headers=headers, data=data)
    response.raise_for_status()  # Raise error for bad status
    token_info = response.json()
    return token_info['access_token'], token_info['expires_in']

# Function to get device data and store in KeyDB
def get_devices_data(access_token, limit=100):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json'
    }
    params = {
        'limit': limit
    }
    last_oid = None
    while True:
        if last_oid:
            params['oid'] = last_oid
        
        response = requests.get(DEVICES_URL, headers=headers, params=params)
        if response.status_code == 429:
            # Handle rate limiting by waiting before retrying
            time.sleep(10)
            continue
        
        response.raise_for_status()
        data = response.json()
        devices = data.get('devices', [])
        
        if not devices:
            break
        
        for device in devices:
            guid = device['guid']
            r.set(guid, str(device))
            last_oid = device['oid']
        
        if len(devices) < limit:
            break

if __name__ == "__main__":
    access_token, expires_in = get_access_token(APPLICATION_KEY)
    print(f"Obtained access token, expires in {expires_in} seconds.")
    
    get_devices_data(access_token, limit=100)
    print("Device data has been stored in KeyDB.")
