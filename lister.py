import os
import json
import time
import redis
import requests
from dotenv import load_dotenv
from sseclient import SSEClient

# Load environment variables
load_dotenv('production.env')

# Initialize Redis (KeyDB) connection
KEYDB_HOST = os.getenv('KEYDB_HOST', 'localhost')
KEYDB_PORT = int(os.getenv('KEYDB_PORT', 6379))
r = redis.StrictRedis(host=KEYDB_HOST, port=KEYDB_PORT, decode_responses=True)

# Constants
LOOKOUT_API_URL = 'https://api.lookout.com'
TOKEN_URL = f'{LOOKOUT_API_URL}/oauth2/token'
DEVICES_URL = f'{LOOKOUT_API_URL}/mra/api/v2/device'
EVENTS_STREAM_URL = f'{LOOKOUT_API_URL}/mra/stream/v2/events'

# Authentication function
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

# Function to stream and process events
def stream_and_process_events(access_token):
    headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'text/event-stream'}
    response = requests.get(EVENTS_STREAM_URL, headers=headers, stream=True)
    response.raise_for_status()
    client = SSEClient(response)
    for event in client.events():
        if event.event == 'events':
            print(f"Event received: {event.data}")
            try:
                event_data = json.loads(event.data)
                process_event(event_data)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {str(e)}")
        else:
            print(f"Unknown event received: {event}")

# Function to process each event
def process_event(event_data):
    if 'actor' in event_data:
        actor = event_data['actor']
        guid = actor.get('guid')
        actor_type = actor.get('type')
        
        if actor_type == 'DEVICE':
            device_details = get_device_details_from_keydb(guid)
            if device_details:
                report_threat(event_data, device_details)
            else:
                print(f"No device details found for GUID: {guid}")
        else:
            print(f"Unhandled actor type: {actor_type}")

# Function to get device details from KeyDB
def get_device_details_from_keydb(guid):
    device_data = r.get(guid)
    if device_data:
        return json.loads(device_data)
    return None

# Function to report or log threat with details
def report_threat(event_data, device_details):
    # Combine the event data with device details
    combined_data = {
        'event': event_data,
        'device_details': device_details
    }
    # Output the combined data (this could be expanded to log to a file or other systems)
    print(json.dumps(combined_data, indent=2))

if __name__ == "__main__":
    # Main entry point
    APPLICATION_KEY = os.getenv('APPLICATION_KEY')
    if not APPLICATION_KEY:
        raise ValueError("APPLICATION_KEY is missing in environment variables.")
    
    access_token, expires_in = get_access_token(APPLICATION_KEY)
    print(f"Obtained access token, expires in {expires_in} seconds.")
    
    # Start streaming and processing events
    stream_and_process_events(access_token)

