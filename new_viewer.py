import os
import json
import time
import redis
import requests
import ast
from dotenv import load_dotenv
from sseclient import SSEClient
from colorama import Fore, Style, init

# Load environment variables and initialize colorama
load_dotenv('production.env')
init(autoreset=True)

# Initialize Redis (KeyDB) connection
KEYDB_HOST = os.getenv('KEYDB_HOST', 'localhost')
KEYDB_PORT = int(os.getenv('KEYDB_PORT', 6379))
r = redis.StrictRedis(host=KEYDB_HOST, port=KEYDB_PORT, decode_responses=True)

# Constants
LOOKOUT_API_URL = 'https://api.lookout.com'
TOKEN_URL = f'{LOOKOUT_API_URL}/oauth2/token'
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
        if event.event == 'heartbeat':
            continue  # Ignore heartbeat events
        elif event.event == 'events':
            print(f"{Fore.GREEN}Event received:")
            try:
                event_data = json.loads(event.data)
                process_event(event_data)
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}Error decoding JSON: {str(e)}")
        else:
            print(f"{Fore.YELLOW}Unknown event received: {event}")

# Function to process each event
def process_event(event_data):
    events = event_data.get('events', [])
    for event in events:
        actor = event.get('actor')
        if actor and actor.get('type') == 'DEVICE':
            guid = actor.get('guid')
            user_details = get_user_details_from_keydb(guid)
            if user_details:
                report_threat(event, user_details)
            else:
                print(f"{Fore.RED}No user details found in KeyDB for GUID: {guid}")

# Function to get user details from KeyDB
def get_user_details_from_keydb(guid):
    user_data = r.get(guid)
    if user_data:
        try:
            return ast.literal_eval(user_data)
        except (ValueError, SyntaxError) as e:
            print(f"{Fore.RED}Error evaluating data for GUID {guid}: {str(e)}")
            return None
    print(f"{Fore.RED}No user data found in KeyDB for GUID: {guid}")
    return None

# Function to report or log threat with user details
def report_threat(event, user_details):
    # Print a summary of the threat
    print(f"{Fore.CYAN}Threat Detected:")
    print(f"Threat Type: {event.get('threat', {}).get('type', 'N/A')}")
    print(f"Severity: {event.get('threat', {}).get('severity', 'N/A')}")
    print(f"User Email: {user_details.get('email', 'N/A')}")
    print(f"Device Model: {user_details.get('hardware', {}).get('model', 'N/A')}")
    print(f"Created Time: {event.get('created_time', 'N/A')}")
    
    # Handle classifications and details with fallback for missing data
    classifications = event.get('threat', {}).get('classifications', [])
    details = event.get('threat', {}).get('details', {})

    # Debugging information
    if not classifications:
        print(f"{Fore.YELLOW}No classifications found for this event.")
    if not details:
        print(f"{Fore.YELLOW}No details found for this event.")

    print(f"Classifications: {json.dumps(classifications, indent=2)}")
    print(f"Details: {json.dumps(details, indent=2)}")

if __name__ == "__main__":
    # Main entry point
    APPLICATION_KEY = os.getenv('APPLICATION_KEY')
    if not APPLICATION_KEY:
        raise ValueError("APPLICATION_KEY is missing in environment variables.")
    
    access_token, expires_in = get_access_token(APPLICATION_KEY)
    print(f"{Fore.BLUE}Obtained access token, expires in {expires_in} seconds.")
    
    # Start streaming and processing events
    stream_and_process_events(access_token)

