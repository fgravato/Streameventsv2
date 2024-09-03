import os
import json
import ast
import redis
import requests
from dotenv import load_dotenv
from sseclient import SSEClient
from colorama import Fore, init

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

# Function to stream and process events with specific types
def stream_and_process_events(access_token, event_types="THREAT,DEVICE,AUDIT"):
    headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'text/event-stream'}
    params = {'types': event_types}  # Filter by specified event types
    response = requests.get(EVENTS_STREAM_URL, headers=headers, params=params, stream=True)
    response.raise_for_status()
    client = SSEClient(response)
    
    for event in client.events():
        if event.event == 'heartbeat':
            continue  # Ignore heartbeat events
        elif event.event == 'events':
            try:
                event_data = json.loads(event.data)
                process_event(event_data)
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}Error decoding JSON: {str(e)}")
        else:
            print(f"{Fore.YELLOW}Unknown event received: {event}")

# Function to get user details from Redis
def get_user_details_from_redis(guid):
    user_data = r.get(guid)
    if user_data:
        try:
            return ast.literal_eval(user_data)
        except (ValueError, SyntaxError) as e:
            print(f"{Fore.RED}Error evaluating data for GUID {guid}: {str(e)}")
            return None
    print(f"{Fore.RED}No user data found in Redis for GUID: {guid}")
    return None

# Function to process each event
def process_event(event_data):
    events = event_data.get('events', [])
    for event in events:
        event_type = event.get('type', 'UNKNOWN')
        change_type = event.get('change_type', 'UNKNOWN')
        created_time = event.get('created_time', 'N/A')
        print(f"{Fore.CYAN}Event Type: {event_type}, Change Type: {change_type}, Created Time: {created_time}")
        
        # Process THREAT type events
        if event_type == 'THREAT':
            threat = event.get('threat', {})
            print(f"  Threat Type: {threat.get('type', 'N/A')}")
            print(f"  Severity: {threat.get('severity', 'N/A')}")
            print(f"  Status: {threat.get('status', 'N/A')}")
            print(f"  Classifications: {json.dumps(threat.get('classifications', []), indent=2)}")
            print(f"  Details: {json.dumps(threat.get('details', {}), indent=2)}")
        
        # Lookup user details from Redis using actor GUID
        actor_guid = event.get('actor', {}).get('guid', 'N/A')
        if actor_guid != 'N/A':
            user_details = get_user_details_from_redis(actor_guid)
            if user_details:
                print(f"{Fore.GREEN}User Email: {user_details.get('email', 'N/A')}")
                print(f"Device Model: {user_details.get('hardware', {}).get('model', 'N/A')}")
        
        print(f"  Actor GUID: {actor_guid}")
        print(f"  Target GUID: {event.get('target', {}).get('guid', 'N/A')}")
        print("\n" + "-"*60 + "\n")

if __name__ == "__main__":
    # Main entry point
    APPLICATION_KEY = os.getenv('APPLICATION_KEY')
    if not APPLICATION_KEY:
        raise ValueError("APPLICATION_KEY is missing in environment variables.")
    
    access_token, expires_in = get_access_token(APPLICATION_KEY)
    print(f"{Fore.BLUE}Obtained access token, expires in {expires_in} seconds.")
    
    # Start streaming and processing events, filtering by specific event types
    stream_and_process_events(access_token, event_types="THREAT,DEVICE,AUDIT")

