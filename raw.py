import os
import requests
from dotenv import load_dotenv
from sseclient import SSEClient
from colorama import Fore, init

# Load environment variables and initialize colorama
load_dotenv('production.env')
init(autoreset=True)

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

# Function to stream and log raw event data
def stream_and_log_events(access_token):
    headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'text/event-stream'}
    response = requests.get(EVENTS_STREAM_URL, headers=headers, stream=True)
    response.raise_for_status()
    client = SSEClient(response)
    
    for event in client.events():
        if event.event == 'heartbeat':
            continue  # Ignore heartbeat events
        elif event.event == 'events':
            # Log the raw event data
            print(f"{Fore.YELLOW}Raw event data: {event.data}")
        else:
            print(f"{Fore.YELLOW}Unknown event received: {event}")

if __name__ == "__main__":
    # Main entry point
    APPLICATION_KEY = os.getenv('APPLICATION_KEY')
    if not APPLICATION_KEY:
        raise ValueError("APPLICATION_KEY is missing in environment variables.")
    
    access_token, expires_in = get_access_token(APPLICATION_KEY)
    print(f"{Fore.BLUE}Obtained access token, expires in {expires_in} seconds.")
    
    # Start streaming and logging raw events
    stream_and_log_events(access_token)

