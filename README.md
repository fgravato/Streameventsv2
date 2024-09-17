# Mobile Risk API (MRA) 2.0 Stream Viewer

This project contains scripts to interact with Version 2.0 of the Mobile Risk API (MRA), display event streams, and manage user data in a Redis (KeyDB) datastore.

## Version
2.0 Stream Viewer with User Identifier

## Prerequisites

- Python 3.x
- KeyDB or Redis installed to store the data set

## Dependencies

The project requires the following Python libraries:

```
os
json
requests
dotenv
sseclient
colorama
redis
ast
time
```

You can install these dependencies using pip:

```
pip install requests python-dotenv sseclient-py colorama redis
```

## Scripts

### 1. raw_viewer.py

This script outputs a raw display of the event stream from V2 of the Mobile Risk API.

### 2. load_data.py

This script loads data into a Redis (KeyDB) datastore for fast lookups on user device and email address based on GUIDs. It should be run before `improvedviewer.py` to ensure all necessary data is available.

Usage:
```
python load_data.py
```

Note: This script should be scheduled to run periodically (e.g., daily or every few hours) to keep the data current. Consider setting up a cron job for this purpose.

### 3. improvedviewer.py

This script builds upon `raw_viewer.py` by adding logic to check the keystore for user information. It requires `load_data.py` to be run first to populate the datastore with the necessary information.

Usage:
```
python improvedviewer.py
```

## Setup

1. Clone this repository to your local machine.

2. Install the required dependencies:
   ```
   pip install requests python-dotenv sseclient-py colorama redis
   ```

3. Ensure KeyDB or Redis is installed and running on your system.

4. Set up the API key:
   - Copy your application key to a file named `application.key` in the project root directory.
   - Create a `production.env` file in the project root directory with the following content:
     ```
     APPLICATION_KEY=your_application_key_here
     ```

5. Run `load_data.py` to populate the Redis datastore with the latest data from the Tenant.

6. Run `improvedviewer.py` to start viewing the event stream with enhanced user information.

## Maintenance

Ensure that `load_data.py` is scheduled to run regularly to keep the datastore updated with the latest information from the Tenant. This can be done using a cron job or a similar scheduling mechanism.

## Security Note

Keep your `application.key` and `production.env` files secure and do not commit them to version control systems.

