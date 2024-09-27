# Mobile Risk API (MRA) 2.0 Stream Viewer with S3 Integration

This project contains a script to interact with Version 2.0 of the Mobile Risk API (MRA), display event streams, manage user data in a Redis (KeyDB) datastore, and upload event data to Amazon S3.

## Version
2.0 Stream Viewer with User Identifier and S3 Integration

## Prerequisites

- Python 3.x
- KeyDB or Redis installed to store the data set
- AWS account with S3 access

## Dependencies

The project dependencies are listed in the `requirements.txt` file. You can install them using pip:

```
pip install -r requirements.txt
```

## Scripts

### improvedviewer-S3.py

This script processes the event stream from V2 of the Mobile Risk API, enriches it with user information from Redis, and uploads the event data to Amazon S3. It includes the following features:

- Authentication with the Mobile Risk API
- Streaming and processing of events (THREAT, DEVICE, AUDIT)
- User information lookup from Redis
- Logging of events and errors
- Uploading of event data to Amazon S3

Usage:
```
python improvedviewer-S3.py
```

## Setup

1. Clone this repository to your local machine.

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Ensure KeyDB or Redis is installed and running on your system.

4. Set up the API key and other environment variables:
   - Create a `production.env` file in the project root directory with the following content:
     ```
     APPLICATION_KEY=your_application_key_here
     KEYDB_HOST=your_keydb_host
     KEYDB_PORT=your_keydb_port
     S3_BUCKET_NAME=your_s3_bucket_name
     S3_REGION=your_s3_region
     ```

5. Configure AWS credentials:
   - Set up your AWS credentials using one of the methods described in the AWS documentation (e.g., AWS CLI configuration, environment variables, or IAM roles if running on an EC2 instance).

6. Run `improvedviewer-S3.py` to start viewing the event stream, enriching it with user information, and uploading to S3.

## Maintenance

Ensure that your Redis database is kept up to date with the latest user information. You may need to implement a separate script or process to periodically update this data.

## Security Note

Keep your `production.env` file and AWS credentials secure and do not commit them to version control systems. Ensure that your S3 bucket has appropriate access controls and encryption settings to protect the stored event data.
