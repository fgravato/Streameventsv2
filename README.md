# Streameventsv2

raw_viewer.py 
 this will output raw display of the event stream from V2 of Lookout MES API

load_data.py
  this will load data into Redis(keydb) datastore for fast lookups on user device and email address based on guids

  improvedviewer.py 
     takes the idea of the raw_viewer.py and adds logic to check the keystore for user information.

    
   Make sure to copy application key to application.key and create production.env file with 
APPLICATION_KEY=

- 
