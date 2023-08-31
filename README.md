# EML Parser

This repository on GitLab contains the code for an application for parsing email files (`.eml`) and exporting to a comma separated value (`.csv`) file. The application classifies the content of the emails and stores them in the .csv file, making it easy to search and analyze large volumes of emails.

## Usage

1. Navigate to the cloned repository on your local machine. 
2. The application will now run and await input.
3. Click on the Upload Email button and select an .eml file
4. An additional work area will be displayed once the .eml has been parsed
5. To parse an `.eml` file, upload it to the application, and the parsed data will be saved to `email_data.csv` in the same directory.
 - Note! use the csv script or have a csv with the following fields before running the application: 
 - fieldnames = ['subject', 'display_name', 'recipient', 'ip_address', 'dmarc', 'spf', 'dkim', 'links', 'classification', 'additional_notes']


## to do

- add triage helper
- add AI modle for analyzing url 
- VT sender domain look up 
 - make more user friendly 

## Screenshots

![Screenshot 2023-08-29 172019](https://github.com/hat7r1ck/mail-triage/assets/110708720/499837a4-9006-4f28-963d-f0a493d12257)


![Screenshot 2023-08-29 172100](https://github.com/hat7r1ck/mail-triage/assets/110708720/4d407342-dd10-453d-a764-3e5b99027e5c)


![Screenshot 2023-08-31 090913](https://github.com/hat7r1ck/mail-triage/assets/110708720/1981ba80-f4d7-4063-985b-ad09c57615a7)
