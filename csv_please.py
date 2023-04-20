import csv

# Create a new CSV file and write the fieldnames
with open('email_data.csv', 'w', newline='') as csvfile:
    fieldnames = ['subject', 'display_name', 'recipient', 'ip_address', 'dmarc', 'spf', 'dkim', 'links', 'classification', 'additional_notes']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
