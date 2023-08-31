import os
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
import tkinter
from tkinter.ttk import Combobox
from tkinter.ttk import Separator
import email
import re
import csv
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
import requests

root = Tk()
root.title("Email Parser")

# Create a scale widget
font_size = IntVar()
font_scale = Scale(root, from_=12, to=20, orient=HORIZONTAL, variable=font_size)
font_scale.grid(row=0, column=0, pady=10)

#Set the default font size
font_size.set(14)

#Update the font size of the output when the scale is adjusted
def update_font_size(event):
    result_text.config(font=("Menlo", font_size.get()))

font_scale.bind("<ButtonRelease-1>", update_font_size)

# New email check function 
def check_if_new_email(subject, recipient):
    is_new_email = True
    last_classification = None
    with open('email_data.csv', 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['subject'] == subject and row['recipient'] == recipient:
                is_new_email = False
                last_classification = row['classification']
                break
    return is_new_email, last_classification

# get body contents 
def get_body():
    if email_message.is_multipart():
                for part in email_message.get_payload():
                    if part.get_content_type() in ['text/plain', 'text/html']:
                        return part.get_payload()
    else:
        return email_message.get_payload()

# Create a new frame for the additional work area
additional_work_area = Frame(root)
additional_work_area.grid(row=3, column=10, columnspan=10, padx=5, pady=5, sticky='nsew')

# Add widgets to the additional work area
text_box = Text(additional_work_area, font=("Menlo", 14), width=50, height=20, wrap=WORD)
text_box.pack()

# Initially hide the additional work area
additional_work_area.grid_remove()
additional_work_area_shown = False

# Create the other widgets
result_text = Text(root, font=("Menlo", 14), width=50, height=50, wrap=WORD)
result_text.grid(row=3, column=0, columnspan=5, padx=5, pady=5, sticky='nsew')

# Drop down widget
classification_var = StringVar(value='Triage')
classification_dropdown = Combobox(root, textvariable=classification_var)
classification_dropdown["values"]=['Phishing', 'Legit', 'Spoof', 'Spam']
classification_dropdown.grid(row=9, column=4, columnspan=1, padx=5, pady=5, sticky='nsew')

# visibility function for additional working area
def toggle_additional_work_area():
    global additional_work_area_shown
    if not additional_work_area_shown:
        additional_work_area.grid(row=3, column=10, columnspan=10, padx=5, pady=5, sticky='nsew')
        classification_dropdown.grid(row=9, column=4, columnspan=1, padx=5, pady=5, sticky='nsew')
        additional_work_area_shown = True
        toggle_additional_work_area_button = Button(root, text="Hide", command=toggle_additional_work_area)
        toggle_additional_work_area_button.grid(row=1, column=4, columnspan=1, padx=5, pady=5, sticky='nsew')
    else:
        additional_work_area.grid_remove()
        classification_dropdown.grid(row=9, column=4, columnspan=1, padx=5, pady=5, sticky='nsew')
        additional_work_area_shown = False
        toggle_additional_work_area_button = Button(root, text="Show", command=toggle_additional_work_area)
        toggle_additional_work_area_button.grid(row=1, column=4, columnspan=1, padx=5, pady=5, sticky='nsew')

# save classification function and button 
# save classification function and button 
def save_classification():
    subject = email_message['Subject']
    recipient = email_message['To']
    classification = classification_var.get()
    additional_notes = text_box.get(1.0, END)
    is_new_email, last_classification = check_if_new_email(subject, recipient)
    
    fieldnames = ['subject', 'display_name', 'recipient', 'ip_address', 'dmarc', 'spf', 'dkim', 'links', 'classification', 'additional_notes']

    if is_new_email:
        with open('email_data.csv', 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({'subject': subject, 'display_name': "", 'recipient': recipient, 'ip_address': "", 'dmarc': "", 'spf': "", 'dkim': "", 'links': "", 'classification': classification, 'additional_notes': additional_notes})
    else:
        rows = []
        with open('email_data.csv', 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row['subject'] == subject and row['recipient'] == recipient and row['classification'] == last_classification:
                    row['classification'] = classification
                    row['additional_notes'] = additional_notes.strip()  # Remove trailing newline
                rows.append(row)
        
        with open('email_data.csv', 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)

    messagebox.showinfo("Email Classification", f"Email classification updated from {last_classification} to {classification}")




save_classification_button = Button(additional_work_area, text="Save Classification", command=save_classification)


# upload email function 
# upload email function
def upload_email():
    global email_message
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw_email = f.read()
            # parse the email
            email_message = email.message_from_string(raw_email)
            subject = email_message.get('Subject', '')  # Use get method to handle missing subject
            recipient = email_message.get('To', '')  # Use get method to handle missing recipient
            body = get_body()

            # check if email is new or has been previously classified
            is_new_email, last_classification = check_if_new_email(subject, recipient)

            # Extract all the stuffs
            headers = email_message.items()
            dmarc = email_message.get("ARC-Authentication-Results: i=1")
            spf = email_message.get("Received-SPF")
            dkim = email_message.get("DKIM-Signature")
            display_name = email_message.get("from")
            ip_address = email_message.get("received", "").split(" ")[-1].strip("[]")
            links = re.findall(r'(https?://[^\s]+)', body)

     
            # show the additional work area
            toggle_additional_work_area()
            
            # enable the save classification button
            save_classification_button.config(state=NORMAL)
            classification_dropdown.grid(row=9, column=4, columnspan=1, padx=5, pady=5, sticky='nsew')

            #result text to GUI - to do: Use syntax highlighter to highlight header information
            result_text.delete(1.0, END)
            result_text.insert(INSERT, f"Is New Email: {is_new_email}\nLast Classification: {last_classification}\n\n---\n")
            result_text.insert(INSERT, f"Subject: {subject}\n")
            result_text.insert(INSERT, f"From: {display_name}\n")
            result_text.insert(INSERT, f"To: {recipient}\n")
            result_text.insert(INSERT, f"Originating IP: {ip_address}\n")
            result_text.insert(INSERT, f"DMARC: {dmarc}\n")
            result_text.insert(INSERT, f"SPF: {spf}\n")
            result_text.insert(INSERT, f"DKIM: {dkim}\n")
            result_text.insert(INSERT, "Links:\n" + '\n'.join(links) + "\n")

            clear_button.grid(row=1, column=2, pady=10)

            submit_button = Button(root, text="Submit", command=lambda: parse_and_classify(subject, recipient, display_name, ip_address, dmarc, spf, dkim, links, is_new_email, last_classification))
            submit_button.grid(row=9, column=0)
            
            additional_work_area_shown = True
            toggle_additional_work_area_button.config(text="Show")

    else:
        messagebox.showerror("Error", "Please select a file before trying to open it.")
        return


# parse and classify function 
def parse_and_classify(subject, recipient, display_name, ip_address, dmarc, spf, dkim, links, is_new_email, last_classification):
    classification = classification_dropdown.get()
    with open('email_data.csv', 'a') as csvfile:
        fieldnames = ['subject', 'display_name', 'recipient', 'ip_address', 'dmarc', 'spf', 'dkim', 'links', 'classification', 'additional_notes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writerow({'subject': subject, 'display_name': display_name, 'recipient': recipient, 'ip_address': ip_address, 'dmarc': dmarc, 'spf': spf, 'dkim': dkim, 'links': links, 'classification': classification, 'additional_notes': ""})
        csvfile.close()
    if is_new_email:
        messagebox.showinfo("Success", "New email and classification saved to CSV file.")
    else:
        messagebox.showinfo("Success", f"Email previously classified as {last_classification}.\n New classification: {classification} saved to CSV file.")


# VirusTotal API key
API_KEY = 'your_api_key'

# Function to send request to VirusTotal
def check_ip_at_virustotal(ip_address):
    api_key = 'YOUR_API_KEY'
    url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': api_key, 'ip': ip_address}
    response = requests.get(url, params=params)
    data = response.json()

def check_ip_button_clicked():
    check_ip_at_virustotal()


# Add VT button to the GUI
vt_result_label = Label(additional_work_area, text="")
vt_result_label.pack()
check_ip_button = Button(additional_work_area, text="Check IP at VirusTotal", command=check_ip_button_clicked)
check_ip_button.pack()


# Clearing the display window function
def clear_form():
    classification_var.set('')
    vt_result_label.config(text="")
    result_text.delete(1.0, END)
    text_box.delete(1.0, END)
    # root.mainloop()


# Create the buttons on gui 
save_classification_button = Button(additional_work_area, text="Save Classification", command=save_classification)
save_classification_button.pack()

toggle_additional_work_area_button = Button(root, text="Show", command=toggle_additional_work_area)
toggle_additional_work_area_button.grid(row=1, column=4, columnspan=1, padx=5, pady=5, sticky='nsew')

upload_button = Button(root, text="Upload Email", command=upload_email)
upload_button.grid(row=1, column=0, padx=5, pady=5)        

clear_button = Button(root, text="Clear", command=clear_form)
clear_button.grid(row=1, column=2, pady=10)


root.mainloop()
