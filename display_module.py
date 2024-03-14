import ttkbootstrap as tb
import tkinter as tk
from tkinter import ttk
from tkinter import *
import email
import re
from tkinter import filedialog
import base64
from tkinterhtml import HtmlFrame
import requests
import os
import magic
import hashlib
import email
from email.parser import BytesParser


class EmailProcessor:
    def __init__(self, file_name):
        self.file_name = file_name

    def select_file(self):
        filetypes = [('EML files', '*.eml'), ('All files', "*.*")]
        file_name = filedialog.askopenfilename(
            title='Select email file', initialdir='/home/kl45h/Desktop/MyProject/emails', filetypes=filetypes)
        if file_name:
            self.file_name = file_name
            return file_name
        else:
            return None

    def pass_email(self):
        if self.file_name:
            try:
                # open the eml file in read mode
                with open(self.file_name, 'rb') as email_file:
                    # parse the eml file content and create the message object
                    eml_message = email.message_from_binary_file(email_file)

                # extract the email contents
                date = eml_message['Date']
                sender = eml_message['From']
                receiver = eml_message['To']
                subject = eml_message['Subject']
                reply_to = eml_message['Reply-To']
                cc = eml_message['Cc']
                bcc = eml_message['Bcc']
                message_id = eml_message['Message-ID']
                originating_ip = eml_message['X-Originating-IP']
                email_body = eml_message['Body']

                origin_ip = originating_ip[1:-1] if originating_ip is not None else None

                match = re.search(r'@([A-Za-z0-9.-]+)', sender)
                if match:
                    origin_domain = match.group(1)
                else:
                    origin_domain = None

                # print the email contents
                e_headers = {'Date': date, 'Sender': sender, 'Reply-To': reply_to, 'Receiver': receiver,
                             'CC': cc, 'BCC': bcc, 'Subject': subject, 'Message ID': message_id,
                             'Originating IP': origin_ip}

                # extract urls from the email body, decode if base64 encoded and print them
                urls = self.extract_urls(eml_message)

                # Extract email body
                email_body, body_content = self.extract_body(eml_message)

                return e_headers, urls, email_body, body_content, eml_message, origin_ip, origin_domain
            except Exception as e:
                print("Error processing email:", e)
                return None
        else:
            return None

    def extract_urls(self, eml_message):
        urls = set()  # Use a set to avoid duplicates

        for part in eml_message.walk():
            if part.get_content_type() == "text/plain":
                urls.update(re.findall(r'(https?://\S+)', str(part.get_payload(decode=True))))
            # elif part.get_content_type() == "text/html":
            #     urls.update(re.findall(r'(https?://\S+)', str(part.get_payload(decode=True))))
        return list(urls)

    def extract_body(self, eml_message):
        email_body = ""
        body_content = ""
        for part in eml_message.walk():
            if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":
                body_content = part.get_payload(decode=True)
                # Decode if base64 encoded
                if part.get('Content-Transfer-Encoding') == 'base64':
                    body_content = base64.b64decode(body_content)
                # Insert the email body content into the Text widget
                email_body += body_content.decode("utf-8", errors="ignore")
        return email_body, body_content


class VirusTotalScanner:
    def __init__(self, origin_domain):
        self.origin_domain = origin_domain

    def perform_vt_scan(self):
        if not self.origin_domain:
            return None, None

        url = f"https://www.virustotal.com/api/v3/domains/{self.origin_domain}"
        api_key = "9ed7909202a8f10e55d5d75f2783bdcce01e1f15d2975e8c4c566ee4bf013440"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            vt_results = response.json()

            summary_intel = vt_results['data']['attributes']['last_analysis_stats']
            engines_intel = vt_results['data']['attributes']['last_analysis_results']

            return summary_intel, engines_intel
        except Exception as e:
            print("Error performing VirusTotal scan:", e)
            return None, None


class FileProcessor:
    def __init__(self, file_name):
        self.file_name = file_name

    def process_email(self):
        if not self.file_name:
            return None

        attachments = self.extract_attachments()

        results = []
        if attachments:
            for attachment in attachments:
                file_info = {
                    'filename': attachment['filename'],
                    'filesize': os.path.getsize(attachment['path']),
                    'filetype': self.identify_file_type(attachment['path']),
                    'md5': self.calculate_hash(attachment['path'], 'md5'),
                    'sha1': self.calculate_hash(attachment['path'], 'sha1'),
                    'sha256': self.calculate_hash(attachment['path'], 'sha256'),
                }
                results.append(file_info)
        else:
            results.append({"message": "No Attached Files"})

        return results

    def extract_attachments(self):
        if not self.file_name:
            return []

        attachments = []

        with open(self.file_name, 'rb') as f:
            msg = BytesParser().parse(f)

            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    attachment_info = {
                        'filename': part.get_filename(),
                        'path': self.save_attachment(part)
                    }
                    attachments.append(attachment_info)

        return attachments

    def save_attachment(self, part):
        filename = part.get_filename()
        file_path = os.path.join('attachments', filename)
        with open(file_path, 'wb') as f:
            f.write(part.get_payload(decode=True))
        return file_path

    def identify_file_type(self, file_path):
        mime = magic.Magic()
        return mime.from_file(file_path)

    def calculate_hash(self, file_path, algorithm):
        hasher = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()


class GUI:
    def __init__(self):
        self.file_name = 'emails/test2.eml'

    def display_page(self):
        root = tb.Window(themename='superhero')
        root.title('Output Window')
        root.geometry('1024x768')
        root.place_window_center()
        root.style.configure('long.TNotebook', tabposition='wn', foreground='red')

        # Create a menu bar
        menu_bar = tb.Menu(root)

        # Create File menu
        file_menu = tb.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New")
        file_menu.add_command(label="Open")
        file_menu.add_command(label="Save")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Create Edit menu
        edit_menu = tb.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="Cut")
        edit_menu.add_command(label="Copy")
        edit_menu.add_command(label="Paste")
        menu_bar.add_cascade(label="Edit", menu=edit_menu)

        # Create Help menu
        help_menu = tb.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About")
        menu_bar.add_cascade(label="Help", menu=help_menu)

        # Configure the root window to use the menu bar
        root.config(menu=menu_bar)

        email_processor = EmailProcessor(self.file_name)
        email_results = email_processor.pass_email()
        if email_results:
            e_headers, urls, email_body, body_content, eml_message, _, origin_domain = email_results

            my_notebook = tb.Notebook(root, bootstyle='dark', style='long.TNotebook')
            my_notebook.pack(fill='both', expand=True)

            headers_tab = tb.Frame(my_notebook)
            urls_tab = tb.Frame(my_notebook)
            body_tab = tb.Frame(my_notebook)
            virustotal_tab = tb.Frame(my_notebook)
            attachments_tab = tb.Frame(my_notebook)
            raw_email_tab = tb.Frame(my_notebook)

            headers_tab.pack(fill='both', expand=True)
            urls_tab.pack(fill='both', expand=True)
            body_tab.pack(fill='both', expand=True)
            virustotal_tab.pack(fill='both', expand=True)
            attachments_tab.pack(fill='both', expand=True)
            raw_email_tab.pack(fill='both', expand=True)

            my_notebook.add(headers_tab, text="Headers")
            my_notebook.add(urls_tab, text="URLs")
            my_notebook.add(body_tab, text="Email Body")
            my_notebook.add(virustotal_tab, text="VirusTotal Results")
            my_notebook.add(attachments_tab, text="Attached Files")
            my_notebook.add(raw_email_tab, text="Raw Email")

            headers_columns = ('header', 'value')
            headers_tree = tb.Treeview(headers_tab, bootstyle="primary", columns=headers_columns, show='headings')
            headers_tree.pack(fill=tk.BOTH, expand=True)
            headers_tree.heading('header', text='Header')
            headers_tree.heading('value', text='Value')
            for header, value in e_headers.items():
                headers_tree.insert('', 'end', values=(header, value))

            urls_scroll = tb.Scrollbar(urls_tab, orient='vertical', bootstyle="primary")
            urls_scroll.pack(side="right", fill="y")
            urls_columns = ('urls')
            urls_tree = tb.Treeview(urls_tab, bootstyle="primary", columns=urls_columns, show='headings')
            urls_tree.pack(fill='both', expand=True)
            urls_tree.heading('urls', text='URLs')
            urls_scroll.config(command=urls_tree.yview)
            for url in urls:
                urls_tree.insert('', 'end', values=(url,))

            body_frame = HtmlFrame(body_tab)
            body_frame.set_content(body_content)
            body_frame.pack(fill="both", expand=True)

            file_processor = FileProcessor(self.file_name)
            attachments = file_processor.process_email()
            if attachments:
                attachments_columns = ('field', 'value')
                attachments_tree = tb.Treeview(attachments_tab, bootstyle="primary", columns=attachments_columns,
                                                show='headings')
                attachments_tree.pack(fill='both', expand=True)
                attachments_tree.heading('field', text='Field')
                attachments_tree.heading('value', text='Value')
                for attachment in attachments:
                    for field, value in attachment.items():
                        attachments_tree.insert('', 'end', values=(field, value))
            else:
                attachments_tree = tb.Treeview(attachments_tab, bootstyle="primary", columns=attachments_columns,
                                                show='headings')
                attachments_tree.pack(fill='both', expand=True)
                attachments_tree.heading('field', text='Field')
                attachments_tree.heading('value', text='Value')
                attachments_tree.insert('', 'end', values=("No Attachments", ""))

            raw_email_scroll = tb.Scrollbar(raw_email_tab, orient='vertical', bootstyle="primary")
            raw_email_scroll.pack(side="right", fill="y")
            raw_email_body = tb.Text(raw_email_tab, wrap='none', yscrollcommand=raw_email_scroll.set)
            raw_email_body.pack(fill='both', expand=True)
            raw_email_body.insert(tk.END, eml_message.as_string())
            raw_email_body.config(state='disabled')
            raw_email_scroll.config(command=raw_email_body.yview)

            summary_intel, engines_intel = VirusTotalScanner(origin_domain).perform_vt_scan()
            if summary_intel and engines_intel:
                summary_intel_tree = tb.Treeview(virustotal_tab, columns=('Category', 'Count'), show='headings')
                summary_intel_tree.heading('Category', text='Category')
                summary_intel_tree.heading('Count', text='Count')
                summary_intel_tree.pack(fill='both', expand=True)
                for category, count in summary_intel.items():
                    summary_intel_tree.insert('', 'end', values=(category, count))

                engines_intel_tree = tb.Treeview(virustotal_tab,
                                                  columns=('Engine Name', 'Category', 'Result', 'Method'),
                                                  show='headings')
                engines_intel_tree.heading('Engine Name', text='Engine Name')
                engines_intel_tree.heading('Category', text='Category')
                engines_intel_tree.heading('Result', text='Result')
                engines_intel_tree.heading('Method', text='Method')
                engines_intel_tree.pack(fill='both', expand=True)
                for engine, details in engines_intel.items():
                    if isinstance(details, dict):
                        engines_intel_tree.insert('', 'end',
                                                  values=(engine, details['category'], details['result'],
                                                          details['method']))
            else:
                no_results_label = tk.Label(virustotal_tab, text="No VirusTotal results available")
                no_results_label.pack()
        root.mainloop()

if __name__ == '__main__':
    gui = GUI()
    gui.display_page()
