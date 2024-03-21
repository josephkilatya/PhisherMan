import ttkbootstrap as tb
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import email
import re
import base64
from tkinterhtml import HtmlFrame
import requests
import os
import magic
import hashlib
from email.parser import BytesParser
import textwrap
from bs4 import BeautifulSoup
from pygments import highlight
from pygments.lexers import HtmlLexer
from pygments.formatters import HtmlFormatter

class EmailProcessor:
    def __init__(self, file_name):
        self.file_name = file_name
   
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
                received = eml_message['Received']
                mime_version = eml_message['MIME-Version']
                content_type = eml_message['Content-Type']
                content_transfer_encoding = eml_message['Content-Transfer-Encoding']
                user_agent = eml_message['User-Agent']
                x_mailer = eml_message['X-Mailer']                
                email_body = eml_message['Body']

                origin_ip = originating_ip[1:-1] if originating_ip is not None else None

                match = re.search(r'@([A-Za-z0-9.-]+)', sender)
                if match:
                    origin_domain = match.group(1)
                else:
                    origin_domain = None

                # print the email contents
                e_headers = {'Date': date, 'Sender': sender, 'Reply-To': reply_to, 'Receiver': receiver,
                             'CC': [cc], 'BCC': [bcc], 'Subject': subject, 'Message ID': message_id,
                             'Originating IP': origin_ip, 'Received': received, 'MIME-Version': mime_version, 
                             'Content-Type': content_type, 'Content-Transfer-Encoding': content_transfer_encoding,
                             'User-Agent': user_agent, 'X-Mailer': x_mailer}

                # extract urls from the email body, decode if base64 encoded and print them
                urls_with_info = self.extract_urls_ports_protocols_from_email(eml_message)

                # Extract email body
                email_body, body_content = self.extract_body(eml_message)

                return e_headers, urls_with_info, email_body, body_content, eml_message, origin_ip, origin_domain
            except Exception as e:
                print("Error processing email:", e)
                return None
        else:
            return None

    def extract_urls_ports_protocols_from_email(self, email_message):
        urls_with_info = []
        try:
            # Regular expression to match URLs with protocol and port
            url_with_info_regex = r'((https?|ftp):\/\/[\w\-]+(\.[\w\-]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?)(?::(\d{1,5}))?'

            # Extract URLs with protocol and port
            matches = re.findall(url_with_info_regex, str(email_message))  # Ensure email_message is converted to string
            for match in matches:
                url = match[0]
                protocol = match[1]
                port = match[4] if match[4] else None
                urls_with_info.append({'url': url, 'protocol': protocol, 'port': port})

        except Exception as e:
            print(f"An error occurred: {str(e)}")

        return urls_with_info


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
        api_key = "VIRUSTOTAL API KEY"
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
            whois_data = vt_results['data']['attributes']['whois']

            return summary_intel, engines_intel, whois_data
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
            results.append({"Message": "No Attached Files"})

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
    def __init__(self, root):
        self.file_name = None
        self.select_instance = EmailProcessor(self.file_name)

        # Create a menu bar
        menu_bar = tb.Menu(root)

        # Create File menu
        file_menu = tb.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="Open File", command=lambda: self.select_file(root))
        file_menu.add_command(label="Close File")
        file_menu.add_command(label="Report")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)
        root.config(menu=menu_bar)

        # Create Settings menu
        settings_menu = tb.Menu(menu_bar, tearoff=0)
        # settings_menu.add_command(label="Cut")
        # settings_menu.add_command(label="Copy")
        # settings_menu.add_command(label="Paste")
        menu_bar.add_cascade(label="Settings", menu=settings_menu)

        # Create About menu
        about_menu = tb.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="About", menu=about_menu)
        about_menu.add_command(label="About", command=self.open_about_window)

        # Configure the root window to use the menu bar
        root.config(menu=menu_bar)

    def select_file(self, root):
        filetypes = [('EML files', '*.eml'), ('All files', "*.*")]
        file_name = filedialog.askopenfilename(
            title='Select email file', initialdir='/home/', filetypes=filetypes)
        if file_name:
            self.file_name = file_name
            self.select_instance = EmailProcessor(self.file_name)
            self.display_page(root)

    # FUnction to wrap text in a tree
    def wrap(self, string, length=1000):
        if string is not None and isinstance(string, str):
            return '\n'.join(textwrap.wrap(string, length))
        else: 
            return string
        # Function to open about window
    def open_about_window(self):
        about_window = tk.Toplevel()
        about_window.title("about email-studio")
        about_window.geometry("660x200")
        about_window.geometry("+%d+%d" % ((about_window.winfo_screenwidth() - 600) / 2, (about_window.winfo_screenheight() - 200) / 2))
        about_window.resizable(False,False)

        # Add credits, copyright information, and purpose of the software
        about_label = ttk.Label(about_window, text="""email-studio 1.00 - Analyzing Phishing emails\n\nDeveloper: Joseph Kilatya\n\nCopyright © 2024 josephkilatya\n\nThis softaware is provided 'as-is', whithout any expressed or implied warranty. \nIn no event will the author be held liable for any damage arising from the use of this software.""")
        about_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)


    def display_page(self, root):
        email_processor = self.select_instance
        email_results = email_processor.pass_email()
        if email_results:
            e_headers, urls_with_info, email_body, body_content, eml_message, _, origin_domain = email_results

            my_notebook = tb.Notebook(root, bootstyle='success', style='long.TNotebook')
            my_notebook.pack(fill='both', expand=True)

            headers_tab = tb.Frame(my_notebook)
            urls_tab = tb.Frame(my_notebook)
            rendered_tab = tb.Frame(my_notebook)
            virustotal_tab = tb.Frame(my_notebook)
            attachments_tab = tb.Frame(my_notebook)
            raw_email_tab = tb.Frame(my_notebook)
            whois_data_tab = tb.Frame(my_notebook)
            raw_html_tab = tb.Frame(my_notebook)

            headers_tab.pack(fill='both', expand=True)
            urls_tab.pack(fill='both', expand=True)
            rendered_tab.pack(fill='both', expand=True)
            virustotal_tab.pack(fill='both', expand=True)
            attachments_tab.pack(fill='both', expand=True)
            raw_email_tab.pack(fill='both', expand=True)
            whois_data_tab.pack(fill='both', expand=True)
            raw_html_tab.pack(fill='both', expand=True)

            my_notebook.add(headers_tab, text="Headers")
            my_notebook.add(urls_tab, text="URLs")
            my_notebook.add(rendered_tab, text="Rendered HTML")
            my_notebook.add(virustotal_tab, text="VirusTotal Results")
            my_notebook.add(attachments_tab, text="Attached Files")
            my_notebook.add(raw_email_tab, text="Raw Email")
            my_notebook.add(whois_data_tab, text="Origin Domain Whois Results")
            my_notebook.add(raw_html_tab, text="Raw HTML")

            headers_columns = ('header', 'value')
            headers_tree = tb.Treeview(headers_tab, bootstyle="primary", columns=headers_columns, show='headings')
            headers_tree.pack(fill=tk.BOTH, expand=True)
            headers_tree.heading('header', text='Header')
            headers_tree.heading('value', text='Value')
            headers_tree.column('header', width=300)
            headers_tree.column('value', width=600)
            headers_tree.heading('value', anchor='w')
            for header, value in e_headers.items():
                headers_tree.insert('', 'end', values=(header, self.wrap(value)))


            urls_scroll = tb.Scrollbar(urls_tab, orient='vertical', bootstyle="primary")
            urls_scroll.pack(side="right", fill="y")

            urls_columns = ('urls', 'protocol', 'port')
                
            if urls_with_info:
                urls_tree = tb.Treeview(urls_tab, bootstyle="primary", columns=urls_columns, show='headings')
                urls_tree.pack(fill=tk.BOTH, expand=True)
                urls_tree.heading('urls', text='URLs')
                urls_tree.heading('protocol', text='Protocol') 
                urls_tree.heading('port', text='Port')
                urls_scroll.config(command=urls_tree.yview)
                for url_info in urls_with_info:  
                    urls_tree.insert('', 'end', values=(url_info['url'], url_info['protocol'], url_info['port'])) 

            else:
                urls_tree = tb.Treeview(urls_tab, bootstyle="primary", columns=urls_columns,
                                                show='headings')
                urls_tree.pack(fill='both', expand=True)
                urls_tree.heading('urls', text='URLs')
                urls_tree.heading('protocol', text='Protocol')
                urls_tree.heading('port', text='Port')
                urls_tree.insert('', 'end', values=("No URLs Found", ""))
            
            body_frame = HtmlFrame(rendered_tab)
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

            summary_intel, engines_intel, whois_data = VirusTotalScanner(origin_domain).perform_vt_scan()
            if summary_intel and engines_intel:
                summary_intel_tree = tb.Treeview(virustotal_tab, columns=('Category', 'Count'), show='headings')
                summary_intel_tree.heading('Category', text='Category')
                summary_intel_tree.heading('Count', text='Count')
                summary_intel_tree.pack(fill='both', expand=True)
                for category, count in summary_intel.items():
                    summary_intel_tree.insert('', 'end', values=(category, count))

                engines_intel_tree = tb.Treeview(virustotal_tab,
                                                    columns=('Engine Name', 'Category', 'Result', 'Method'),
                                                    show='headings',
                                                    bootstyle='primary')
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
                
            whois_data_widget = tb.Text(whois_data_tab, wrap="word")
            whois_data_widget.pack(fill='both', expand=True)
            whois_data_widget.insert('1.0', whois_data)
            whois_data_widget.config(state='disabled')

            soup = BeautifulSoup(body_content, 'html.parser')
            formatted_html = soup.prettify

            html_text_widget = tb.Text(raw_html_tab, wrap="word", font=("Courier", 12))
            html_text_widget.pack(fill='both', expand=True)
            html_text_widget.insert("1.0", formatted_html)
            html_text_widget.config(state='disabled')


if __name__ == '__main__':

    root = tb.Window(themename='superhero')
    root.title('Email-Studio')
    root.geometry('1024x768')
    root.place_window_center()
    root.style.configure('long.TNotebook')
    
    gui = GUI(root)
    gui.display_page(root)

    root.mainloop()
