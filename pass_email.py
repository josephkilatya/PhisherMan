# This file is used to pass the email from the user to the main program
import email
import os
import glob
from email import policy
from multiprocessing import Pool

EXTENSIONS = ['eml']
def main():
    file_name = 'emails/test.eml'
    get_email_from_user(file_name)
    extract_attachments(file_name)
    
def get_email_from_user(file_name):
    # open the eml file in read mode
    with open(file_name, 'rb') as email_file:
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

    #Extracting url from the email body
    # body = eml_message.get_payload()
    # body = body.split('http://')[1]
    # body = body.split(' ')[0]
    # print(body)


    # body = ''

    # # if the message is multipart, iterate over the parts and concatenate the text parts
    # if eml_message.is_multipart():
    #     for part in eml_message.walk():
    #         content_type = part.get_content_type()
    #         if content_type == 'text/plain' or content_type == 'text/html':
    #             body += part.get_payload()
    # else:
    #     body = eml_message.get_payload()

    # print the email contents
    print('Date:', date)
    print('From:', sender)
    print('Reply-To:', reply_to)
    print('To:', receiver)
    print('Cc:', cc)
    print('Bcc:', bcc)
    print('Subject:', subject)
    print('Message-ID:', message_id)

 #   print('Body:', body)
    
# Function to extract attachments from the email
def extract_attachments(filename):
        """
        Try to extract the attachments from all files in cwd
        """
        # ensure that an output dir exists
        od = "output"
        os.path.exists(od) or os.makedirs(od)
        output_count = 0
        try:
            with open(filename, "r") as f:
                msg = email.message_from_file(f, policy=policy.default)
                for attachment in msg.iter_attachments():
                    try:
                        output_filename = attachment.get_filename()
                    except AttributeError:
                        print("Got string instead of filename for %s. Skipping." % f.name)
                        continue
                    # If no attachments are found, skip this file
                    if output_filename:
                        with open(os.path.join(od, output_filename), "wb") as of:
                            try:
                                of.write(attachment.get_payload(decode=True))
                                output_count += 1
                            except TypeError:
                                print("Couldn't get payload for %s" % output_filename)
                if output_count == 0:
                    print("No attachment found for file %s!" % f.name)
        # this should catch read and write errors
        except IOError:
            print("Problem with %s or one of its attachments!" % f.name)
        return 1, output_count
   
# execute the main function
if __name__ == '__main__':
    main()
    # let's do this in parallel, using cpu count as number of threads
    pool = Pool(None)
    res = pool.map(extract_attachments, glob.iglob("*.%s" % EXTENSIONS))
    # need these if we use _async
    pool.close()
    pool.join()
    # 2-element list holding number of files, number of attachments
    numfiles = [sum(i) for i in zip(*res)]
    print("Done: Processed {} files with {} attachments.".format(*numfiles))
