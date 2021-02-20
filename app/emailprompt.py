# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START gmail_quickstart]


from __future__ import print_function
import os
from app import Config
import pickle
import os.path
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import smtplib, ssl
from email.message import Message
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mimetypes
import base64
from httplib2 import Http
from oauth2client import file, client, tools
from validate_email import validate_email
from itsdangerous import URLSafeTimedSerializer
from flask import render_template, url_for
from threading import Thread
from flask import current_app
from datetime import datetime

SECRET_KEY = Config.SECRET_KEY
SALT = Config.SECURITY_PASSWORD_SALT

# set current year
year = datetime.utcnow().year

# app = Flask(__name__)
# app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://mail.google.com/'] 

def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client_id.json', SCOPES)
            creds = flow.run_local_server(port=9999)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)

    # Call the Gmail API
    results = service.users().labels().list(userId='me').execute()
    labels = results.get('labels', [])

    # if not labels:
    #     print('No labels found.')
    # else:
    #     print('Labels:')
    #     for label in labels:
    #         print(label['name'])
    return service

def create_message(sender, to, subject, message_text, type): #Type could be plain-text of HTML
  """Create a message for an email.

  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.
    Type: Defines message content, plain-text or HTML

  Returns:
    An object containing a base64url encoded email object.
  """

  if (type == 'HTML'):
    part1 = MIMEText(message_text, "html")
    message = MIMEMultipart("alternative")
    message.attach(part1)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
  elif (type == 'plain-text'):
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
  return {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode()}

def create_message_with_attachment(
    sender, to, subject, message_text, file):
  """Create a message for an email.

  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.
    file: The path to the file to be attached.

  Returns:
    An object containing a base64url encoded email object.
  """
  message = MIMEMultipart()
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject

  msg = MIMEText(message_text)
  message.attach(msg)

  content_type, encoding = mimetypes.guess_type(file)

  if content_type is None or encoding is not None:
    content_type = 'application/octet-stream'
  main_type, sub_type = content_type.split('/', 1)
  if main_type == 'text':
    fp = open(file, 'rb')
    msg = MIMEText(fp.read(), _subtype=sub_type)
    fp.close()
  elif main_type == 'image':
    fp = open(file, 'rb')
    msg = MIMEImage(fp.read(), _subtype=sub_type)
    fp.close()
  elif main_type == 'audio':
    fp = open(file, 'rb')
    msg = MIMEAudio(fp.read(), _subtype=sub_type)
    fp.close()
  else:
    fp = open(file, 'rb')
    msg = MIMEBase(main_type, sub_type)
    msg.set_payload(fp.read())
    fp.close()
  filename = os.path.basename(file)
  msg.add_header('Content-Disposition', 'attachment', filename=filename)
  message.attach(msg)

  return {'raw': base64.urlsafe_b64encode(message.as_string().encode()).decode()}

def send_message(service, user_id, message):
  """Send an email message.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message: Message to be sent.

  Returns:
    Sent Message.
  """
  try:
    message = (service.users().messages().send(userId=user_id, body=message)
               .execute())
    print ('Message Id: %s' % message['id'])
    return message
  except HttpError as error:
    print ('An error occurred: %s' % error)

def generate_confirmation_token(email):
	serializer = URLSafeTimedSerializer( SECRET_KEY )
	print('serializer', serializer)
	return serializer.dumps({'email':email}, salt=SALT)


def confirm_token(token, expiration=3600):
	serializer = URLSafeTimedSerializer( SECRET_KEY )
	try:
		result = serializer.loads(token, salt=SALT, max_age=expiration)
	except:
		return False
	
	return result

def check_email_validation(email):

	#print('email', email)

	# valid = validate_email(email, verify=True)
	# verify option is for checking if that email exists
	# default is False
	# validate_email(email) default just examine wether the input email format is correct

	valid = validate_email(email)
	#print('valid', valid)
	return valid

def send_mail(app, email, msg_txt, subject, _type):
	message = create_message(Config.ADMINS[1], email, subject, msg_txt, _type)
	service = main()
	send_message(service, 'me', message)
	return


def send_email_confirmation_mail(email, subject, template_url, logo_url):
  """Send an email confirmation message asynchronously.

  Args:
    email: Recipient email address.
    subject: Email subject
    template_url: template to be used.
    logo_url: url to the brand logo

  Returns:
    Nothing.
  """
  token = generate_confirmation_token(email)
  confirm_url = url_for('confirm_email', token=token, _external=True)
  html = render_template(str(template_url), confirm_url=confirm_url, logo_url=logo_url)
	#send_mail(email, html)
	#send_mail(email, html, subject, 'HTML')
  """send email asynchronously"""
  Thread(target=send_mail, args=(current_app._get_current_object(), email, html, subject, 'HTML')).start()
  return

def send_shops_email_confirmation_mail(email, subject, template_url, iconurl, logourl,client, cover_message):
  """Send an email confirmation message asynchronously.

  Args:
    email: Recipient email address.
    subject: Email subject
    template_url: template to be used.

  Returns:
    Nothing.
  """
  token = generate_confirmation_token(email)
  confirm_url = url_for('confirm_email', token=token, _external=True)
  html = render_template(str(template_url), confirm_url=confirm_url, iconurl=iconurl, logourl=logourl, 
  client=client, cover_message=cover_message)
	#send_mail(email, html)
	#send_mail(email, html, subject, 'HTML')
  """send email asynchronously"""
  Thread(target=send_mail, args=(current_app._get_current_object(), email, html, subject, 'HTML')).start()
  return

def send_password_reset_mail(email, subject, template_url):
  """Send a password reset email asynchronously.

  Args:
    email: Recipient email address.
    subject: Email subject
    template_url: template to be used.

  Returns:
    Nothing.
  """
  token = generate_confirmation_token(email)
  reset_url = url_for('password_reset', token=token, _external=True)
  html = render_template(str(template_url), reset_url=reset_url)
	#send_mail(email, html)
  #send_mail(email, html, subject, 'HTML')
  """send email asynchronously"""
  Thread(target=send_mail, args=(current_app._get_current_object(), email, html, subject, 'HTML')).start()
  return

def send_password_reset_email(user):
  """Send a password reset email asynchronously.

  Args:
    user: user loaded from User model.

  Returns:
    Nothing.
  """
  token = user.get_reset_password_token()
  subject = '[Fliptzblog] Reset Your Password'
  html = render_template('email/reset_password.html', user=user, token=token)
  email = user.email
  Thread(target=send_mail, args=(current_app._get_current_object(), email, html, subject, 'HTML')).start()

def send_error_email(error):
  # emailprompt.send_mail(app, 'ceo@sarbtech.com', str(formatted_lines), 'error_trace', 'plain-text')
  time_stamp = datetime.now()
  subject = '[' + str(time_stamp) + '] ' + 'Fliptzblog-error_trace'
  Thread(target=send_mail, args=(current_app._get_current_object(), Config.ADMINS[0], error, subject, 'plain-text')).start()

def send_shipping_update_mail(email, subject, template_url, shipping_data, phone, logo_url, client, cover_message):
  """Send a shipping update notification email asynchronously.
  Args:
    email: Recipient email address.
    subject: Email subject
    template_url: template to be used.
    shipping_data: a dictionary of shipping detaills
    phone: updated phone number
    logo_url: client's logo url
    client: current client
    cover_message: client's cover message

  Returns:
    Nothing.
  """
  token = generate_confirmation_token(email)
  html = render_template(str(template_url), client=client, address=shipping_data['shipping_address'],
  city=shipping_data['city'], locality=shipping_data['locality'], landmark=shipping_data['landmark'],
  phone=phone, postal_code=shipping_data['postal_code'], state=shipping_data['state'], country=shipping_data['country'],
  lat=shipping_data['lat'], lng=shipping_data['lng'], logo_url=logo_url, cover_message=cover_message, year=year)
	#send_mail(email, html)
  #send_mail(email, html, subject, 'HTML')
  """send email asynchronously"""
  Thread(target=send_mail, args=(current_app._get_current_object(), email, html, subject, 'HTML')).start()
  return

def send_sales_invoice(email, subject, template_url, logo_url, client, cover_message, mailing_dict, mailing_list):
  """Send sales invoice email asynchronously.
  Args:
    email: Recipient email address.
    subject: Email subject
    template_url: template to be used.
    mailing_dict: a dictionary of order detaills
    mailing_list: a list of cart items
    logo_url: client's logo url
    client: current client
    cover_message: client's cover message

  Returns:
    Nothing.
  """
  token = generate_confirmation_token(email)
  html = render_template(str(template_url), client=client,mailing_dict=mailing_dict, mailing_list=mailing_list,
   logo_url=logo_url, cover_message=cover_message, year=year)
	#send_mail(email, html)
  #send_mail(email, html, subject, 'HTML')
  """send email asynchronously"""
  Thread(target=send_mail, args=(current_app._get_current_object(), email, html, subject, 'HTML')).start()
  return

# def send_confirmation_mail(_from, _to, subject, type):
#   app = Flask(__name__)
#   app.config.from_pyfile('config.py')
#   app.config['SERVER_NAME'] = '127.0.0.1:9999/'
#   from web.model_cloudsql import init_app
#   init_app(app)

#   @app.route('/home/confirm/<token>')
#   def confirm_email(token):
#       # try:
#       #     data = emailprompt.confirm_token(token)
#       # except:
#       #     return 'token expired'

#       # user = users.query.filter_by(email=data['email']).first()
#       # if user:
#       #     user.authenticated=True
#       #     db.session.add(user)
#       #     db.session.commit()

#       return ('ok' + str(token) + ' here')
#   with app.app_context():
#     service = main()
#     token = generate_confirmation_token(_to)
#     confirm_url = url_for('confirm_email', token=token, _external=True)
#     html = render_template('email.html', confirm_url=confirm_url)
#     message = create_message(_from, _to, subject, html, type)
#     send_message(service, 'me', message)
#   return
  
if __name__ == '__main__':
    service = main()
    # send_message(service, 'me', message)
    #send_mail(app, 'ceo@sarbtech.com', 'Just testing', 'test-email', 'plain-text')
    #send_confirmation_mail('bot@sarbtech.com', 'ceo@sarbtech.com', 'Gmail-Test', 'HTML')
    #send_password_reset_mail('ceo@sarbtech.com', 'test-email','')
# [END gmail_quickstart]