#! /usr/bin/env python
# -*- coding: utf-8 -*-

# standard library imports
import sys
import time
import email
import platform
import smtplib

# related third party imports


# local application/library specific imports


def create_message_id():
    hostname = platform.node()
    timestamp = time.time()

    timestring = time.strftime("%a-%d%b%Y-%H%M%S")

    message_id = "%s-%s@%s" % (timestring, timestamp, hostname)

    return message_id


class TestMail:
    def __init__(self, mailfrom="phönix@unicom.ws", rcpttos = ["test@unicom.ws"]):

        self.mailfrom = mailfrom
        self.rcpttos = rcpttos

    def _message_template(self, rcpttos, mailfrom, subject, message_text, multipart=True):
        """A function which provides a core template for the test mails."""

        if multipart == True:
            email_message = email.MIMEMultipart.MIMEMultipart()
        else:
            email_message = email.MIMEText.MIMEText(message_text)
        email_message['From'] = mailfrom
        email_message['To'] = ", ".join(rcpttos)
        email_message['Date'] = email.utils.formatdate(localtime=True)
        email_message['Subject'] = subject
        email_message['Message-Id'] = create_message_id()

        return email_message

    def get_virus(self):
        message_text = u"Phönix Test E-Mail"
        subject = u"[VIRUS] Phönix Test E-Mail"

        email_message = self._message_template(self.rcpttos, self.mailfrom, subject, message_text)

        email_message.attach(email.MIMEText.MIMEText(message_text))

        email_part = email.MIMEBase.MIMEBase('application', "octet-stream")
        email_part.set_payload("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-self.ANTIVIRUS-TEST-FILE!$H+H*")
        email.encoders.encode_base64(email_part)
        email_part.add_header("Content-Disposition", "attachment; filename=eicar.virus")
        email_message.attach(email_part)

        return email_message

    def get_spam(self):

        message_text = u"Phönix Test E-Mail\n\nXJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
        subject = u"[SPAM] Phönix Test E-Mail"

        email_message = self._message_template(self.rcpttos, self.mailfrom, subject, message_text)

        return email_message

    def get_normal(self):

        message_text = "uPhönix Test E-Mail\n\nDiese E-Mail sollte weder als Virus noch als Spam gekenzeichnet sein!"
        subject = u"[NORMAL] Phönix Test E-Mail"

        email_message = self._message_template(self.rcpttos, self.mailfrom, subject, message_text)

        return email_message


class TestMailSender(TestMail):
    """A class for sending test mails."""

    def __init__(self, smtp_ip, smtp_port, mailfrom="phönix@unicom.ws", rcpttos = ["test@unicom.ws"]):
        self.smtp_ip = smtp_ip
        self.smtp_port = smtp_port

        self.mailfrom = mailfrom
        self.rcpttos = rcpttos

    def _send(self, email_message):
        """A Function to send the Test Mails."""

        try:
            server = smtplib.SMTP(self.smtp_ip, self.smtp_port)
            if self._username != "":
                server.login(self._username, self._password)
            server.sendmail(self.mailfrom, self.rcpttos, email_message.getvalue())
            server.quit()
        except socket.error, err:
            sys.stderr.write("Error: Sending mail failed! %s:%s\n" % (self.smtp_ip, self.smtp_port))
            sys.stderr.write("%s %s" % (err[0], err[1]))
        except Exception, err:
            sys.stderr.write("Error: Sending mail failed! %s:%s\n" % (self.smtp_ip, self.smtp_port))
            sys.stderr.write(err)

    def send_virus(self):
        """Sends a test-mail containing the EICAR Standard Anti-Virus Test File."""

        # VIRUS Mail
        print "Sending virus mail..."

        self._send(self.get_virus)

    def send_spam(self):
        """Sends a test-mail containing spam."""

        print "Sending spam mail..."

        self._send(self.get_spam,)

    def send_normal(self):
        """Sends a normal test-mail"""

        print "Sending a normal(containing not a virus and not spam) mail..."

        self._send(self.get_normal)

