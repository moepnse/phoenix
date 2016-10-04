#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
               spamc --> PROCESS SPAMC/1.2
               spamc --> Content-length: <size>
  (optional)   spamc --> User: <username>
               spamc --> \r\n [blank line]
               spamc --> --message sent here--

               spamd --> SPAMD/1.1 0 EX_OK
               spamd --> Content-length: <size>
               spamd --> \r\n [blank line]
               spamd --> --processed message sent here--
"""

# standard library imports
import socket

# related third party imports
import email

# local application/library specific imports
from testmail import TestMail


# Just check if the passed message is spam or not and reply as described below
CHECK = "CHECK"

# Check if message is spam or not, and return score plus list of symbols hit
SYMBOLS = "SYMBOLS"

# Check if message is spam or not, and return score plus report
REPORT = "REPORT" 

# Check if message is spam or not, and return score plus report if the message is spam
REPORT_IFSPAM = "REPORT_IFSPAM"

# Ignore this message -- client opened connection then changed its mind
SKIP = "SKIP"

# Return a confirmation that spamd is alive.
PING = "PING"

# Process this message as described above and return modified message
PROCESS = "PROCESS"

VERSION = "SPAMC/1.2"

CONTENT_LENGTH = "Content-length:"

LINE_BREAK = "\r\n"

IP = "localhost"
PORT = 783

X_SPAM = "X-Spam"
X_SPAM_SCORE = "X-Spam-Score"

YES = "Yes"
NO = "No"


class SpamC:

    def __init__(self, ip=IP, port=PORT, username="", **kwargs):

        self._ip = ip
        self._port = port

        self._username = username

        self._x_spam = kwargs.get("x_spam", X_SPAM)
        self._x_spam_score = kwargs.get("x_spam_score", X_SPAM_SCORE)

        self._mapping = {True: YES, False: NO}

        self._debug = kwargs.get("debug", False)

    def check(self, message):

        self._command = CHECK
        self._message = message

        return self._execute()

    def symbol(self, message):

        self._command = SYMBOL
        self._message = message

        return self._execute()

    def report(self, message):

        self._command = REPORT
        self._message = message

        return self._execute()

    def report_ifspam(self, message):

        self._command = REPORT_IFSPAM
        self._message = message

        return self._execute()

    def skip(self, message):

        self._command = skip
        self._message = message

        return self._execute()

    def ping(self, message):

        self._command = PING
        self._message = message

        return self._execute()

    def process(self, message):

        self._command = PROCESS
        self._message = message

        return self._execute()

    def check_mail(self, email_message):
        data = self.check(email_message.as_string())

        spam = False
        tmp = data.split('\r\n')
        for line in tmp:
            if line.startswith("Spam"):
                tmp2 = line.split(";")

                if tmp2[0].split(":")[1].strip().lower() == "true":
                    spam = True

                score = tmp2[1]

        email_message.__setitem__(self._x_spam, self._mapping.get(spam, NO))
        email_message.__setitem__(self._x_spam_score, score)

        return email_message

    def _execute(self):
        self._connect()
        self._set_command()
        self._send()
        data = self._recv()
        self._socket.close()
        return data

    def _set_command(self):
        if self._command == "PONG" or self._command == "SKIP":
            self._communication_string = "%s%s%s" % (self._command, VERSION, LINE_BREAK)
        else:
            self._communication_string = "%s %s%s" % (self._command, VERSION, LINE_BREAK)
            self._communication_string += "%s %s%s" % (CONTENT_LENGTH, len(self._message)+2, LINE_BREAK)
            if self._username != "":
                self._communication_string += "username: %s%s" % (self._username, LINE_BREAK)

            self._communication_string += "%s%s%s" % (LINE_BREAK, self._message, LINE_BREAK)

    def _connect(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._ip, self._port))

    def _send(self):
        if self._debug:
            print self._communication_string
        self._socket.send(self._communication_string)

    def _recv(self):
        data = ""
        while 1:
            puffer = self._socket.recv(1024)
            if puffer == "":
                break
            data += puffer 

        return data


def initialize():
    return SpamC("localhost", 783)


def main():
    test_mail = TestMail()
    spamc = SpamC("localhost", 783)
    print spamc.check_mail(test_mail.get_spam().as_string()).as_string()


if __name__ == "__main__":
    main()
