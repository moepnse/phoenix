#! /usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Richard Lamboj'
__copyright__ = 'Copyright 2013, Unicom'
__credits__ = ['Richard Lamboj']
__license__ = 'Proprietary'
__version__ = '0.1'
__maintainer__ = 'Richard Lamboj'
__email__ = 'rlamboj@unicom.ws'
__status__ = 'Development'

# standard library imports
import os
import pwd
import grp
import sys
import getopt
import time
import socket
import smtpd
import email
import signal
import asyncore
import threading
import multiprocessing
import multiprocessing.reduction

# related third party imports

# local application/library specific imports
import plugin_system

from logging import log, STD_OUT, STD_ERR


RESEND_TIMEOUT = 60
PID_FILE = u"/var/run/phoenix/phoenix.pid"


class Worker(multiprocessing.Process):
    """
    A Class to Check Mails
    """

    def __init__(self, q):
        self._q = q
        self.__plugin_system = plugin_system.PluginSystem()
        self.__plugins = self.__plugin_system.load_plugins()
        self._plugins = []
        for plugin in self.__plugins:
            self._plugins.append(plugin.initialize())
            log("Initialized plugin %s" % plugin.__file__, STD_OUT)
        multiprocessing.Process.__init__(self)
        self.start()

    def _del_message_items(self):
        self._email_message.__delitem__("X-Virus")
        self._email_message.__delitem__("X-Spam")
        self._email_message.__delitem__("X-Spam-Score")
        self._email_message.__delitem__("X-MailScanner")

    def _create_message_id(self, domain):
        """
        A Function to create a Message Id
        """

        timestamp = int(time.time())

        message_id = "%s.%s.%s" % ("no-message-id-found", domain, timestamp)

        return message_id

    def _get_message_informations(self):
        message_id = self._email_message.__getitem__("Message-Id")
        subject = self._email_message.__getitem__("Subject")

        domain = self._mailfrom.split("@", 1)[1]

        if message_id == None:
            message_id = self.create_message_id(domain)
            email_message.__setitem__("Message-Id", message_id)

        if subject == None:
            subject = "No Subject!"
        # The form is: "=?charset?encoding?encoded text?=".
        elif subject.startswith("=?") and subject.endswith("?="):
            try:
                header_enc = email.Header.decode_header(subject)[0]
                #subject = unicode(header_enc[0], header_enc[1]).encode('ascii', 'replace')
                subject = unicode(header_enc[0], header_enc[1])
            except:
                log("%s Error: Subject Encode Error!\n" % (message_id), STD_ERR)

        self._subject = subject
        self._message_id = message_id
        self._domain = domain

    def _store_email(self):
        try:
            file = open(os.path.join(self._spool_path, self._message_id), 'w')
            file.write(self._data)
            file.close()
        except IOError, err:
            log("Error: %s" % err, STD_ERR)

    def run(self):
        log("Worker started", STD_OUT)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        while True:
            run, data = self._q.get() # Get an item from the queue
            if not run:
                log("Worker stopped", STD_OUT)
                break
            client_handle, mail = data
            fd = multiprocessing.reduction.rebuild_handle(client_handle)
            self.__conn = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
            self.check(*mail)

    def check(self, peer, mailfrom, rcpttos, data, mail_nr=0, **kwargs):

        self._x_mail_scanner = kwargs.get("x_mail_scanner")

        self._resend_timeout = kwargs.get("resend_timeout", RESEND_TIMEOUT)

        self._mailfrom = mailfrom
        self._rcpttos = rcpttos
        self._data = data
        self._mail_nr = mail_nr

        self._email_message = email.message_from_string(self._data)

        # Delete some Header Tags from the E-Mail
        self._del_message_items()

        # Setting the "X-MailScanner" Tag
        self._email_message.__setitem__("X-MailScanner", "%s" % (self._x_mail_scanner))

        # Fetching some Informations from the Mail Headers
        self._get_message_informations()

        log("%s got mail from: %s" % (self._message_id, self._mailfrom), STD_OUT)

        for plugin in self._plugins:
            plugin.check_mail(self._email_message)
        # Save the Mail on the Local Filesystem
        #self._store_email()


    def _send_mail(self):
        """
        A Function to send Mails
        """

        send_complete = False
        msg = "250 Ok"
        while send_complete == False:
            try:
                #server = smtplib.SMTP("localhost", 10025)
                server = smtplib.SMTP(self._releace_smtp_ip, self._relay_smtp_port)
                if self._username != "":
                    server.login(self._username, self._password)
                server.sendmail(self._mailfrom, self._rcpttos, self._email_message.as_string())
                server.quit()
                send_complete = True
            except:
                log("%s Error: Trying to send mail again in %s Seconds...\n" % (self._message_id, self._resend_timeout), STD_ERR)
                time.sleep(self._resend_timeout)
        self.__conn.send(self, msg + '\r\n')



class SMTPChannel(smtpd.SMTPChannel):

    # Implementation of base class abstract method
    def found_terminator(self):
        line = smtpd.EMPTYSTRING.join(self.__line)
        print >> smtpd.DEBUGSTREAM, 'Data:', repr(line)
        self.__line = []
        if self.__state == self.COMMAND:
            if not line:
                self.push('500 Error: bad syntax')
                return
            method = None
            i = line.find(' ')
            if i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i+1:].strip()
            method = getattr(self, 'smtp_' + command, None)
            if not method:
                self.push('502 Error: command "%s" not implemented' % command)
                return
            method(arg)
            return
        else:
            if self.__state != self.DATA:
                self.push('451 Internal confusion')
                return
            # Remove extraneous carriage returns and de-transparency according
            # to RFC 821, Section 4.5.2.
            data = []
            for text in line.split('\r\n'):
                if text and text[0] == '.':
                    data.append(text[1:])
                else:
                    data.append(text)
            self.__data = smtpd.NEWLINE.join(data)
            s= self.__server.process_message(self.__peer,
                                                   self.__mailfrom,
                                                   self.__rcpttos,
                                                   self.__data,
                                                   self.__conn)
            self.__rcpttos = []
            self.__mailfrom = None
            self.__state = self.COMMAND
            self.set_terminator('\r\n')
            #if not status:
            #    self.push('250 Ok')
            #else:
            #    self.push(status)



class Phoenix(smtpd.SMTPServer):
    """
    The MailScanner Class
    """

    # SMTPChannel class to use for managing client connections
    channel_class = SMTPChannel

    def __init__(self, localaddr=("localhost", 10024), remoteaddr=None, relay_smtp=("localhost", 10025), resend_timeout=60, spool_path="/var/spool/phoenix"):

        # Relay SMTP
        self._relay_smtp_ip = relay_smtp[0]
        self._relay_smtp_port = relay_smtp[1]

        self._resend_timeout = resend_timeout

        self._spool_path = spool_path

        self._x_mail_scanner = "%s %s %s" % (__name__, __version__, __status__)

        self.mail_nr = 0
        self.threads = []

        self._pool_size = multiprocessing.cpu_count()
        log("Found %s cpu-cores" % self._pool_size, STD_OUT)
        self._q = multiprocessing.Queue()

        self._workers = [Worker(self._q) for i in xrange(self._pool_size)]

        #log("%s %s %s" % (APP_NAME, APP_VER, APP_STATUS), STD_OUT)

        group = grp.getgrgid(os.getegid())[0]
        user = pwd.getpwuid(os.geteuid())[0]

        log("User: %s" % (user), STD_OUT)
        log("Group: %s" % (group), STD_OUT)

        smtpd.SMTPServer.__init__(self, localaddr, remoteaddr)
        log("Listen: %s:%s" % (localaddr[0], localaddr[1]), STD_OUT)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            conn, addr = pair
            print >> smtpd.DEBUGSTREAM, 'Incoming connection from %s' % repr(addr)
            channel = self.channel_class(self, conn, addr)

    def check(self):
        """
        A Function to Check if every important File is readable, or executeable
        """

        # All Folders they should be writable
        folders_write = [self._spool_path]
        for folder in folders_write:
            if os.path.isdir(folder):
                if not os.access("%s" % folder, os.W_OK):
                    log("Can not write in: %s" % folder, STD_ERR)
            else:
                log("Dir not found: %s" % file, STD_ERR)

    def process_message(self, peer, mailfrom, rcpttos, data, conn):
        """
        A Function to Handle a Message from the SMTP
        """
        client_handle = multiprocessing.reduction.reduce_handle(conn.fileno())
        self._q.put((True, (client_handle, (peer, mailfrom, rcpttos, data)))) # Put an item on the queue

    def shutdown(self):
        for worker in self._workers:
            self._q.put((False, None))


def signal_handler(signal, frame):
    print "Crtl+C pressed. Shutting down."
    phoenix.shutdown()
    sys.exit(0)


if __name__ == "__main__":
    global phoenix

    ip = "localhost"
    port = 10024
    parent_smtp_ip = "localhost"
    parent_stmp_port = 25
    relay_smtp_ip = "localhost"
    relay_smtp_port = 10025
    resend_timeout=60
    spool_path="/var/spool/phoenix"

    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help", "send-test-mail", "try-resend=", "parent-smtp-ip=", "parent-smtp-port=", "relay-smtp-ip=", "relay-smtp-port=", "ip=", "port=", "daemon"])
    except getopt.GetoptError, err:
            # print help information and exit:
            sys.stderr.write(str(err)+"\n") # will print something like "option -a not recognized"
            #usage()
            sys.exit(2)

    for o, a in opts:
        if o == "--daemon":
            daemon(PID_FILE)
        elif o == "--ip":
            ip = a
        elif o == "--port":
            port = a
        elif o == "--parent-smtp-ip":
            parent_smtp_ip = a
        elif o == "--parent-smtp-port":
            parent_smtp_port = a
        elif o == "--relay-stmp-ip":
            relay_smtp_ip = a
        elif o == "--relay-smtp-port":
            relay_smtp_port = a
        elif o == "--try-resend":
            resend_timeout=a
        elif o == "--spool-path":
            spool_path=a

    # For Client and sql
    for o, a in opts:

        if o in ("-h", "--help"):
            print """
-h, --help

--send-test-mail

--try-resend=SEC

--parent-smtp-ip=IP
--parent-smtp-port=PORT

--relay-smtp-ip=IP
--relay-smtp-port=PORT

--ip=IP
--port=PORT

--spool-path=STRING
"""
            sys.exit(0)

    phoenix = Phoenix(localaddr=(ip, port), remoteaddr=None, relay_smtp=(relay_smtp_ip, relay_smtp_port), resend_timeout=resend_timeout, spool_path=spool_path)
    signal.signal(signal.SIGINT, signal_handler)
    asyncore.loop()
