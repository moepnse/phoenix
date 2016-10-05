#!/usr/bin/env python
# -*- coding: utf-8 -*-

# standard library imports
import os
import re
import sys
import getopt
import time

# related third party imports
import pyclamd

# local application/library specific imports
from logging import log, STD_OUT, STD_ERR
from testmail import TestMail


YES = "YES"
NO = "NO"
UNKNOWN = "UNKNOWN"

# E-Mail Header Tags
X_VIRUS_NAME = "X-Virus-Name"
X_VIRUS = "X-Virus"
X_VIRUS_SCAN_ERROR = "X-Virus-Scan-Error"

# Default temp-dir
TMP_PATH = u"/var/tmp/phoenix/clamav"


# Exception Class
class BreakScanning(Exception):
    pass


class AntiVirusBase:
    """The AntiVirus Class"""

    def __init__(self, **kwargs):

        self._mail_nr =  kwargs.get("mail_nr", 0)

        self._x_virus_name = kwargs.get("x_virus_name", X_VIRUS_NAME)
        self._x_virus = kwargs.get("x_virus", X_VIRUS)
        self._x_virus_scan_error = kwargs.get("x_virus_scan_error", X_VIRUS_SCAN_ERROR)

        self._tmp_path = kwargs.get("tmp_path", TMP_PATH)

        self._regex = re.compile("\.[A-Za-z]{3,4}\.exe")
        self._cd = pyclamd.ClamdUnixSocket()

    def check_mail(self):
        pass

    def set_tags(self):
        """Sets the tags in the e-mail header"""

        self._email_message.__delitem__(self._x_virus)
        if self._virus == True:
            self._email_message.__setitem__(self._x_virus, YES)
            for virus in self._viruses:
                # add a new "X-Virus-Name" Header
                self._email_message.__setitem__(self._x_virus_name, virus.name)

        elif self._virus == False:
            self._email_message.__setitem__(self._x_virus, NO)
        else:
            self._email_message.__setitem__(self._x_virus, UNKNOWN)

        if self._scan_error == True:
            self._email_message.__setitem__(self._x_virus_scan_error, YES)
        else:
            self._email_message.__setitem__(self._x_virus_scan_error, NO)


class AntiVirusScanFile(AntiVirusBase):

    def __init__(self, **kwargs):
        AntiVirusBase.__init__(self, **kwargs)

    def check_mail(self, email_message):
        self._virus = False
        self._viruses = []

        self._scan_error = False
        self._email_message = email_message
        self._message_id = self._email_message.__getitem__("Message-Id")
        self._subject = self._email_message.__getitem__("Subject")

        self._timestamp = int(time.time())

        try:
            self._att_dir = os.path.join(self._tmp_path, "att_%s_%s_%s" % (self._message_id, self._timestamp, self._mail_nr))
            self._check_dir()
            self._part_nr = 0

            for self._part in self._email_message.walk():
                self._part_nr += 1
                #print part_nr

                #print part.get_content_maintype()
                #print part.get_content_subtype()

                if self._part.get_content_maintype() == 'multipart':
                    continue

                self._msgtype = self._part.get_content_type()
                self._filename = self._part.get_filename()

                if self._filename == None:
                    self._filename = "att_%s_%s" % (time.time(), self._part_nr)
                    log("%s [ClamAV] Error: No filename!" % (self._message_id), STD_ERR)
                    #continue
                else:
                    self._encode_filename()
                self._check_illegal_filename()

                log("%s [ClamAV] Filename: %s" %  (self._message_id, self._filename), STD_OUT)
                self._path = os.path.join(self._att_dir, self._filename)

                self._store_part()
                self._scan_file()
                self._clean_up()
        except BreakScanning:
            self._scan_error = True

            if self._email_message.__getitem__(self._x_virus) != YES:
                self._virus = None

            return self._virus

    def _encode_filename(self):
        """Encodes the filename if its necessary"""

        # The form is: "=?charset?encoding?encoded text?=".
        if self._filename.startswith("=?") and self._filename.endswith("?="):
            try:
                self._header_enc = email.Header.decode_header(self._filename)[0]
                #self._filename = unicode(self._header_enc[0], self._header_enc[1]).encode('ascii', 'replace')
                self._filename = unicode(self._header_enc[0], self._header_enc[1])
            except:
                log("%s [ClamAV] Error: Filename encoding error!" % (self._message_id), STD_ERR)

    def _check_illegal_filename(self):
        """Check for illegale filenames: *.jpg.exe, *.jpeg.exe, *.pdf.exe"""

        try:
            if re.match(self._regex, self._filename):
                self._virus = True
        except:
            pass

    def _check_dir(self):
        """Check if the dir exists and verify that the dir is read- and writeable"""

        if not os.path.exists(self._att_dir):
            try:
                os.makedirs(self._att_dir)
            except IOError, err:
                if err[0] == 2:
                    log("%s [ClamAV] Error: No such file or directory: %s" % (self._message_id, self._path), STD_ERR)
                elif err[0] == 13:
                    log("%s [ClamAV] Error: Access denied: %s" % (self._message_id, self._path), STD_ERR)
                    raise BreakScanning()
            except Exception, err:
                log("%s [ClamAV] Error: Could not create directory: %s" % (self._message_id, self._att_dir), STD_ERR)
                log("%s [ClamAV] Unexpected error: %s" % (self._message_id, err), STD_ERR)
                raise BreakScanning()
        else:
            log("%s [ClamAV] Error: Path already exists: %s" % (self._message_id, self._att_dir), STD_ERR)

    def _store_part(self):
        """Stores every part of the e-mail on the filesystem"""

        part = self._part.get_payload(decode=True)

        try:
            file = open(self._path, 'wb')
            file.write(part)
            file.close()
        except IOError, err:
            if err[0] == 2:
                log("%s [ClamAV] Error: No such file or directory: %s" % (self._message_id, self._path), STD_ERR)
            elif err[0] == 13:
                log("%s [ClamAV] Error: Access denied: %s" % (self._message_id, self._path), STD_ERR)
            raise BreakScanning()
        except Exception, err:
            log("%s [ClamAV] Unexpected error: %s" % (self._message_id, err), STD_ERR)
            raise BreakScanning()

    def _scan_file(self):
        """Scans the file for viruses"""

        try:
            ret = self._cd.scan_file(self._path)

            if self._email_message.__getitem__(self._x_virus) != YES and ret == None:
                self._virus = False
            elif ret != None:
                self._virus = True
                self._viruses.append(ret[self._path])

        #except pyclamd.ScanError, err:
        #    log("%s [ClamAV] Error: %s" % (self._message_id, err), STD_ERR)
        #    raise BreakScanning()
        except Exception, err:
            if self._email_message.__getitem__(self._x_virus) != YES:
                self._virus = None
            log("%s [ClamAV] Unexpected error: %s" % (self._message_id, err), STD_ERR)
            raise BreakScanning()

    def _clean_up(self):
        """Cleans up the temporary files"""

        try:
            os.remove(self._path)
        except:
            log("%s [ClamAV] Error: Could not delete file: %s" % (self._message_id, self._path), STD_ERR)
            raise BreakScanning()


class AntiVirusScanStream(AntiVirusBase):

    def __init__(self, **kwargs):
        AntiVirusBase.__init__(self, **kwargs)

    def check_mail(self, email_message):
        self._virus = False
        self._viruses = []

        self._scan_error = False

        self._email_message = email_message
        self._message_id = self._email_message.__getitem__("Message-Id")
        self._subject = self._email_message.__getitem__("Subject")

        self._timestamp = int(time.time())

        try:
            self._part_nr = 0

            for self._part in self._email_message.walk():
                self._part_nr += 1
                #print part_nr

                #print part.get_content_maintype()
                #print part.get_content_subtype()

                if self._part.get_content_maintype() == 'multipart':
                    continue

                self._scan_stream()

        except BreakScanning:
            self._scan_error = True

            if self._email_message.__getitem__(self._x_virus) != YES:
                self._virus = None

            return self._virus

    def _scan_stream(self):
        """Scans the Stream for Viruses"""

        try:
            ret = pyclamd.scan_stream(self._part)

            if self._email_message.__getitem__(self._x_virus) != YES and ret == None:
                self._virus = False
            elif ret != None:
                self._virus = True
                self._viruses.append(ret["stream"])

        #except pyclamd.ScanError, err:
        #    log("%s [ClamAV] Error: %s" % (self._message_id, err), STD_ERR)
        #    raise BreakScanning()
        except Exception, err:
            if self._email_message.__getitem__(self._x_virus) != YES:
                self._virus = None
            log("%s [ClamAV] Unexpected error: %s" % (self._message_id, err), STD_ERR)
            raise BreakScanning()


def initialize(options, long_options):
    tmp_path = TMP_PATH
    try:
        opts, args = getopt.getopt(sys.argv[1:], options, long_options)
    except getopt.GetoptError, err:
            # print help information and exit:
            sys.stderr.write(str(err)+"\n") # will print something like "option -a not recognized"
            #usage()
            sys.exit(2)

    for o, a in opts:
        if o == "--tmp-path":
            tmp_path = a
    return AntiVirusScanFile(tmp_path=tmp_path)


def main():
    test_mail = TestMail()

    print "AntiVirusScanStream"
    anti_virus = AntiVirusScanStream()
    print anti_virus.check_mail(test_mail.get_virus())

    print "AntiVirusScanFile"
    anti_virus = AntiVirusScanFile()
    print anti_virus.check_mail(test_mail.get_virus())


def get_options():
    return "", ["tmp-path="]


def get_help():
    return """
--clamav-tmp-path=PATH
"""


if __name__ == "__main__":
    main()