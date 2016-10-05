#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os

from logging import log, STD_ERR, STD_OUT
from proc import is_running


class CanNotWritePIDFile(Exception):
    pass


class Daemon(object):
    def __init__(self, pid_file, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        sys.stdin = open(stdin, "a+")
        sys.stdout = open(stdout, "a+")
        sys.stderr = open(stderr, "a+")
    def run(self):

        check_pid_path(pid_file)

        try:
            fh = open(self._pid_file, "r")
            pid = fh.read.strip()
            fh.close()
        except IOError:
            pid = 0

        if pid:
            if is_running(pid):
                sys.stderr.write("Daemon is already running!")

        self.start_daemon()

    def start_daemon(self):
        # do the UNIX double-fork magic, see Stevens' "Advanced
        # Programming in the UNIX Environment" for details (ISBN 0201563177)
        try:
            # Fork a child process. Return 0 in the child and the child’s process id in the parent.
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            log("fork #1 failed: %d (%s)" % (e.errno, e.strerror), STD_ERR)
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")   #don't prevent unmounting....
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            # Fork a child process. Return 0 in the child and the child’s process id in the parent.
            pid = os.fork()
            if pid > 0:

                fh = open(pid_file,'w+')
                fh.write("%s\n" %  self._pid)
                fh.close()

                # exit from second parent, print eventual PID before
                #print "Daemon PID %d" % pid
                #open(PIDFILE,'w').write("%d"%pid)
                sys.exit(0)
        except OSError, err:
            log("fork #2 failed: %d (%s)" % (err.errno, err.strerror), STD_ERR)
            sys.exit(1)


def check_pid_path(pid_file):
    """creates pid-file path if necessary"""

    path, filename = os.path.split(pid_file)

    if not os.path.exists(path):
        tmp = path.split("/")
        for part in tmp:
            path_old = path_new 
            path_new = "/%s" % part
            if not os.path.exists(path_new):
                path_new = path_old
                break

        if not os.access(path_new, os.W_OK):
            raise CanNotWritePIDFile()

        """
        tmp = path[1:].split("/")
        new_path = "/"

        for path_part in range(tmp) - 1:
            if not os.path.exists(path_part):
                os.mkdir(path_part)

            new_path = os.path.join(new_path, path_part)
        """
        os.makedirs(path, mode=700)


def daemonize(pid_file, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):

    if isinstance(stdin, str):
        sys.stdin = open(stdin, "a+")
    elif isinstance(stdin, file):
        sys.stdin = stdin

    if isinstance(stdout, str):
        sys.stdout = open(stdout, "a+")
    elif isinstance(stdout, file):
        sys.stdout = stdout

    if isinstance(stderr, str):
        sys.stderr = open(stderr, "a+")
    elif isinstance(stderr, file):
        sys.stderr = stderr

    check_pid_path(pid_file)

    try:
        fh = open(pid_file, "r")
        pid = fh.read()
        pid = pid.strip()
        fh.close()
    except IOError:
        pid = 0

    if pid:
        if is_running(pid):
            log("Daemon is already running!", STD_ERR)

    # Beim Systemaufruf Fork erzeugt der aktuelle Prozess eine Kopie von sich selbst, welche dann als Kindprozess des erzeugenden Programmes läuft. Der Kindprozess übernimmt die Daten, den Maschinencode und den Befehlszähler vom Elternprozess und erhält vom Betriebssystem (wie der Elternprozess und jeder andere Prozess auch) eine eigene Prozessnummer, die PID (engl. "Process IDentifier"). In der Folge verwaltet das Betriebssystem den Kindprozess als eigenständige Instanz des Programms und führt ihn unabhängig vom Elternprozess aus.

    # Ein Kindprozess arbeitet normalerweise nicht exakt wie der Elternprozess weiter, sondern enthält abweichende Anweisungen oder/und neue Einstellungen.

    # An dem Rückgabewert von fork() wird erkannt, in welchem Prozess man sich befindet. Liefert fork() eine 0 zurück, kennzeichnet dies den Kindprozess, im Vaterprozess wird die PID des Kindes zurückgeliefert. Bei einem Fehler liefert fork() einen Wert kleiner 0 und kein Kindprozess wurde erzeugt.

    # do the UNIX double-fork magic, see Stevens' "Advanced
    # Programming in the UNIX Environment" for details (ISBN 0201563177)
    try:
        # Fork a child process. Return 0 in the child and the child’s process id in the parent.
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, err:
        log("fork #1 failed: %d (%s)" % (err.errno, err.strerror), STD_ERR)
        sys.exit(1)

    # decouple from parent environment
    os.chdir("/")   #don't prevent unmounting....
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        # Fork a child process. Return 0 in the child and the child’s process id in the parent.
        pid = os.fork()
        if pid > 0:

            fh = open(pid_file,'w+')
            fh.write("%s\n" %  pid)
            fh.close()

            # exit from second parent, print eventual PID before
            #print "Daemon PID %d" % pid
            #open(PIDFILE,'w').write("%d"%pid)
            sys.exit(0)
    except OSError, err:
        log("fork #2 failed: %d (%s)" % (err.errno, err.strerror), STD_ERR)
        sys.exit(1)