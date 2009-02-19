#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TODO:  Add the ability to pass command line arguments to uploaded and executed files

# Import standard Python modules
import getpass, threading, Queue, sys, os, re
from optparse import OptionParser
from time import sleep
import traceback

# Import non-standard stuff below
try:
    import paramiko
except:
    print("ERROR: paramiko is a required module. Please install it")
    exit(1)
    
__version__ = '1.0.2'
__license__ = "GNU General Public License (GPL) Version 3"
__version_info__ = (1, 0, 0)
__author__ = 'Dan McDougall <YouKnowWho@YouKnowWhat.com>'

__doc__ = \
"""
SSH Power Tool (SSHPT): This program will attempt to login via SSH to a list of servers supplied in a text file (one host per line).  It supports multithreading and will perform simultaneous connection attempts to save time (10 by default).  Results are output to stdout in CSV format and optionally, to an outfile (-o).

If no username and/or password are provided as command line arguments or via a credentials file the program will prompt for the username and password to use in the connection attempts.

This program is meant for situations where shared keys are not an option.  If all your hosts are configured with shared keys for passwordless logins you don't need the SSH Power Tool.
"""

# Setup some global defaults
VERBOSE = True
OUTFILE = None
DEBUG = False


def verbose(s):
    """Prints string, 's' if global, VERBOSE is set to True"""
    if VERBOSE:
        print s

def debug(s):
    """Prints string, 's' if global, DEBUG is set to True"""
    if DEBUG:
        print s
    
def normalizeString(string):
    """Removes/fixes leading/trailing newlines/whitespace and escapes double quotes with double quotes (to comply with CSV format)"""
    srting = re.sub(r'(\r\n|\r|\n)', '\n', string) # Convert all newlines to unix newlines
    string = string.strip() # Remove leading/trailing whitespace/blank lines
    srting = re.sub(r'(")', '""', string) # Convert double quotes to double double quotes (e.g. 'foo "bar" blah' becomes 'foo ""bar"" blah')
    return string

class OutputThread(threading.Thread):
    """This thread is here to prevent SSHThreads from simultaneously writing to the same file and mucking it all up.  Essentially, it allows the program to write results to an outfile as they come in instead of all at once when the program is finished.  This also prevents a 'kill -9' from destroying report resuls and also lets you do a 'tail -f <outfile>' to watch results in real-time."""
    def __init__(self, output_queue):
        threading.Thread.__init__(self, name="OutputThread")
        self.output_queue = output_queue

    def quit(self):
        sys.exit(0)

    def writeOut(self, queueObj):
        """Write 'text' to stdout (if VERBOSE is True) and to the outfile (if enabled)"""
        message = "\"%s\",\"%s\",\"%s\"" % (queueObj['hostname'], queueObj['connection_result'], queueObj['command_output'])
        verbose(message)
        if OUTFILE is not None:
            message = "%s\n" % message
            outlist = open(OUTFILE, 'a')
            outlist.write(message)
            outlist.close()

    def run(self):
        while True:
            queueObj = self.output_queue.get()
            if queueObj == "quit":
                self.quit()
            self.writeOut(queueObj)
            self.output_queue.task_done()

class SSHThread(threading.Thread):
    """Connects to a host and optionally runs a command or copies a file over SFTP.
    Must be instanciated with:
      id                    A thread ID
      ssh_connect_queue     Queue.Queue() for receiving orders
      output_queue          Queue.Queue() to output results
    
    Here's the list of variables that are added to the output queue before it is put():
        queueObj['hostname']
        queueObj['username']
        queueObj['password']
        queueObj['command'] - String: Command that was executed
        queueObj['local_filepath'] - String: SFTP local file path
        queueObj['remote_filepath'] - String: SFTP file destination path
        queueObj['execute'] - Boolean
        queueObj['remove'] - Boolean
        queueObj['sudo'] - Boolean
        queueObj['run_as'] - String: User to execute the command as (via sudo)
        queueObj['connection_result'] - String: 'SUCCESS'/'FAILED'
        queueObj['command_output'] - String: Textual output of the command after it was executed
    """
    def __init__ (self, id, ssh_connect_queue, output_queue):
        threading.Thread.__init__(self, name="SSHThread-%d" % (id,))
        self.ssh_connect_queue = ssh_connect_queue
        self.output_queue = output_queue
        self.id = id

    def quit(self):
        sys.exit(0)

    def run (self):
        try:
            while True:
                queueObj = self.ssh_connect_queue.get()
                if queueObj == 'quit':
                    self.quit()
                hostname = queueObj['hostname']
                username = queueObj['username']
                password = queueObj['password']
                timeout = queueObj['timeout']
                command = queueObj['command']
                local_filepath = queueObj['local_filepath']
                remote_filepath = queueObj['remote_filepath']
                execute = queueObj['execute']
                remove = queueObj['remove']
                sudo = queueObj['sudo']
                run_as = queueObj['run_as']
                debug("SSHThread-%s running attemptConnection(%s, %s, <password>, %s, %s, %s, %s, %s, %s, %s, %s)" % (self.id, hostname, username, timeout, command, local_filepath, remote_filepath, execute, remove, sudo, run_as))
                success, command_output = attemptConnection(hostname, username, password, timeout, command, local_filepath, remote_filepath, execute, remove, sudo, run_as)
                if success:
                    queueObj['connection_result'] = "SUCCESS"
                else:
                    queueObj['connection_result'] = "FAILED"
                queueObj['command_output'] = command_output
                self.output_queue.put(queueObj)
                self.ssh_connect_queue.task_done()
        except Exception, detail:
            print detail
            self.quit()

def startOutputThread():
    """Starts up the OutputThread (which is used by SSHThreads to print/write out results)."""
    output_queue = Queue.Queue()
    output_thread = OutputThread(output_queue)
    output_thread.setDaemon(True)
    output_thread.start()
    return output_queue

def stopOutputThread():
    """Shuts down the OutputThread"""
    for t in threading.enumerate():
        if t.getName().startswith('OutputThread'):
            debug("stopping %s..." % t.getName())
            t.quit()
            debug("...stopped")
    return True

def startSSHQueue(output_queue, max_threads):
    """Setup concurrent threads for testing SSH connectivity.  Must be passed a Queue (output_queue) for writing results."""
    ssh_connect_queue = Queue.Queue()
    for thread_num in range(max_threads):
        ssh_thread = SSHThread(thread_num, ssh_connect_queue, output_queue)
        ssh_thread.setDaemon(True)
        ssh_thread.start()
        debug("SSHThread-%s spawned" % thread_num)
    return ssh_connect_queue

def stopSSHQueue():
    """Shut down the SSH Threads"""
    for t in threading.enumerate():
        if t.getName().startswith('SSHThread'):
            debug("stopping %s..." % t.getName())
            t.quit()
            debug("...stopped")
    return True

def queueSSHConnection(ssh_connect_queue, hostname, username, password, timeout, command, local_filepath, remote_filepath, execute, remove, sudo, run_as):
    """Add files to the SSH Queue (ssh_connect_queue)"""
    queueObj = {}
    queueObj['hostname'] = hostname
    queueObj['username'] = username
    queueObj['password'] = password
    queueObj['timeout'] = timeout
    queueObj['command'] = command
    queueObj['local_filepath'] = local_filepath
    queueObj['remote_filepath'] = remote_filepath
    queueObj['execute'] = execute
    queueObj['remove'] = remove
    queueObj['sudo'] = sudo
    queueObj['run_as'] = run_as
    ssh_connect_queue.put(queueObj)
    return True

def paramikoConnect(hostname, username, password, timeout):
    """Connects to 'hostname' and returns a Paramiko transport object to use in further communications"""
    # Uncomment this line to turn on Paramiko debugging (good for troubleshooting why some servers report connection failures)
    #paramiko.util.log_to_file('paramiko.log')
    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=22, username=username, password=password, timeout=timeout)
    except Exception, detail:
        # Connecting failed (for whatever reason)
        ssh = str(detail)
    return ssh

def sftpPut(transport, local_filepath, remote_filepath):
    """Uses SFTP to transfer a local file (local_filepath) to a remote server at the specified path (remote_filepath) using the given Paramiko transport object."""
    debug("Opening an SFTP channel...")
    sftp = transport.open_sftp()
    filename = os.path.basename(local_filepath)
    if filename not in remote_filepath:
        remote_filepath = os.path.normpath(remote_filepath + "/" + filename)
    debug("SFTP'ing %s to the server as %s" % (local_filepath, remote_filepath))
    sftp.put(local_filepath, remote_filepath)

def sudoExecute(transport, command, password, run_as='root'):
    """Executes the given command via sudo as the specified user (run_as) using the given Paramiko transport object.
    Returns stdout, stderr (after command execution)"""
    debug("sudoExecute: Running '%s' via sudo as '%s'" % (command, run_as))
    stdin, stdout, stderr = transport.exec_command("sudo -S -u %s %s" % (run_as, command))
    if stdout.channel.closed is False: # If stdout is still open then sudo is asking us for a password
        stdin.write('%s\n' % password)
        stdin.flush()
    return stdout, stderr

def executeCommand(transport, command, sudo=False, run_as='root', password=None):
    """Executes the given command via the specified Paramiko transport object.  Will execute as sudo if passed the necessary variables (sudo=True, password, run_as).
    Returns stdout (after command execution)"""
    if sudo:
        stdout, stderr = sudoExecute(transport=transport, command=command, password=password, run_as=run_as)
    else:
        stdin, stdout, stderr = transport.exec_command(command)
    command_output = stdout.readlines()
    return command_output
    
def attemptConnection(hostname, username, password, timeout=30, command=False, local_filepath=False, remote_filepath='/tmp/', execute=False, remove=False, sudo=False, run_as='root'):
    """Attempt to login to 'hostname' using 'username'/'password' and execute 'command'.
    Will excute the command via sudo if 'sudo' is set to True (as root by default) and optionally as a given user (run_as).
    Returns the connection result as a boolean and the command result as a string."""

    debug("attemptConnection(%s, %s, <password>, %s, %s, %s, %s, %s, %s, %s, %s)" % (hostname, username, timeout, command, local_filepath, remote_filepath, execute, remove, sudo, run_as))
    connection_result = True
    
    # TODO: Add stderr handling
    if hostname != "":
        try:
            ssh = paramikoConnect(hostname, username, password, timeout)
            if type(ssh) == type(""): # If ssh is a string that means the connection failed and 'ssh' is the detail as to why
                connection_result = False
                command_output = ssh
                return connection_result, command_output
            if local_filepath:
                sftpPut(ssh, local_filepath, remote_filepath)
                if execute:
                    debug("attemptConnection: Setting %s on %s as executable" % (filename, hostname))
                    stdin, stdout, stderr = ssh.exec_command("chmod a+x %s" % remote_filepath) # Make it executable (a+x in case we run as another user via sudo)
                    command = remote_filepath # The command to execute is now the uploaded file
                else: # We're just copying a file (no execute) so let's return it's details
                    command = "ls -l %s" % remote_filepath
            if command:
                debug("attemptConnection: Executing '%s' on %s" % (command, hostname))
                command_output = executeCommand(transport=ssh, command=command, sudo=sudo, run_as=run_as, password=password)
            elif command is False and execute is False: # If we're not given anything to execute run the uptime command to make sure that we can execute *something*
                stdin, stdout, stderr = ssh.exec_command('uptime')
                command_output = stdout.readlines()
            if local_filepath and remove:
                ssh.exec_command("rm -f %s" % remote_filepath) # Clean up/remove the file we just uploaded and executed
            ssh.close()
            command_output = "".join(command_output)
            command_output = normalizeString(command_output)
        except Exception, detail:
            # Connection failed
            #traceback.print_exc()
            #print "Exception: %s" % detail
            connection_result = False
            command_output = detail
            ssh.close()
        return connection_result, command_output

def sshpt(hostlist, username, password, max_threads=10, timeout=30, command=False, local_filepath=False, remote_filepath="/tmp/", execute=False, remove=False, sudo=False, run_as='root', output_queue=None):
    """Given a list of hosts (hostlist) and credentials (username, password), connect to them all via ssh and optionally:
        * Execute a command (command) on the host.
        * SFTP a file to the host (local_filepath, remote_filepath) and optionally, execute it (execute).
        * Execute said command or file via sudo as root or another user (run_as).
    
    If you're importing this program as a module you can pass this function your own Queue (output_queue) to be used for writing results via your own class (for example, to record results into a database or a different file format).  Alternatively you can just override the writeOut() method in OutputThread (it's up to you =)."""

    if output_queue is None:
        output_queue = startOutputThread()
    # Start up the Output and SSH threads
    debug("Starting %s connection threads..." % max_threads)
    ssh_connect_queue = startSSHQueue(output_queue, max_threads)
    
    while len(hostlist) != 0: # Only add items to the ssh_connect_queue if there are available threads to take them.
        for host in hostlist:
            if ssh_connect_queue.qsize() <= max_threads:
                queueSSHConnection(ssh_connect_queue, host, username, password, timeout, command, local_filepath, remote_filepath, execute, remove, sudo, run_as)
                hostlist.remove(host)
        sleep(1)
    ssh_connect_queue.join() # Wait until all jobs are done before exiting
    output_queue.join() # Ditto

def main():
    """Main program function:  Grabs command-line arguments, starts up threads, and runs the program."""

    # Bring in some globals
    global OUTFILE
    global VERBOSE
    global DEBUG

    # Grab command line arguments and the command to run (if any)
    usage = "usage: %prog [options] [command] [arguments...]"
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option("-f", "--file", dest="hostfile", default=None, help="Location of the file containing the host list.", metavar="<file>")
    parser.add_option("-o", "--outfile", dest="OUTFILE", default=None, help="Location of the file where the results will be saved.", metavar="<file>")
    parser.add_option("-a", "--authfile", dest="authfile", default=None, help="Location of the file containing the credentials to be used for connections (format is \"username:password\").", metavar="<file>")
    parser.add_option("-t", "--threads", dest="max_threads", default=10, type="int", help="Number of threads to spawn for simultaneous connection attempts [default: 10].", metavar="<int>")
    parser.add_option("-u", "--username", dest="username", default=None, help="The username to be used when connecting.", metavar="<username>")
    parser.add_option("-P", "--password", dest="password", default=None, help="The password to be used when connecting (not recommended--use an authfile unless the username and password are transient", metavar="<password>")
    parser.add_option("-q", "--quiet", action="store_false", dest="VERBOSE", default=True, help="Don't print status messages to stdout (only print errors).")
    parser.add_option("-d", "--debug", action="store_true", dest="DEBUG", default=False, help="Print debugging messages (to stdout).")
    parser.add_option("-c", "--copy-file", dest="copy_file", default=None, help="Location of the file to copy to and optionally execute (-x) on hosts.", metavar="<file>")
    parser.add_option("-D", "--dest", dest="destination", default="/tmp/", help="Path where the file should be copied on the remote host (default: /tmp/).", metavar="<path>")
    parser.add_option("-x", "--execute", action="store_true", dest="execute", default=False, help="Execute the copied file (just like executing a given command).")
    parser.add_option("-r", "--remove", action="store_true", dest="remove", default=False, help="Remove (clean up) the SFTP'd file after execution.")
    parser.add_option("-T", "--timeout", dest="timeout", default=30, help="Timeout (in seconds) before giving up on an SSH connection (default: 30)", metavar="<seconds>")
    parser.add_option("-s", "--sudo", action="store_true", dest="sudo", default=False, help="Use sudo to execute the command (default: as root).")
    parser.add_option("-U", "--sudouser", dest="run_as", default="root", help="Run the command (via sudo) as this user.", metavar="<username>")
    (options, args) = parser.parse_args()

    # Check to make sure we were passed at least one command line argument
    try:
        sys.argv[1]
    except:
        print "\nError:  At a minimum you must supply an input hostfile (-f)"
        parser.print_help()
        sys.exit(2)

    command = False
    return_code = 0

    # Assume anything passed to us beyond the command line switches is the command to be executed
    if len(args) > 0:
        command = " ".join(args)

    # Assign the options to more readable variables
    username = options.username
    password = options.password
    local_filepath = options.copy_file
    remote_filepath = options.destination
    execute = options.execute
    remove = options.remove
    sudo = options.sudo
    max_threads = options.max_threads
    timeout = options.timeout
    run_as = options.run_as
    VERBOSE = options.VERBOSE
    DEBUG = options.DEBUG
    OUTFILE = options.OUTFILE

    if options.hostfile == None:
        print "Error: You must supply a file (-f <file>) containing the host list to check."
        print "Use the -h option to see usage information."
        sys.exit(2)

    if options.OUTFILE is None and options.VERBOSE is False:
        print "Error: You have not specified any mechanism to output results."
        print "Please don't use quite mode (-q) without an output file (-o <file>)."
        sys.exit(2)

    if local_filepath is not None and command is not False:
        print "Error: You can either run a command or execute a file.  Not both."
        sys.exit(2)

    # Read in the host list to check
    debug("Reading in %s..." % options.hostfile)
    hostlist = open(options.hostfile).read()

    if options.authfile is not None:
        debug("Using authfile for credentials.")
        credentials = open(options['authfile']).readline()
        username, password = credentials.split(":")

    # Get the username and password to use when checking hosts
    if options.username == None:
        username = raw_input('Username: ')
    if options.password == None:
        password = getpass.getpass('Password: ')

    hostlist_list = []

    try: # This wierd little sequence of loops allows us to hit control-C in the middle of program execution and get immediate results
        for hostname in hostlist.split("\n"): # Turn the hostlist into an actual list
            if hostname != "":
                hostlist_list.append(hostname)
        sshpt(hostlist_list, username, password, max_threads, timeout, command, local_filepath, remote_filepath, execute, remove, sudo, run_as)
    except KeyboardInterrupt:
        print 'caught KeyboardInterrupt, exiting...'
        return_code = 1 # Return code should be 1 if the user issues a SIGINT (control-C)
    except Exception, detail:
        print 'caught Exception...'
        print detail
        return_code = 2
    finally:
        # Clean up
        stopSSHQueue()
        stopOutputThread()
        sys.exit(return_code)

if __name__ == "__main__":
    main()