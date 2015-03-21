# Created by Will Furnell for the OpenNIC Project.

#!/usr/bin/python
# Required imports
import socketserver
from ldap3 import *
import time
import sqlite3
import configparser

# Get required information from the configuration file
config = configparser.ConfigParser()
config.sections()
config.read('config.ini')  # The configuration file containing all nessasary options.


#Let the user know what is happening
print("Starting OpenNIC WHOIS Server (LDAP Backend) " + config['info']['version'] + " (Python)")

###
# Error codes, used for debugging/troubleshooting: [Not currently in use]
# E: 00 - Unknown
# E: 01 - DNS Error, name could not be found in DNS
# E: 02 - LDAP Error, name could not be found in LDAP database
# E: 03 - LDAP Error, could not connect to LDAP server
# E: 04 - Internal Error, could not bind to port
###

#Useful functions for modifying outputs


def nb(result):  # Remove brackets from search result
        return str(result).replace("['", '').replace("']", '')


def ndc(result):  # Remove extra info from user UID (Used in searching)
        return str(result).replace("['uid=", '').replace(",o=users,dc=opennic,dc=glue']", '')

def nb_sql(result): # Remove brackets from IP address
    return str(result).replace("('", '').replace("',)", '')



def converttimestamp(timestamp):

    #Set up original timestamp
    timestamp_native = time.strptime(timestamp, '%Y%m%d%H%M%SZ')
    #Output human readable timestamp
    return time.strftime('%Y-%m-%d', timestamp_native)

# All the possible T1 servers. This is for showing the registrar in the output. If there are ever more than 25,
# just add more to the array. (now in config file)
on_registrars = config['main']['t1s']

ip = []

#The main whois server code can be found here. Sorry, not very pretty - but it gets the job done.


class WhoisServer(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    #All data sent to the client must be .encode() because you can only send bytes, not strings.
    #Not very pretty, but that's the best I can do for now.

    # A simple not in registry message
    def notfound(self):
        self.request.sendall(('Error! Not found in OpenNIC registry!\
                            \nOnly .OSS, .PARODY. TEST, .PIRATE, .KEY and .P2P domains are currently part of this service.\
                            \nICANN domains cannot be queried using this service.\
                            \nFor more information on OpenNIC Whois, please see ' + config['info']['domain'] + '\n').encode())

    # Disclaimer message for those doing queries.
    def print_disclaimer(self):
        self.request.sendall(('Whois Server Version BETA (' + config['info']['domain'] + ')\
                            \nWelcome to the OpenNIC Registry!\
                            \nThe following information is presented in the hopes that it will be useful, but OpenNIC\
                            \nmakes ABSOLUTELY NO GUARANTEE as to its accuracy. For more information please visit\
                            \nwww.opennic.glue or www.opennicproject.org.\n\n').encode())
    # Offline message
    def offline(self):
        self.request.sendall(('ERROR:\
                            \nOpenNIC Whois Service Offline Temporarily. Please try again later.\
                            \n\n').encode())

    # Lower disclaimer
    def disclaimer2(self):
        self.request.sendall(('\n\nNOTE: THE WHOIS DATABASE IS A CONTACT DATABASE ONLY. LACK OF A DOMAIN\n'
                             'RECORD DOES NOT SIGNIFY DOMAIN AVAILABILITY.').encode())

    # Queries exceeded message
    def exceeded(self):
        self.request.sendall(('\n\nERROR: Maximum requests exceeded for today!\n'
                             'See the limits at ' + config['info']['limiturl']).encode())

    # Where the bulk of the program occours.
    def handle(self):
        #This is initiated each time the user searches for a domain.

        # self.request is the TCP socket connected to the client
        self.domain = self.request.recv(1024)
        domain = self.domain.decode('utf-8').strip()
        print('Domain Lookup: ' + domain + '. By ' + str(self.client_address))

        #Today's Date
        date = time.strftime('%Y-%m-%d')

        # Connect to SQLLITE Database so we can log the user's IP, checking how many requests they have made.
        # Create a database in RAM
        db = sqlite3.connect(':memory:')
        # Creates or opens a file called on-whois-db.db with a SQLite3 DB
        db = sqlite3.connect(config['main']['dbfile'])

        cursor = db.cursor()

        ip = (nb_sql(self.client_address[0]))

        numqueries = 1  # Initialise variable

        cursor.execute('SELECT queries FROM ipdb WHERE (date = ? AND ip = ?)', (date, ip))
        queries = cursor.fetchone()

        if queries is None:
            numqueries = 1
            print('IP NOT in DB for today - adding')
            cursor.execute('INSERT INTO ipdb(date, ip, queries) values(?, ?, ?)', (date, ip, numqueries))
            db.commit()
        else:
            numqueries = queries[0] + 1  # Add one to the number of queries if one exists
            cursor.execute("UPDATE ipdb SET queries = ? WHERE (ip = ? AND date = ?)", (numqueries, ip, date))
            db.commit()

        #Output TOS
        self.print_disclaimer()

        reginfo = ""
        manager = ""

        if numqueries < int(config['main']['maxqueries']):
            #Get Extension
            domsplit = domain.split(".")

            if len(domsplit) == 1:
                domain = domain + "."

            # LDAP connection details
            s = Server(config['ldap']['server'], port=636, get_info = GET_ALL_INFO, use_ssl=True)

            #Connect to LDAP server
            print("Trying to connect to LDAP Server")
            try:
                print("Connection & search in progress")
                c = Connection(s, auto_bind=True, client_strategy=STRATEGY_SYNC, user=config['ldap']['user_dn'], password=config['ldap']['password'])
                c.search(search_base='o=zones,dc=opennic,dc=glue', search_filter='(associatedDomain=' + domain + ')',
                         search_scope=SEARCH_SCOPE_WHOLE_SUBTREE, attributes = ['associatedDomain', 'description', 'manager',
                         'dateExpiration', 'createTimestamp', 'modifyTimestamp', 'zoneDisabled', 'creatorsName'])
                result = c.response
                print("Connection successful, search performed")
            except LDAPException:
                #Got to exit, as without a backend, the server is useless
                result = ""
                self.offline()
                print("Connection & search FAILED")
            except OSError:
                #Got to exit, as without a backend, the server is useless.
                result = ""
                self.offline()
                print("Connection & search FAILED")

            # Give the output if applicable

            if result:

                #Main output
                for r in result:
                    #Set up manager variable, makes things neater later on
                    manager = ndc(r['attributes']['manager'])
                    reginfoname = ndc(r['attributes']['creatorsName']).lower()

                    if reginfoname in on_registrars:
                        reginfo = reginfoname + ".opennic.glue"
                    else:
                        reginfo = ndc(r['attributes']['creatorsName'])

                    #Here's the fun part - output to the user
                    self.request.sendall(('Domain Name: ' + nb(r['attributes']['associatedDomain']) + '\n').encode())
                    self.request.sendall(('Domain Registered: ' + converttimestamp(nb(r['attributes']['createTimestamp'])) + '\n').encode())
                    self.request.sendall(('Domain Modified: ' + converttimestamp(nb(r['attributes']['modifyTimestamp'])) + '\n').encode())
                    try:
                        self.request.sendall(('Domain Expires: ' + converttimestamp(nb(r['attributes']['dateExpiration'])) + '\n').encode())
                    except KeyError:
                        self.request.sendall(('Domain Expires: Never \n').encode())
                    #Attribute may be blank, so assume OK if it is
                    try:
                        test = r['attributes']['zoneDisabled']
                        if nb(r['attributes']['zoneDisabled']) == "TRUE":
                            self.request.sendall('Status:  Disabled\n'.encode())
                        else:
                            self.request.sendall('Status: OK \n'.encode())
                    except KeyError:
                        self.request.sendall('Status: OK \n'.encode())

                    #Get user information from DB
                try:
                    #c2 = Connection(s, auto_bind=True, client_strategy=STRATEGY_SYNC, user=config['ldap']['user_dn'], password=config['ldap']['password'])
                    c.search(search_base='o=users,dc=opennic,dc=glue', search_filter='(uid=' + manager + ')', search_scope=SEARCH_SCOPE_WHOLE_SUBTREE, attributes = ['cn', 'mail'])
                    user_result = c.response
                    c.close()
                except e:
                    #Got to exit, as without a backend, the server is useless
                    user_result = ""
                    print("Connection & search for user FAILED, falling back to Unknown" + e.strerror)

                #Was there any user info?
                if user_result:
                    for ur in user_result:
                        self.request.sendall(('Registrant: ' + nb(ur['attributes']['cn']) + '\n').encode())
                        self.request.sendall(('Registrant Contact: ' + nb(ur['attributes']['mail']) + '\n').encode())
                else:
                    self.request.sendall('Registrant: Unknown\n'.encode())
                    self.request.sendall('INFO: Domain could be abandoned! \n'.encode())

                #Extra info
                self.request.sendall(('Registrar: ' + reginfo + '\n').encode())

            else:
                #Give a not found error
                self.notfound()
        else:
            self.exceeded()
        #Output lower disclaimer
        self.disclaimer2()

        db.commit()
if __name__ == "__main__":

    try:
        # Create the server, binding to port specified
        server = socketserver.TCPServer(('', int(config['main']['port'])), WhoisServer)

        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
    except OSError as e:
        #Port is probably already bound. Error nicely.
        print('E: 04: Error! ' + e.strerror)
