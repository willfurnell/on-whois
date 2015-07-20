# Created by Will Furnell

#!/usr/bin/python
# Required imports
import socketserver
import time
import sqlite3
import configparser
from ldap3 import *

# Get required information from the configuration file
config = configparser.ConfigParser()
config.sections()
config.read('config.ini')  # The configuration file containing all nessasary options.


# Let the user know what is happening
print("Starting OpenNIC WHOIS Server (LDAP Backend) " + config['info']['version'] + " (Python)")


# Useful functions for modifying outputs

def getUID(result):  # Remove extra info from user UID (Used in searching)
        return str(result).replace("uid=", '').replace(",o=users,dc=opennic,dc=glue", '')


def censoremail(result):
    if "@" in result:
        email = result.replace("@", ' AT ')
    else:
        email = result

    return email

# All the possible T1 servers. This is for showing the registrar in the output. If there are ever more than 25,
# just add more to the array. (now in config file)
on_registrars = config['main']['t1s']

ip = []


# The main WHOIS server

class WhoisServer(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    # A simple not in registry message
    def notfound(self):
        self.s('Error! Not found in OpenNIC registry!\
                            \nOnly .OSS, .PARODY. TEST, .PIRATE, .KEY and .P2P domains are currently part of this service.\
                            \nICANN domains cannot be queried using this service.\
                            \nFor more information on OpenNIC Whois, please see ' + config['info']['domain'] + '\n')

    # Disclaimer message for those doing queries.
    def top_disclaimer(self):
        self.s('Whois Server (' + config['info']['domain'] + ')\
                            \nWelcome to the OpenNIC Registry!\
                            \nThe following information is presented in the hopes that it will be useful, but OpenNIC\
                            \nmakes ABSOLUTELY NO GUARANTEE as to its accuracy. For more information please visit\
                            \nwww.opennic.glue or www.opennicproject.org.\n\n')
    # Offline message
    def offline(self):
        self.s('ERROR:\
                \nOpenNIC Whois Service Offline Temporarily. Please try again later.\
                \n\n')

    # Lower disclaimer
    def bottom_disclaimer(self):
        self.s('\n\nNOTE: THE WHOIS DATABASE IS A CONTACT DATABASE ONLY. LACK OF A DOMAIN\n'
                'RECORD DOES NOT SIGNIFY DOMAIN AVAILABILITY.')

    # Queries exceeded message
    def exceeded(self):
        self.s('\n\nERROR: Maximum requests exceeded for today!\n'
                'See the limits at ' + config['info']['limiturl'])

    def s(self, string):
        self.request.sendall(string.encode())

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

        ip = self.client_address[0]

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
        self.top_disclaimer()

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
            except LDAPException as e:
                #Got to exit, as without a backend, the server is useless
                result = ""
                self.offline()
                print("Connection & search FAILED: " + str(e))
            except OSError as e2:
                #Got to exit, as without a backend, the server is useless.
                result = ""
                self.offline()
                print("Connection & search FAILED: " + str(e2))

            # Give the output if applicable

            if result:

                #Main output
                for r in result:
                    #Set up manager variable, makes things neater later on
                    manager = getUID(r['attributes']['manager'][0])
                    reginfoname = getUID(r['attributes']['creatorsName'])


                    if reginfoname.lower() in on_registrars:
                        reginfo = reginfoname + ".opennic.glue"
                    elif reginfoname == "cn=root,dc=opennic,dc=glue":
                        reginfo = "OpenNIC"
                    else:
                        reginfo = getUID(r['attributes']['creatorsName'][0])

                    #Here's the fun part - output to the user
                    self.s('Domain Name: ' + r['attributes']['associatedDomain'][0] + '\n')
                    self.s('Domain Registered: ' + str(r['attributes']['createTimestamp']) + '\n')
                    self.s('Domain Modified: ' + str(r['attributes']['modifyTimestamp']) + '\n')
                    try:
                        self.s('Domain Expires: ' + str(r['attributes']['dateExpiration']) + '\n')
                    except KeyError:
                        self.s('Domain Expires: Never \n')
                    #Attribute may be blank, so assume OK if it is
                    try:
                        test = r['attributes']['zoneDisabled']
                        if r['attributes']['zoneDisabled'] == "TRUE":
                            self.s('Status:  Disabled\n')
                        else:
                            self.s('Status: OK \n')
                    except KeyError:
                        self.s('Status: OK \n')

                    #Get user information from DB
                try:
                    #c2 = Connection(s, auto_bind=True, client_strategy=STRATEGY_SYNC, user=config['ldap']['user_dn'], password=config['ldap']['password'])
                    c.search(search_base='o=users,dc=opennic,dc=glue', search_filter='(uid=' + manager + ')', search_scope=SEARCH_SCOPE_WHOLE_SUBTREE, attributes = ['cn', 'mail'])
                    user_result = c.response
                    #c.close()
                except:
                    #Got to exit, as without a backend, the server is useless
                    user_result = ""
                    print("Connection & search for user FAILED, falling back to Unknown")

                #Was there any user info?
                if user_result:
                    for ur in user_result:
                        self.s('Registrant: ' + ur['attributes']['cn'][0] + '\n')
                        self.s('Registrant Contact: ' + censoremail(ur['attributes']['mail'][0]) + '\n')
                else:
                    self.s('Registrant: Unknown\n')
                    self.s('Registrant: Domain could be abandoned! \n')
                    self.s('Registrant Contact: OpenNIC \n')

                #Extra info
                self.s('Registrar: ' + reginfo + '\n')

            else:
                #Give a not found error
                self.notfound()
        else:
            self.exceeded()
        #Output lower disclaimer
        self.bottom_disclaimer()

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
        print('OS Error: ' + e.strerror)
