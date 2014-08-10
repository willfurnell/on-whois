__author__ = 'willfurnell'
import sqlite3
db = sqlite3.connect('on-whois-db.db')

cursor = db.cursor()
cursor.execute('''CREATE TABLE ipdb (date text, ip text, queries int)''')

db.commit()