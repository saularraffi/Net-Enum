import argparse
from nm import Nmap
from webScanner import WebScanner
import sys
import nmap
from ftpScanner import FtpScanner
from ftplib import FTP
from smbScanner import SmbScanner
from termcolor import colored
import socket
from smtpScanner import SmtpScanner
from time import sleep
from smb.SMBConnection import SMBConnection
import os
from mysqlScanner import MysqlScanner
from datetime import datetime
import mysql.connector

target = '10.0.2.9'

mydb = mysql.connector.connect(
	host="10.0.2.9",
	user="root",
	password=""
)

print(mydb)