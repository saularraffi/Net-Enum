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
import ssl
import subprocess

target = '10.0.2.9'

mysqlscan = MysqlScanner(target, 3306)
print(mysqlscan.runCommand(username='root', command='use dvwa; select * from users;'))