#!/usr/bin/python3
import subprocess
import os
import socket
import shlex
import sys
import getopt
from termcolor import cprint
from pwn import *


def banner():           
    cprint("┌─┐┬ ┬┌┬┐┌─┐┌┬┐┌─┐┌─┐",'green')
    cprint("├─┤│ │ │ │ ││││├─┤├─┘",'green')
    cprint("┴ ┴└─┘ ┴ └─┘┴ ┴┴ ┴┴  v1.0",'green')
    cprint("Automatic scanning of multiple hosts using nmap",'yellow')
    cprint("Author: evilmorty",'yellow')

def def_handler(sing, frame):
    cprint('Canceled by user', 'white', 'on_red')
    sys.exit(1)

def createFolder(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        return False

def hostUp(ip):
    command = "ping -c 1 "+ip
    args = shlex.split(command)
    p = subprocess.Popen(args, stderr=STDOUT, stdout=PIPE)  # return string not bytes
    p.communicate()
    if  p.returncode == 0:
        return True
    else:
        return False
    sleep(0.100)
    p.terminate()

def validateIp(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def nmap_allports(ip):
    command = "nmap -sS -p- --open -n " + ip + " -oG allPorts"
    args = shlex.split(command)
    p=subprocess.Popen(args, stderr=STDOUT, stdout=PIPE)
    p.communicate()
    if p.returncode == 0:
        return True
    else:
        return False
    sleep(0.100)
    p.terminate()

def nmap_extractPorts():
    command="cat allPorts | grep -oP '\d{2,5}/open' | awk '{print $1}' FS=\"/\" | xargs | tr ' ' ','"
    ports = subprocess.check_output(command, shell=True, universal_newlines=True)
    return ports

def downloand_xsl():
    command = "wget https://raw.githubusercontent.com/evilmorty06/nmap_style/main/report_nmap_style.xsl -O /tmp/nmap_spanish_style.xsl"
    args = shlex.split(command)
    p=subprocess.Popen(args, stderr=STDOUT, stdout=PIPE)
    p.communicate()
    if p.returncode == 0:
        return True
    else:
        return False
    sleep(0.100)
    p.terminate()

def nmap_html():
    command = "xsltproc -o targeted.html /tmp/nmap_spanish_style.xsl targeted.xml"
    args = shlex.split(command)
    p=subprocess.Popen(args, stderr=STDOUT, stdout=PIPE)
    p.communicate()
    if p.returncode == 0:
        return True
    else:
        return False
    sleep(0.100)
    p.terminate()

def nmap_targeted(ip,ports):
    command="nmap -p" + ports +" -sC -sV "+ ip + " -oA targeted"
    args = shlex.split(command)
    p=subprocess.Popen(args, stderr=STDOUT, stdout=PIPE)
    p.communicate()
    if p.returncode == 0:
        return True
    else:
        return False
    sleep(0.100)
    p.terminate()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, def_handler)
    banner()
    if not os.geteuid() == 0:
        cprint("\nThe tool must be run as root, try again\n",'red')
    else:
        target = ""
        output = ""
        if len(sys.argv) != 5:
            print("\n[!] Usage: python3 "+sys.argv[0] +" -t <target> -o <path for output>\n")
        else:
            argv = sys.argv[1:]
            try:
                opts, args = getopt.getopt(argv, "t:o:")
                for opt, arg in opts:
                    if opt in ['-t']:
                        target = arg
                    elif opt in ['-o']:
                        output = arg
                
                print("---------------------------------")
                print("Target:  " + target)
                print("Output:  " + output)
                print("---------------------------------")

            except:
                print("[!] Usage: python3 "+sys.argv[0] +" -t <target> -o <path for output>\n")

            downloand_xsl()
            with open(target) as fp:
                line = fp.readline()
                cnt = 1

                while line:
                    p1 = log.progress(line.rstrip(string.whitespace))
                    p1.status("Running..")
                    sleep(1)
                    if validateIp(line) is True:
                        p1.status("Validating if the IP is valid..")
                        cprint("\t[✔] Valid IP",'green')
                        if hostUp(line) is True:
                            p1.status("Validating if the host is up..")
                            cprint("\t[✔] The host is up",'green')
                            sleep(1)
                            createFolder(output+line.strip())
                            os.chdir(output+line.strip())
                            p1.status("Scanning...")
                            if nmap_allports(line) is True:
                                cprint("\t[✔] Open ports : "+nmap_extractPorts(),'green',end="", flush=True)
                                p1.status("Getting details of open ports...")
                                if nmap_targeted(line,nmap_extractPorts()) is True:
                                    cprint("\t[✔] Detail of services",'green')
                                    p1.status("Creating report...")
                                    if nmap_html() is True:
                                        cprint("\t[✔] Report generated",'green')
                                    else:
                                        cprint("\t[✔] Valid IP",'green')
                                        cprint("\t[✔] The host is up",'green')
                                        cprint("\t[✔] Scan all ports",'green')
                                        cprint("\t[✔] Detail of services",'green')
                                        cprint("\t[✖] Report generated",'red')
                                        p1.failure("Failed")
                                else:
                                    cprint("\t[✔] Valid IP",'green')
                                    cprint("\t[✔] The host is up",'green')
                                    cprint("\t[✔] Scan all ports",'green')
                                    cprint("\t[✖] Detail of services",'green')
                                    p1.failure("Failed")
                            else:
                                cprint("\t[✔] Valid IP",'green')
                                cprint("\t[✔] The host is up",'green')
                                cprint("\t[✖] Scan all ports",'red')
                                p1.failure("Failed")

                            os.chdir('..')

                        else:
                            cprint("\t[✔] Valid IP",'green')
                            cprint("\t[✖] The host is up",'red')
                            p1.failure("Failed")         
                    else:
                        cprint("\t[✖] Valid IP",'red')
                        p1.failure("Failed")
                    line = fp.readline()
                    cnt = cnt+1

            p1 = log.success("Succesfully")

    
