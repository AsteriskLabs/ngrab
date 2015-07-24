#!/usr/bin/python
#
# grab an entire folder of nessus scans
# in .nessus format and dump them in the directory
#
# useful for when you had to do fifty scans for some ungodly reason
# 
# note that this only grabs the most recent scan, it doesn't care about scan history
#
# written by ak of Asterisk Information Security

import requests
import argparse
import os

# GLOBALS - set these if you will use this script often or you just
# want to live your life YOLO, otherwise use the CLI arguments
gusername = "admin"
gpassword = "guest"
gip = "127.0.0.1"
gport="8834"

def main():
    # disable requests warnings as nessus scanner's generally use self signed SSL
    # you should remove/comment the following line if you want to see these warnings 
    # by default, we disable them as most nessus scanners will not have a CA signed cert
    requests.packages.urllib3.disable_warnings()
    # get arguments ready
    parser = argparse.ArgumentParser(prog="grab_folder", 
        description='''
        A program to grab a folder full of nessus files and dump
        the export files into a directory.
        Note that this script ignores SSL Self Signed Certs. This functionality can be
        re-enabled if your nessus machine has a signed certificate, or if the certificate
        is in your operating system trust store.
        ''',
        epilog='''
        Warning: Will overwrite output files if same name exists. This generally 
        doesn't happen, as nessus adds some random letters to the end of the scan name
        before appending .nessus, but this disclaimer is here just in case :)
        '''
        )
    parser.add_argument("-o", "--output",
        help="output folder that will be created in the current directory",
        default="output",
        metavar="filename",
        dest="outfolder"
        )
    parser.add_argument("-f", "--folder",
        help="nessus folder id for input",
        nargs="?",
        metavar="folder id",
        dest="infolder",
        required=True
        )
    parser.add_argument("-n", "--nessus",
        help="nessus host ip address",
        nargs="?",
        metavar="ip address",
        dest="ip",
        default=gip
        )
    parser.add_argument("-P", "--port",
        help="nessus host ip address",
        nargs="?",
        metavar="port number",
        dest="port",
        default=gport
        )
    parser.add_argument("-u", "--username",
        help="nessus username",
        nargs="?",
        metavar="username",
        dest="username",
        default=gusername
        )
    parser.add_argument("-p", "--password",
        help="nessus password",
        nargs="?",
        metavar="password",
        dest="password",
        default=gpassword
        )   
    args = parser.parse_args()
    # check outdir
    if os.path.isdir(args.outfolder) == False:
        os.mkdir(args.outfolder, 0644)
    # authenticate
    payload = {"username":args.username, "password":args.password}
    host = "https://"+args.ip+":"+args.port
    r = requests.post(host+"/session", data=payload, verify=False)
    # I know this can be done much more cleanly, but yolo
    cookie = {"X-Cookie":"token="+r.json()["token"]}
    # lets grab the scan list, yolo for some injection maybe
    r = requests.get(host+"/scans?folder_id="+args.infolder, headers=cookie, verify=False)
    scanformat = {"format":"nessus"}
    for scan in r.json()["scans"]:
        sid = str(scan["id"])
        f = requests.post(host+"/scans/"+sid+"/export", headers=cookie, verify=False, data=scanformat)
        try:
            fid = str(f.json()["file"])
            status = "no"
            while status != "ready":
                s = requests.get(host+"/scans/"+sid+"/export/"+fid+"/status", headers=cookie, verify=False)
                status = s.json()["status"]
            scanout = requests.get(host+"/scans/"+sid+"/export/"+fid+"/download?"+cookie["X-Cookie"], verify=False, stream=True)
            # i'm sorry about the above line, it's not my fault and I don't know why nessus passes the cookie as as a get param
            # this is probabaly a CVE (although nesuss is HTTPS so tenable is probably fine) but meh, enjoy more injection!
            filename =  scanout.headers["content-disposition"].split("=")[1].strip('"')
            with open(args.outfolder+"/"+filename, 'wb') as nessus:
                nessus.write(scanout.content)
                nessus.flush()
                nessus.close()
            print filename + " Has been written to disk"
        except:
            print scan["name"] + " was skipped for some reason!"
    # don't forget to kill the session token! because security or something
    r = requests.delete(host+"/session", headers=cookie, verify=False)

if __name__ == "__main__":
        # windows friendly!~<3
        main()
