'''
Created on Dec 3, 2015
@author: astrick
'''
import SimpleHTTPServer
import SocketServer
import urlparse
import argparse
import pcapTimeliner
import sys

PORT = 8000
parser = argparse.ArgumentParser(description='PCAP File')
parser.add_argument('pcapFile', help='PCAP file to be analyzed')
parser.add_argument('domainFilter', help='List of domains to filter out')
args = parser.parse_args()
domainNameFile = args.domainFilter
pcapFile = args.pcapFile


class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    def do_GET(self):
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
        
        # Parse query data & params to find out what was passed
        parsedParams = urlparse.urlparse(self.path)
        queryData = urlparse.parse_qs(parsedParams.query)
        
        if (queryData):
            if('timeliner' in queryData.keys()):
                args = [pcapFile, domainNameFile]
                runTimeLiner()
            if('action' in queryData.keys()):
                self.updateDomainNameList(queryData)
    
    def updateDomainNameList(self, queryData):
        domainName = queryData['domainName']
        action = queryData['action']
        dfile = open(domainNameFile, 'a')
        
        if (action[0] == 'add'):
            #check to see if already exists
            exist = 'false'
            dfile = open(domainNameFile, 'r')
            dread = dfile.readlines()
            for dline in dread:
                if (dline.strip() == domainName[0].strip()):
                    exist = 'true' 
            dfile.close()
            
            if (exist == 'false'):
                dfile = open(domainNameFile, 'a')
                dfile.write(domainName[0]+"\n")
                dfile.close()
        
        if (action[0] == 'delete'):
            dfile = open(domainNameFile, 'r+')
            dread = dfile.readlines()
            dfile.seek(0)
            for dline in dread:
                if (dline.strip() != domainName[0].strip()):
                    dfile.write(dline)  
            dfile.truncate()
            dfile.close()
        

def runTimeLiner():
    timeLinerHandle = pcapTimeliner.pcapTimeliner(args.pcapFile,args.domainFilter)
    timeLinerHandle.run()
    
def main(argv):
    Handler = ServerHandler
    runTimeLiner() 
    httpd = SocketServer.TCPServer(("", PORT), Handler)
    print "Serving at: localhost ",PORT
    httpd.serve_forever()

if __name__ == '__main__':
        main(sys.argv)