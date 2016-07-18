'''
Created on Nov 27, 2015
Final for CS6963
@author: astrick
'''
import os
import subprocess
import pcapTimelinerDB
import datetime
import timelineHTMLGenerator
 
tshark = "/usr/local/bin/tshark"  # make sure the path to tshark is configured correctly
nslookup = '/usr/bin/nslookup'    
    
class pcapTimeliner():
    
    def __init__(self, pFile, dFile):
        self.pcapFile = pFile
        self.dnsFilterFile = dFile
        self.outputDir = '{0}/output'.format(os.path.dirname(os.path.abspath(__file__)))
        self.createcleandir()
        #self.pcapStreams = self.outputDir + os.sep + 'pcapStreams.txt' 
        self.session = pcapTimelinerDB.init(self.outputDir)
        
    def str2bool(self, v):
        return v.lower() in ("yes", "true", "t", "1")
    
    def createcleandir(self):
        if not os.path.exists(self.outputDir): 
            os.makedirs(self.outputDir)
        else:
            databaseDir = self.outputDir
            subprocess.call(["/bin/rm", "-r", databaseDir], stdout=subprocess.PIPE)   
            os.makedirs(self.outputDir)           
           
    def parseNSLookup(self, val):
        ipToLookup = val.split(':')
        cmd = nslookup, ipToLookup[0]
        nslookupStr, error = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        substring = "name ="
        for line in nslookupStr.splitlines():
            if (substring in line):
                result = line.split('=');
                return result[1].strip('.')       
           
    def buildLocalDNSLookup(self):
        cmd = tshark, "-r", self.pcapFile, "-Y", "dns", "-n", "-T", "fields", "-e", "dns.qry.name", "-e", "dns.a"
        streams, error = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        for line in streams.splitlines():
            dnsEntry = line.split();
            if (len(dnsEntry) > 1):
                ips = dnsEntry[1].split(',')
                for ip in ips:
                    pcapTimelinerDB.addToDnsMapTable(self.session, ip, dnsEntry[0])
         
     
    def dnsLookup(self, ip):
        ipOnly = ip.split(':')
        results = self.session.execute("SELECT DISTINCT hostname FROM dnsMap where ipAddr ='" + ipOnly[0] + "'")
        hostname = ""
        for h in results:
            hostname = str(h[0])
        if (len(hostname) == 0):
            hostname = self.parseNSLookup(ip) 
        return hostname
           
    def calculateEndTime(self, date, startTime, durationTime):          
        startTimeStr = date + ' ' + startTime
        #convert time string into a date time object for calculating endTime
        tmpDT = datetime.datetime.strptime(startTimeStr, '%Y-%m-%d %H:%M:%S')
        m = tmpDT.month - 1
        sDT = tmpDT.replace(month=m)
  
        #assumption durationtime is always in seconds.milliseconds
        try:       
            dO = datetime.datetime.strptime(durationTime, '%S.%f') 
            d = datetime.datetime.time(dO)
            mins = 0
            hours = 0
        except:
            try:
                dO = datetime.datetime.strptime(durationTime, '%M.%S.%f')
                d = datetime.datetime.time(dO)
                mins = d.minute
                hours = 0
            except:
                dO = datetime.datetime.strptime(durationTime, '%H.%M.%S.%f')
                d = datetime.datetime.time(dO)
                mins = d.minute
                hours = d.hour
                
        dur = datetime.timedelta(microseconds=(d.microsecond),seconds=d.second,minutes=mins,hours=hours)
        eDT = sDT + dur
        startTime = self.parseDateTime(sDT)
        endTime = self.parseDateTime(eDT)
        return { 'endTime':endTime,'startTime':startTime}
        
    def parseDateTime(self, dateTimeObj):    
        formattedDT = dateTimeObj.strftime("%Y,%m,%d,%H,%M,%S,%f")[:-3]
        return formattedDT
        
    def parsePcaptoDB(self):  
        print ' BUILDING TIME LINER' 
        cmd = tshark, "-r", self.pcapFile, "-z" , "conv,tcp" , "-qt", "ad"
        streams, error = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        for line in streams.splitlines():
            values = line.split();
            if(len(values) == 12):     
                # use second column of ips, first column is the internal location 
                ip2 = values[2].split('.')
                if ((ip2[0] != '10') and (ip2[0] != '192' and ip2[1] != '168')):
                    hostname = self.dnsLookup(values[2])
                    hostStr = str(hostname).strip()
                    if(hostStr != 'None') and (float(values[11]) > 0):
                        val = hostStr.split('.')[::-1]
                        domainName = val[1].strip() + '.' + val[0].strip()
                        times = self.calculateEndTime(values[9], values[10],values[11])
                        pcapTimelinerDB.addToParsedPcapTable(self.session, values[0], values[2], times['startTime'], times['endTime'], hostStr, domainName,"true")           
        self.filterDomainsInDB()
        self.buildDisplay()
        self.prettyprintDB()


    def filterDomainsInDB(self): 
        filters = self.dnsFilterFile
        results = self.session.execute("SELECT * FROM parsedPcapData")
        for row in results:
            ffile = open(filters, 'r')
            for dFilter in ffile.readlines():
                filter1 = dFilter.strip()
                if(row[6] == filter1):
                    self.session.query(pcapTimelinerDB.parsedPcapTable).filter_by(id=row[0]).update({"display": u"false"})
        
    def prettyprintDB(self):
        print 'DNS Map Results:'
        print '================'
        results = self.session.execute("SELECT * FROM dnsMap")
        for row in results:
            print'%s, %s, %s \n' % (row[0], row[1], row[2]) 
        print '\n\n PCAP Results:'
        print '=================='
        results = self.session.execute("SELECT * FROM parsedPcapData")
        for row in results:
            print'%s, %s, %s, %s, %s, %s, %s, %s\n' % (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7])
      
    def buildCSVReports(self):
        #create report file in csv format
        now = datetime.datetime.now()
        print 'now: ', now
        dnsReportname = '{0}/archive/{1}'.format(os.path.dirname(os.path.abspath(__file__)),'dnsMap_' +str(now)+'.csv')
        dnsReport = open( dnsReportname, 'w+')
        #iterate through dnsMap db and build report in csv format
        result = self.session.execute("SELECT * FROM dnsMap")
        header = '#,IP Address, Hostname\n'
        dnsReport.write(header)
        for row in result:
            row = '%s,%s,%s\n' % (row[0],row[1],row[2])
            dnsReport.write(row)
            
        pcapReportname = '{0}/archive/{1}'.format(os.path.dirname(os.path.abspath(__file__)),'parsedPcapData_' +str(now)+'.csv')
        pcapReport = open( pcapReportname, 'w+')
        #iterate through dnsMap db and build report in csv format
        result = self.session.execute("SELECT * FROM parsedPcapData")
        header = '#,ipAddr1, ipAddr2, s-YYYY,s-mm,s-dd,s-hh,s-min,s-sec, s-subsec, e-YYYY,e-mm,e-dd,e-hh,e-min,e-sec,e-subsec, hostname,domainName, display,\n'
        pcapReport.write(header)
        for row in result:
            row = '%s, %s, %s, %s, %s, %s, %s, %s\n' % (row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7])
            pcapReport.write(row)
            
        print 'CSV REPORT located @ ', dnsReportname
        print 'CSV REPORT located @ ', pcapReportname
        
          
    def buildDisplay(self):
        results = self.session.execute("SELECT * FROM parsedPcapData")
        displayLine = title = ''
        for row in results:
            if (self.str2bool(row[7])):
                idc = "{ id:"
                idv = str(row[0])
                groupc =", group: '"
                groupv = row[6]
                contentc ="', content: '"
                contentv = row[5]
                stimec = "', start: new Date("
                stimev = row[3]
                etimec = "), end: new Date("
                etimev = row[4]
                typeb = "), type: 'box'"
                end = "},\n"
                title = row[1]
                displayLine = displayLine + idc + idv + groupc + groupv + contentc + contentv + stimec + stimev + etimec + etimev + typeb + end
               
        displayLine = (displayLine[:-2]) 
        groupList = []
        results2 = self.session.execute("SELECT DISTINCT domainName FROM parsedPcapData where display = 'true'")  
        for row in results2:
            groupList.append(str(row[0]))
            
            
        internalIPAddress = title.split(":")    
        groupNum = len(groupList)   
        timeline = timelineHTMLGenerator.buildPage("TCP Activity Timeliner for "+internalIPAddress[0], displayLine, groupNum, groupList )
        newHTMLFile = self.outputDir + os.sep + 'timelinerPage.html' 
        f = open(newHTMLFile, 'w')
        f.write(timeline)
        
    def run(self):    
        # create object handle to run program
        self.buildLocalDNSLookup()
        self.parsePcaptoDB()
        self.buildCSVReports()
        self.prettyprintDB()
    
        
     
#if __name__ == '__main__':
 #       main(sys.argv)
        
        
        
        
