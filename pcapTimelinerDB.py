'''
Created on Nov 28, 2015
@author: astrick
'''
import logging
import sys
import os

try:
    from sqlalchemy import Column, Integer, String
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import create_engine
    from sqlalchemy import exc
except ImportError as e:
    print "Module `{0}` not installed".format(e.message[16:])
    sys.exit()
    
# === SQLAlchemy Config tip taken from the fingerprint.py class ===
Base = declarative_base()
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)

class parsedPcapTable(Base):
    __tablename__ = 'parsedPcapData'
    id = Column(Integer, primary_key=True)  # unique stream id
    ipAddr1 = Column(String)
    ipAddr2 = Column(String)
    startTime = Column(String)
    endTime = Column(String)
    hostname = Column(String)
    domainName = Column(String)
    display = Column(String)
       
    def __init__(self, ipAddr1, ipAddr2, startTime, endTime, hostname, domainName, display, **kwargs):
        self.ipAddr1 = ipAddr1
        self.ipAddr2 = ipAddr2
        self.startTime = startTime
        self.endTime = endTime
        self.hostname = hostname
        self.domainName = domainName
        self.display = display
        
class dnsTable(Base):
    __tablename__ = 'dnsMap'
    id = Column(Integer, primary_key=True)  # unique stream id
    ipAddr = Column(String, unique=True)
    hostname = Column(String)
       
    def __init__(self, ipAddr, hostname, **kwargs):
        self.ipAddr = ipAddr
        self.hostname = hostname

def init(outputDir):
    db = outputDir + os.sep + 'pcapTimeliner.db'
    engine = create_engine('sqlite:///' + db, echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    return session
    
def addToParsedPcapTable(session, ipAddr1, ipAddr2, startTime, endTime, hostname, domainName, display): 
    row = {'ipAddr1':ipAddr1, 'ipAddr2':ipAddr2, 'startTime':startTime,'endTime':endTime, 'hostname':hostname, 'domainName':domainName,'display':display}  
    session.add(parsedPcapTable(**row))
    session.commit()
    session.close()
    
def addToDnsMapTable(session, ipAddr, hostname): 
    row = {'ipAddr':ipAddr, 'hostname':hostname}  
      
    try:
        session.add(dnsTable(**row))
        session.commit()
    except exc.IntegrityError:
        session.rollback()
        #print 'This ip occurs more then once in dns entries, continue processing!'
    except:
        print 'There was a db error while processing the dns entries into the dnsMap'
        raise
    
    