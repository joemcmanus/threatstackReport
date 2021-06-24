#!/usr/bin/env python3

from mohawk import Sender
import requests
from os import path
import sys
import time
import configparser
import json
import sqlite3
import datetime



config=configparser.ConfigParser()
configFile = 'threatstack.cfg'
if not path.exists(configFile):
    print("ERROR: No config file found, should be set in threatstack.cfg")
    sys.exit()

config.read(configFile)
    
default = config['default']
dbFile=config['default']['dbFile']
tsHost= "https://" + config['default']['tsHost']
tsUserID=config['default']['tsUserID']
tsOrgID=config['default']['tsOrgID']
tsAPIKey=config['default']['tsAPIKey']
tsCredentials={ 'id': tsUserID, 'key': tsAPIKey, 'algorithm': 'sha256' }

def is_json(myjson):
    try:
        # json_object is not used.  It's purpose is to generate an exception if 
        # it is not valid
        json_object = json.loads(myjson)
    except json.JSONDecodeError:
        print("JSONDecodeError")
        return False
    except TypeError:
        print("TypeError")
        return False
    except ValueError:
        print("ValueError")
        return False
    except:
        print("Unexpected error:", sys.exc_info()[0])
        return False
    else:
        return True

def getAgents(credentials, tsHost, tsOrdID, reportID, token=None):
    content_type = 'application/json'
    METHOD = 'GET'
    
    if token == None:
        URI_PATH = '/v2/agents?status=online'
    else:
        URI_PATH = '/v2/agents?status=online' + "&token=" + token

    URL = tsHost + URI_PATH

    try:
        sender = Sender(credentials, 
                        URL, 
                        METHOD, 
                        always_hash_content=False,
                        ext=tsOrgID)
    except:
        print("Unexpected error:", sys.exc_info()[0])
    
    try:
        response = requests.get(URL,
                                headers={'Authorization': sender.request_header,
                                         'Content-Type': content_type})

        ret_code = response.status_code
        if isinstance(ret_code,int): 
            print("Request returned", ret_code)
            if (ret_code == 429):
                print("Returned 429, Waiting 90 seconds to continue")
                time.sleep(90)
            if ret_code == 200:
                # Success
                pass
            elif ret_code == 400:
                # Internal server error
                pass
            elif ret_code == 500:
                # Internal server error
                try:
                    sender = Sender(credentials,
                                    URL,
                                    METHOD,
                                    always_hash_content=False,
                                    ext=ORGANIZATION_ID)
                except:
                    print("Unexpected error:", sys.exc_info()[0])

                try:
                    response = requests.get(URL,
                                            headers={'Authorization': sender.request_header,
                                                     'Content-Type': content_type})

                    ret_code = response.status_code
                except:
                    pass
        else:
            print("Status code received is not an integer.")
            raise Exception("Status code received", ret_code, "is not an integer.")
        
        if is_json(response.text) == True:
            json_object = json.loads(response.text)
            if isinstance(json_object, dict):
                if 'agents' in json_object:
                    if isinstance(json_object['agents'],list):
                        agents = json_object['agents']
                        print("Returned",len(agents),"agents")

                        if len(agents) >= 1:
                            agents_list = []
                            for agent in agents:
                                temp_agent = {}
                                ipAddressList = ""
                                for key, val in agent.items():
                                    if key == 'id':
                                        temp_agent[key] = val
                                    elif key == 'instanceId':
                                        temp_agent[key] = val
                                    elif key == 'status':
                                        temp_agent[key] = val
                                    elif key == 'version':
                                        temp_agent[key] = val
                                    elif key == 'name':
                                        temp_agent[key] = val
                                    elif key == 'description':
                                        temp_agent[key] = val
                                    elif key == 'hostname':
                                        temp_agent[key] = val
                                    elif key == 'ipAddresses':
                                    
                                        for addrType, ipAddresses in agent['ipAddresses'].items():
                                            # Exclude link_local
                                            if addrType == 'private' or addrType == 'public':
                                                for addr in ipAddresses:
                                                # Exclude localhost
                                                    if addr != '127.0.0.1/8' and addr != '::1/128':
                                                        ipAddressList = ipAddressList = " , " + addr
                                                            
                                            temp_agent[key] = ipAddressList
                                    elif key == 'tags':
                                        temp_agent[key] = str(val)
                                    elif key == 'osVersion':
                                        temp_agent[key] = val
                                    else:
                                        pass
                                if len(temp_agent) >= 1:
                                    agents_list.append(temp_agent)
                                    t=(temp_agent['id'], temp_agent['instanceId'], temp_agent['status'], temp_agent['version'], temp_agent['name'], temp_agent['description'], temp_agent['hostname'], temp_agent['ipAddresses'], temp_agent['tags'], temp_agent['osVersion'], reportID) 
                                    query='insert into hosts (agentId, instanceId, status, version, name, description, hostname, ipAddresses, tags, osVersion, reportID) values(?,?,?,?,?,?,?,?,?,?,?)'
                                    cursor=db.cursor()
                                    cursor.execute(query, t)
                                    db.commit()

                        else:
                            print("Why?")
                            
                if 'token' in json_object:
                    if json_object['token'] != None:
                        print("Found pagination token.")
                        paginationToken = json_object['token']
                        getAgents(credentials, tsHost, tsOrgID, reportID, token=paginationToken)

            else:
                print("Unexpected data structure.  Expected dictionary")
                print(json_object)
                
    except TypeError as e:
        print ("Type Error:", e)
    except ValueError as e:
        print ("Value Error:", e)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise

def queryOneRow(query):
    cursor=db.cursor()
    cursor.execute(query)
    result=cursor.fetchone()
    return(result)

    
if path.exists(dbFile):
    print("DB File Found")
    db = sqlite3.connect(dbFile)
    db.row_factory = sqlite3.Row 
if not path.exists(dbFile):
    print("DB File not found, creating")
    db = sqlite3.connect(dbFile)
    db.row_factory = sqlite3.Row
    query="""CREATE TABLE reports (reportID INTEGER PRIMARY KEY, 
        timestamp datetime NOT NULL)"""
    queryOneRow(query)

    query="""CREATE TABLE hosts (reportID INTEGER,
        agentId,
        instanceId,
        status,
        version,
        name,
        description,
        hostname,
        ipAddresses,
        tags,
        osVersion,
        FOREIGN KEY(reportID) REFERENCES reports(reportID)
        )"""
    queryOneRow(query)

    query="""CREATE TABLE vulns (reportID INTEGER,
        cve TEXT,
        host TEXT,
        FOREIGN KEY(reportID) REFERENCES reports(reportID)
        )"""
    queryOneRow(query)

#Create and return the ID of the report, PK and FK for rest of DB.
query='insert into reports(timestamp) values(datetime())'
queryOneRow(query)
query='SELECT reportID,timestamp FROM reports ORDER BY timestamp DESC LIMIT 1'
reportID,timestamp=queryOneRow(query)

getAgents(tsCredentials, tsHost, tsOrgID, reportID)
