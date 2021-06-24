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
import argparse
from prettytable import PrettyTable
import plotly
import plotly.graph_objs as go


parser = argparse.ArgumentParser(description='Threatstack Daily Report Generator')
parser.add_argument('--inventory', help="Generate inventory", action="store_true")
parser.add_argument('--vulns', help="Generate vulnerability list", action="store_true")
parser.add_argument('--report', help="Generate report", action="store_true")
parser.add_argument('--outdir', help="Output directory for files", action="store")
parser.add_argument('--slack', help="Post to Slack", action="store_true")
parser.add_argument('--channel', help="Slack Channel to post to", action="store")
parser.add_argument('--token', help="Slack bot token, or use OS_ENVIRON", action="store")
parser.add_argument('--graphs', help="Display graphs where available", action="store_true")

args=parser.parse_args()

if len(sys.argv) == 1: 
    parser.print_help()
    sys.exit()


#print what we are doing
table= PrettyTable(["Option", "Value"])
table.add_row(["Get new inventory", args.inventory])
table.add_row(["Get new vulnerability list", args.inventory])
table.add_row(["Print report", args.report])
table.add_row(["Post to Slack", args.slack])
table.add_row(["Slack channel", args.channel])
table.add_row(["Create Graphs", args.graphs])
table.add_row(["Output Dir", args.outdir])
print(table)

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


def getVulns(credentials, tsHost, tsOrgID, agentId, instanceId, hostname, tags, token=None):
    if token == None:
        URI_PATH = '/v2/vulnerabilities?agentId=' + agentId + "&hasSecurityNotices=true"
    else:
        URI_PATH = '/v2/vulnerabilities?agentId=' + agentId + "&hasSecurityNotices=true&token=" + token
        
    URL = tsHost + URI_PATH

    content_type = 'application/json'
    METHOD = 'GET'

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
            if (ret_code == 429):
                print("Returned 429, Waiting 64 seconds to continue")
                time.sleep(90)
            if ret_code == 200:
                # Success
                pass
            elif ret_code == 400:
                # Internal server error
                pass
            elif ret_code == 500:
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
                except:
                    # Internal server error
                    pass
            else:
                print(response.status_code, response.text)
        else:
            print("Status code received is not an integer.")
            raise Exception("Status code received", ret_code, "is not an integer.")
        
        if is_json(response.text) == True:
            json_object = json.loads(response.text)
            if isinstance(json_object, dict):
                if 'cves' in json_object:
                    if isinstance(json_object['cves'],list):
                        cves = json_object['cves']
                        print("Returned",len(cves),"cves")

                        if len(cves) >= 1:
                                cves_list = []
                                for cve in cves:
                                    temp_cve = {}
                                    temp_cve['agentId'] = agentId
                                    temp_cve['instanceId'] = instanceId
                                    temp_cve['hostname'] = hostname
                                    temp_cve['tags'] = tags
                                    for key, val in cve.items():
                                        if key == 'cveNumber':
                                            temp_cve[key] = val
                                        elif key == 'reportedPackage':
                                            temp_cve[key] = val
                                        elif key == 'systemPackage':
                                            temp_cve[key] = val
                                        elif key == 'vectorType':
                                            temp_cve[key] = val
                                        elif key == 'severity':
                                            temp_cve[key] = val
                                        elif key == 'isSuppressed':
                                            temp_cve[key] = val
                                        else:
                                            pass
                                    if len(temp_cve) >= 1:
                                        cves_list.append(temp_cve)
                                        t=(reportID, temp_cve['hostname'], temp_cve['cveNumber'], temp_cve['severity'], temp_cve['reportedPackage'])
                                        query="INSERT into vulns(reportID, host, cve, sev, package) values(?,?,?,?,?)"
                                        cursor.execute(query, t)
                                        db.commit()

                            
                if 'token' in json_object:
                    if json_object['token'] != None:
                        print("Found pagination token.")
                        paginationToken = json_object['token']

                        getVulns(credentials, BASE_PATH, ORGANIZATION_ID, OUTPUT_FILE, agentId, instanceId, hostname, tags, token=paginationToken)
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
        sev TEXT,
        host TEXT,
        package TEXT,
        FOREIGN KEY(reportID) REFERENCES reports(reportID)
        )"""
    queryOneRow(query)


if args.inventory:
    query='insert into reports(timestamp) values(datetime())'
    queryOneRow(query)
    query='SELECT reportID,timestamp FROM reports ORDER BY timestamp DESC LIMIT 1'
    reportID,timestamp=queryOneRow(query)
    getAgents(tsCredentials, tsHost, tsOrgID, reportID)

if args.vulns: 
    query='SELECT reportID,timestamp FROM reports ORDER BY timestamp DESC LIMIT 1'
    reportID,timestamp=queryOneRow(query)

    t=(reportID,)
    query="select agentID, instanceID, name, tags from hosts where reportID=?"
    cursor=db.cursor()
    cursor.execute(query, t)
    result=cursor.fetchall()

    for row in result:
        agentId = row[0]
        instanceId = row[1]
        hostname = row[2]
        tags = row[3]
        getVulns(tsCredentials, tsHost, tsOrgID, agentId, instanceId, hostname, tags)
               

if args.report:
    #select previous reportID
    query='SELECT reportID,timestamp FROM reports ORDER BY timestamp DESC LIMIT 1,1'
    lastReportID,lastTimestamp=queryOneRow(query)

    query='SELECT reportID,timestamp FROM reports ORDER BY timestamp DESC LIMIT 1'
    reportID,timestamp=queryOneRow(query)

    #Create the table
    table=PrettyTable(["", lastTimestamp, timestamp])
