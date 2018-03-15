import subprocess
import os
import urllib2, base64
import sys
import json
import socket
import time
import optparse
from optparse import OptionGroup
import xml
import xml.etree.ElementTree as ET
import logging
import ConfigParser

config= ConfigParser.ConfigParser()
config.read('config.ini')

AMBARI_USER_ID=config.get('configuration','ambari_user')
AMBARI_USER_PW=config.get('configuration','ambari_user_password')
AMBARI_DOMAIN=config.get('configuration','ambari_host')
PEM_FILE=config.get('configuration','pem_file')
AMBARI_PORT=config.get('configuration','ambari_port')


dirpath = os.getcwd()
ssl_script=''.join([dirpath,'/ssl_create.sh'])
host_file=''.join([dirpath,'/hosts.txt'])
protocol = 'http'

logger = logging.getLogger('AmbariConfig')
HTTP_PROTOCOL = 'http'
HTTPS_PROTOCOL = 'https'
SET_ACTION = 'set'
PUT_REQUEST_TYPE = 'PUT'
PROPERTIES = 'properties'
ATTRIBUTES = 'properties_attributes'
CLUSTERS = 'Clusters'
DESIRED_CONFIGS = 'desired_configs'
TYPE = 'type'
TAG = 'tag'
ITEMS = 'items'
TAG_PREFIX = 'version'
GET_REQUEST_TYPE = 'GET'



#####Create shell script to be executed on Ambari server##
with open("ssl_create.sh","w") as w :
     w.write("""\
#!/bin/bash
mkdir -p /var/lib/ambari-server/resources/ssl_setup
AMBARI_SERVER=`hostname -f`

#netstat -tn 2>/dev/null | grep ':8441' | awk '{print $5}' |sed -e 's/::ffff://' | cut -f1 -d: | uniq | sort -rn >/tmp/hosts.txt
#curl -s -u admin:admin http://$AMBARI_SERVER:8080/api/v1/clusters/seclab/hosts | grep host_name | awk -F':' '{print $2}' | tr -d '\"' > /tmp/hosts.txt

for i in `cat /tmp/hosts.txt`
do
keytool -genkey -noprompt -alias server -dname "CN=$i, OU=support, O=HWX, L=Bengaluru, S=Karnataka, C=IN" -keystore /var/lib/ambari-server/resources/ssl_setup/$i.jks -storepass changeit -keypass changeit -validity 365

#cp /etc/security/serverKeys/$i.jks /etc/security/clientKeys/

keytool -noprompt -export -file /var/lib/ambari-server/resources/ssl_setup/$i.pem -keystore /var/lib/ambari-server/resources/ssl_setup/$i.jks -alias server -storepass changeit
keytool -noprompt -import -file /var/lib/ambari-server/resources/ssl_setup/$i.pem -keystore /var/lib/ambari-server/resources/ssl_setup/all.jks -storepass changeit -alias $i
done
#CONTENT="<actionDefinition>\\n<actionName>ssl_setup</actionName>\\n<actionType>USER</actionType>\\n</inputs>\\n<targetService/>\\n<targetComponent/>\\n<defaultTimeout>60</defaultTimeout>\\n<description>Copy Keystore to ALl agents</description>\\n<targetType>ALL</targetType>\\n</actionDefinition>"
CONTENT="<actionDefinition>\\n<actionName>ssl_setup</actionName>\\n<actionType>SYSTEM</actionType>\\n<inputs/>\\n<targetService/>\\n<targetComponent/>\\n<defaultTimeout>60</defaultTimeout>\\n<description>Copy Keystore to ALl agents</description>\\n<targetType>ALL</targetType>\\n<permissions>HOST.ADD_DELETE_COMPONENTS, HOST.ADD_DELETE_HOSTS, SERVICE.ADD_DELETE_SERVICES</permissions>\\n</actionDefinition>"
C=$(echo $CONTENT | sed 's/\//\\\\\//g')

sed -i.bak "/<\/actionDefinitions>/ s/.*/${C}\\n&/" /var/lib/ambari-server/resources/custom_action_definitions/system_action_definitions.xml

#### setup truststore on Ambari-server ###

cp /var/lib/ambari-server/resources/ssl_setup/all.jks /etc/ambari-server/conf/ambari-truststore.jks
#ambari-server setup-security --security-option=setup-truststore --truststore-type=jks --truststore-path=/etc/ambari-server/conf/ambari-truststore.jks --truststore-password=changeit --truststore-reconfigure

echo "Restarting Ambari Server"

ambari-server stop
sleep 5

ambari-server start

listen=1
if [ listen == 1 ]
then
  echo "Waiting for port 8080"
  netstat -an | grep ":8080"
  listen=`echo $?`
fi
###Restore system_action_definitions after restart

#cp /var/lib/ambari-server/resources/custom_action_definitions/system_action_definitions.xml.bak /var/lib/ambari-server/resources/custom_action_definitions/system_action_definitions.xml

##Start python SimpleHTTPServer 
cd /var/lib/ambari-server/resources/ssl_setup
python -m SimpleHTTPServer 8000 &> /dev/null &
echo $! > /tmp/http.pid
#kill -9 `cat /tmp/http.pid`
""")
os.chmod("ssl_create.sh",0755)

###Create Custom action script for Ambari for keystore copy task##

with open("ssl_setup.py","w") as w :
     w.write("""\
import urllib
import os
import shutil
import subprocess
import socket
import ConfigParser

subprocess.call(['mkdir', '-p', '/etc/security/clientKeys/'])
subprocess.call(['mkdir', '-p', '/etc/security/serverKeys/'])
certfile=socket.gethostname()
config= ConfigParser.ConfigParser()
config.read('/etc/ambari-agent/conf/ambari-agent.ini')
ambari_server=config.get('server','hostname')
#url1="http://%s:8080/resources/ssl_setup/%s.jks" % (ambari_server,certfile)
#url2="http://%s:8080/resources/ssl_setup/all.jks" % (ambari_server)

url1="http://%s:8000/%s.jks" % (ambari_server,certfile)
url2="http://%s:8000/all.jks" % (ambari_server)

urllib.urlretrieve (url1, "/etc/security/serverKeys/keystore.jks")
urllib.urlretrieve (url2, "/etc/security/clientKeys/all.jks")
shutil.copy2('/etc/security/serverKeys/keystore.jks', '/etc/security/clientKeys/keystore.jks')
""")
os.chmod("ssl_setup.py",0755)

def ambariREST( restAPI ) :
    url="http://"+AMBARI_DOMAIN+":"+str(AMBARI_PORT)+restAPI
    request = urllib2.Request(url)
    base64string = base64.encodestring('%s:%s' % (AMBARI_USER_ID, AMBARI_USER_PW)).replace('\n', '')
    request.add_header("Authorization", "Basic %s" % base64string)
    result = urllib2.urlopen(request)
    return(json.load(result))


def getClusterName() :
    json_data = ambariREST("/api/v1/clusters")
    cname = json_data["items"][0]["Clusters"]["cluster_name"]
    ###cversion =json_data["items"][0]["Clusters"]["version"]
    return cname


CLUSTER=getClusterName()
CLUSTER_API="/api/v1/clusters/"+CLUSTER
DESIRED_CONFIGS_URL = CLUSTER_API + '?fields=Clusters/desired_configs'
CONFIGURATION_URL = CLUSTER_API + '/configurations?type={1}&tag={2}'


def getAmbariHostName() :
    restAPI = CLUSTER_API+"/hosts?fields=Hosts/ip"
    json_data =  ambariREST(restAPI)
    for index in range(len(json_data['items'])):
        host=json_data['items'] [index] ['Hosts'] ['host_name']
        sys.stdout=open("hosts.txt","a")
        print host
        sys.stdout.close()
    return 

def getAmbariHostsIP() :
    restAPI = CLUSTER_API+"/hosts?fields=Hosts/ip"
    json_data =  ambariREST(restAPI)
    for index in range(len(json_data['items'])):
        print json_data['items'] [index] ['Hosts'] ['ip']
    return
    
def getMRHistory():
    restAPI = CLUSTER_API+"/services/MAPREDUCE2/components/HISTORYSERVER"
    json_data =  ambariREST(restAPI)
    history_server=json_data['host_components'][0]['HostRoles']['host_name']
    #print history_server['host_components'][0]['HostRoles']['host_name']
    return history_server
    
def sshAmbariAgents() : 
    restAPI = CLUSTER_API+"/hosts?fields=Hosts/ip"
    json_data =  ambariREST(restAPI)
    for index in range(len(json_data['items'])):
        host_ip=json_data['items'] [index] ['Hosts'] ['ip']
        scp1=''.join(['scp', ' ', '-i', PEM_FILE, ' ','ssl_setup.py', ' ', 'root', '@', host_ip, ':', '/var/lib/ambari-agent/cache/custom_actions/scripts'])
        os.system(scp1)
 
def sshAmbariServer() :
    ssh1=''.join(['scp',' ', '-p', ' ', '-i', PEM_FILE, ' ', ssl_script, ' ', host_file, ' ', 'root', '@', AMBARI_DOMAIN, ':', '/tmp'])
    os.system(ssh1)
    ssh2=''.join(['ssh',' ', 'root', '@', AMBARI_DOMAIN, ' ' ,'-i', PEM_FILE, ' ', '/tmp/ssl_create.sh'])
    os.system(ssh2)
    test=True
    while test :
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       result = sock.connect_ex((AMBARI_DOMAIN, int(AMBARI_PORT)))
       #print "Waiting for Ambari server to start"
       if result == 0:
           #print "\nAmbari port 8080 is UP now proceeding with further tasks"
           test=False
    #s='.'
    #sys.stdout.write( s )
    #sys.stdout.flush()
    time.sleep(2)
    sock.close()
    
    
history_server=getMRHistory()

#def clean_up():

def requestCopyKeystore() :
    #url="http://"+AMBARI_DOMAIN+":"+str(AMBARI_PORT)+restAPI
    url = "http://"+AMBARI_DOMAIN+":"+str(AMBARI_PORT)+CLUSTER_API+"/requests"
    data = {"RequestInfo":{"context":"Execute an action", "action" : "ssl_setup", "service_name" : "", "component_name":"", "hosts":" "}}
    data1= json.dumps(data)
    request = urllib2.Request(url)
    base64string = base64.encodestring('%s:%s' % (AMBARI_USER_ID, AMBARI_USER_PW)).replace('\n', '')
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('X-Requested-By', 'ambari')
    request.add_data(data1)
    #print request.data
    result = urllib2.urlopen(request)
    #return(json.load(result))
    
def restartRequired(): 
    url = "http://"+AMBARI_DOMAIN+":"+str(AMBARI_PORT)+CLUSTER_API+"/requests"
    data = {"RequestInfo":{"command":"RESTART","context":"Restart all required services","operation_level":"host_component"},"Requests/resource_filters":[{"hosts_predicate":"HostRoles/stale_configs=true"}]}
    data1= json.dumps(data)
    request = urllib2.Request(url)
    base64string = base64.encodestring('%s:%s' % (AMBARI_USER_ID, AMBARI_USER_PW)).replace('\n', '')
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('X-Requested-By', 'ambari')
    request.add_data(data1)
    result = urllib2.urlopen(request)


def changeConfig(config_type,key,value):
  #change_config_main() 
  #print "Changing config for %s" % config_type
  host=AMBARI_DOMAIN
  login=AMBARI_USER_PW
  password=AMBARI_USER_ID
  port=AMBARI_PORT

  def api_accessor(host, login, password, protocol, port):
    def do_request(api_url, request_type=GET_REQUEST_TYPE, request_body=''):
     try:
      url = '{0}://{1}:{2}{3}'.format(protocol, host, port, api_url)
      admin_auth = base64.encodestring('%s:%s' % (login, password)).replace('\n', '')
      request = urllib2.Request(url)
      request.add_header('Authorization', 'Basic %s' % admin_auth)
      request.add_header('X-Requested-By', 'ambari')
      request.add_data(request_body)
      request.get_method = lambda: request_type
      response = urllib2.urlopen(request)
      #print url
      response_body = response.read()
     except Exception as exc:
      raise Exception('Problem with accessing api. Reason: {0}'.format(exc))
     return response_body
    return do_request


  def create_new_desired_config(cluster, config_type, properties, attributes, accessor):
    new_tag = TAG_PREFIX + str(int(time.time() * 1000000))
    new_config = {
      CLUSTERS: {
        DESIRED_CONFIGS: {
          TYPE: config_type,
          TAG: new_tag,
          PROPERTIES: properties
        }
      }
    }
    if len(attributes.keys()) > 0:
      new_config[CLUSTERS][DESIRED_CONFIGS][ATTRIBUTES] = attributes
    request_body = json.dumps(new_config)
    new_file = 'doSet_{0}.json'.format(new_tag)
    logger.info('### PUTting json into: {0}'.format(new_file))
    output_to_file(new_file)(new_config)
    accessor(CLUSTER_API.format(cluster), PUT_REQUEST_TYPE, request_body)
    logger.info('### NEW Site:{0}, Tag:{1}'.format(config_type, new_tag))


  def get_current_config(cluster, config_type, accessor):
    config_tag = get_config_tag(cluster, config_type, accessor)
    logger.info("### on (Site:{0}, Tag:{1})".format(config_type, config_tag))
    response = accessor(CONFIGURATION_URL.format(cluster, config_type, config_tag))
    config_by_tag = json.loads(response)
    current_config = config_by_tag[ITEMS][0]
    return current_config[PROPERTIES], current_config.get(ATTRIBUTES, {})

  def update_specific_property(config_name, config_value):
    def update(cluster, config_type, accessor):
      properties, attributes = get_current_config(cluster, config_type, accessor)
      properties[config_name] = config_value
      return properties, attributes
    return update


  def set_properties(cluster, config_type, args, accessor):
    logger.info('### Performing "set":')

    if len(args) == 1:
      config_file = args[0]
      root, ext = os.path.splitext(config_file)
      if ext == ".xml":
        updater = update_from_xml(config_file)
      elif ext == ".json":
        updater = update_from_file(config_file)
      else:
        logger.error("File extension {0} doesn't supported".format(ext))
        return -1
      logger.info('### from file {0}'.format(config_file))
    else:
      config_name = args[0]
      config_value = args[1]
      updater = update_specific_property(config_name, config_value)
      logger.info('### new property - "{0}":"{1}"'.format(config_name, config_value))
    update_config(cluster, config_type, updater, accessor)
    return 0
  def update_config(cluster, config_type, config_updater, accessor):
    properties, attributes = config_updater(cluster, config_type, accessor)
    create_new_desired_config(cluster, config_type, properties, attributes, accessor)

  def change_config_main():
    user = AMBARI_USER_ID
    password = AMBARI_USER_PW
    #port = 8080
    #protocol = 'http'

    action = 'set'
    host = AMBARI_DOMAIN
    cluster = CLUSTER
    #config_type = sys.argv[4]
    #key=sys.argv[5]
    #value=sys.argv[6]
    #print "IN MAIN"
    accessor = api_accessor(host, user, password, protocol, AMBARI_PORT)
    if action == SET_ACTION:
      action_args = [key, value]
      return set_properties(cluster, config_type, action_args, accessor)

  def get_config_tag(cluster, config_type, accessor):
    response = accessor(DESIRED_CONFIGS_URL.format(cluster))
    try:
      desired_tags = json.loads(response)
      current_config_tag = desired_tags[CLUSTERS][DESIRED_CONFIGS][config_type][TAG]
    except Exception as exc:
      raise Exception('"{0}" not found in server response. Response:\n{1}'.format(config_type, response))
    return current_config_tag

  def output_to_file(filename):
    def output(config):
      with open(filename, 'w') as out_file:
        out_file.write(format_json(config))
    return output
  def format_json(dictionary, tab_level=0):
    output = ''
    tab = ' ' * 2 * tab_level
    for key, value in dictionary.iteritems():
      output += ',\n{0}"{1}": '.format(tab, key)
      if isinstance(value, dict):
        output += '{\n' + format_json(value, tab_level + 1) + tab + '}'
      else:
        output += '"{0}"'.format(value)
    output += '\n'
    return output[2:]
  change_config_main() 
   
   
history_server_url="https://"+history_server+":"+"19890"+"/jobhistory/logs"


getAmbariHostName()
sshAmbariServer()


def sslAgentWait() :
  restAPI = CLUSTER_API+"/hosts?fields=Hosts/host_state"
  json_data =  ambariREST(restAPI)
  for index in range(len(json_data['items'])):
    host_state=json_data['items'] [index] ['Hosts'] ['host_state']
    if host_state is 'HEARTBEAT_LOST' :
        index = 0
        time.sleep(2)
  sshAmbariAgents()     
  requestCopyKeystore()

sslAgentWait()
changeConfig('hdfs-site','dfs.http.policy','HTTPS_ONLY')
changeConfig('ssl-client','ssl.client.keystore.password','changeit')
changeConfig('ssl-client','ssl.client.truststore.password','changeit')
changeConfig('ssl-server','ssl.server.truststore.password','changeit')
changeConfig('ssl-server','ssl.server.keystore.password','changeit')
changeConfig('ssl-server','ssl.server.keystore.keypassword','changeit')
changeConfig('yarn-site','yarn.log.server.url','HTTPS_ONLY')
changeConfig('yarn-site','yarn.log.server.url',history_server_url)
changeConfig('mapred-site','mapreduce.jobhistory.http.policy','HTTPS_ONLY')
changeConfig('mapred-site','mapreduce.jobhistory.webapp.https.address','0.0.0.0:19890')
restartRequired()



