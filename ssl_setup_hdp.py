import subprocess
import os
import urllib2, base64
import sys
import json
import socket
import time
import logging
import ConfigParser

config= ConfigParser.ConfigParser()
config.read('config.ini')

logging.addLevelName(logging.WARNING, "\033[1;31m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
logging.addLevelName(logging.INFO, "\033[1;31m%s\033[1;0m" % logging.getLevelName(logging.INFO))
logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')

AMBARI_USER_ID=config.get('configuration','ambari_user')
AMBARI_USER_PW=config.get('configuration','ambari_user_password')
AMBARI_DOMAIN=config.get('configuration','ambari_host')
PEM_FILE=config.get('configuration','pem_file')
AMBARI_PORT=config.get('configuration','ambari_port')


dirpath = os.getcwd()
ssl_script=''.join([dirpath,'/ssl_create.sh'])
host_file=''.join([dirpath,'/hosts.txt'])
protocol = 'http'

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


logging.info('CREATING ssl_create script %s' %(ssl_script))

#####Create shell script to be executed on Ambari server##
with open("ssl_create.sh","w") as w :
     w.write("""\
#!/bin/bash

if [ $1 == "setup" ]
then
mkdir -p /var/lib/ambari-server/resources/ssl_setup
AMBARI_SERVER=`hostname -f`

for i in `cat /tmp/hosts.txt`
do
keytool -genkey -keyalg rsa -keysize 2048 -noprompt -alias server -dname "CN=$i, OU=support, O=HWX, L=SantaClara, S=CA, C=US" -keystore /var/lib/ambari-server/resources/ssl_setup/$i.jks -storepass changeit -keypass changeit -validity 365

#cp /etc/security/serverKeys/$i.jks /etc/security/clientKeys/

keytool -noprompt -export -file /var/lib/ambari-server/resources/ssl_setup/$i.pem -keystore /var/lib/ambari-server/resources/ssl_setup/$i.jks -alias server -storepass changeit
keytool -noprompt -import -file /var/lib/ambari-server/resources/ssl_setup/$i.pem -keystore /var/lib/ambari-server/resources/ssl_setup/all.jks -storepass changeit -alias $i
done

##Start python SimpleHTTPServer 
cd /var/lib/ambari-server/resources/
python -m SimpleHTTPServer 8000 &> /dev/null &
ps -ef | grep SimpleHTTPServer | grep -v grep | awk -F' ' '{print $2}' > /tmp/SimpleHTTPServer.pid
fi

if [ $1 == "kill" ]
then
kill -9 `cat /tmp/SimpleHTTPServer.pid`
fi 

if [ $1 == "setup-truststore" ]
then
cp /var/lib/ambari-server/resources/ssl_setup/all.jks /etc/ambari-server/conf/ambari-truststore.jks
ambari-server setup-security --security-option=setup-truststore --truststore-type=jks --truststore-path=/etc/ambari-server/conf/ambari-truststore.jks --truststore-password=changeit --truststore-reconfigure
echo "Restarting Ambari Server"
ambari-server restart
fi
""")
os.chmod("ssl_create.sh",0755)

###Create Custom action script for Ambari keystore copy operation##

with open("validate_configs.py","w") as w :
     w.write("""\
import urllib
import os
import shutil
import subprocess
import ConfigParser
import time

subprocess.call(['mkdir', '-p', '/etc/security/clientKeys/'])
subprocess.call(['mkdir', '-p', '/etc/security/serverKeys/'])

certfile=socket.gethostname()
config= ConfigParser.ConfigParser()
config.read('/etc/ambari-agent/conf/ambari-agent.ini')
ambari_server=config.get('server','hostname')

url1="http://%s:8000/ssl_setup/%s.jks" % (ambari_server,certfile)
url2="http://%s:8000/ssl_setup/all.jks" % (ambari_server)
url3="http://%s:8000/custom_actions/scripts/validate_configs.py" % (ambari_server)

urllib.urlretrieve (url1, "/etc/security/serverKeys/keystore.jks")
urllib.urlretrieve (url2, "/etc/security/clientKeys/all.jks")
shutil.copy2('/etc/security/serverKeys/keystore.jks', '/etc/security/clientKeys/keystore.jks')
time.sleep(2)
urllib.urlretrieve (url3, "/var/lib/ambari-agent/cache/custom_actions/scripts/validate_configs.py")
""")
os.chmod("validate_configs.py",0755)

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
    return history_server
    
def sshAmbariAgents() : 
    restAPI = CLUSTER_API+"/hosts?fields=Hosts/ip"
    json_data =  ambariREST(restAPI)
    for index in range(len(json_data['items'])):
        host_ip=json_data['items'] [index] ['Hosts'] ['ip']
        scp1=''.join(['scp', ' ', '-i', PEM_FILE, ' ','validate_configs.py', ' ', 'root', '@', host_ip, ':', '/var/lib/ambari-agent/cache/custom_actions/scripts'])
        os.system(scp1)
 
def sshAmbariServer() :
    ssh1=''.join(['scp',' ', '-p', ' ', '-i', PEM_FILE, ' ', ssl_script, ' ', host_file, ' ', 'root', '@', AMBARI_DOMAIN, ':', '/tmp'])
    os.system(ssh1)
    ssh2=''.join(['ssh',' ', 'root', '@', AMBARI_DOMAIN, ' ' ,'-i', PEM_FILE, ' ', '/tmp/ssl_create.sh setup'])
    os.system(ssh2)

history_server=getMRHistory()

def clean_up():
    ssh2=''.join(['ssh',' ', 'root', '@', AMBARI_DOMAIN, ' ' ,'-i', PEM_FILE, ' ', '/tmp/ssl_create.sh kill'])
    os.system(ssh2)
    os.remove(ssl_script)
    os.remove(host_file)


def requestCopyKeystore() :

    url = "http://"+AMBARI_DOMAIN+":"+str(AMBARI_PORT)+CLUSTER_API+"/requests"
    data = {"RequestInfo":{"context":"Execute an action", "action" : "validate_configs", "service_name" : "", "component_name":"", "hosts":" "}}
    data1= json.dumps(data)
    request = urllib2.Request(url)
    base64string = base64.encodestring('%s:%s' % (AMBARI_USER_ID, AMBARI_USER_PW)).replace('\n', '')
    request.add_header("Authorization", "Basic %s" % base64string)
    request.add_header('X-Requested-By', 'ambari')
    request.add_data(data1)
    result = urllib2.urlopen(request)

    
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

  def api_accessor(AMBARI_DOMAIN, AMBARI_USER_ID, AMBARI_USER_PW, protocol, AMBARI_PORT):
    def do_request(api_url, request_type=GET_REQUEST_TYPE, request_body=''):
     try:
      url = '{0}://{1}:{2}{3}'.format(protocol, AMBARI_DOMAIN, AMBARI_PORT, api_url)
      admin_auth = base64.encodestring('%s:%s' % (AMBARI_USER_ID, AMBARI_USER_PW)).replace('\n', '')
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
    logging.info('### PUTting json into: {0}'.format(new_file))
    output_to_file(new_file)(new_config)
    accessor(CLUSTER_API.format(cluster), PUT_REQUEST_TYPE, request_body)
    logging.info('### NEW Site:{0}, Tag:{1}'.format(config_type, new_tag))
    os.remove(new_file)


  def get_current_config(cluster, config_type, accessor):
    config_tag = get_config_tag(cluster, config_type, accessor)
    logging.info("### on (Site:{0}, Tag:{1})".format(config_type, config_tag))
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
    logging.info('### Performing "set":')

    if len(args) == 1:
      config_file = args[0]
      root, ext = os.path.splitext(config_file)
      if ext == ".xml":
        updater = update_from_xml(config_file)
      elif ext == ".json":
        updater = update_from_file(config_file)
      else:
         logging.error("File extension {0} doesn't supported".format(ext))
        return -1
       logging.info('### from file {0}'.format(config_file))
    else:
      config_name = args[0]
      config_value = args[1]
      updater = update_specific_property(config_name, config_value)
      logging.info('### new property - "{0}":"{1}"'.format(config_name, config_value))
    update_config(cluster, config_type, updater, accessor)
    return 0
  def update_config(cluster, config_type, config_updater, accessor):
    properties, attributes = config_updater(cluster, config_type, accessor)
    create_new_desired_config(cluster, config_type, properties, attributes, accessor)

  def change_config_main():
    action = 'set'
    cluster = CLUSTER
    accessor = api_accessor(AMBARI_DOMAIN, AMBARI_USER_ID, AMBARI_USER_PW, protocol, AMBARI_PORT)
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


logging.info('Creating the hosts.txt file')
getAmbariHostName()

logging.info('Execute Ambari server prepare')
sshAmbariServer()

logging.info('Execute Ambari agent prepare')
sshAmbariAgents() 


logging.info('Execute Ambari API to copy keystore on all agents')    
requestCopyKeystore()


changeConfig('hdfs-site','dfs.http.policy','HTTPS_ONLY')
changeConfig('ssl-client','ssl.client.keystore.password','changeit')
changeConfig('ssl-client','ssl.client.truststore.password','changeit')
changeConfig('ssl-server','ssl.server.truststore.password','changeit')
changeConfig('ssl-server','ssl.server.keystore.password','changeit')
changeConfig('ssl-server','ssl.server.keystore.keypassword','changeit')
changeConfig('yarn-site','yarn.http.policy','HTTPS_ONLY')
changeConfig('yarn-site','yarn.log.server.url',history_server_url)
changeConfig('mapred-site','mapreduce.jobhistory.http.policy','HTTPS_ONLY')
changeConfig('mapred-site','mapreduce.jobhistory.webapp.https.address','0.0.0.0:19890')

logging.info('Execute Ambari API to restart all required services') 
restartRequired()
