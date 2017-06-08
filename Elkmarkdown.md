# Collecting Syslogs from FreeIPA and clients using ELK Stack


## Introduction:

In this tutorial, we will go over the installation of an ELK stack server version 5.4 on CentOS 7 and configure it to collect from a two subnets a FreeIPA server and its linux clients and a Samba server with its windows clients. ELK stack is an application bundle used for log collection that gives users access to logs from all of its clients in a centralized location. FreeIPA and Samba are both directory servers. 

## Architecture:

ELK stands for Elasticsearch, Logstash and Kibana which do the majority of the work on the server side. For the ELK-clients we will be using both the FreeIPA and Samba server plus their respective clients

The following is a summary of the processing order:

The Beats application in each client forwards the desired logs to Logstash for processing and indexing. Once the logs are indexed, they are stored on Elasticsearch. Finally Kibana provides an interface for searching and visualizing the logs then uses Nginx as reverse proxy to make them available to the user. 

## Prerequisites:
* Root access to the workstations
* FreeIPA server and a Samba server
* The Elk stack server specs will vary depending on the amount of logs
  * OS: Centos 7
  * RAM: 4GB (The recommended minimal is 16GB, Enterprise should be 32GB+)
  * CPU: 2
* The FreeIPA server is assumed to be already deployed and not covered in this tutorial
    * FreeIPA:
      * OS: CentOS 7
   * IPA client:
     * OS: Fedora 25
* The Samba server is assumed to be already deployed and not covered in this tutorial
  * Samba:
    * OS: CentOS 7
  * client:
    * OS: Windows 10
* Timing is critical for synchronization (note: sync for windows client requires NTP server installation on the samba server and a GPO to be used)

## Installation Order

1. Elasticsearch
X-Pack for Elasticsearch
2. Kibana
X-Pack for Kibana
3. Logstash
4. Beats

## Security
First check to see if your firewall is properly configured port 5044 should be open also http and https should be listed as services. Use the following command to check:

`$ firewall-cmd --list-all`

output:

`public (active)`<br/>
`target: default`<br/>
`icmp-block-inversion: no`<br/>
`interfaces: eth0`<br/>
`sources:`<br/>
`services: http https ssh`<br/>
`ports: 5044/tcp`<br/>
`protocols:`<br/>
`masquerade: no`<br/>
`forward-ports:`<br/>
`sourceports:`<br/>
`icmp-blocks:`<br/>
`rich rules:`<br/>

If either of the above mentioned is missing use the commands below to add them:

`$ firewall-cmd --add-port=5044/tcp --permanent --zone=public`

`$ firewall-cmd --zone=public --permanent --add-service=http`

`$ firewall-cmd --zone=public --permanent --add-service=https`

Once complete use this command:

`$ firewall-cmd --reload`

Check Selinux status

`$ sestatus`

Change settings accordingly (enabled, disabled, permissive) We will disable for now but keep in mind that when deployed, the proper permission should be added. The config file is /etc/selinux/config change the value "enabled" to "disabled".

## ELK Stack Installation:

### Install Java 8:

First we need to install Java as it is needed by Elasticsearch and Logstash. In following this section you will accept the Oracle Binary License Agreement for Java SE so you should check it out first [here](http://www.oracle.com/technetwork/java/javase/terms/license/index.html).

`$ cd ~`<br/>

`$ wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u131-b11/d54c1d3a095b4ff2b6607d096fa80163/jdk-8u131-linux-x64.rpm"`<br/>

Install the RPM file with the following command then delete it with the second:

`$ rpm -ivh jdk-8u131-linux-x64.rpm`<br/>

`$ rm ~/jdk-8u*-linux-x64.rpm`<br/>

### Install Elasticsearch

The following command will import the Elasticsearch public GPG key into rpm:

`$ sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch`<br/>

Create a new yum repository in /etc/yum.repos.d/ using vi text editor or your favorite editor

`$ vi /etc/yum.repos.d/elasticsearch.repo`<br/>

Note: To write press ‘i’ to enter insert mode
Now inside the file:
~~~~
[elasticsearch-5.x]
name=Elasticsearch repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
~~~~

Now save and exit. 

Once this is complete the following command will install Elasticsearch:

`$ sudo yum -y install elasticsearch`<br/>

Now let us open up the configuration file with the following command:

`$ sudo vi /etc/elasticsearch/elasticsearch.yml`<br/>

Utilizing the following setting will secure your Elasticsearch instance from outside access via HTTP API.

~~~~
network.host: localhost
~~~~
Save and exit

Now start and enable Elasticsearch to start at boot up with the following commands: 

`$ sudo systemctl start elasticsearch`<br/>

`$ sudo systemctl enable elasticsearch`<br/>

### Elasticsearch Directory layout of RPM installation
**Type**|**Description**|**Default Location**|**Setting**
:-----:|:-----:|:-----:|:-----:
home|Elasticsearch home directory or $ES\_HOME|/usr/share/elasticsearch| 
bin|Binary scripts including elasticsearch to start a node and elasticsearch-plugin to install plugins|/usr/share/elasticsearch/bin| 
conf|Configuration files including elasticsearch.yml|/etc/elasticsearch|path.conf
conf|Environment variables including heap size, file descriptors.|/etc/sysconfig/elasticsearch| 
data|The location of the data files of each index / shard allocated on the node. Can hold multiple locations.|/var/lib/elasticsearch|path.data
logs|Log files location.|/var/log/elasticsearch|path.logs
plugins|Plugin files location. Each plugin will be contained in a subdirectory.|/usr/share/elasticsearch/plugins| 
repo|Shared file system repository locations. Can hold multiple locations. A file system repository can be placed into any subdirectory of any directory specified here.|Not configured|path.repo
script|Location of script files.|/etc/elasticsearch/scripts|path.scripts

### Install X-pack on Elasticsearch
In our basic installation we will be using the x-pack’s Monitoring function so we will need to install X-pack. Make sure that the version matches your current installation. 

Install X-Pack through the Elasticsearch home directory for each one of your nodes by running elasticsearch-plugin and automatically grant it permissions with the following command:

`$ /usr/share/elasticsearch/bin/elasticsearch-plugin install x-pack --batch`<br/>

then restart Elasticsearch:

`$ systemctl restart elasticsearch`<br/>

Now that Elasticsearch with X-pack is up and running, let's install Kibana.<br/>
## Install Kibana
The Elasticsearch repo Contains the Kibana packages and uses the same GPG key we installed earlier so we can simply install Kibana with the following command:

`$ sudo yum -y install kibana`<br/>

Now let us open up the configuration file with the following command:

`$ sudo vi /etc/kibana/kibana.yml`<br/>

We will be using a Nginx as reverse proxy for external access so we need to set kibana access to localhost with the following settings:
~~~~
server.port: 5601
...
server.host: "localhost"
~~~~
Save and exit.

Now start and enable Kibana to start at boot up with the following commands: 

`$ sudo systemctl start kibana`<br/>

`$ sudo chkconfig kibana on`<br/>

### Kibana Directory layout of RPM installation:
**Type**|**Description**|**Default Location**|**Setting**
:-----:|:-----:|:-----:|:-----:
home|Kibana home directory or $KIBANA\_HOME|/usr/share/kibana| 
bin|Binary scripts including kibana to start the Kibana server and kibana-plugin to install plugins|/usr/share/kibana/bin| 
config|Configuration files including kibana.yml|/etc/kibana| 
data|The location of the data files written to disk by Kibana and its plugins|/var/lib/kibana| 
optimize|Transpiled source code. Certain administrative actions (e.g. plugin install) result in the source code being retranspiled on the fly.|/usr/share/kibana/optimize| 
plugins|Plugin files location. Each plugin will be contained in a subdirectory.|/usr/share/kibana/plugins| 


### Install X-pack on Kibana
Install X-Pack through the Kibana home directory for each one of your nodes by running elasticsearch-plugin 

`$ /usr/share/kibana/bin/kibana-plugin install x-pack`<br/>

`$ sudo systemctl restart kibana`<br/>

## License setup
prepare for basic license by disabling all features but monitoring by adding the following lines in elasticsearch.yml and kibana.yml once complete save and exit

`$ sudo vi /etc/elasticsearch/elasticsearch.yml`<br/>
~~~~
xpack.security.enabled: false
xpack.graph.enabled: false
xpack.watcher.enabled: false
~~~~
`$ sudo vi /etc/kibana/kibana.yml`<br/>
~~~~
xpack.security.enabled: false
xpack.graph.enabled: false
xpack.watcher.enabled: false
~~~~
Restart Elasticsearch and Kibana with the following commands:

`$ sudo systemctl restart elasticsearch`<br/>

`$ sudo systemctl restart kibana`<br/>

Download the license from [here](https://www.elastic.co/subscriptions):

secure copy from your computer to the server you will be prompted for a password substitute for the name of your license  and your destination. The license naming convention should follow firstname and last name followed by a code.

`$ scp /Downloads/firstname-lastname-*.json user@Elk_Stack_IP:~`<br/>

now inside your Elk stack server in your home directory make a copy of the license renaming the copy to license.json:

`$ cp firstname-lastname-bla-bla.json license.json`<br/>

Now use the following command to Send a request to the license API and specify the file that contains your new license. You will be prompted for the default user's password which is "changeme" this setting will be disabled once the license is 

`$ curl -XPUT -u elastic 'http://localhost:9200/_xpack/license?acknowledge=true' -H "Content-Type: application/json" -d @license.json`<br/>

you should get the following output:

`{"acknowledged":true,"license_status":"valid"}`<br/>

## Install Nginx
Nginx will allow access to the Kibana since Kibana is setup to listen to localhost

The following commands will install nginx, httpd-tools and the required repositories:

`$ sudo yum -y install epel-release`<br/>

`$ sudo yum -y install nginx httpd-tools`<br/>

Since installing the Basic license required us to disable X-packs security we have no way to secure Kibana’s web interface. We will instead make use of Nginx’s user authentication using the following command (substitute kibadmin with your user name) enter a password when prompted:

`$ sudo htpasswd -c /etc/nginx/htpasswd.users kibadmin`<br/>

Now let us open up the configuration file with the following command:

`$ sudo vi /etc/nginx/nginx.conf`<br/>

Delete the server block since we will create a separate configuration file:
~~~~
server       	<-- from here 
{
...
...
}		<-- to here
~~~~
Save and exit.
The following command will create the new server configuration for our Kibana web interface:

`$ sudo vi /etc/nginx/conf.d/kibana.conf`<br/>
~~~~
server {

listen 80;

server_name your.server.com;
    # to add additional authentication uncomment the two bellow
   	auth_basic "Restricted Access";
  	auth_basic_user_file /etc/nginx/htpasswd.users;

   	location / {
       		proxy_pass http://localhost:5601;
       		proxy_http_version 1.1;
       		proxy_set_header Upgrade $http_upgrade;
       		proxy_set_header Connection 'upgrade';
       		proxy_set_header Host $host;
       		proxy_cache_bypass $http_upgrade;        
   	}
}
~~~~
Save exit then start and enable Nginx to start at boot up with the following commands: 

`$ sudo systemctl start nginx`<br/>

`$ sudo systemctl enable nginx`<br/>

if Selinux is not disabled the following command allow Kibana to work properly

`$ sudo setsebool -P httpd_can_network_connect 1`<br/>

You can access Kibana either through the ELK_Stack_IP address or FQDN use the Nginx authentication at login

http://ELK_Stack_IP<br/>
or<br/>
http://FQDM<br/>


## Install Logstash
The Elasticsearch repo Contains the Logstash packages and uses the same GPG key we installed earlier so we can simply install Kibana with the following command:

`$ sudo yum -y install logstash`

Logstash is installed but it is not configured yet.
### Logstash Directory Layout for RPM Packages
**Type**|**Description**|**Default Location**|**Setting**
:-----:|:-----:|:-----:|:-----:
home|Home directory of the Logstash installation.|/usr/share/logstash| 
bin|Binary scripts including logstash to start Logstash and logstash-plugin to install plugins|/usr/share/logstash/bin| 
settings|Configuration files, including logstash.yml, jvm.options, and startup.options|/etc/logstash|path.settings
conf|Logstash pipeline configuration files|/etc/logstash/conf.d|path.config
logs|Log files|/var/log/logstash|path.logs
plugins|Local, non Ruby-Gem plugin files. Each plugin is contained in a subdirectory. Recommended for development only.|/usr/share/logstash/plugins|path.plugins

## Generate SSL Certificates
To Authenticate communication between ELK server and beats clients we will need to create SSL certificate and key pairs. You have two options. Use Option 1 if you do not have a DNS setup to resolve your FQDN. Use Option 2 if you do.
#### Option 1: IP Address
Now let us open up the OpenSSL configuration file with the following command:

`$ sudo vi /etc/pki/tls/openssl.cnf`

under the [ v3_ca ] section add the following line:
~~~~
subjectAltName = IP: ELK_server_private_ip
~~~~
Save and exit.
The following commands will create your SSL certificate and key pair

`$ cd /etc/pki/tls`

`$ sudo openssl req -config /etc/pki/tls/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt`

Skip Option 1 if you went with this option
#### Option 2: FQDN (DNS)
The following commands will create your SSL certificate and key pair using the ELK_STACK_FQDN make sure your DNS is able to resolve this FQDN:

`$ cd /etc/pki/tls`

`$ sudo openssl req -subj '/CN=ELK_STACK_FQDN/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt`

## Configure Logstash
The following three configuration files will govern how Logstash handles input, outputs and filtering to further customize your installation you can find configuration options [here](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-elasticsearch.html#plugins-outputs-elasticsearch-sniffing).

The following command will create the input configuration paste the input { } block that follows which will set up Logstash to listen to port 5044 and authenticate via the SSL certificate and key pair:

`$ sudo vi /etc/logstash/conf.d/input.conf`
~~~~
input {
 	beats {
   	port => 5044
   	ssl => true
   	ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
   	ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
	client_inactivity_timeout => "86400"
 	}
}
~~~~
Save and quit. 

The following command will create the filter configuration paste the filter { } block that follows which will set up Logstack filter to look for syslogs then structure them using grok:

`$ sudo vi /etc/logstash/conf.d/filter.conf`
~~~~
filter {
 	if [type] == "syslog" {
   	grok {
     		match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
     		add_field => [ "received_at", "%{@timestamp}" ]
     		add_field => [ "received_from", "%{host}" ]
   	}
syslog_pri { }
   	date {
     		match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
   }
 }
}
~~~~
The following command will create the output configuration paste the output { } block that follows which will forward the the structured message to Elasticsearch:

`$ sudo vi /etc/logstash/conf.d/output.conf`
~~~~
output {
 		elasticsearch {
   			hosts => ["localhost:9200"]
   			sniffing => true
   			manage_template => false
   			index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
   			document_type => "%{[@metadata][type]}"
 		}
}
~~~~
Save and exit
Now start and enable Logstash to start at boot up with the following commands: 

`$ sudo systemctl restart logstash`

`$ sudo systemctl enable logstash`

## Load Kibana Dashboards
As a starting point we will be using the Elastic dashboards and index patterns the following commands will download zip file containing the dashboards and  extract its content using the unzip command to your home directory:

`$ cd ~`

`$ wget "https://artifacts.elastic.co/downloads/beats/beats-dashboards/beats-dashboards-5.4.0.zip"`

`$ unzip beats-dashboards-*.zip`

Now navigate to the extracted directory:

`$ cd beats-dashboards-*`

Download and unzip the ./load.sh script form the repo. Given the option "-d" and the beat directory it will run a curl command for each of the json files inside. For our installation we will need filebeat and winlogbeat.

`$ wget https://github.com/mzamora9913/ELK-Stack/raw/master/load.zip`

`$ unzip load.sh.zip`

`$ ./load.sh -d filebeat`

`$ ./load.sh -d winlogbeat`

These are the index patterns corresponding to each beat:

[packetbeat-]YYYY.MM.DD <br/>
[topbeat-]YYYY.MM.DD<br/>
[filebeat-]YYYY.MM.DD<br/>
[winlogbeat-]YYYY.MM.DD<br/>
[heartbeat-]YYYY.MM.DD<br/>
## Load Filebeat Index Template in Elasticsearch
To configure Elasticsearch to analyze beat fields we will need to load a template for each one of our beats. The following is an example template for Filebeat. for template information go [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-modules.html)

`$ vi filebeat-index-template.json`

inside the file add the following:
~~~~
{
  "mappings": {
	"_default_": {
  	"_all": {
    	"enabled": true,
    	"norms": {
      	"enabled": false
    	}
  	},
  	"dynamic_templates": [
    	{
      	"template1": {
        	"mapping": {
          	"doc_values": true,
          	"ignore_above": 1024,
          	"index": "not_analyzed",
          	"type": "{dynamic_type}"
        	},
        	"match": "*"
      	}
    	}
  	],
  	"properties": {
    	"@timestamp": {
      	"type": "date"
    	},
    	"message": {
      	"type": "string",
      	"index": "analyzed"
    	},
    	"offset": {
      	"type": "long",
      	"doc_values": "true"
    	},
    	"geoip"  : {
      	"type" : "object",
      	"dynamic": true,
      	"properties" : {
        	"location" : { "type" : "geo_point" }
      	}
    	}
  	}
	}
  },
  "settings": {
	"index.refresh_interval": "5s"
  },
  "template": "filebeat-*"
}
~~~~
Save and exit
 The following command will load the template substitute “filebeat” for other beats if needed

`$ curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json`

The following ouput will confirm it was accepted

`{`<br/>
`  	"acknowledged" : true`<br/>
`}`<br/>

## Set Up Filebeat on FreeIPA server
### Copy SSL Certificate
On your ELK server Secure copy the SSL certificate you created to ELK client using its ip and user

`$ scp /etc/pki/tls/certs/logstash-forwarder.crt user@client_server_private_address:/tmp`

create the certs directory and move logstash-forwarder.crt this will be the location we will give the configuration file later so remember this path

`$ sudo mkdir -p /etc/pki/tls/certs`<br/>

`$ sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/`

Install Filebeat Package
The following command will import the Elasticsearch public GPG key into rpm to the ELK Client:

`$ sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch`


Create a new yum repository in /etc/yum.repos.d/ using vi text editor or your favorite editor

`$ sudo vi /etc/yum.repos.d/elastic-beats.repo`

Now inside the file:
~~~~
[elasticsearch-5.x]
name=Elasticsearch repository for 5.x packages
baseurl=https://artifacts.elastic.co/packages/5.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
~~~~

Now save and exit 

Once this is complete the following command will install Filebeat:

`$ sudo yum -y install filebeat`

(optional install procedure)<br/>
`$ curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-5.4.0-x86_64.rpm`

`$ sudo rpm -vi filebeat-5.4.0-x86_64.rpm`

### Filebeat Directory Layout for RPM Packages
**Type**|**Description**|**Location**
:-----:|:-----:|:-----:
home|Home of the Filebeat installation.|/usr/share/filebeat|
scripts|import_dashboards migrate_beat_config_1_x_to_5_0.py|/usr/share/filebeat/scripts
bin|The location for the binary files.| /user/share/filebeat|s
conf|The location for the configuration files|/etc/filebeat
data|The location for persistent data files.|/var/lib/filebeat
logs|The location for the logs created by filebeat|/var/log/filebeat
### Configure Filebeat
Filebeat will need to be configured to forward logs to logstash. Here is a list of optimal logs that should be collected FreeIPA [site](http://www.freeipa.org/page/Centralized_Logging)

Now let us open up the configuration file in the ELK client with the following command the YAML format is particular with spacing so make sure your file paths have 4 spaces preceding  :

`$ sudo vim /etc/filebeat/filebeat.yml`


find the paths section which will list the logs that will be shipped out. Comment out the default path "- /var/log/*.log" which gathers generic logs and add the following customized log paths (For each of FreeIPA clients we will follow these instructions minus the FreeIPA server logs):
~~~~
…
paths:
#freeIPA server logs
        - /var/log/httpd/error_log
        - /var/log/krb5kdc.log
        - /var/log/dirsrv/slapd-<REALM>/access
        - /var/log/dirsrv/slapd-<REALM>/errors
        - /var/log/pki/pki-tomcat/ca/transactions
# freeIPA local logs 
        - /var/log/sssd/*.log
        - /var/log/audit/audit.log
        - /var/log/secure
#        - /var/log/*.log
~~~~
Immediately after the paths add the document type so it matches the filter settings on Logstash (0 spaces)
~~~~
...
document_type: syslog
...
~~~~

Now comment out all of the Elasticsearch output settings and uncomment/add the Logstash output configurations as followed to direct output to logstash, limit the size to 1024, and authenticate the SSL(make sure you substitute your Elk stack ip). 
~~~~
#----------------------------- Elasticsearch output --------------------------------
  #output.elasticsearch:
    # The Logstash hosts
    #hosts: ["ELK_server_private_IP:9200"]
#----------------------------- Logstash output --------------------------------
  output.logstash:
    # The Logstash hosts
    hosts: ["ELK_server_private_IP:5044"]
    # add me to specify the size
    bulk_max_size: 1024
    
    # Optional SSL. By default is off
    # List of root certificates for HTTPS server verification (this path should match the SSL path we created earlier)
      ssl.certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]
~~~~
Now start and enable Filebeat to start at boot up with the following commands: 

`$ sudo systemctl start filebeat`<br/>

`$ sudo systemctl enable filebeat`<br/>

### Test Filebeat Installation
to test the configuration we can run Filebeat in the forefront with our current yml file in the ELK client.

`$ /usr/share/filebeat/bin/filebeat -e -c /etc/filebeat/filebeat.yml`<br/>

if you see this:

`2017/05/11 22:24:26.794660 modules.go:93: ERR Not loading modules. Module directory not found: /usr/share/filebeat/bin/module`<br/>

do this in your ELK stack client(where you installed filebeat):

`$ sudo mkdir /usr/share/filebeat/bin/module`<br/>

`$ sudo cp -a /usr/share/filebeat/module/. /usr/share/filebeat/bin/module`<br/>


use the following command on your ELK server to check that the logs are making it to your Elasticsearch.

`$ curl -XGET 'http://localhost:9200/filebeat-*/_search?pretty'`<br/>


Expect something similar to this:

`{`<br/>
`     "_index" : "filebeat-2016.01.29",`<br/>
`      "_type" : "log",`<br/>
`      "_id" : "AVKO98yuaHvsHQLa53HE",`<br/>
`      "_score" : 1.0,`<br/>
`      "_source":{"message":"Feb  3 14:34:..................................`<br/>
`    }`<br/>

An empty output indicates that no logs are loading for the filebeat-* index. Verify your configuration and see
**"Some Troubleshooting / helpful commands"** section below for help. If you received the expected output, continue to the next step.

Go into the Kibana web interface  http:/ip and you will be prompted to choose your default index pattern click on filebeat-*

![alt](https://github.com/mzamora9913/ELK-Stack/blob/master/Select_Index_1.png?raw=true)

Now click on the Star symbol to the right to make the index default

![alt](https://github.com/mzamora9913/ELK-Stack/blob/master/Select_Index_2.png?raw=true)

Now you should go to Discover and do a search. For example "*user*" will return any logs with a particular user just substitute “user” for a actual user in your system the ‘*’ are wildcards. 

![alt](https://github.com/mzamora9913/ELK-Stack/blob/master/Search_Index.png?raw=true)

## Set Up Winlogbeat on Windows 10 client
### Copy SSL Certificate
Login as local Administrative user

Download and setup WinSCP from [here](https://winscp.net/eng/download.php)

Open WinSCP and establish a connection to your Elk stack server
copy the certificate /etc/pki/tls/cert/logstash-forwarder.crt to the Download folder in your windows machine.

Download Winlogbeat [here](https://www.elastic.co/downloads/beats/winlogbeat). The zip file should be extracted then renamed to Winlogbeat into the C:\Program Files directory

Move the certificate from Download to your new winlogbeat folder right click the certificate and select to install certificate, install on local machine then ok on the next two options

Using an Administrative PowerShell execute the following command to allow scripts to be run

`PS C:\ Set-ExecutionPolicy UnRestricted`<br/>

click “yes to all” to the script warning


Now navigate to the Winlogbeat directory and run the install-service-winlogbeat.ps1 script

`PS C:\Users\Administrator> cd 'C:\Program Files\Winlogbeat'`<br/>

`PS C:\Program Files\Winlogbeat> .\install-service-winlogbeat.ps1`<br/>

say yes to the script warning

To open the configuration file you will need to install notepad++ from [here](https://notepad-plus-plus.org/download/v7.4.1.html). Once installed you will need to right-click the notepad++ icon and run as administrator. From the application open the winlogbeat.yml configuration file located at C:\Program Files\Winlogbeat\winlogbeat.yml
configure winlogbeat: [Configuration Options (Reference)](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-configuration-details.html).
Here’s a sample config that works for our setup everything else gets commented out using <br/>
Winlogbeat Configuration Example
~~~~
...
winlogbeat.event_logs:
  - name: Application
	ignore_older: 72h
  - name: Security
  - name: System

#----------------------------- Logstash output --------------------------------
output.logstash:
  # The Logstash hosts
  hosts: ["192.168.122.107:5044"]

  ssl.certificate_authorities: ['C:/Program Files/Winlogbeat/logstash-forwarder.crt']
#================================ Logging ============================

logging.to_files: true
logging.files:
  path: C:/Program Files/Winlogbeat/Logs
logging.level: info
~~~~

To start winlogbeat use the following

`PS C:\Program Files\Winlogbeat> Start-Service winlogbeat`<br/>

In case you run into issues this is the location of the winlogbeat logs C:\ProgramData\Winlogbeat\Logs\winlogbeat.

to see the status run this command

`PS C:\Program Files\Winlogbeat> services.msc`<br/>


## Some troubleshooting / helpful commands
### Summary of elasticsearch configuration:
`curl "localhost:9200/_nodes/settings?pretty=true"`<br/>

Nginx error logs

`$ tail /var/log/nginx/error.log`<br/>

### Configure Kibana logs

`$ mkdir /usr/share/kibana/log && touch /usr/share/kibana/log/kibana.log`<br/>

`$ chown kibana /usr/share/kibana/log/kibana.log && chgrp /usr/share/kibana/log/kibana.log`<br/>

uncomment and change the following line in the kibana.yml file
~~~~
logging.dest: /usr/share/kibana/log/kibana.log
~~~~
restart kibana with<br/>

`$ systemctl restart kibana`<br/>

check the logs

`$ tail /usr/share/kibana/log/kibana.log`<br/>

This is my error just in case you get the same problem:
~~~~
{"type":"log","@timestamp":"2017-05-16T18:35:06Z","tags":["fatal"],"pid":14370,"level":"fatal","message":"EACCES: permission denied, open '/usr/share/kibana/optimize/bundles/monitoring.entry.js'","error":{"message":"EACCES: permission denied, open '/usr/share/kibana/optimize/bundles/monitoring.entry.js'","name":"Error","stack":"Error: EACCES: permission denied, open '/usr/share/kibana/optimize/bundles/monitoring.entry.js'\n	at Error (native)","code":"EACCES"}}
~~~~
Do the same thing if you get the the above error for ml.entry.js

This tells us that Kibana does not have permission to open said files so we will need to it permission. 

`$ chown kibana /usr/share/kibana/optimize/bundles/monitoring.entry.js && chgrp kibana /usr/share/kibana/optimize/bundles/monitoring.entry.js`<br/>

`$ chown kibana /usr/share/kibana/optimize/bundles/ml.entry.js && chgrp kibana /usr/share/kibana/optimize/bundles/ml.entry.js`<br/>

### Configure Elasticsearch logs
We need to edit /usr/lib/systemd/system/elasticsearch.service and delete the line that has --quiet to enable loging:

`$ vim /usr/lib/systemd/system/elasticsearch.service`<br/>
~~~~
ExecStart=/usr/share/elasticsearch/bin/elasticsearch \
                                               -p ${PID_DIR}/elasticsearch.pid \
--quiet \
                                               -Edefault.path.logs=${LOG_DIR} \
                                               -Edefault.path.data=${DATA_DIR} \
                                               -Edefault.path.conf=${CONF_DIR}
~~~~
to view logs use the following commands:<br/>
`$ tail /var/log/elasticsearch/elasticsearch.log`<br/>

view Logstash logs<br/>
`$ tail /var/log/logstash/logstash-plain.log`<br/>

## References:

* [Official Elastic Docs](https://www.elastic.co/guide/index.html)
* [Mitchell Anicas - How to Install Elasticsearch Logstash and Kibana ELK Stack on Centos-7](https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7)
