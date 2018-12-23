#Update 14-09-18
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# READING IN THE DATA
import re
import pandas as pd
import numpy as np


headers=['domain', 'path', 'size', 'ip', 'foo', 'bar', 'datetime', 'request', 'status', 'size2', 'referer', 'user_agent']
regex = r'(?:(.*?) (.*) (\d+?|-) )?(\d+\.\d+\.\d+\.\d+|-) (.*?) (.*?) \[(.*?)\] "(.*?[^\\])" (.*?) (\d+?|-)(?: "(.*?)" "(.*?)")?$'

array = []
l=0
with open("projects/cybersecurity/httpd-access.log","r") as file:
#with open("short.txt","r") as file:
    for line in file:        
        values = []
        if re.match(regex, line) is not None:
            m = re.match(regex, line)
            for i in range(1,13):  
                if m.group(i) is not None:
                    values.append(m.group(i)) 
                else:
                    values.append('None')
                    #print(values[i])
        
        #This else statement print everyline of the log that the Regex can't match
        #I've tried it with 50 lines of log and there was 0 erros
        else:
            print(l+1)
        
        #I've created a list of list (because i think it's the easiest solution to do it)
        array.append(values)        
        #This line just counts the line number, because we need it with the last else statement above 
        l+=1
        
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# CREATE DATAFRAME
df = pd.DataFrame(array, columns=headers)
df.head()
#df.dtypes

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# CLEAN THE DATA

#CONVERT DATE TIME
from datetime import datetime

f = '%d/%b/%Y:%H:%M:%S %z'
time_conv = lambda x: datetime.strptime(x, f)
df['datetime']=df['datetime'].apply(time_conv)

#CONVERT TO NUMERIC
df[['size','size2','status']] = df[['size','size2','status']].apply(pd.to_numeric, errors="coerce")

#DIVIDE BY COLUMN DETAILS (BOTS OR NOT)
df['bot_or_not']= df['user_agent'].str.contains('bot')

#CHANGE TIME FROM EARLIEST TIME
df['delta_t']=df['datetime']-np.min(df['datetime'])

#REMOVE UNNECESSARY COULMNS
df=df.drop(columns='foo')
df=df.drop(columns='bar')
df=df.drop(columns='size2')
df.head()

#CONVERT DATE TIME
from datetime import datetime

f = '%d/%b/%Y:%H:%M:%S %z'
time_conv = lambda x: datetime.strptime(x, f)
df['datetime']=df['datetime'].apply(time_conv)

#CONVERT TO NUMERIC
df[['size','size2','status']] = df[['size','size2','status']].apply(pd.to_numeric, errors="coerce")

#DIVIDE BY COLUMN DETAILS (BOTS OR NOT)
df['bot_or_not']= df['user_agent'].str.contains('bot')

#CHANGE TIME FROM EARLIEST TIME
df['delta_t']=df['datetime']-np.min(df['datetime'])

#REMOVE UNNECESSARY COULMNS
df=df.drop(columns='foo')
df=df.drop(columns='bar')
df=df.drop(columns='size2')
df.head()

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# SPLIT THE REQUEST

regex_request = r'(?:(?:(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|TRACE))?(?: ?)(?:(.*))?(?: ))?(?:(.*))?'

request_method,request_content,request_version= [],[],[]

for item in df['request']:
    if re.match(regex_request, item) is not None:
        rq = re.match(regex_request, item)
        request_method.append(rq.group(1))
        request_content.append(rq.group(2))
        request_version.append(rq.group(3))
    else:
        request_method,request_content,request_version = None,None,None

df['request_method'],df['request_content'],df['request_version'] = request_method,request_content,request_version


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# XML RPC

#DIVIDE BY COLUMN DETAILS (WITH XML RPC OR NOT)
df['xmlrpc']= df['request_content'].str.contains('xmlrpc.php')
df
#If there is Wordpress installed on the website
#It can be supspicious
df.index[df['xmlrpc'] == True].tolist()
#Hackers, probably ! ... Yees ! :P
#They try to determine if you’re running a piece of software, or if you are running a specific version of some software.
df.index[(df["xmlrpc"] == True) & (df["status"] == 404)].tolist()
#CREATE A COLUMN XMLRPC_SERIOUS
xmlrpc_serious = []
for index,value in enumerate(df['xmlrpc']):
    if df['xmlrpc'].iloc[index] == True and df["status"].iloc[index] == 404:
        xmlrpc_serious.append(True)
    else:
        xmlrpc_serious.append(False)

df['xmlrpc_serious'] = xmlrpc_serious

### LOOK ALSO FOR 200 STATUS
#CREATE A NEW COLUMN XMLRPC WARNING
df.index[(df["xmlrpc"] == True) & (df["status"] == 200)].tolist()

#CREATE A COLUMN XMLRPC_WARNING
xmlrpc_warning = []
for index,value in enumerate(df['xmlrpc']):
    if df['xmlrpc'].iloc[index] == True and df["status"].iloc[index] == 200:
        xmlrpc_warning.append(True)
    else:
        xmlrpc_warning.append(False)

df['xmlrpc_warning'] = xmlrpc_warning



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# SEARCHING FOR ANY INJECTION

regrex_login='pass|password|Password|Pass|pswd|pwd|username|Username'
regex_sudo = 'sudo'
regex_a2 = "/(\')|(\%27)|(\-\-)|(#)|(\%23)/ix"
regex_sql = '/(\')|(\%27)|(\-\-)|(#)|(\%23)/ix'
regex_sql2="/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix"
regex_xss = "/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix" 
#regex_os = "/(\||%00|system\(|eval\(|`|\\)/i"
regex_xss_img = "/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/I"
regex_cd = '\/\.\./'
regex_groups = 'etc\/groups'
regex_sql_to_shell = '/exec(\s|\+)+(s|x)p\w+/ix'
regex_remote_file = '/(https?|ftp|php|data):/i'

df['SQL']= df['request_content'].str.contains(regex_sql)
df['SQL2']= df['request_content'].str.contains(regex_sql2)


df['xss']= df['request_content'].str.contains(regex_xss)
#df['os']= df['request_content'].str.contains(regex_os)
df['regex_xss_img']= df['request_content'].str.contains(regex_xss_img)



df['login']= df['request_content'].str.contains(regrex_login)
df['sudo']= df['request_content'].str.contains(regex_sudo)
df['cd']= df['request_content'].str.contains(regex_cd)
df['groups'] = df['request_content'].str.contains(regex_groups)

df['SQL_union']=df['request_content'].loc[df['SQL']==True].str.contains('union')
df['SQL_union']=df['SQL_union'].fillna(False)


df['a2_injection']=df['request_content'].str.contains(regex_a2)

df['sql_shell']=df['request_content'].str.contains(regex_sql_to_shell)
df['remote_file']=df['request_content'].str.contains(regex_remote_file)

'''
TO LOOK FOR
same ip , different domain, xmlrpc
short amount of time '''
#df['goingup']=goingup
     
df.head()

