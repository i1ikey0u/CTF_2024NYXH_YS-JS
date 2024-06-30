
**能源协会****团队决赛**
# 说明
1、只有部分赛题的WriteUp，希望大家能多多补充
2、由于本次赛事，是多个赛题公用一个题目环境的设置，靠记忆进行的记录，可能题解过程分布在不同的题目下。
# 操作员站异常访问
操作员站已经沦陷，频繁存在非工作人员IP地址访问3389端口，请检查风险项并进行清理，并设置用户帐户被锁定的登录尝试失败的次数为30
## 题目环境1
rdp 192.26.1.211   3389  用户名:Administrator
## 操作内容
![](media/image1.png)
切换桌面，进入系统
查看网络连接情况
![](media/image2.png)
通过组策略配置账号锁定阈值

![](media/image3.png)
安装安全软件，病毒查杀：有个木马文件在C盘，直接删除即可。

禁止开机启动项
![](media/image4.png)
![](media/image5.png)






# 操作员站恶意代码
安全人员发现当前主机怀疑存在无文件/落地了ps1文件，尝试寻找并分析存在异常内容，解密数据，提取到包含IP明文信息的数据（文件末尾20字节），将该数据的16进制数据作为flag进行提交。例如：提取到数据为b’\\xff\\xff21.245.253.72\\x00\\x00\\x01\\x86\\xa0’ 16进制为 FFFF32312E3234352E3235332E373200000186A0,则flag为 flag{FFFF32312E3234352E3235332E373200000186A0}
## 题目环境1
rdp 192.26.1.211   3389  用户名:Administrator
## 操作内容
搜索本机所有的powershell脚本，筛查找到恶意的ps1文件：package.ps1

![](media/image6.png)
找到异常的ps1文件，时间和位置异常
![](media/image7.png)
审计文件：
![](media/image8.png)
解码base64：
![](media/image9.png)
格式化： 
![](media/image10.png)
再次base64解码
![](media/image11.png)
找到关键函数，XOR函数
![](media/image12.png)
XOR解码后，结合脚本中的代码，对gzip压缩流进行解压，在末尾发现关键IP地址信息，结合题目要求，提交即可

![](media/image13.png)

flag{FF3130332E3137382E3232382E333200000186A0}

# 逻辑控制安全防护
演练活动即将开启，为了防止某时间段工业设备点位被恶意篡改，请通过赛题提供的工控防火墙针对写线圈进行加固。请注意：防火墙仅限该题使用，且不能干扰上下位正常通讯（仅允许读操作）。在检测期间，请保证104#断路器处于合闸状态。

工控防火墙: https://[见当前场景拓扑中外部地址]:10443
账户: superadmin
密码: M2B\*h%-3Is
## 题目环境1
rdp 192.26.1.211   3389  用户名:Administrator
## 操作内容


# 能源管理漏洞分析
能源管理系统存在owasp-top10安全漏洞，请分析相关攻击行为，针对漏洞进行防护及网站连接数据库账户降权。具体加固方式在满足竞赛规则条件下不做额外限制。
## 题目环境2
rdp 192.26.1.97   3389  用户名:Administrator
## 操作内容
是个WEB应用，对账号密码进行爆破，找到弱口令
![](media/image14.png)
对页面的输入进行审计，发现注入：
![](media/image15.png)POST /FtyInfoSetting.aspx HTTP/1.1
Host: 192.26.1.97
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: \*/\*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-MicrosoftAjax: Delta=true
Cache-Control: no-cache
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Content-Length: 1078
Origin: http://192.26.1.97
Connection: close
Referer: http://192.26.1.97/FtyInfoSetting.aspx
Cookie: _lang=zh-tw; ASP.NET_SessionId=piwi0wguuhkzlln44x1hahxv; .ASPXAUTH=AC0A4018EA68BCDDDB4B93E367E2D1BB04AE92ECC8407317EA8AE982D00AEFF99C7F841147BAB2BFE154045DE9AD0EE114A60FB3DCAB790E00CC1D03357696CBE702E542C5D71C2C282D89581CC0755435112571926DE9C8D01EE369C8462A0B5EDADB4FA9C64FFDD54FB9EA55430C8932DB0BC2C5ABB7FC74D7A2C5FB428B2C
Priority: u=1

scrMgr=upanAddWarn%7CbtnBiiAddType&amp;__EVENTTARGET=&amp;__EVENTARGUMENT=&amp;__VIEWSTATE=%2FdnHnWsFGD%2BUJQYrA%2BBZdhQ9jbN1AjhUfOLAaWX7ayIEPtw5t2kRyg0ks4PiRx6sdsgpbQppDRxX%2FAw0bcUsoPXZSdKO3orxyP%2FE1Qg4m0naCbvfEu5dzTaJutiGTb85D6k9xxdQJl7I8HohcF3DqLWFx3tPQYKlz8tM7VZsQ83khgWThZRJ0h9SjPK4zj%2FTCkB9EUr8thdJPUtpwSbQtaZlab3y39ob7qGij4blyqrFQUJBOhyFGGxXkYOYuHiKx58wPnhY6a5TdY8EgJmEtzxfTjKuVbXZaQw1y9yXfZIFy8uunMxHFHoBjkbOjX8B0ewWZ2jfH2o05LIqZnx%2BFYs1edZQrH0DV3ZkoR%2B36twTOvGJ8gCZoWrJIhebAC6IFmqd3zeh8O2cOIQOdpDyWqtg8TVoKTvjY%2FvkckBNqGr1MH9%2BCTvbxRumyZCy9BfRvQNLAd%2BvitQUc4MXpyiYG%2BhZFuykXgbW8CpJ%2F1iqY8C3uoz2KFiT9KLc5qD0%2BsR0CsFuL%2F3UdyN3FsXSkqxOi%2BrPm7ADxJ%2F6XvKOvQ4jmmGYM9VwiZy1hZ69KtzzAXtg&amp;__VIEWSTATEGENERATOR=6B5DD445&amp;__VIEWSTATEENCRYPTED=&amp;__EVENTVALIDATION=FRAzRcykfeNr%2FxmVMSYRj4ICpggCfJS6gH8XgMWI8x1T05muWYw4uBnd7aL%2BmZ5fUcWM8oxWz56cL9AHfH8y0ITPC4eJijMMtrtTO%2BzVfqj0qZXSvFRQ77INnBWn4pWIH2%2Bim3CuqVC%2BDtB6928d6%2B8tysM4prhldrRTYnHgMW6fK7A6TVLeWzWguveouj3KT9j3fjzIZ7tpyoPWQL5vL%2FpX8VWid%2BpHRJY33qjB1S0%3D&amp;txName_t=1\*&amp;__ASYNCPOST=true&amp;btnBiiAddType=%E6%96%B0%E5%A2%9E

经过测试，发现可以通过注入漏洞，获得shell
![](media/image16.png)
安装D盾防护即可

# 能源管理后门查杀
能源管理系统Web应用框架被攻击者留下了后门，请定位分析后清理相关后门程序.
## 题目环境2
rdp 192.26.1.97   3389  用户名:Administrator

## 操作内容
D盾扫描，发现相关风险项目，挨个尝试，最后定位是利用了SysteManagenentAutomcat.dll
将其相关配置代码在web.config里面删除，并将SysteManagenentAutomcat.dll文件删除。
重启IIS应用即可check通过

![](media/image17.png)


# NSA黑客武器攻击

操作系统遭受了黑客利用NSA黑客武器库泄漏的工具发起的网络攻击事件，为了临时缓解风险，请采用如下方式处置
1.关闭存在漏洞的服务端口
2.清理开机持久化后门
## 题目环境3
rdp  192.26.2.209  3389        用户名:Administrator       
## 操作内容


# 恶意蠕虫病毒清理

操作系统感染了恶意蠕虫病毒并释放了挖矿程序，请针对[文件、服务、挖矿进程]分别进行清理，恢复系统正常运行状态
## 题目环境3
rdp  192.26.2.209  3389        用户名:Administrator       
## 操作内容
![](media/image18.png)

![](media/image19.png)

![](media/image20.png)
![](media/image21.png)

# 施耐德电气协议防护
UMAS协议是施耐德电气（SE）的专有协议，用于配置和监控施耐德电气PLC，通过UMAS协议可以执行一些高权限的操作，例如对PLC启动/停止操作。该协议存在一些高危风险，攻击者可以利用攻击脚本完成PLC未授权启动/停止操作，对工厂生产控制系统带来严重的危害，请针对这一情况请利用你所掌握的知识对PLC未授权启动/停止操作的行为进行防御。

注意：如需操作PLC环境请点击右上角拓扑场景
## 题目环境3
rdp  192.26.2.209  3389        用户名:Administrator  
## 操作内容

# 持久化威胁分析
管理员发现操作系统每间隔10分钟就会执行一次创建账户，请清理计划任务文件、后门程序文件、及注册表
## 题目环境4
rdp  192.26.3.175  3389        用户名:Administrator       
## 操作内容

![](media/image22.png)

![](media/image23.png)

![](media/image24.png)
![](media/image25.png)


# 工业生产数据窃密
仿真器PLC经常存在非组态软件访问的情况，请检查读点位所用hex报文和对应具体组态工程画面位置文字作为flag提交，如读取报文为0300001f02f08032010000031a000e00000401120a10020002000083005dc0,响应报文为0300001b02f08032030000031a0002000600000401ff0400100000，工程中位置为皮带传送，则flag为flag{皮带传送-0300001f02f08032010000031a000e00000401120a10020002000083005dc0}

## 题目环境4
rdp  192.26.3.175  3389        用户名:Administrator       
## 操作内容

# Scada组态软件加固
黑客拿下工程师站管理员权限，未设置权限控制的Scada的组态软件可在工艺监控画面上随意操作。请对Scada系统（非操作系统）进行加固。加固完成后应当保持scada系统运行正常，请完成如下全部配置后举手示意，**此题由裁判人工判分**。
1.对Scada系统的工程文件进行加密
2.创建用户，设置强登录口令，分配具备的安全区权限。
3.画面的按钮、输入框等需要操作的行为划分安全区（即限制某个用户可以操作）。
## 题目环境4

rdp  192.26.3.175  3389        用户名:Administrator       
## 操作内容
![](media/image26.png)

![](media/image27.png)

![](media/image28.png)


# 系统关键信息隐藏
管理员怀疑操作系统中存在后门对网络信息及进程进行了隐藏，请定位具体隐藏进程名称，如隐藏进程名称为MySQL,则flag提交格式为: flag{MySQL}

## 题目环境5
ssh  192.26.3.40  22        用户名:root       
## 操作内容
![](media/image29.png)
![](media/image30.png)
# 智造应用框架漏洞
综管平台WEB应用存在框架漏洞，结合攻击行为，保证业务正常运行情况下进行加固，并完成内存马的清理工作
## 题目环境5
ssh  192.26.3.40  22        用户名:root       
## 操作内容


# 设备管理临时修复
结合日志和监测攻击行为，针对WEB应用存在的漏洞进行防护加固，具体加固方式在满足竞赛规则条件下不做额外限制

## 题目环境6

rdp  192.26.2.246  3389        用户名:Administrator     
![](media/image31.png)

![](media/image32.png)
![](media/image33.png)

![](media/image34.png)
  
# 设备管理Webshell
设备管理系统WEB应用存在后门代码，请分析定位后并完成清理工作
## 题目环境6
rdp  192.26.2.246  3389        用户名:Administrator      

# 拓扑图
![](media/image35.png)

![](media/image36.png)

