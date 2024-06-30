
**能源协会****个人****决赛****赛题和****W****rite****U****p**

# 这是一个秘密
通过流量分析，发现使用s7comm协议，在协议中发现了两个数据包存在read结果，将两个包的数据结果进行拼接，使用base64解码获取flag

## 赛题附件
/决赛个人赛赛题附件/01这是一个密码.zip
## 操作内容

![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image1.png)
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image2.png)
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image3.png)



## flag
flag{alwaysforward!!}
# win内存取证3
分析win内存镜像，电脑中有一张记录flag的图片，请找出来，并获得flag,flag格式为flag{xxx}
## 赛题附件
/决赛个人赛赛题附件/02win内存取证3-mem.7z （文件超大，见网盘分享）
## 操作内容
直接使用volatility进行分析，filescan，发现桌面存在以777.png文件
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image4.png)**
提取777.png文件
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image5.png)**
获得flag


## flag
flag{2shygsbnajwjji}
# 104协议
分析目标流量中的工控流量，并从流量中识别其中的flag，提交格式：flag{XXXXXXXX}
## 赛题附件
/决赛个人赛赛题附件/03_104.zip
## 操作内容
结合“这是一个秘密”题目的base64特征，以及104协议特征，提取base64，解码即可。
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image6.png)**

**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image7.png)**



## flag
flag{2024nyaqgfzsl}

# 代理流量

有一台Web应用服务器发现被攻击者获取了权限，并对内网做了扫描。请尝试分析攻击过程，并找到代理工具的回连地址及端口，提交地址端口，示意：10.10.10.10:8080，提交flag为flag{10.10.10.10:8080},flag格式flag{xxx}
## 赛题附件
/决赛个人赛赛题附件/ 04代理流量.zip
## 操作内容
查看http请求和相应，排除干扰
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image8.png)**

结合题目，发现关键代码HTTP交互流量，其中有个 frpc.ini文件，通过解析代码，找到关键参数。
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image9.png)**
unhex解码即可。
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image10.png)**

## flag
flag{192.168.157.111:8888}

# APT窃密事件溯源

某单位遭遇威胁组织攻击，威胁组织对攻陷的主机进行了信息收集并窃取机密信息，安防设备捕获到攻击流量（hack.pcap），结合提供的开源APT分析报告，研判发起本次攻击事件的APT组织窃取的文件。flag格式为flag{}

## 赛题附件
/决赛个人赛赛题附件/05APT窃密事件溯源-APT窃密.zip  （文件超大，见网盘分享）
## 操作内容
直接查看相关HTTP通信内容，或者导出http对象挨个排查
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image11.png)
排除干扰，多次尝试，即可获得flag
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image12.png)**
C:\\20211101111621_888888888.txt"
Content-Type: text/plain

8888888888888888888888888888888888
7777777777777777777777777777777
66666666666666
55555555555
44444444444

C:\\20211101111734_error1log.txt
20211101111621_C:\\Users\\wdr\\Desktop\\test\\888888888.txt||20211101110626_C:\\Users\\wdr\\Desktop\\test\\1.txt||
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image13.png)**

## flag
flag{C:\\Users\\wdr\\Desktop\\test\\888888888.txt}
# modbus
先运行服务器再运行客户端，产生流量。找到流量中的flag
## 赛题附件
/决赛个人赛赛题附件/06modbus.zip 
## 操作内容
运行客户端和服务端
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image14.png)
发现收到回复，125， 即flag的最后的花括号 { 的Ascii值，推测是对flag倒序逐个字符发送或接受。 
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image15.png)**
多次运行，触发程序bug，发现监听的地址和端口
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image16.png)**
发现server监听在5502端口
通过wireshark抓取本地环回地址流量，找到5502端口的流量
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image17.png)**
追踪流，即可找到flag

## flag
flag{sgcc_modbus_hack}

# 寻找矿池地址

请分析服务器(root/Root@123)被挖矿的地址连接池，找到域名和端口，flag为flag{域名:端口},flag格式为flag{xxxx}
## 赛题附件
在线环境，无附件
## 操作内容
查看网络链接监听情况，未发现异常链接，只有很多数据库链接。
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image18.png)

查看进程树，发现redis进程，推测是利用redis进行的漏洞利用

**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image19.png)**
排查redis配置文件，发现一个仿冒百度的一个域名，尝试提交，通过
**![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image20.png)**

### 解法2
sshfs 登录挂载后，使用火绒进行病毒查杀，发现异常。
## flag
flag{www.baiiduu.com:3333}

# 工控流量分析二
请你帮助小刘分析流量包，黑客在PLC中写入了flag。flag 形式如下： flag{xxxx}
## 赛题附件
/决赛个人赛赛题附件/08工控流量分析二.zip
## 操作内容

tshark.exe -r sample.pcap  -Y "modbus" -T fields -e modbus.regval_uint16 &gt; .modbus_register_values.txt


查看modbus流量，发现寄存器中存在较多的值
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image21.png)

提取modbus数据包 
结合 “黑客在PLC中写入了flag” 写入的关键字，发现PNG图片的相关bin文件信息
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image22.png)
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image23.png)

![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image24.png)
对单个IP的写操作流进行重组拼接，PNG图片无法正常显示。

![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image25.png)
发现 Register Number存在一定的升序，则将不同IP和PLC的所有写操作都提取出来

![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image26.png)

提取寄存器的数据，
结合寄存器的数据包的特征，32个byte，每个数都是双字节。编写py脚本，按照 Register Number的顺序，写入一个文件。

import struct
rstdic = {}
with open (r'grepdata3.txt', 'r') as f:
    for l in f:
        l = l.strip()
        l2 = l.split(';')
        # print(l2[0], l2[1])
        tmpd = {int(key): value for key, value in zip(l2[0].split(','),  l2[1].split(','))}
        rstdic.update(tmpd)

with open(r'.rst.bin', 'wb') as rstf:
    for key, value in sorted(rstdic.items()):
        num = int(value)
        tb = struct.pack('&gt;H', num)
        rstf.write(tb)

在文件中发现3个PNG图片头，挨个拆分，发现第三个PNG图片内存在flag信息。
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image27.png)
## flag
flag{Welcome_To_thE_coMPEtition}
## 感谢
[https://www.bilibili.com/video/BV15r421F7Ma/](https://www.bilibili.com/video/BV15r421F7Ma/)

# data-encry

编译文件，执行文件，获取flag,flag格式flag{xxxx}
## 赛题附件
/决赛个人赛赛题附件/09_data-encry.rar
## 操作内容
.ll 文件是LLVM Intermediate Representation（LLVM IR）的纯文本形式，它是编译过程中的一个中间步骤，介于源代码和机器码之间。要编译这样的文件，你需要使用LLVM工具链中的相关工具，特别是 llc（LLVM Compiler）来将其转换为目标平台的汇编代码或机器码。
### 解法1（补充解法）
阅读查看该文件。发现内置变量字符串：
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image28.png)

结合题说明，只需要执行，无需用户输入，则根据字符的规律  kqfl{}  -&gt;  flag{}  判断出来是简单的位移密码，位移为5.
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image29.png)
获得flag：
flag{sgcc-yes-llvm}
### 解法2（来自网络，未成功）
流程：
1、安装LLVM工具链
2、使用llc将.ll转换为汇编代码
3、编译汇编代码为对象文件
4、接对象文件生成可执行文件

llc -filetype=asm code.ll -o code.s
as code.s -o code.o   未成功


用 clang 进行编译，输入以下命令：
llvm-as input.ll -o output.bc
llc output.bc -o output.s
clang output.s -o executable   未成功

逆向 把明文信息存储在 v8 中 用函数 decrypt 进行解密![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image30.png)
把所有字符减5，得到flag
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image31.png)



## flag
flag{sgcc-yes-llvm}
# 损坏的图片
黑客将系统锁死后，系统上多了一个损坏的图片，据安全专家评估，图片可能隐含了解密系统的密钥，找到损坏图片中隐藏的flag解锁系统吧。
## 赛题附件
/决赛个人赛赛题附件/10损坏的图片.zip
## 操作内容



文件头存在异常，修复文件头，即可打开图片：
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image32.png)
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image33.png)

修复后，修改正确的后缀 jpg，可以打开。
结合经验，使用stegdetect 进行图片检测，发现jphide隐写

![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image34.png)

多次尝试，没找到密码，放弃。
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image35.png)

文件末尾有冗余的数据，还未发挥作用。
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image36.png)

将前面的图片，使用图搜图（后续补充），是个喜剧组合名字叫monty Python
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image37.png)
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image38.png)
额外数据的 以  80 04 开头，是py序列化后的开头标识。
编写脚本，将其反序列化：
结果如下：
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image39.png)

疑似是坐标的数组，主数组内，每个元素是一个数组，数组内的坐标数量不同，都是从小到大的顺序，疑似是控制台字符画，按行输出 \* 号

使用脚本，打印字符画，获得flag
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image40.png)

其他战队的绘制：
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image41.jpeg)
## flag
flag{2024nyjy777\*}

# NYWL2024002
附件是一个PLC项目文件以及相关的截图，请分析里面的PLC程序，求MD0的值为多少时可使MD4的值为9498.563，flag为MD0的值，flag格式为flag{xxx},例如MD0的值是123，那么flag就是flag{123}
## 赛题附件
/决赛个人赛赛题附件/11_NYWL2024002.zip
## 操作内容(赛后补充)




## flag







# 失窃的MP4文件(未解答)

已知黑客入侵某内部系统后，使用自定义的协议格式回传窃取的高价值mp4文件，请针对目标流量还原被窃取文件，找到flag标识，格式：flag{XXXX_XXXX_XXXX_XXXX}

## 赛题附件
/决赛个人赛赛题附件/12失窃的MP4文件-file2.pcap.zip  （文件超大，见网盘分享）
## 操作内容
发现流量只有 tcp和 sslv2两类，追踪tcp流发现，存在一定规律的交互
![](https://github.com/i1ikey0u/CTF_2024NYXH_YS-JS/raw/main/prs_media/image42.png)


## flag



# 超大赛题附件
https://www.alipan.com/s/KNai6nugf3P
提取码: 80gw

已包含所有超过github大小限制的赛题，无需重复下载

# 感谢：

油气组-铁人10队， 发电组-SQM  电网组-三星堆凤凰神树 等微信群类的队伍
大赛微信群内分享的相关内容及链接：
链接：https://pan.baidu.com/s/1R2FZEQm_pmQM1mRIGYMxww?pwd=eqp4 
提取码：eqp4 

[https://www.cnblogs.com/Mercurysur/p/13324911.html](https://www.cnblogs.com/Mercurysur/p/13324911.html) 


