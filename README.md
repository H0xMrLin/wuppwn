Help:<br />
+==================================================================================+<br />
 WupPwn.py<br />
Python3 WupPwn.py HarFileName <br />
[pd=filedName:Value|pd=filedName:$DicFileName] [if=responseContent] [ifnot=responseContent] [ifend=responseContent] [out=OutFileName]<br />
 HarFileName har文件名 谷歌或Firefox web抓包保存为har entries下可以看到所有请求的地址及参数 可以删除一些不必要的请求让程序更快运行<br />
 pd 设置上传数据 字段名:值 或者 字段名:字典<br />
 if=xxx 如果内容是xxx那就记录 可多个用||隔开<br />
 ifnot=xxx 如果内容不是xxx哪就记录 可多个用||隔开<br />
 ifend=xxx 如果内容是xxx那就记录并结束 可多个用||隔开<br />
 out=xx.txt 输出记录到文件<br />
 see=on|off 查看每次尝试破解响应<br />
 Current request method have: GET/POST<br />
 *且目前不支持http请求头带 RFC 标识 (RFC-eg: ':method':'POST')可以检查是否有<br />
 md5=XXX 将 指定字段名的值进行md5加密再暴力破解 一般=password||passwd||pwd ...<br />
 th=5 设置5个线程同时运行<br />
 版本警告:<br />
 《!》: 切勿用作违法使用，仅供渗透测试，如非法使用该工具与作者无关。 Makerby:Pwn0_+x_X<br />
+=============================================================================+<br />
