#!/bin/bash

# 前言
# 为什么要自己搭邮服发信 
# 第一,灵活方便,随用随搭,一旦上了有价值的目标之后就立即销毁,相对目标自身的实际价值来讲,这个成本并不算非常高,只有在用的时候才把邮件服务开起来,不用的时候就关掉
# 第二,全程可控,用各种第三方邮服去代发的问题就在于你根本不知道别人到底在后端做了啥(但你做了啥,别人却看的一清二楚),当然,不仅仅只是这一个方面
# 第三,把这个再稍微延申扩展下,比如,写个漂亮的GUI套上,转身一变其实就是个很好的开源钓鱼平台
# 等等等等等等....不再赘述

# 大致部署过程如下
# 首先,去申请一个近似域名(即跟目标相似度最高的域名,不建议用伪造,通常都会直接被各种邮件网关拦掉),然后再到域名里去添加好如下记录
# 一条名为mail的A记录,指向 vpsip
# 一条MX记录 @ ,指向 mail.yourdomain.com,优先级1
# 一条名为smtp的CNAME记录,指向mail.yourdomain.com
# 一条名为pop3的CNAME记录,指向mail.yourdomain.com
# 一条名为imap的CNAME记录,指向mail.yourdomain.com
# 一条txt记录, @ 值为 v=spf1 a mx -all

# 接着,去自己的VPS上执行一些初始操作
# passwd												# 改密码
# echo "mail.mwr-center.com" > /etc/hostname  			# 修改机器名	
# echo 104.224.146.167 mail.mwr-center.com >> /etc/hosts     	# 修改解析
# shutdown -r now   									# 最后,重启系统使之生效
# 之后,等上大概个半小时左右(其实可能要不了这么久),主要是为了等域名解析记录生效,之后再开始执行该脚本

# 详细确认您的VPS厂商是否允许所有邮件服务端口正常通信(安全组是否已放开相关邮件服务端口)
# 很多厂商为了避免vps被用来滥发垃圾邮件而导致ip被标记,默认会直接禁掉25端口通信
# 最后,再仔细确认下自己的VPS IP和域名曾经是否进过各种黑名单,比如,曾经被人用来做过C2,RAT域名,发过垃圾邮件 等等等...这些问题后续都会严重影响邮件的实际送达率

# 脚本最终部署的环境,包括 Certbot + Postfix + Dovecot + Opendkim ...
# 时间仓促,脚本写的并不是很精细,有空的话,可以把所有的前期检测及服务起停动作都可以写成函数进行调用,方便一些


if [ $# -eq 0 ] ||  [ $# != 3 ] ;then
	echo -e "\n#####################################################################################"
	echo "#								                    #"
	echo "#     发信平台一键部署脚本 (Tested on Ubuntu 16.04 LTS 64bit)	                    #"
	echo "#  			       					                    #"
	echo "# 					      Author: klion 		            #"
	echo "#  			       		      2020.5.8		                    #"
	echo "#                       					                    #"
	echo "#####################################################################################"
	echo "#          							                    #"
	echo "#     Usage:            					                    #"
	echo "#        /root/MailSrv_Autoinstall.sh  你的VPSIP 你的域名 接收测试邮件的邮箱(随意)  #"
	echo "#        /root/MailSrv_Autoinstall.sh  \"13.29.117.68\" \"happy.com\" \"admin@boy.org\"   #"
	echo "#                       					                    #"
	echo -e "#####################################################################################\n"
    exit
fi

vpsip=$1
yourdomain=$2
yourmail=$3

# 判断当前用户权限
if [ `id -u` -ne 0 ];then
	echo -e "\n\033[33m请以 root 权限 运行该脚本! \033[0m\n"
	exit
fi

# 安装基础工具及相关依赖
ping github.com -c 5 >/dev/null 2>&1
if [ $? -eq 0 ];then
	echo -e "\n\e[92m请仔细确认域名的相关解析记录都已事先添加好且可正常解析 ! \e[0m"
	sleep 2
	echo -e "\e[94m网络正常,开始安装基础工具及相关依赖,请稍后...\e[0m"
	sleep 2
	apt-get update >/dev/null 2>&1
	apt-get install gcc gdb make cmake socat telnet tree tcpdump iptraf iftop nethogs lrzsz git unzip curl wget vim python2.7 python2.7-dev -y >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo -e "\e[94m相关工具及依赖库已全部安装成功,准备安装 Postfix,请稍后...\e[0m\n"
		sleep 2
	else
		echo -e "工具安装失败,请检查后重试!"
		exit
	fi
else
	echo -e "网络连接似乎有问题,请检查后重试!"
	exit
fi

echo -e "=========================================================================\n"

# 安装配置nc
which "add-apt-repository" > /dev/null
if [ $? -eq 0 ];then
	add-apt-repository universe >/dev/null 2>&1
	if [ $? -eq 0 ];then
		apt-get install netcat-traditional -y >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo -e "\e[94mNc 安装成功 ! \e[0m"
			update-alternatives --set nc /bin/nc.traditional >/dev/null 2>&1
			if [ $? -eq 0 ];then
				echo -e "\e[94mNc 配置成功 ! \e[0m\n"
				sleep 1
			else
				echo -e "Nc 配置失败,请检查后重试!"
				exit
			fi
		else
			echo -e "Nc 安装失败,请检查后重试!"
			exit
		fi
	else
		echo -e "PPA 添加失败,请检查后重试!"
		exit
	fi
else
	echo -e "add-apt-repository 命令不存在,请尝试安装后重试!"
	exit
fi


# 判断当前系统中是否有占用邮件服务端口的进程
arr=(25 110 143 465 587 993 995 8891)
for(( i=0;i<${#arr[@]};i++))
do
	nc -z -v -w 2 127.0.0.1 ${arr[i]} >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo -e "${arr[i]} 端口被占用,请kill掉相关进程后重试!"
		exit
	fi
done;

# 检查当前系统之前是否已安装过邮件服务
if [ -d "/etc/postfix/" ] ; then
	echo -e "Postfix 已安装,为尽可能避免后续出问题,请尝试卸载后再重新安装!"
	exit
	if [ -d "/etc/dovecot/" ] ;then
		echo -e "Dovecot 已安装,为尽可能避免后续出问题,请尝试卸载后再重新安装!"
		exit
		if [ -d "/etc/letsencrypt/" ] ;then
			echo -e "Certbot 可能已经安装过,为尽可能避免后续出问题,请尝试删除证书目录后再重新申请!"
			exit
		fi
	fi
fi

echo -e "=========================================================================\n"

# 安装postfix
which "debconf-set-selections" > /dev/null
if [ $? -eq 0 ];then
	echo -e "\e[94m开始安装Postfix,请稍后...\e[0m"
	debconf-set-selections <<< "postfix postfix/mailname string mail.${yourdomain}"
	debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
	if [ $? -eq 0 ];then
		apt-get install --assume-yes postfix -y >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo -e "\e[94mPostfix安装成功,准备安装Certbot,请稍后...\e[0m\n"
			sleep 2
		else
			echo -e "Postfix安装失败,请检查后重试..."
			exit
		fi
	else
		echo -e "Debconf Set 失败,请检查后重试..."
		exit
	fi
else
	echo -e "Debconf 不存在,请手工安装后重试..."
	exit
fi

echo -e "=========================================================================\n"

# 安装certbot,申请免费证书,此处务必要注意,同一个域名不能申请次数太多,貌似三次就不给了
apt-get install certbot -y >/dev/null 2>&1
if [ $? -eq 0 ];then
	echo -e "\e[94mCertbot安装成功,准备申请证书\e[0m"
	certbot certonly --non-interactive --standalone -d mail.${yourdomain} --agree-tos -m ad@svr.org >/dev/null 2>&1
	if [ $? -eq 0 ] && [ -d "/etc/letsencrypt/live/mail.${yourdomain}/" ]; then
		echo -e "\e[94m证书申请成功,开始配置Postfix, 请稍后...\e[0m\n"
	else
		echo -e "证书申请失败,请检查后重试..."
		exit
	fi
else
	echo -e "Certbot安装失败,请检查后重试..."
	exit
fi

echo -e "=========================================================================\n"

# 配置 Postfix
cat << EOF > /etc/postfix/main.cf
myhostname = mail.${yourdomain}
myorigin = $mydomain
mydomain = ${yourdomain}
mydestination = $mydomain, $myhostname, mail.${yourdomain}, localhost.${yourdomain}, , localhost
smtpd_banner = $myhostname ESMTP $mail_name (TmpSrv)
home_mailbox = Maildir/
mynetworks = 0.0.0.0 ${vpsip} 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
biff = no
append_dot_mydomain = no
readme_directory = no
smtpd_tls_cert_file=/etc/letsencrypt/live/mail.${yourdomain}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/mail.${yourdomain}/privkey.pem
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_local_domain =
smtpd_sasl_security_options = noanonymous
broken_sasl_auth_clients = yes
smtpd_sasl_auth_enable = yes
smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtp_tls_note_starttls_offer = yes
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891
milter_protocol = 2
milter_default_action = accept
disable_vrfy_command = yes
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = mail.${yourdomain}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
relayhost = 
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
EOF
if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/postfix/main.cf 配置修改成功 ! \e[0m"
	sleep 2
else
	echo -e "/etc/postfix/main.cf 配置修改失败,请检查后重试... !"
	exit
fi

cat << EOF > /etc/postfix/master.cf
smtp      inet  n       -       y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix	-	n	n	-	2	pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  ${nexthop} ${user}
EOF
if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/postfix/master.cf 配置修改成功, 准备安装Dovecot, 请稍后...\e[0m\n"
	sleep 2
else
	echo -e "/etc/postfix/master.cf 配置修改失败,请检查后重试...!\n"
	exit
fi

echo -e "=========================================================================\n"

# 安装 Dovecot
apt-get install dovecot-core dovecot-imapd dovecot-pop3d -y >/dev/null 2>&1
if [ $? -eq 0 ];then
	echo -e "\e[94mDovecot安装成功,准备配置Dovecot,请稍后...\e[0m"
	sleep 2
else
	echo -e "Dovecot安装失败,请检查后重试..."
	exit
fi

cat << EOF > /etc/dovecot/conf.d/10-master.conf
service imap-login {
  inet_listener imap {
  }
  inet_listener imaps {
  }
}
service pop3-login {
  inet_listener pop3 {
  }
  inet_listener pop3s {
  }
}
service lmtp {
  unix_listener lmtp {
  }
}
service imap {
}
service pop3 {
}
service auth {
  unix_listener auth-userdb {
  }
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
}
service auth-worker {
}
service dict {
  unix_listener dict {
  }
}
EOF
if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/dovecot/conf.d/10-master.conf 配置修改成功 ! \e[0m"
	sleep 2
else
	echo -e "/etc/dovecot/conf.d/10-master.conf 配置修改失败,请检查后重试!"
	exit
fi


cat << EOF > /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login
!include auth-system.conf.ext

# egrep -v '^$|#' /etc/dovecot/conf.d/10-mail.conf
mail_location = maildir:~/Maildir
namespace inbox {
  inbox = yes
}
EOF
if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/dovecot/conf.d/10-auth.conf 配置修改成功 ! \e[0m"
	sleep 2
else
	echo -e "/etc/dovecot/conf.d/10-auth.conf 配置修改失败,请检查后重试!"
	exit
fi

cat << EOF >  /etc/dovecot/conf.d/20-pop3.conf
pop3_uidl_format = %08Xu%08Xv
protocol pop3 {
}
EOF
if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/dovecot/conf.d/20-pop3.conf 配置修改成功 ! \e[0m"
	sleep 2
else
	echo -e "/etc/dovecot/conf.d/20-pop3.conf 配置修改失败,请检查后重试!"
	exit
fi

cat << EOF > /etc/dovecot/conf.d/10-ssl.conf
ssl = yes
ssl_cert = </etc/letsencrypt/live/mail.${yourdomain}/fullchain.pem
ssl_key = </etc/letsencrypt/live/mail.${yourdomain}/privkey.pem
EOF
if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/dovecot/conf.d/10-ssl.conf 配置修改成功 ! \e[0m\n"
	sleep 2
else
	echo -e "/etc/dovecot/conf.d/10-ssl.conf 配置修改失败,请检查后重试!"
	exit
fi

echo -e "=========================================================================\n"

# 安装 Opendkim
apt-get install opendkim opendkim-tools -y >/dev/null 2>&1
if [ $? -eq 0 ];then
	echo -e "\e[94mOpendkim 安装成功 ! \e[0m"
	sleep 2
else
	echo -e "Opendkim 安装失败,请检查后重试!"
	exit
fi

mkdir -p /var/run/opendkim
if [ -d "/var/run/opendkim/" ]; then
	echo -e "\e[94m/var/run/opendkim/ 目录创建成功 ! \e[0m"
	sleep 2
	mkdir /etc/opendkim
	if [ -d "/etc/opendkim" ]; then
		echo -e "\e[94m/etc/opendkim 目录创建成功! 准备配置Opendkim ,请稍后...\e[0m"
		chown -R opendkim:opendkim /var/run/opendkim
		sleep 2
	else
		echo -e "/etc/opendkim 目录创建失败,请检查后重试!"
		exit
	fi
else
	echo -e "/var/run/opendkim/ 目录创建失败,请检查后重试!"
	exit
fi

cat << EOF > /etc/opendkim.conf
Syslog			yes
UMask			002
Domain			${yourdomain}
Canonicalization	relaxed/relaxed
Mode			sv
OversignHeaders		From
TrustAnchorFile       /usr/share/dns/root.key
ExternalIgnoreList refile:/etc/opendkim/TrustedHosts
InternalHosts refile:/etc/opendkim/TrustedHosts
KeyTable refile:/etc/opendkim/KeyTable
LogWhy Yes
PidFile /var/run/opendkim/opendkim.pid
SigningTable refile:/etc/opendkim/SigningTable
Socket inet:8891@127.0.0.1
SyslogSuccess Yes
TemporaryDirectory /var/tmp
UserID opendkim:opendkim
EOF

if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/opendkim.conf 配置修改成功 ! \e[0m"
	sleep 2
else
	echo -e "/etc/opendkim.conf 配置修改失败,请检查后重试!"
	exit
fi

mkdir /etc/opendkim/keys/${yourdomain} -p
if [ -d "/etc/opendkim/keys/${yourdomain}" ]; then
	echo -e "\e[94m/etc/opendkim/keys/${yourdomain} 目录创建成功 ! \e[0m"
	sleep 2
else
	echo -e "/etc/opendkim/keys/${yourdomain} 目录创建失败! 请检查后重试!"
	exit
fi

opendkim-genkey -D /etc/opendkim/keys/${yourdomain}/ -d ${yourdomain} -s default
if [ $? -eq 0 ];then
	echo -e "\e[94mopendkim-genkey 生成成功! \e[0m"
	echo "default._domainkey.${yourdomain} ${yourdomain}:default:/etc/opendkim/keys/${yourdomain}/default.private" > /etc/opendkim/KeyTable
	echo "*@${yourdomain} default._domainkey.${yourdomain}" > /etc/opendkim/SigningTable
	echo "127.0.0.1" > /etc/opendkim/TrustedHosts
	sleep 2
else
	echo -e "opendkim-genkey 生成失败, 请检查后重试!"
fi

cat << EOF > /etc/default/opendkim
SOCKET="local:/var/run/opendkim/opendkim.sock"
SOCKET="inet:8891@127.0.0.1"
EOF
if [ $? -eq 0 ];then
	echo -e "\e[94m/etc/default/opendkim 配置修改成功 ! \e[0m\n"
	chown -R opendkim:opendkim /etc/opendkim/keys/${yourdomain}
	sleep 2
else
	echo -e "/etc/default/opendkim 配置修改失败,请检查后重试!"
	exit
fi

echo -e "=========================================================================\n"

# 启动邮件服务
systemctl restart postfix.service
if [ $? -eq 0 ];then
	echo -e "\e[94mPostfix 服务启动成功 ! \e[0m"
	sleep 2
	systemctl restart dovecot.service
	if [ $? -eq 0 ];then
		echo -e "\e[94mDovecot 服务启动成功 ! \e[0m"
		sleep 2
		systemctl restart opendkim.service
		if [ $? -eq 0 ];then
			echo -e "\e[94mOpendkim 服务启动成功 ! \e[0m\n"
			sleep 2
		else
			echo -e "Opendkim 服务启动失败! 请检查后重试...!"
			exit
		fi
	else
		echo -e "Dovecot 服务启动失败! 请检查后重试...!"
		exit
	fi
else
	echo -e "Postfix 服务启动失败! 请检查后重试...!"
	exit
fi

echo -e "=========================================================================\n"

# 握手测试
openssl s_client -showcerts -connect mail.${yourdomain}:465 <<< 'Q' >/dev/null 2>&1
if [ $? -eq 0 ];then
	echo -e "\e[94m465端口正常握手 ! \e[0m"
	sleep 2
	openssl s_client -showcerts -connect mail.${yourdomain}:993 <<< 'Q' >/dev/null 2>&1
	if [ $? -eq 0 ];then
		echo -e "\e[94m993端口正常握手 ! \e[0m"
		sleep 2
		openssl s_client -showcerts -connect mail.${yourdomain}:995 <<< 'Q' >/dev/null 2>&1
		if [ $? -eq 0 ];then
			echo -e "\e[94m995端口正常握手 ! \e[0m"
			sleep 2
		else
			echo -e "995端口请求正常, 请检查后重试...!"
			exit
		fi
	else
		echo -e "993端口请求, 请检查后重试... !"
		exit
	fi
else
	echo -e "465端口请求异常, 请检查后重试...!"
	exit
fi

if [ -f "/var/log/mail.log" ]; then
	echo -e "\e[94m邮件收发记录日志文件路径: /var/log/mail.log\e[0m\n"
	sleep 2
else
	echo -e "请从头一步步仔细排查所有安装配置选项,而后重试\n"
fi

echo -e "=========================================================================\n"

echo -e "请到自己的域名中添加一个名为 '\033[33m_dmarc\033[0m' 的txt记录,并将如下值写进入"
echo -e "\e[94mv=DMARC1;p=none;rua=mailto:admin@${yourdomain}\e[0m"
sleep 2 && echo

echo -e "请到自己的域名中添加一个名为 '\033[33mdefault._domainkey\033[0m' 的txt记录,之后将如下值写入,此处脚本将等待八分钟后执行,以预留出足够的时间去添加记录"
cat /etc/opendkim/keys/${yourdomain}/default.txt && echo 
sleep 480

echo -e "=========================================================================\n"

# 添加邮箱用户
echo -e "\e[92m开始添加测试邮箱账户\e[0m\n"
id system >/dev/null 2>&1
if [ $? != 0 ];then
	useradd -m system -s /sbin/nologin
	echo -e "\e[94m邮箱账户system 添加成功 ! \e[0m"
	sleep 2
	id admin >/dev/null 2>&1
	if [ $? != 0 ];then
		useradd -m admin -s /sbin/nologin
		echo -e "\e[94m邮箱账户admin 添加成功 ! \e[0m"
		sleep 2
		id manager >/dev/null 2>&1
		if [ $? != 0 ];then
			useradd -m manager -s /sbin/nologin
			echo -e "\e[94m邮箱账户manager 添加成功 ! \e[0m\n"
			sleep 2
		else
			echo -e "邮箱账户manager 添加失败!"
			exit
		fi
	else
		echo -e "邮箱账户admin 添加失败!"
		exit
	fi
else
	echo -e "邮箱账户system 添加失败!"
	exit
fi

echo -e "=========================================================================\n"

# 注意,实际中也不建议去伪造(较大几率被拦截),用近似域名会相对好很多,此处的邮件内容是随便写的,实际用的时候替换下即可
cat << EOF >  mails.txt

helo client
MAIL FROM:<admin@${yourdomain}>
RCPT TO:<${yourmail}>
DATA
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_23428_577824230.1592032872041"
From: =?GBK?B?wLTX1Lvw0Me1xM7KuvI=?= <admin@${yourdomain}>
To: ${yourmail} <${yourmail}>
Subject: =?GBK?B?t6LQxbf+zvHG97Cy17Cy4srU08q8/g==?=

------=_Part_23428_577824230.1592032872041
Content-Type: text/plain; charset=GBK
Content-Transfer-Encoding: base64

t6LQxbf+zvHG99LRsLLXsLPJuaajrM3mtcS/qtDEICE=
------=_Part_23428_577824230.1592032872041
Content-Type: text/html; charset=GBK
Content-Transfer-Encoding: base64

PGRpdiBzdHlsZT0ibGluZS1oZWlnaHQ6MS43O2NvbG9yOiMwMDAwMDA7Zm9udC1zaXplOjE0cHg7
Zm9udC1mYW1pbHk6QXJpYWwiPjxwIHN0eWxlPSJtYXJnaW46MDsiPrei0MW3/s7xxvfS0bCy17Cz
ybmmo6zN5rXEv6rQxCAhPC9wPjwvZGl2Pg==
------=_Part_23428_577824230.1592032872041--
.
quit
EOF

cat mails.txt | /bin/nc -vv mail.${yourdomain} 25 >/dev/null 2>&1
if [ $? -eq 0 ];then
	# 如果收件箱找不到邮件,请到垃圾箱看看,一般前面配置没问题,域名/ip没进黑名单的情况下,几乎是不会进垃圾箱的
	echo -e "\e[94m测试邮件已发送成功,请前往 ${yourmail} 邮箱收件箱查看 ! \e[0m"
	echo -e "\e[94m恭喜! 至此,发信平台已全部部署完成 ! \e[0m\n"
else
	echo -e "测试邮件发送失败,请从头逐步仔细核对您的所有邮件服务配置后重试 ! \n"
	exit
fi

rm -fr mails.txt

# 一键停止所有邮件服务
# systemctl stop postfix.service
# if [ $? -eq 0 ];then
# 	echo -e "\e[94mPostfix 服务已停止 ! \e[0m"
# 	sleep 3
# 	systemctl stop dovecot.service
# 	if [ $? -eq 0 ];then
# 		echo -e "\e[94mDovecot 服务已停止! \e[0m"
# 		sleep 3
# 		systemctl stop opendkim.service
# 		if [ $? -eq 0 ];then
# 			echo -e "\e[94mOpendkim 服务已停止! \e[0m\n"
# 			sleep 3
# 		else
# 			echo -e "Opendkim 服务关闭失败! 请检查后重试...!"
# 			exit
# 		fi
# 	else
# 		echo -e "Dovecot 服务关闭失败! 请检查后重试...!"
# 		exit
# 	fi
# else
# 	echo -e "Postfix 服务关闭失败! 请检查后重试...!"
# 	exit
# fi


#!/bin/bash
# 批量延迟发信
# while read -r line
# do
#  	sed -i "s/Targetmail/$line/g" mail.txt
#  	sleep 2
#  	cat mail.txt | /bin/nc -vv mail.yourdomain.com 25 >/dev/null 2>&1
#  	if [ $? -eq 0 ];then
#		echo -e "$line 发送成功...."
#  	else
#		echo -e "$line 发送失败...."
#		exit
#  	fi
# 	sleep 2
# 	sed -i "s/$line/Targetmail/g" mail.txt
# done < targetmails.txt

