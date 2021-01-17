#!/bin/sh

if [ ! -d "etc" ]; then
  mkdir etc/
  cd etc/ || exit

cat > raok.cfg <<'endmsg'
{
    "settings" : {
        "hosts": {
            "127.0.0.1": {
            "secret": "radpass"
            },
            "127.0.0.2": {
            "secret": "radpass"
            }
        },
        "acct": {
            "host": "127.0.0.1",
            "secret": "radpass"
        },
        "redis": {
            "host": "127.0.0.1",
            "port": 6379
        }
    },
    "users" : {
    }
}
endmsg

cat > raok-demo.cfg <<'endmsg'
{
    "settings" : {
        "hosts": {
            "127.0.0.1": {
            "secret": "radpass"
            },
            "192.168.122.40": {
            "secret": "radpass"
            },
            "192.168.122.1": {
            "secret": "radpass"
            },
            "192.168.122.2": {
            "secret": "radpass"
            }
        },
        "acct": {
            "host": "127.0.0.1",
            "secret": "radpass"
        },
        "redis": {
            "host": "127.0.0.1",
            "port": 6379
        }
    },
    "users" : {
        "default": {
            "Auth": {
                "Fortinet-Group-Name": [ "GROUP", "RAD-DEFAULT" ]
            },
            "Settings": {
                "Delay": 0
            }
        },
        "rasta": {
            "Auth": {
                "Framed-IP-Address": "10.33.33.32",
                "Fortinet-Group-Name": "RAD-GROUP1"
            }
        },
        "user": {
            "Access": false,
            "Auth": {
                "Framed-IP-Address": "1.3.3.3",
                "Fortinet-Group-Name": "RAD-DENIED"
            }
        },
        "chal": {
            "Challenge" : "Please enter your birthdate",
            "Auth": {
                "Framed-IP-Address": "10.33.33.33",
                "Class": "RAD-GRP"
            }
        },
        "chalupa": {
            "Challenge" : "FIRST:SECOND",
            "Auth": {
                "Framed-IP-Address": "10.33.33.34",
                "Class": "RAD-GRP"
            }
        },
        "nologin": {
	          "Access": false
	      },
        "smithproxy": {
            "Auth": {
                "Smithproxy-Policy": "DropIt"
            }
        },
        "debbie": {
            "Auth": {
                "Password": "DebbieIsHero",
                "Framed-IP-Address": "10.33.33.32",
                "Fortinet-Group-Name": "RAD-GROUP1"
            },
            "Acct": {
                "Start": {
                    "NAS-IP-Address": "10.0.0.100",
                    "Framed-IP-Address": "10.0.0.44",
                    "Called-Station-Id": "00-04-5F-00-AF-DF",
                    "NAS-Identifier": "acct-test",
                    "Calling-Station-Id": "00-01-24-80-B3-9C",
                    "Acct-Session-Id" : "debbie-444",
                    "Class": "RAD-VIP",
                    "NAS-Port": 0
                },
                "Interim-Update" : {
                    "Acct-Session-Id" : "debbie-444",
                    "Framed-IP-Address": "10.0.0.33",
                    "Class": "RAD-VIP"
                },
                "Stop": {
                    "Acct-Session-Id" : "debbie-444",
                    "Acct-Input-Octets": 100000,
                    "Acct-Output-Octets": 100000,
                    "Acct-Session-Time": 3600,
                    "Acct-Terminate-Cause": "User-Request"
                }
            }
        }
     }
}
endmsg


cat > dictionary <<'endmsg'
# Version $Id: dictionary,v 1.1.1.1 2002/10/11 12:25:39 wichert Exp $
#
#	This file contains dictionary translations for parsing
#	requests and generating responses.  All transactions are
#	composed of Attribute/Value Pairs.  The value of each attribute
#	is specified as one of 4 data types.  Valid data types are:
#
#	string  - 0-253 octets
#	ipaddr  - 4 octets in network byte order
#	integer - 32 bit value in big endian order (high byte first)
#	date    - 32 bit value in big endian order - seconds since
#					00:00:00 GMT,  Jan.  1,  1970
#
#	FreeRADIUS includes extended data types which are not defined
#	in RFC 2865 or RFC 2866.  These data types are:
#
#	abinary - Ascend's binary filter format.
#	octets  - raw octets, printed and input as hex strings.
#		  e.g.: 0x123456789abcdef
#
#
#	Enumerated values are stored in the user file with dictionary
#	VALUE translations for easy administration.
#
#	Example:
#
#	ATTRIBUTE	  VALUE
#	---------------   -----
#	Framed-Protocol = PPP
#	7		= 1	(integer encoding)
#

#
#	Include compatibility dictionary for older users file. Move this
#	directive to the end of the file if you want to see the old names
#	in the logfiles too.
#
#$INCLUDE dictionary.compat	# compability issues
#$INCLUDE dictionary.acc
#$INCLUDE dictionary.ascend
#$INCLUDE dictionary.bay
#$INCLUDE dictionary.cisco
#$INCLUDE dictionary.livingston
#$INCLUDE dictionary.microsoft
#$INCLUDE dictionary.quintum
#$INCLUDE dictionary.redback
#$INCLUDE dictionary.shasta
#$INCLUDE dictionary.shiva
#$INCLUDE dictionary.tunnel
#$INCLUDE dictionary.usr
#$INCLUDE dictionary.versanet
#$INCLUDE dictionary.erx
#$INCLUDE dictionary.freeradius
#$INCLUDE dictionary.alcatel

#
#	Following are the proper new names. Use these.
#
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	User-Password		2	string
ATTRIBUTE	CHAP-Password		3	octets
ATTRIBUTE	NAS-IP-Address		4	ipaddr
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Service-Type		6	integer
ATTRIBUTE	Framed-Protocol		7	integer
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Framed-IP-Netmask	9	ipaddr
ATTRIBUTE	Framed-Routing		10	integer
ATTRIBUTE	Filter-Id		11	string
ATTRIBUTE	Framed-MTU		12	integer
ATTRIBUTE	Framed-Compression	13	integer
ATTRIBUTE	Login-IP-Host		14	ipaddr
ATTRIBUTE	Login-Service		15	integer
ATTRIBUTE	Login-TCP-Port		16	integer
ATTRIBUTE	Reply-Message		18	string
ATTRIBUTE	Callback-Number		19	string
ATTRIBUTE	Callback-Id		20	string
ATTRIBUTE	Framed-Route		22	string
ATTRIBUTE	Framed-IPX-Network	23	ipaddr
ATTRIBUTE	State			24	octets
ATTRIBUTE	Class			25	octets
ATTRIBUTE	Vendor-Specific		26	octets
ATTRIBUTE	Session-Timeout		27	integer
ATTRIBUTE	Idle-Timeout		28	integer
ATTRIBUTE	Termination-Action	29	integer
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	Proxy-State		33	octets
ATTRIBUTE	Login-LAT-Service	34	string
ATTRIBUTE	Login-LAT-Node		35	string
ATTRIBUTE	Login-LAT-Group		36	octets
ATTRIBUTE	Framed-AppleTalk-Link	37	integer
ATTRIBUTE	Framed-AppleTalk-Network 38	integer
ATTRIBUTE	Framed-AppleTalk-Zone	39	string

ATTRIBUTE	Acct-Status-Type	40	integer
ATTRIBUTE	Acct-Delay-Time		41	integer
ATTRIBUTE	Acct-Input-Octets	42	integer
ATTRIBUTE	Acct-Output-Octets	43	integer
ATTRIBUTE	Acct-Session-Id		44	string
ATTRIBUTE	Acct-Authentic		45	integer
ATTRIBUTE	Acct-Session-Time	46	integer
ATTRIBUTE       Acct-Input-Packets	47	integer
ATTRIBUTE       Acct-Output-Packets	48	integer
ATTRIBUTE	Acct-Terminate-Cause	49	integer
ATTRIBUTE	Acct-Multi-Session-Id	50	string
ATTRIBUTE	Acct-Link-Count		51	integer
ATTRIBUTE	Acct-Input-Gigawords    52      integer
ATTRIBUTE	Acct-Output-Gigawords   53      integer
ATTRIBUTE	Event-Timestamp         55      date

ATTRIBUTE	CHAP-Challenge		60	string
ATTRIBUTE	NAS-Port-Type		61	integer
ATTRIBUTE	Port-Limit		62	integer
ATTRIBUTE	Login-LAT-Port		63	integer

ATTRIBUTE	Acct-Tunnel-Connection	68	string

ATTRIBUTE	ARAP-Password           70      string
ATTRIBUTE	ARAP-Features           71      string
ATTRIBUTE	ARAP-Zone-Access        72      integer
ATTRIBUTE	ARAP-Security           73      integer
ATTRIBUTE	ARAP-Security-Data      74      string
ATTRIBUTE	Password-Retry          75      integer
ATTRIBUTE	Prompt                  76      integer
ATTRIBUTE	Connect-Info		77	string
ATTRIBUTE	Configuration-Token	78	string
ATTRIBUTE	EAP-Message		79	string
ATTRIBUTE	Message-Authenticator	80	octets
ATTRIBUTE	ARAP-Challenge-Response	84	string	# 10 octets
ATTRIBUTE	Acct-Interim-Interval   85      integer
ATTRIBUTE	NAS-Port-Id		87	string
ATTRIBUTE	Framed-Pool		88	string
ATTRIBUTE	NAS-IPv6-Address	95	octets	# really IPv6
ATTRIBUTE	Framed-Interface-Id	96	octets	# 8 octets
ATTRIBUTE	Framed-IPv6-Prefix	97	octets	# stupid format
ATTRIBUTE	Login-IPv6-Host		98	octets	# really IPv6
ATTRIBUTE	Framed-IPv6-Route	99	string
ATTRIBUTE	Framed-IPv6-Pool	100	string

ATTRIBUTE	Digest-Response		206	string
ATTRIBUTE	Digest-Attributes	207	octets	# stupid format

#
#	Experimental Non Protocol Attributes used by Cistron-Radiusd
#

# 	These attributes CAN go in the reply item list.
ATTRIBUTE	Fall-Through		500	integer
ATTRIBUTE	Exec-Program		502	string
ATTRIBUTE	Exec-Program-Wait	503	string

#	These attributes CANNOT go in the reply item list.
ATTRIBUTE	User-Category		1029	string
ATTRIBUTE	Group-Name		1030	string
ATTRIBUTE	Huntgroup-Name		1031	string
ATTRIBUTE	Simultaneous-Use	1034	integer
ATTRIBUTE	Strip-User-Name		1035	integer
ATTRIBUTE	Hint			1040	string
ATTRIBUTE	Pam-Auth		1041	string
ATTRIBUTE	Login-Time		1042	string
ATTRIBUTE	Stripped-User-Name	1043	string
ATTRIBUTE	Current-Time		1044	string
ATTRIBUTE	Realm			1045	string
ATTRIBUTE	No-Such-Attribute	1046	string
ATTRIBUTE	Packet-Type		1047	integer
ATTRIBUTE	Proxy-To-Realm		1048	string
ATTRIBUTE	Replicate-To-Realm	1049	string
ATTRIBUTE	Acct-Session-Start-Time	1050	date
ATTRIBUTE	Acct-Unique-Session-Id  1051	string
ATTRIBUTE	Client-IP-Address	1052	ipaddr
ATTRIBUTE	Ldap-UserDn		1053	string
ATTRIBUTE	NS-MTA-MD5-Password	1054	string
ATTRIBUTE	SQL-User-Name	 	1055	string
ATTRIBUTE	LM-Password		1057	octets
ATTRIBUTE	NT-Password		1058	octets
ATTRIBUTE	SMB-Account-CTRL	1059	integer
ATTRIBUTE	SMB-Account-CTRL-TEXT	1061	string
ATTRIBUTE	User-Profile		1062	string
ATTRIBUTE	Digest-Realm		1063	string
ATTRIBUTE	Digest-Nonce		1064	string
ATTRIBUTE	Digest-Method		1065	string
ATTRIBUTE	Digest-URI		1066	string
ATTRIBUTE	Digest-QOP		1067	string
ATTRIBUTE	Digest-Algorithm	1068	string
ATTRIBUTE	Digest-Body-Digest	1069	string
ATTRIBUTE	Digest-CNonce		1070	string
ATTRIBUTE	Digest-Nonce-Count	1071	string
ATTRIBUTE	Digest-User-Name	1072	string
ATTRIBUTE	Pool-Name		1073	string
ATTRIBUTE	Ldap-Group		1074	string
ATTRIBUTE	Module-Success-Message	1075	string
ATTRIBUTE	Module-Failure-Message	1076	string
#		X99-Fast		1077	integer

#
#	Non-Protocol Attributes
#	These attributes are used internally by the server
#
ATTRIBUTE	Auth-Type		1000	integer
ATTRIBUTE	Menu			1001	string
ATTRIBUTE	Termination-Menu	1002	string
ATTRIBUTE	Prefix			1003	string
ATTRIBUTE	Suffix			1004	string
ATTRIBUTE	Group			1005	string
ATTRIBUTE	Crypt-Password		1006	string
ATTRIBUTE	Connect-Rate		1007	integer
ATTRIBUTE	Add-Prefix		1008	string
ATTRIBUTE	Add-Suffix		1009	string
ATTRIBUTE	Expiration		1010	date
ATTRIBUTE	Autz-Type		1011	integer

#
#	Integer Translations
#

#	User Types

VALUE		Service-Type		Login-User		1
VALUE		Service-Type		Framed-User		2
VALUE		Service-Type		Callback-Login-User	3
VALUE		Service-Type		Callback-Framed-User	4
VALUE		Service-Type		Outbound-User		5
VALUE		Service-Type		Administrative-User	6
VALUE		Service-Type		NAS-Prompt-User		7
VALUE		Service-Type		Authenticate-Only	8
VALUE		Service-Type		Callback-NAS-Prompt	9
VALUE		Service-Type		Call-Check		10
VALUE		Service-Type		Callback-Administrative	11

#	Framed Protocols

VALUE		Framed-Protocol		PPP			1
VALUE		Framed-Protocol		SLIP			2
VALUE		Framed-Protocol		ARAP			3
VALUE		Framed-Protocol		Gandalf-SLML		4
VALUE		Framed-Protocol		Xylogics-IPX-SLIP	5
VALUE		Framed-Protocol		X.75-Synchronous	6

#	Framed Routing Values

VALUE		Framed-Routing		None			0
VALUE		Framed-Routing		Broadcast		1
VALUE		Framed-Routing		Listen			2
VALUE		Framed-Routing		Broadcast-Listen	3

#	Framed Compression Types

VALUE		Framed-Compression	None			0
VALUE		Framed-Compression	Van-Jacobson-TCP-IP	1
VALUE		Framed-Compression	IPX-Header-Compression	2
VALUE		Framed-Compression	Stac-LZS		3

#	Login Services

VALUE		Login-Service		Telnet			0
VALUE		Login-Service		Rlogin			1
VALUE		Login-Service		TCP-Clear		2
VALUE		Login-Service		PortMaster		3
VALUE		Login-Service		LAT			4
VALUE		Login-Service		X25-PAD			5
VALUE		Login-Service		X25-T3POS		6
VALUE		Login-Service		TCP-Clear-Quiet		7

#	Login-TCP-Port		(see /etc/services for more examples)

VALUE		Login-TCP-Port		Telnet			23
VALUE		Login-TCP-Port		Rlogin			513
VALUE		Login-TCP-Port		Rsh			514

#	Status Types

VALUE		Acct-Status-Type	Start			1
VALUE		Acct-Status-Type	Stop			2
VALUE		Acct-Status-Type	Interim-Update		3
VALUE		Acct-Status-Type	Alive			3
VALUE		Acct-Status-Type	Accounting-On		7
VALUE		Acct-Status-Type	Accounting-Off		8
#	RFC 2867 Additional Status-Type Values
VALUE		Acct-Status-Type	Tunnel-Start		9
VALUE		Acct-Status-Type	Tunnel-Stop		10
VALUE		Acct-Status-Type	Tunnel-Reject		11
VALUE		Acct-Status-Type	Tunnel-Link-Start	12
VALUE		Acct-Status-Type	Tunnel-Link-Stop	13
VALUE		Acct-Status-Type	Tunnel-Link-Reject	14

#	Authentication Types

VALUE		Acct-Authentic		RADIUS			1
VALUE		Acct-Authentic		Local			2

#	Termination Options

VALUE		Termination-Action	Default			0
VALUE		Termination-Action	RADIUS-Request		1

#	NAS Port Types

VALUE		NAS-Port-Type		Async			0
VALUE		NAS-Port-Type		Sync			1
VALUE		NAS-Port-Type		ISDN			2
VALUE		NAS-Port-Type		ISDN-V120		3
VALUE		NAS-Port-Type		ISDN-V110		4
VALUE		NAS-Port-Type		Virtual			5
VALUE		NAS-Port-Type		PIAFS			6
VALUE		NAS-Port-Type		HDLC-Clear-Channel	7
VALUE		NAS-Port-Type		X.25			8
VALUE		NAS-Port-Type		X.75			9
VALUE		NAS-Port-Type		G.3-Fax			10
VALUE		NAS-Port-Type		SDSL			11
VALUE		NAS-Port-Type		ADSL-CAP		12
VALUE		NAS-Port-Type		ADSL-DMT		13
VALUE		NAS-Port-Type		IDSL			14
VALUE		NAS-Port-Type		Ethernet		15
VALUE		NAS-Port-Type		xDSL			16
VALUE		NAS-Port-Type		Cable			17
VALUE		NAS-Port-Type		Wireless-Other		18
VALUE		NAS-Port-Type		Wireless-802.11		19

#	Acct Terminate Causes, available in 3.3.2 and later

VALUE           Acct-Terminate-Cause    User-Request            1
VALUE           Acct-Terminate-Cause    Lost-Carrier            2
VALUE           Acct-Terminate-Cause    Lost-Service            3
VALUE           Acct-Terminate-Cause    Idle-Timeout            4
VALUE           Acct-Terminate-Cause    Session-Timeout         5
VALUE           Acct-Terminate-Cause    Admin-Reset             6
VALUE           Acct-Terminate-Cause    Admin-Reboot            7
VALUE           Acct-Terminate-Cause    Port-Error              8
VALUE           Acct-Terminate-Cause    NAS-Error               9
VALUE           Acct-Terminate-Cause    NAS-Request             10
VALUE           Acct-Terminate-Cause    NAS-Reboot              11
VALUE           Acct-Terminate-Cause    Port-Unneeded           12
VALUE           Acct-Terminate-Cause    Port-Preempted          13
VALUE           Acct-Terminate-Cause    Port-Suspended          14
VALUE           Acct-Terminate-Cause    Service-Unavailable     15
VALUE           Acct-Terminate-Cause    Callback                16
VALUE           Acct-Terminate-Cause    User-Error              17
VALUE           Acct-Terminate-Cause    Host-Request            18

#VALUE		Tunnel-Type		L2TP			3
#VALUE		Tunnel-Medium-Type	IP			1

VALUE		Prompt			No-Echo			0
VALUE		Prompt			Echo			1

#
#	Non-Protocol Integer Translations
#

VALUE		Auth-Type		Local			0
VALUE		Auth-Type		System			1
VALUE		Auth-Type		SecurID			2
VALUE		Auth-Type		Crypt-Local		3
VALUE		Auth-Type		Reject			4
VALUE		Auth-Type		ActivCard		5
VALUE		Auth-Type		EAP			6
VALUE		Auth-Type		ARAP			7

#
#	Cistron extensions
#
VALUE		Auth-Type		Ldap			252
VALUE		Auth-Type		Pam			253
VALUE		Auth-Type		Accept			254

VALUE		Auth-Type		PAP			1024
VALUE		Auth-Type		CHAP			1025
VALUE		Auth-Type		LDAP			1026
VALUE		Auth-Type		PAM			1027
VALUE		Auth-Type		MS-CHAP			1028
VALUE		Auth-Type		Kerberos		1029
VALUE		Auth-Type		CRAM			1030
VALUE		Auth-Type		NS-MTA-MD5		1031
VALUE		Auth-Type		CRAM			1032
VALUE		Auth-Type		SMB			1033

#
#	Authorization type, too.
#
VALUE		Autz-Type		Local			0

#
#	Experimental Non-Protocol Integer Translations for Cistron-Radiusd
#
VALUE		Fall-Through		No			0
VALUE		Fall-Through		Yes			1

VALUE		Packet-Type	Access-Request			1
VALUE		Packet-Type	Access-Accept			2
VALUE		Packet-Type	Access-Reject			3
VALUE		Packet-Type	Accounting-Request		4
VALUE		Packet-Type	Accounting-Response		5
VALUE		Packet-Type	Accounting-Status		6
VALUE		Packet-Type	Password-Request		7
VALUE		Packet-Type	Password-Accept			8
VALUE		Packet-Type	Password-Reject			9
VALUE		Packet-Type	Accounting-Message		10
VALUE		Packet-Type	Access-Challenge		11
VALUE		Packet-Type	Status-Server			12
VALUE		Packet-Type	Status-Client			13


##
# Fortinet VSA
#

VENDOR Fortinet 12356

BEGIN-VENDOR Fortinet
ATTRIBUTE   Fortinet-Group-Name            1   string
ATTRIBUTE   Fortinet-Client-IP-Address     2   ipaddr
ATTRIBUTE   Fortinet-Vdom-Name             3   string
ATTRIBUTE   Fortinet-Client-IPv6-Address   4   octets
ATTRIBUTE   Fortinet-Interface-Name        5   string
ATTRIBUTE   Fortinet-Access-Profile        6   string
#
# Integer Translations
#
# END-VENDOR Fortinet


# -*- text -*-
#
#	Microsoft VSA, from RFC 2548
#
#	$Id: dictionary.microsoft,v 1.8 2005/08/08 22:23:37 aland Exp $
#

VENDOR		Microsoft			311

ATTRIBUTE	MS-CHAP-Response			1	string	Microsoft
ATTRIBUTE	MS-CHAP-Error				2	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-1				3	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-2				4	string	Microsoft
ATTRIBUTE	MS-CHAP-LM-Enc-PW			5	string	Microsoft
ATTRIBUTE	MS-CHAP-NT-Enc-PW			6	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Policy		7	string	Microsoft
# This is referred to as both singular and plural in the RFC.
# Plural seems to make more sense.
ATTRIBUTE	MS-MPPE-Encryption-Type			8	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Types		8	string	Microsoft
ATTRIBUTE	MS-RAS-Vendor				9	integer	Microsoft
ATTRIBUTE	MS-CHAP-Domain				10	string	Microsoft
ATTRIBUTE	MS-CHAP-Challenge			11	string	Microsoft
ATTRIBUTE	MS-CHAP-MPPE-Keys			12	string	Microsoft
ATTRIBUTE	MS-BAP-Usage				13	integer	Microsoft
ATTRIBUTE	MS-Link-Utilization-Threshold		14	integer	Microsoft
ATTRIBUTE	MS-Link-Drop-Time-Limit			15	integer	Microsoft
ATTRIBUTE	MS-MPPE-Send-Key			16	string	Microsoft
ATTRIBUTE	MS-MPPE-Recv-Key			17	string	Microsoft
ATTRIBUTE	MS-RAS-Version				18	string	Microsoft
ATTRIBUTE	MS-Old-ARAP-Password			19	string	Microsoft
ATTRIBUTE	MS-New-ARAP-Password			20	string	Microsoft
ATTRIBUTE	MS-ARAP-PW-Change-Reason		21	integer	Microsoft

ATTRIBUTE	MS-Filter				22	string	Microsoft
ATTRIBUTE	MS-Acct-Auth-Type			23	integer	Microsoft
ATTRIBUTE	MS-Acct-EAP-Type			24	integer	Microsoft

ATTRIBUTE	MS-CHAP2-Response			25	string	Microsoft
ATTRIBUTE	MS-CHAP2-Success			26	string	Microsoft
ATTRIBUTE	MS-CHAP2-CPW				27	string	Microsoft

ATTRIBUTE	MS-Primary-DNS-Server			28	ipaddr	Microsoft
ATTRIBUTE	MS-Secondary-DNS-Server			29	ipaddr	Microsoft
ATTRIBUTE	MS-Primary-NBNS-Server			30	ipaddr	Microsoft
ATTRIBUTE	MS-Secondary-NBNS-Server		31	ipaddr	Microsoft

#ATTRIBUTE	MS-ARAP-Challenge	33	octets

#
#	Integer Translations
#

#	MS-BAP-Usage Values

VALUE	MS-BAP-Usage			Not-Allowed		0
VALUE	MS-BAP-Usage			Allowed			1
VALUE	MS-BAP-Usage			Required		2

#	MS-ARAP-Password-Change-Reason Values

VALUE	MS-ARAP-PW-Change-Reason	Just-Change-Password	1
VALUE	MS-ARAP-PW-Change-Reason	Expired-Password	2
VALUE	MS-ARAP-PW-Change-Reason	Admin-Requires-Password-Change 3
VALUE	MS-ARAP-PW-Change-Reason	Password-Too-Short	4

#	MS-Acct-Auth-Type Values

VALUE	MS-Acct-Auth-Type		PAP			1
VALUE	MS-Acct-Auth-Type		CHAP			2
VALUE	MS-Acct-Auth-Type		MS-CHAP-1		3
VALUE	MS-Acct-Auth-Type		MS-CHAP-2		4
VALUE	MS-Acct-Auth-Type		EAP			5

#	MS-Acct-EAP-Type Values

VALUE	MS-Acct-EAP-Type		MD5			4
VALUE	MS-Acct-EAP-Type		OTP			5
VALUE	MS-Acct-EAP-Type		Generic-Token-Card	6
VALUE	MS-Acct-EAP-Type		TLS			13
endmsg


cat > nlog.conf <<'endmsg'
[loggers]
keys=root,nLog

[handlers]
keys=consoleHandler

[formatters]
keys=simpleFormatter

[logger_root]
level=INFO
handlers=consoleHandler

[logger_nLog]
level=INFO
handlers=consoleHandler
qualname="nLog"
propagate=0

[handler_consoleHandler]
class=StreamHandler
level=INFO
formatter=simpleFormatter
args=(sys.stdout,)

[formatter_simpleFormatter]
format=%(asctime)s - %(levelname)s - %(message)s
datefmt=

endmsg
fi
