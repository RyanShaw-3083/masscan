#ifndef MASSCAN_APP_H
#define MASSCAN_APP_H

/*
 * 警告:这些常量用于文件中，所以不要更改值。
 * 在末尾添加新的
 */
enum ApplicationProtocol {
    PROTO_NONE,
    PROTO_HEUR,
    PROTO_SSH1,
    PROTO_SSH2,
    PROTO_HTTP,
    PROTO_FTP,
    PROTO_DNS_VERSIONBIND,
    PROTO_SNMP,             /* 简单网络控制协议（SNMP）, udp/161 */
    PROTO_NBTSTAT,          /* netbios, udp/137 */
    PROTO_SSL3,
    PROTO_SMB,              /* SMB tcp/139 and tcp/445 */
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_IMAP4,
    PROTO_UDP_ZEROACCESS,
    PROTO_X509_CERT,
    PROTO_HTML_TITLE,
    PROTO_HTML_FULL,
    PROTO_NTP,              /* 网络时间协议（NTP）, udp/123 */
    PROTO_VULN,
    PROTO_HEARTBLEED,
    PROTO_TICKETBLEED,
    PROTO_VNC_RFB,
    PROTO_SAFE,
    PROTO_MEMCACHED,
    PROTO_SCRIPTING,
    PROTO_VERSIONING,
    PROTO_COAP,         /* 受限应用协议（CoAP）, udp/5683, RFC7252 */
    PROTO_TELNET,
    PROTO_RDP,          /* 微软远程桌面（RDP） tcp/3389 */
    
    PROTO_end_of_list /* 列表末尾，必须是这个元素 */
};

const char *
masscan_app_to_string(enum ApplicationProtocol proto);

enum ApplicationProtocol
masscan_string_to_app(const char *str);

#endif
