#ifndef _MISC_H_
#define _MISC_H_

extern void _log_event_backup(char *log_pathname, char *msg);
extern int ipv4_str_to_ip(char *str, ulong *ip);
extern int ipv6_str_to_ip(char *str, unsigned char *ip);

#endif /* _MISC_H_ */
