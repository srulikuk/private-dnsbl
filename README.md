# Private DNSBL for Postfix SpamTrap  

#### Private DNSBL using BIND and fail2ban to manage entries from postfix spamtrap. The IP entries are then banned by the reject_rbl_client in postfix.  

*  [How it works](#hotitworks)
*  [Setup](#setup)
    *  [BIND9 Config](#bind9config)
    *  [Postfix Config](#postfixconfig)
    *  [Python3 Config](#python3config)
    *  [Fail2ban Config](#fail2banconfig)
    *  [Logrotate](#logrotate)
*  [dnsbl.py Explained](#dnsblexplained)
    *  [Usage/Options](#usageoptions)
*  [Credits](#credits)  

#### <a name="howitoworks">How it works</a>
A regex in postfix is triggered when a spamtrap[1] is hit, fail2ban gets this from the mail log and executes a python script that adds the IP to the DNSBL which is in turn used by postfix to block future emails (the IP, sender and triggered spamtrap are logged to a file).  

The reason I decided to use DNSBL instead of just banning the IP in ipset is for statistics, this way I can see how many emails were blocked from this DNSBL and other statistics from the mail log.   

_[1]: you will need to find how / where to put those email address out in the open to get the spammers to scrape them._


## <a name="setup">_Setup_</a>  

**NOTE:** My setup for the DNSBL domain is `dns.private.bl` replace with your own (As I am only using it locally I do not need to use a real domain)  

**Assumptions:**
*  BIND is installed and configured, (else this seems to be a decent guide [linuxbabe.com local DNS resolver on ubuntu](https://www.linuxbabe.com/ubuntu/set-up-local-dns-resolver-ubuntu-18-04-16-04-bind9))
    *  If setting up bind now or if your DNS settings are not using your bind for resolving you might need to change the settings for resolve and relink /etc/resolv.conf (to test if you are using your bind for resolving `dig A facebook.com` and see in the output 'SERVER' to see which dns was used).
    *  If you using only ipv4 make sure to have `OPTIONS="-4"` in /etc/default/bind9
*  Postfix is configured and running. (many good guides available on the www)  
*  Fail2ban is configured and running. (many good guides available on the www)  

---
### <a name="bind9config">BIND9 Config</a>

1.  Create a dnssec key to allow only authenticated queries. The following will create 2 files, a `.key` and `.private` file  

     `:~# dnssec-keygen -a HMAC-MD5 -b 512 -n USER dns.private.bl_rndc-key`  

2.  Get the key from the `.private` file and create the file `/etc/bind/dns.private.bl_rndc-key` put the key inside it and name the `key` accordingly (the file needs to be 640 mode and owned by bind:bind)
```
key "dns.private.bl_rndc-key" {
        algorithm hmac-md5;
        secret "rg2aizg+T6XkKkmpI42K7g*******==";
};
```  

3.  Create a zone file `/var/cache/bind/dns.private.bl` (owned by bind:bind) and put the following inside, (make sure to update/replace as required)
```
$ORIGIN .  
$TTL 900        ; 15 minutes
dns.private.bl          IN SOA  ns1.private.bl. private.bl. (
                                1          ; serial
                                3600       ; refresh (1 hour)
                                600        ; retry (10 minutes)
                                432000     ; expire (5 days)
                                10         ; minimum (10 seconds)
                                )
                        NS      ns1.private.bl.
                        A       127.0.0.1
$ORIGIN dns.private.bl.
$TTL 900        ; 15 minutes  

dns                     A       127.0.0.1
```  

4.  In `/etc/bind/named.conf.local` add the zone, (make sure to update/replace as required)
```
//--------------------------------------------------------------
// Dynamic update zone for DNS Blackhole List.
//--------------------------------------------------------------
zone "dns.private.bl" {
    type master;
    allow-update { 127.0.0.1; };
    allow-transfer { 127.0.0.1; };
    file "/var/cache/bind/dns.private.bl";
    max-journal-size 500k;
};
include "/etc/bind/dns.private.bl_rndc-key";
```  

5.  Test the named.conf file with  
  `:~# named-checkconf`  
   and test the zone file with  
  `:~# named-checkzone dns.private.bl /var/cache/bind/dns.private.bl`  

6. Restart bind `systemctl restart bind9.service`

---
### <a name="postfixconfig">Postfix Config</a>

1. Create the file `/etc/postfix/spamtraps` with the SpamTrap entries such as;
```
/(some_trap|some_other_trap)@mydomain.tld/i                DISCARD triggers spamtrap
/(some_trap|some_other_trap)@myother.tld/i                 DISCARD triggers spamtrap
```  

2. In `/etc/postfix/main.cf` add the rules to the smtpd_recipient_restrictions block, note the following  
  -  To use less resources its best to put the spamtrap rule before the network checks but after the authenticated users.   
  -  Put you DNSBL at the top of your rbl's  

```
## EXAMPLE ##
smtpd_recipient_restrictions = permit_sasl_authenticated
        permit_mynetworks,
        check_recipient_access regexp:/etc/postfix/spamtraps,
        ...
        reject_rbl_client dns.private.bl,
        ...
```  

3.  Reload postfix `postfix reload`  

---

### <a name="python3config">Python3 Config</a>
1.  If not installed, install the following python3 packages `apt install python3-dnspython python3-tz`
2.  Copy the `myvars.py` file to `_myvars.py` **and update the vars with the correct values**.  

---

### <a name="fail2banconfig">Fail2ban Config</a>  
1.  Copy the file `fail2ban/action_spamtrap.local` to `/etc/fail2ban/action.d/spamtrap.local` **make sure the path to the dnsbl.py file is correct** and the bantime is as you require (default set to 7 days)
2.  Copy the file `fail2ban/filter_spamtrap.local` to `/etc/fail2ban/filter.d/spamtrap.local`
3.  Copy the `jail_spamtrap.local` to `/etc/fail2ban/jail.d/spamtrap.local` (or add the section to your existing jail conf file) **make sure the logpath is the correct one to your mail log** and bantime is as you require.  
4.  Reload fail2ban `fail2ban-client reload`  


---

### <a name="logrotate">Logrotate</a>
To rotate the log file of the DNSBL entries copy the file `dnsbl_log` to your logrotate dir (`/etc/logrotate.d/`)  
Rotates monthly keeping 13 logs (update to your requirements).  

---
### END OF CONFIG ##
---

### <a name="dnsblexplained">dnsbl.py Explained</a>
The arguments which the python script is called with are set in the fail2ban action file, its workings are as follows;  

The python script adds/removes the IP from the DNSBL and adds the entries to log file /var/log/dnsbl_spamtrap.log in the following format;  
`<date_time>,IP-BANNED=<ip>,TRAP=<email@addr.ess>,SENDER-HOST=<host>,SENDER-EMAIL=<email@ddr.ess>`  
example log entry;  
`2020-11-29Z23:08:01,IP-BANNED=11.12.13.14,TRAP=<my@spamtrap.com>,SENDER-HOST=mail.outbound.some.spammer.com,SENDER-EMAIL=<stupid@spammer.com>`  

To manually add/remove/query the DNSBL call the script with the following arguments/options;  

<a name="usageoptions">**Usage/Options:**</a>
`-t` (type) - Always required, followed by a single choice;
-  `a` - Add an IP entry
-  `r` - Remove an entry
-  `q` - Query an IP (check if its listed)
-  `x` - Zone transfer
-  Unless the -t (type) is `x` the -i option must be provided followed by an IP address  

To add a IP entry you would call it `python3 /path/dnsbl.py -t a -i 1.2.3.4`  

When adding an IP entry there additional optional arguments;  
-  `-tr` - followed by an email address (this is the trap email address that was triggered)
-  `-hs` - followed by the host name (the host that sent the email to the spamtrap)
-  `-s`  - followed by an email address (the senders email address)

---

### <a name="credits">Credits</a>
---
Although I have tweaked the DNSBL instructions and very much re-written the python script most of the setup and python concept was taken from / inspired by "niccolo" on this page https://www.rigacci.org/wiki/doku.php/doc/appunti/linux/sa/spamassassin_private_dnsbl  

The postfix spamtrap trigger was cobbled together from various answers on the page https://serverfault.com/questions/67507/how-do-i-spamtrap-with-postfix
