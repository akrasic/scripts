#!/bin/bash
#
# Terrible, just terrible(TM)
#
# Report used IPs
# Last change: Fri, 04/26/2013
#------------------------------------------------------

# Dependency check
#
if [ ! -f "/usr/local/cpanel/cpanel" ]; then
  echo "This is not a cPanel server, I demand a cPanel server!"
fi
which bc > /dev/null 2>&1
if [ "$?" -eq "1"  ]; then
  echo "Error: bc is required"
  exit 1
fi

function displayHelp {
  echo "OPTIONS:"
  echo -e "\t-n\tMinimalistic output"
  echo -e "\t-v\tVerbose output"
  echo -e "\t-p\tShow PTR information for remote IPs"
  echo -e "\t-c\tColorize output"
  echo -e "\t-h\tDisplays this message\n"
  echo -e "USAGE:"
  echo -e "\t To colorize output add \"-c\" before passing \"-n\" or \"-v\""
  echo -e "\t To pull in PTR info add \"-p\" before passing \"-n\" or \"-v\", can be mixed with \"-c\""


   exit 1
 }


function normalDisplay {
      echo -e  "\_[$i] [$used $dnsreport $dnsmsg] [$sslvoid] [$sslreport] [Owner: $owner]";
}

function verboseDisplay {
  echo -e "\_$i $used"
  echo -e "\tDomain status: $dnsreport"
  if [ "$dnsreport" == "${GREEN}ACTIVE${EC}" ]; then echo -e "\tAssigned IP: ${GREEN}$dnscheck${EC}"; fi
  echo -e "\tNameservers: $dnsns"
  if [ "$dnsreport" == "${RED}INACTIVE${EC}" ]; then echo -e "\tCurent host: ${RED}$dnsmsg${EC}"; fi
  echo -e "\t-------- SSL INFO --------"
  if [ -n "$ssldomain" ]; then echo -e "\tSSL Domain: $ssldomain"; fi
  if [ -n "$sslvoid" ]; then echo -e "\tSSL Mismatch: $sslvoid"; fi
  echo -e "\tSSL status: $sslreport"
  echo -e "\tOwner: $owner"
  echo -e "\t-------------------------"
 }

#
# Get server information
#-------------------------------------------
function checkIP {
  echo -e "$HOSTNAME\n---------------------------"
  echo "Total additional ranges `awk '{split($0,a,":");print a[1];}' /etc/ips  | awk '{split($1,a,".");print a[1]"."a[2]"."a[3]}' | sort -u | wc -l`"
  echo "Ranges and number of IPs:"

  #
  # Loop trough the assigned IPs
  awk '{split($0,a,":");print a[1];}' /etc/ips  | awk '{split($1,a,".");print a[1]"."a[2]"."a[3]}' | uniq -c | awk {'print $2" "$1'} | while read i; do

    fnum=$(echo $i| awk {'print $2'})
    fip=$(echo $i | awk {'print $1'})
    first=$(grep $fip /etc/ips | head -1 | cut -d: -f1)
    last=$(grep $fip /etc/ips | tail -1 | cut -d: -f1|awk {'split($1,a,"."); print a[4];'})

    echo -e "\t$first-$last\t$fnum IPs";

    # Display the free IPs for this range
    grep $fip /etc/ips | cut -d: -f1 | while read ss;do sslused=$(grep $ss /etc/domainips | awk {'print $2'}); if [ -z "$sslused" ]; then echo -e "\t\t$ss"; fi; done
  done

  #
  # Check on dedicated IP addresses and assigned accounts
  # =>  If the main domain is inactive, check for additional domains if they aren't active on the account
  #------------------------------------------------------------------------------------------------------------
  echo -e "\nList used/free IPs per range\n========================================================"
  awk '{split($0,a,":");print a[1];}' /etc/ips | while read i; do
    used=$(grep $i /etc/domainips | awk {'print $2'});
    owner=$( egrep ^OWNER= /var/cpanel/users/`/scripts/whoowns $used` | cut -d= -f2);
    dnsreport=
    dnscount=
    dnscheckf=
    dnsmsg=
    sslvalid=
    sslreport=
    sslvoid=
    ssldomain=
    cert_expiry_date=
    seconds_until_expiry=
    days_until_expiry=
    #sslmatch=1
    now=
    hname=
    hnamef=
    hnamecount=
    valid=
    dnsns=

    if [ -z "$used" ]; then
      echo -e "\_$i  \t${GREEN}UNUSED${EC}";
    else
      #
      # Get SSL certificate information from the dedicated IP address :443
      sslout=$( echo " GET / HTTP/1.0" | openssl x509 -in  <(openssl s_client -connect $i:443 2>&1)  -noout -subject 2>&1  );
      if [ "$?" -gt 0 ]; then
        sslreport="${RED}SSL NOT INSTALLED, :443 quiet${EC}"
      else
        #
        # Obtain the certificate information and calculate the certificate expiry date
        ssldomain=$( echo " GET / HTTP/1.0" | openssl x509 -in  <(openssl s_client -connect $i:443 2>/dev/null)  -noout -subject | awk {'split($0,a,"/CN="); print a[2];'} | cut -d/ -f1);
        cert_expiry_date=$( echo " GET / HTTP/1.0" | openssl x509 -in  <(openssl s_client -connect $i:443 2>/dev/null)  -noout -enddate | awk -F= ' /notAfter/ { printf("%s\n",$NF); } ');
        seconds_until_expiry=$(echo "$(date --date="$cert_expiry_date" +%s) - $(date +%s)" |bc);
        days_until_expiry=$(echo "$seconds_until_expiry/(60*60*24)" |bc);

        if [ "$days_until_expiry" -gt 0 ]; then
          sslreport="${GREEN}SSL VALID for $days_until_expiry days${EC}"
        else
          sslreport="${RED}SSL EXPIRED "$days_until_expiry" days ago${EC}"
        fi
      fi

      # Bugfix - notify if the SSL domain doesn't match the main domain
      if [ -n "$ssldomain" ]; then
        if  [ "$ssldomain" == "$used" ]; then
          sslvoid="${GREEN}CN $ssldomain matches${EC}"
        elif [ "$ssldomain" == "www.$used" ]; then
          sslvoid="${GREEN}CN $ssldomain matches${EC}"
        elif [ "$ssldomain" == "*.$used" ]; then
          sslvoid="${GREEN}CN $ssldomain matches${EC}"
        else
          sslvoid="${RED}CN $ssldomain doesn't match${EC}"
        fi
      else
        sslvoid="${RED}NO CN${EC}"
      fi

    # Get domain nameservers for verbose output
    if [ "$VERBOSE" == "1" ]; then
      dnsns=$( dig +short $used NS | sed 's/\.$//g' |  tr "\\n" " ")

      for digns in $(dig +short $used NS | sed 's/\.$//g');do
       # | while read digns; do
        gout=$(grep "$digns" /etc/wwwacct.conf )
        if [ -n "$gout" ]; then
          valid=1
        else
          valid=0
        fi
      done

      #dnsns=$( dig +short $used NS | sed 's/\.$//g' |  tr "\\n" " ")

      if [ "$valid" == "1" ]; then
        dnsns="${GREEN}$dnsns${EC}"
      else
        dnsns="${RED}$dnsns${EC}"
      fi
    fi

    # Get the main A record for the domain from global DNS
    dnscheck=$(dig +short $used A)
    if [ "$dnscheck" == "$i" ]; then
      if [ "$VERBOSE" == "1" ]; then
        dnsreport="${GREEN}ACTIVE${EC}"
      else
        dnsreport="${GREEN}$used resolves to $dnscheck${EC}"
      fi
    else
      if [ -z "$dnscheck" ]; then
        dnsreport="${RED}NOT REGISTERED${EC}"
      else
        dnsreport="${RED}INACTIVE${EC}"

        ##
        ## Check for hostname/PTR record
        if [ "$ENABLE_PTR" == "1" ]; then
          hname=$(dig +short -x $dnscheck PTR)
          hnamecount=$(dig +short -x $dnscheck PTR | wc -l)

          if [ "$hnamecount" == "1" ]; then
            hnamef=$hname
          elif  [ "$hnamecount" -gt "1" ]; then
            hname=$(echo $hname | tr "\\n" " ")
            hnamef="2 PTRs: $hname"
          else
            hnamef="NO PTR"
          fi
        fi

        ## Enumerate number of records
        dnscount=$(echo $dnscheck | wc -l)
        if [ "$dnscount" -gt "1" ]; then
          dnscheckf=$( echo $dnscheck | tr "\\n" " ")
          dnsmsg="Multiple A records $hnamef"
        else
          dnsmsg="${RED}$dnscheck $hnamef${EC}"
        fi
      fi
    fi

    if [ "$verbose" == "-v" ]; then
      verboseDisplay
    elif [ "$verbose" == "-n" ]; then
      normalDisplay
    else
      normalDisplay
    fi
  fi

 done
}


function enableColor {
  COLOR=1
  RED="\e[31m"
  GREEN="\e[32m"
  EC="\033[0m"

}
 option=
 COLOR=
 ENABLE_PTR=
 VERBOSE=
 while getopts "nvhcp" OPTION; do
   option=1
   case $OPTION in
     n) verbose="-n";  checkIP;  ;;
     v) VERBOSE=1;verbose="-v"; checkIP; ;;
     h) displayHelp ;;
     c) enableColor ;;
     p) ENABLE_PTR=1 ;;
     ?) displayHelp ;;
   esac
 done

 if [ -z "$option" ]; then
   displayHelp
 fi
