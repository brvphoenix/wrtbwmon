#!/usr/bin/awk

function inInterfaces(host){
    return(interfaces ~ "(^| )"host"($| )")
}


function newRule(arp_ip,
    ipt_cmd){
    # checking for existing rules shouldn't be necessary if newRule is
    # always called after db is read, arp table is read, and existing
    # iptables rules are read.
    ipt_cmd="iptables -t mangle -j RETURN -s " arp_ip
    system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
    ipt_cmd="iptables -t mangle -j RETURN -d " arp_ip
    system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
}

function delRule(arp_ip,
    ipt_cmd){

    ipt_cmd="iptables -t mangle -D RRDIPT_FORWARD -s " arp_ip
    system(ipt_cmd " -j RETURN 2>/dev/null")
    ipt_cmd="iptables -t mangle -D RRDIPT_FORWARD -d " arp_ip
    system(ipt_cmd " -j RETURN 2>/dev/null")
}

function total(i){
    return(bw[i "/in"] + bw[i "/out"])
}

function date(    cmd, d){
    cmd="date '+%Y/%m/%d %X'"
    cmd | getline d
    close(cmd)
    #!@todo could start a process with "while true; do date ...; done"
    return(d)
}

function DateToStr(str){
    return(str " | sed 's/[\: \/]/-/g' | awk -F- " " '{print $1 $2 $3 $4 $5 $6}'")
}

BEGIN {
    od=""
    fid=1
    debug=0
    rrd=0
}

/^#/ { # get DB filename
    FS=","
    dbFile=FILENAME
    next
}

# data from database; first file
FNR==NR { #!@todo this doesn't help if the DB file is empty.

    lb=$1

    if(!(lb in mac)){
        mac[lb]        =  $1
        ip[lb]         =  $2
        inter[lb]      =  $3
        bw[lb "/in"]   =  $4
        bw[lb "/out"]  =  $5
        firstDate[lb]  =  $7
        lastDate[lb]   =  $8 
    }
    else{
        if(DateToStr($7)<DateToStr(firstDate[lb]))
            firstDate[lb]  =  $7
        if(DateToStr($8)>DateToStr(lastDate[lb])){
            ip[lb]         =  $2
            inter[lb]      =  $3
            lastDate[lb]   =  $8
        }
        bw[lb "/in"]   =  bw[lb "/in"] + $4
        bw[lb "/out"]  =  bw[lb "/out"] + $5
    }
    next
}

# not triggered on the first file
FNR==1 {
    FS=" "
    fid++ #!@todo use fid for all files; may be problematic for empty files
    next
}

# arp: ip hw flags hw_addr mask device
fid==2 {
    #!@todo regex match IPs and MACs for sanity
    lb=$1
    if($6 != wanIF && $3 != "0x0" && lb ~ "^" ipReg){
        hosts[lb]      = ""
        arp_mac[lb]   = $4
        arp_ip[lb]    = $1
        arp_inter[lb] = $6
        arp_bw[lb "/in"]   =  ""
        arp_bw[lb "/out"]  =  ""
        arp_firstDate[lb]  =  date()
        arp_lastDate[lb]   =  ""
    }
    next
}

#!@todo could use mangle chain totals or tailing "unnact" rules to
# account for data for new hosts from their first presence on the
# network to rule creation. The "unnact" rules would have to be
# maintained at the end of the list, and new rules would be inserted
# at the top.

# skip line
# read the chain name and deal with the data accordingly
fid==3 && $1 == "Chain"{
    rrd=$2 ~ /RRDIPT_.*/
    next
}

fid==3 && rrd && (NF < 9 || $1=="pkts"){ next }

fid==3 && rrd { # iptables input
    if($6 != "*"){
        m=$6
        n=m "/out"
    } else if($7 != "*"){
        m=$7
        n=m "/in"
    } else if($8 != "0.0.0.0/0"){
        m=$8
        n=m "/out"
    } else { # $9 != "0.0.0.0/0"
        m=$9
        n=m "/in"
    }

    if(!(m in arp_ip) && !inInterfaces(m)){
        delRule(m)
    }
    else{
        if(m in hosts && !inInterfaces(m))
        {
            delete hosts[m]
        }

        if($2 > 0){ # counted some bytes
    	    if(mode == "diff" || mode == "noUpdate")
    	        print n, $2
    	    if(mode!="noUpdate"){
    	        if(inInterfaces(m)){ # if label is an interface
    	    	    if(!(m in arp_mac)){ # if label was not in db (also not in
    	    	    		 # arp table, but interfaces won't be
    	    	    		 # there anyway)
    	    	        arp_firstDate[m] = date()
    	    	        arp_mac[m] = arp_inter[m] = m
    	    	        arp_ip[m] = "NA"
    	    	        arp_bw[m "/in"]=arp_bw[m "/out"]= 0
    	    	    }
    	        }
    	        arp_bw[n]=$2
    	        arp_lastDate[m] = date()
    	    }
        }
    }

}

END {
    if(mode=="noUpdate") exit
    close(dbFile)
    system("rm -f " dbFile)
    print "#mac,ip,iface,in,out,total,first_date,last_date" > dbFile
    OFS=","

    for(ii in arp_ip){
        lb=arp_mac[ii]

        if(lb in mac){
            if(arp_lastDate[ii] != ""){
                bw[lb "/in"]   +=  arp_bw[ii "/in"]
                bw[lb "/out"]  +=  arp_bw[ii "/out"]
                lastDate[lb]   =  arp_lastDate[ii]
            }
        }
        else{
            bw[lb "/in"]   =  arp_bw[ii "/in"]
            bw[lb "/out"]  =  arp_bw[ii "/out"]
            firstDate[lb]  =  lastDate[lb] = arp_firstDate[ii]
        }
        ip[lb]         =  arp_ip[ii]
        inter[lb]      =  arp_inter[ii]
    }

    for(i in mac)
    if(total(i)>0)
        print mac[i], ip[i], inter[i], bw[i "/in"], bw[i "/out"], total(i), firstDate[i], lastDate[i] > dbFile
    close(dbFile)
    # for hosts without rules
    for(host in hosts) if(!inInterfaces(host)) newRule(host)
}
