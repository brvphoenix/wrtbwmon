#!/usr/bin/awk

function inInterfaces(host) {
	return(interfaces ~ "(^| )" host "($| )")
}

function newRule(arp_ip, ipt_cmd) {
	# checking for existing rules shouldn't be necessary if newRule is
	# always called after db is read, arp table is read, and existing
	# iptables rules are read.
	ipt_cmd=iptKey " -t mangle -j RETURN -s " arp_ip
	system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
	ipt_cmd=iptKey " -t mangle -j RETURN -d " arp_ip
	system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
}

function delRule(arp_ip, ipt_cmd) {
	ipt_cmd=iptKey " -t mangle -D RRDIPT_FORWARD -s " arp_ip
	system(ipt_cmd " -j RETURN 2>/dev/null")
	ipt_cmd=iptKey " -t mangle -D RRDIPT_FORWARD -d " arp_ip
	system(ipt_cmd " -j RETURN 2>/dev/null")
}

function total(i) {
	return(bw[i "/in"] + bw[i "/out"])
}

BEGIN {
	od=""
	fid=1
	debug=0
	rrd=0
	if (ipv6) {
		tbNF	= 8
		iptKey	= "ip6tables"
	} else {
		tbNF	= 9
		iptKey	= "iptables"
	}
}

/^#/ { # get DB filename
	FS=","
	dbFile=FILENAME
	next
}

# data from database; first file
FNR==NR { #!@todo this doesn't help if the DB file is empty.
	lb=$1

	if (!(lb in mac)) {
		mac[lb]		= $1
		ip[lb]		= $2
		inter[lb]	= $3
		bw[lb "/in"]	= $6
		bw[lb "/out"]	= $7
		firstDate[lb]	= $9
		lastDate[lb]	= $10
	} else {
		if ($9 < firstDate[lb])
			firstDate[lb]	= $9
		if ($10 > lastDate[lb]) {
			ip[lb]		= $2
			inter[lb]	= $3
			lastDate[lb]	= $10
		}
		bw[lb "/in"]	+= $6
		bw[lb "/out"]	+= $7
	}

	speed[lb "/in"]		= 0
	speed[lb "/out"]	= 0
	next
}

# not triggered on the first file
FNR==1 {
	FS=" "
	fid++ #!@todo use fid for all files; may be problematic for empty files
	if(fid == 2) next
}

# arp: ip hw flags hw_addr mask device
fid==2 {
	#!@todo regex match IPs and MACs for sanity
	if (ipv6) {
		statFlag= ($4!="FAILED" && $4!="INCOMPLETE")
		macAddr	= $5
		hwIF	= $3
	} else {
		statFlag= ($3 != "0x0")
		macAddr	= $4
		hwIF	= $6
	}

	lb=$1
	if (hwIF != wanIF && lb ~ "^" ipReg && statFlag) {
		hosts[lb]		= ""
		arp_mac[lb]		= macAddr
		arp_ip[lb]		= $1
		arp_inter[lb]		= hwIF
		arp_bw[lb "/in"]	= 0
		arp_bw[lb "/out"]	= 0
		arp_firstDate[lb]	= systime()
		arp_lastDate[lb]	= ""
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

fid==3 && $1 == "Chain" {
	rrd=$2 ~ /RRDIPT_.*/
	next
}

fid==3 && rrd && (NF < tbNF || $1=="pkts") { next }

fid==3 && rrd { # iptables input
	if (ipv6) {
		lfn = 5
		tag = "::/0"
	} else {
		lfn = 6
		tag = "0.0.0.0/0"
	}

	if ($(lfn) != "*") {
		m = $(lfn)
		n = m "/in"
	} else if ($(++lfn) != "*") {
		m = $(lfn)
		n = m "/out"
	} else if ($(++lfn) != tag) {
		m = $(lfn)
		n = m "/out"
	} else { # $(++lfn) != tag
		m = $(++lfn)
		n = m "/in"
	}

	if (!(m in arp_ip) && !inInterfaces(m)) {
		delRule(m)
	} else {
		if (m in hosts && !inInterfaces(m)) delete hosts[m]

		if (mode == "diff" || mode == "noUpdate") print n, $2
		if (mode!="noUpdate") {
			if (inInterfaces(m)) { # if label is an interface
				if (!(m in arp_mac)) {
				# if label was not in db (also not in
				# arp table, but interfaces won't be
				# there anyway
					cmd = "cat /sys/class/net/" m "/address"
					cmd | getline arp_mac[m]
					close(cmd)
					arp_firstDate[m]	= systime()
					arp_inter[m] 		= m
					arp_ip[m]		= "NA"
					arp_bw[m "/in"]		= arp_bw[m "/out"] = 0
				}
			}

			if ($2 > 0) { # counted some bytes
				arp_bw[n]	= $2
				arp_lastDate[m]	= systime()
			}
		}
	}
}

END {
	if (mode=="noUpdate") exit

	for (ii in arp_ip) {
		lb=arp_mac[ii]

		if (lb in mac) {
			if (arp_lastDate[ii] != "") {
				bw[lb "/in"]	+= arp_bw[ii "/in"]
				bw[lb "/out"]	+= arp_bw[ii "/out"]
				lastDate[lb]	= arp_lastDate[ii]
			}
		} else {
			bw[lb "/in"]	= arp_bw[ii "/in"]
			bw[lb "/out"]	= arp_bw[ii "/out"]
			firstDate[lb]	= lastDate[lb] = arp_firstDate[ii]
		}
		mac[lb]		= arp_mac[ii]
		ip[lb]		= arp_ip[ii]
		inter[lb]	= arp_inter[ii]

		if (interval != 0) {
			speed[lb "/in"]	= int(arp_bw[ii "/in"] / interval)
			speed[lb "/out"]= int(arp_bw[ii "/out"] / interval)
		}
	}

	close(dbFile)
	print "#mac,ip,iface,speed_in,speed_out,in,out,total,first_date,last_date" > dbFile
	OFS=","

	for (i in mac)
		print mac[i], ip[i], inter[i], speed[i "/in"], speed[i "/out"], bw[i "/in"], bw[i "/out"], total(i), firstDate[i], lastDate[i] > dbFile
	close(dbFile)
	# for hosts without rules
	for(host in hosts) if(!inInterfaces(host)) newRule(host)
}
