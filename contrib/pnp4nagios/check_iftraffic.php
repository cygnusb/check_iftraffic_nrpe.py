<?php

$stats = array();
foreach($this->DS as $KEY=>$VAL) {
	if(true !== strpos($VAL["NAME"], "-")) {
		list($kind, $interface) = explode("-", $VAL["NAME"]);
		if(!array_key_exists($interface, $stats)) {
			$stats[$interface] = array();
		}
		$stats[$interface][$kind] = $VAL;
	}
}

function labels($var, $aggr, $text) {
	$ret = "";
	foreach($aggr as $key=>$func) {
		$ret .= "GPRINT:$var:$func:\"$text";
		if($key + 1 == sizeof($aggr)) {
			$ret .= '\\l" ';
		} else {
			$ret .= ' " ';
		}
	}
	return $ret;
}

foreach($stats as $interface=>$ifacestat) {
	$ds_name["$interface-bytes"] = "$interface-bytes";
	$ds_name["$interface-packets"] = "$interface-packets";
	$opt["$interface-bytes"] = '--vertical-label Bytes --title "' . $this->MACRO['DISP_HOSTNAME'] . ' / ' . $interface . ' Bytes"';
	$opt["$interface-packets"] = '--vertical-label Packets --title "' . $this->MACRO['DISP_HOSTNAME'] . ' / ' . $interface . ' Packets"';
	$def["$interface-bytes"] = "";
	if(array_key_exists("out", $ifacestat)) {
		$def["$interface-bytes"] .= rrd::def("out", $VAL['RRDFILE'], $ifacestat["out"]['DS'], "AVERAGE");
	}
	if(array_key_exists("in", $ifacestat)) {
		$def["$interface-bytes"] .= rrd::def("posin", $VAL['RRDFILE'], $ifacestat["in"]['DS'], "AVERAGE");
		$def["$interface-bytes"] .= "CDEF:in=posin,-1,* ";
	}
	$def["$interface-packets"] = "";
	foreach(array("pkt", "err", "drop") as $kind) {
		if(array_key_exists("${kind}out", $ifacestat)) {
			$def["$interface-packets"] .= rrd::def("${kind}out", $VAL['RRDFILE'], $ifacestat["${kind}out"]['DS'], "AVERAGE");
		}
		if(array_key_exists("${kind}in", $ifacestat)) {
			$def["$interface-packets"] .= rrd::def("pos${kind}in", $VAL['RRDFILE'], $ifacestat["${kind}in"]['DS'], "AVERAGE");
			$def["$interface-packets"] .= "CDEF:${kind}in=pos${kind}in,-1,* ";
		}
	}
	$def["$interface-bytes"] .= 'COMMENT:"             Max           Avg          Last\\l" ';
	$aggrs = array("MAX", "AVERAGE", "LAST");
	if(array_key_exists("in", $ifacestat)) {
		$def["$interface-bytes"] .= 'AREA:in#008800:"In   " ';
		$def["$interface-bytes"] .= labels("posin", $aggrs, "%6.1lf %SB/s");
	}
	if(array_key_exists("out", $ifacestat)) {
		$def["$interface-bytes"] .= 'AREA:out#00cc00:"Out  " ';
		$def["$interface-bytes"] .= labels("out", $aggrs, "%6.1lf %SB/s");
	}
	$def["$interface-packets"] .= 'COMMENT:"                 Max          Avg         Last\\l" ';
	if(array_key_exists("pktin", $ifacestat)) {
		$def["$interface-packets"] .= 'AREA:pktin#00aa00:"In       " ';
		$def["$interface-packets"] .= labels("pospktin", $aggrs, "%6.1lf %S/s");
	}
	if(array_key_exists("pktout", $ifacestat)) {
		$def["$interface-packets"] .= 'AREA:pktout#00cc00:"Out      " ';
		$def["$interface-packets"] .= labels("pktout", $aggrs, "%6.1lf %S/s");
	}
	if(array_key_exists("dropin", $ifacestat)) {
		$def["$interface-packets"] .= 'LINE1:dropin#0000ff:"Drop In  " ';
		$def["$interface-packets"] .= labels("posdropin", $aggrs, "%6.1lf %S/s");
	}
	if(array_key_exists("dropout", $ifacestat)) {
		$def["$interface-packets"] .= 'LINE1:dropout#0000ff:"Drop Out " ';
		$def["$interface-packets"] .= labels("dropout", $aggrs, "%6.1lf %S/s");
	}
	if(array_key_exists("errin", $ifacestat)) {
		$def["$interface-packets"] .= 'LINE1:errin#ff0000:"Err In   " ';
		$def["$interface-packets"] .= labels("poserrin", $aggrs, "%6.1lf %S/s");
	}
	if(array_key_exists("errout", $ifacestat)) {
		$def["$interface-packets"] .= 'LINE1:errout#ff0000:"Err Out  " ';
		$def["$interface-packets"] .= labels("errout", $aggrs, "%6.1lf %S/s");
	}
}

?>
