<?php
# 此檔案不能使用 UTF-8 編碼，include 會造成 json_encode 失敗 (IE10, Chrome)
ini_set("max_execution_time", "300");

function _get($str)
{
	$val = !empty($_GET[$str]) ? $_GET[$str] : null;
	return $val;
}

function _post($str)
{
	$val = !empty($_POST[$str]) ? $_POST[$str] : null;
	return $val;
}

function safe($value)
{
	$value = htmlentities($value, ENT_QUOTES, 'UTF-8');
	$value = htmlspecialchars($value);
	return $value;
}

function ping($host_and_port, $timeout)
{
  $hp = preg_split("/\:/", $host_and_port);
  $tB = microtime(true);
  if (!fsockopen($hp[0], $hp[1], $errno, $errstr, $timeout)) { return "down (".$errno.") - ".$errstr; }
  $tA = microtime(true);
  return round((($tA - $tB) * 1000), 0)." ms";
}

function left($string, $count) { // 取得左字串
  return substr($string, 0, $count);
}

function right($value, $count) { // 取得右字串
	$value = substr($value, (strlen($value) - $count), strlen($value));
	return $value;
}

function replace_arr($str, $arr)
{
  $str = preg_replace_callback(
           '/\?/',
           function($matches) use (&$arr) {
           	 return "'<font color=green>".array_shift($arr)."</font>'";
           },
           $str, -1);
	return $str;
}

function getmicrotime() { // 取得現在時間 (micro-sec)
  list($usec, $sec) = explode(" ",microtime());
  return ((float)$usec + (float)$sec);
}

// Function to get the client IP address
function get_client_ip() {
	$ipaddress = '';
	if (getenv('HTTP_CLIENT_IP'))
	    $ipaddress = getenv('HTTP_CLIENT_IP');
	else if(getenv('HTTP_X_FORWARDED_FOR'))
	    $ipaddress = getenv('HTTP_X_FORWARDED_FOR');
	else if(getenv('HTTP_X_FORWARDED'))
	    $ipaddress = getenv('HTTP_X_FORWARDED');
	else if(getenv('HTTP_FORWARDED_FOR'))
	    $ipaddress = getenv('HTTP_FORWARDED_FOR');
	else if(getenv('HTTP_FORWARDED'))
	   $ipaddress = getenv('HTTP_FORWARDED');
	else if(getenv('REMOTE_ADDR'))
	    $ipaddress = getenv('REMOTE_ADDR');
	else
	    $ipaddress = 'UNKNOWN';
	return $ipaddress;
}

function get_conn_state() {
	// save connection info
	$connStat = connection_status();
	switch($connStat) {
		case 0: $connStat = "Normal"; break;
		case 1: $connStat = "Aborted"; break;
		case 2: $connStat = "Timeout"; break;
		case 3: $connStat = "Aborted and Timeout"; break;
	}
	return $connStat;
}

function datetimeDiff($BEN, $END) {
	$beg_arr = preg_split("/,/", $BEN);
	$end_arr = preg_split("/,/", $END);
	$diff = strtotime($end_arr[0]) - strtotime($beg_arr[0]);
	$diff += ($end_arr[1]*1000 + $end_arr[2] - $beg_arr[1]*1000 - $beg_arr[2])/1000/1000;
	return number_format($diff,3);
}

function hiddenCode($number) {
	if(preg_match('/[\d+]/',$number)) {
		$arr = str_split($number);
		$hide_str = '';
		for($i=0; $i<count($arr); $i++) {
			// 小於5碼，只遮2碼
			if(count($arr) <= 5) {
				if($i>=1 && $i<count($arr)-1)
					$hide_str .= '*';
				else
					$hide_str .= $arr[$i];
			} else { // 大於 4 碼，處理方式
				if($i>=5 && $i<count($arr)-3)
					$hide_str .= '*';
				else
					$hide_str .= $arr[$i];
			}
		}
		return $hide_str;
	}
	return $number;
}

function getPayloadType($code) { // 取得RTP種類
	switch($code) {
		case 0:
			return "ITU-T G.711 PCMU";
		case 1:
			return "USA Federal Standard FS-1016";
		case 2:
			return "ITU-T G.721";
		case 3:
			return "GSM 06.10";
		case 4:
			return "ITU-T G.723";
		case 5:
			return "DVI4 8000 samples/s";
		case 6:
			return "DVI4 16000 samples/s";
		case 7:
			return "Experimental linear predictive encoding from Xerox PARC";
		case 8:
			return "ITU-T G.711 PCMA";
		case 9:
			return "ITU-T G.722";
		case 10:
			return "16-bit uncompressed audio, stereo";
		case 11:
			return "16-bit uncompressed audio, monaural";
		case 12:
			return "Qualcomm Code Excited Linear Predictive coding";
		case 13:
			return "Comfort noise";
		case 14:
			return "MPEG-I/II Audio";
		case 15:
			return "ITU-T G.728";
		case 16:
			return "DVI4 11025 samples/s";
		case 17:
			return "DVI4 22050 samples/s";
		case 18:
			return "ITU-T G.729";
		case 19:
			return "Comfort noise (old)";
		case $code >= 20 && $code <= 24:
			return "Unassigned";
		case 25:
			return "Sun CellB video encoding";
		case 26:
			return "JPEG-compressed video";
		case 27:
			return "Unassigned";
		case 28:
			return "'nv' program";
		case 29:
			return "Unassigned";
		case 30:
			return "Unassigned";
		case 31:
			return "ITU-T H.261";
		case 32:
			return "MPEG-I/II Video";
		case 33:
			return "MPEG-II transport streams";
		case 34:
			return "ITU-T H.263";
		case $code >= 96 && $code <= 127:
			return "DynamicRTP-Type-".$code;
	}
	return $code;
}

function getShortPayloadType($code) { // 取得RTP種類
	switch($code) {
		case 0:
			return "g711U";
		case 1:
			return "fs-1016";
		case 2:
			return "g721";
		case 3:
			return "GSM";
		case 4:
			return "g723";
		case 5:
			return "DVI4 8k";
		case 6:
			return "DVI4 16k";
		case 7:
			return "Exp. from Xerox PARC";
		case 8:
			return "g711A";
		case 9:
			return "g722";
		case 10:
			return "16-bit audio, stereo";
		case 11:
			return "16-bit audio, monaural";
		case 12:
			return "Qualcomm";
		case 13:
			return "CN";
		case 14:
			return "MPEG-I/II Audio";
		case 15:
			return "g728";
		case 16:
			return "DVI4 11k";
		case 17:
			return "DVI4 22k";
		case 18:
			return "g729";
		case 19:
			return "CN(old)";
		case $code >= 20 && $code <= 24:
			return "Unassigned";
		case 25:
			return "CellB";
		case 26:
			return "JPEG";
		case 28:
			return "NV";
		case 27: case 29:	case 30:
			return "Unassigned";
		case 31:
			return "h261";
		case 32:
			return "MPEG-I/II Video";
		case 33:
			return "MPEG-II streams";
		case 34:
			return "h263";
		case $code >= 96 && $code <= 127:
			return "DTMF-";
	}
	return $code;
}

function getFaxCode($state) { // 取得傳真狀態
	switch($state) {
		case 'NSF':
			$state = 'Non Standard Facilities';
			break;
		case 'DIS':
			$state = 'Digital Identification Signal';
			break;
		case 'CSI':
			$state = 'Called Subscriber Identification';
			break;
		case 'TSI':
			$state = 'Transmitting Subscriber Identification';
			break;
		case 'DCS':
			$state = 'Digital Command Signal';
			break;
		case 'CFR':
			$state = 'Confirmation To Receive';
			break;
		case 'CTC':
			$state = 'Continue To Correct';
			break;
		case 'CTR':
			$state = 'Response For Continue To Correct';
			break;
		case 'CIG':
			$state = 'Calling Subscriber Identification';
			break;
		case 'FIT':
			$state = 'Failure To Train';
			break;
		case 'MPS':
			$state = 'Multipage Signal';
			break;
		case 'MCF':
			$state = 'Message ConFirmation';
			break;
		case 'PPR':
			$state = 'Partial Page Request';
			break;
		case 'PPS':
			$state = 'Partial Page Signals';
			break;
		case 'EOR':
			$state = 'End Of Retransmission';
			break;
		case 'ERR':
			$state = 'Response For End Retransmission';
			break;
		case 'EOP':
			$state = 'End Of Procedure';
			break;
		case 'EOM':
			$state = 'End Of Message';
			break;
		case 'CRP':
			$state = 'Command Repeat';
			break;
		case 'DCN':
			$state = 'Disconnect';
			break;
		case 'DTC':
			$state = 'Digital Transmit Command';
			break;
		case 'NSC':
			$state = 'Non Standard Facilities Command';
			break;
		case 'NSS':
			$state = 'Non Standard Facilities Set Up';
			break;
		case 'PRI-EOM':
			$state = 'Procedure Interrupt - End Of Message';
			break;
		case 'PRI-MPS':
			$state = 'Procedure Interrupt - Multipage Signal';
			break;
		case 'PIN':
			$state = 'Procedural Interrupt Negative';
			break;
		case 'RR':
			$state = 'Receive Ready';
			break;
		case 'RNR':
			$state = 'Receiver Not Ready';
			break;
	}
	return $state;
}

function getApplicationId($code) {
	if(strlen($code) > 0) {
		switch($code) {
			case 16777216:
				return '3GPP Cx';
			case 16777217:
				return '3GPP Sh';
			case 3:
				return 'Diameter Base Accounting';
			default:
				return $code;
		}
	}
	return;
}

function getShortCommandCode($code, $direction) {
	$v = "A";
	if($direction) {
		$v = "R";
	}
	if(strlen($code) > 0) {
		switch($code) {
		 case 271:
		   return "AC".$v;
		 case 300:
		   return "UA".$v;
		 case 301:
		   return "SA".$v;
		 case 302:
		   return "LI".$v;
		 case 303:
		   return "MA".$v;
		 case 304:
		   return "RT".$v;
		 case 305:
		   return "PP".$v;
		 case 306:
		   return "UD".$v;
		 case 307:
		   return "PU".$v;
		 default:
		   return $code;
		}
	}
	return;
}

function getAllCommandCode($code, $direction) {
	$v = " Answer";
	if($direction) {
		$v = " Request";
	}
	if(strlen($code) > 0) {
		switch($code) {
		 case 271:
		   return "Accounting".$v;
		 case 300:
		   return "User-Authorization".$v;
		 case 301:
		   return "Server-Assignment".$v;
		 case 302:
		   return "Location-Info".$v;
		 case 303:
		   return "Multimedia-Auth".$v;
		 case 304:
		   return "Registration-Termination".$v;
		 case 305:
		   return "Push-Profile".$v;
		 case 306:
		   return "User-Data".$v;
		 case 307:
		   return "Profile-Update".$v;
		 default:
		   return $code;
		}
	}
	return;
}

function getResultCode($code) {
	if(strlen($code) > 0) {
		switch($code) {
			case 1001:
				return 'DIAMETER_MULTI_ROUND_AUTH';
			case 2001:
				return 'DIAMETER_SUCCESS';
			case 2002:
				return 'DIAMETER_LIMITED_SUCCESS';
			case 2003:
				return 'DIAMETER_FIRST_REGISTRATION';
			case 2004:
				return 'DIAMETER_SUBSEQUENT_REGISTRATION';
			case 2005:
				return 'DIAMETER_UNREGISTERED_SERVICE';
			case 2006:
				return 'DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED';
			case 2007:
				return 'DIAMETER_SERVER_SELECTION';
			case 2008:
				return 'DIAMETER_SUCCESS_AUTH_SENT_SERVER_NOT_STORED';
			case 2009:
				return 'DIAMETER_SUCCESS_RELOCATE_HA';
	// <!-- 2010-2999 Unassigned -->
			case 3001:
				return 'DIAMETER_COMMAND_UNSUPPORTED';
			case 3002:
				return 'DIAMETER_UNABLE_TO_DELIVER';
			case 3003:
				return 'DIAMETER_REALM_NOT_SERVED';
			case 3004:
				return 'DIAMETER_TOO_BUSY';
			case 3005:
				return 'DIAMETER_LOOP_DETECTED';
			case 3006:
				return 'DIAMETER_REDIRECT_INDICATION';
			case 3007:
				return 'DIAMETER_APPLICATION_UNSUPPORTED';
			case 3008:
				return 'DIAMETER_INVALID_HDR_BITS';
			case 3009:
				return 'DIAMETER_INVALID_AVP_BITS';
			case 3010:
				return 'DIAMETER_UNKNOWN_PEER';
	// <!-- 3011-3999 Unassigned -->
			case 4001:
				return 'DIAMETER_AUTHENTICATION_REJECTED';
			case 4002:
				return 'DIAMETER_OUT_OF_SPACE';
			case 4003:
				return 'DIAMETER_ELECTION_LOST';
			case 4005:
				return 'DIAMETER_ERROR_MIP_REPLY_FAILURE';
			case 4006:
				return 'DIAMETER_ERROR_HA_NOT_AVAILABLE';
			case 4007:
				return 'DIAMETER_ERROR_BAD_KEY';
			case 4008:
				return 'DIAMETER_ERROR_MIP_FILTER_NOT_SUPPORTED';
			case 4010:
				return 'DIAMETER_END_USER_SERVICE_DENIED';
			case 4011:
				return 'DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE';
			case 4012:
				return 'DIAMETER_CREDIT_LIMIT_REACHED';
			case 4013:
				return 'DIAMETER_USER_NAME_REQUIRED';
	// <!-- 4014-4999 Unassigned -->
			case 5001:
				return 'DIAMETER_AVP_UNSUPPORTED';
			case 5002:
				return 'DIAMETER_UNKNOWN_SESSION_ID';
			case 5003:
				return 'DIAMETER_AUTHORIZATION_REJECTED';
			case 5004:
				return 'DIAMETER_INVALID_AVP_VALUE';
			case 5005:
				return 'DIAMETER_MISSING_AVP';
			case 5006:
				return 'DIAMETER_RESOURCES_EXCEEDED';
			case 5007:
				return 'DIAMETER_CONTRADICTING_AVPS';
			case 5008:
				return 'DIAMETER_AVP_NOT_ALLOWED';
			case 5009:
				return 'DIAMETER_AVP_OCCURS_TOO_MANY_TIMES';
			case 5010:
				return 'DIAMETER_NO_COMMON_APPLICATION';
			case 5011:
				return 'DIAMETER_UNSUPPORTED_VERSION';
			case 5012:
				return 'DIAMETER_UNABLE_TO_COMPLY';
			case 5013:
				return 'DIAMETER_INVALID_BIT_IN_HEADER';
			case 5014:
				return 'DIAMETER_INVALID_AVP_LENGTH';
			case 5015:
				return 'DIAMETER_INVALID_MESSAGE_LENGTH';
			case 5016:
				return 'DIAMETER_INVALID_AVP_BIT_COMBO';
			case 5017:
				return 'DIAMETER_NO_COMMON_SECURITY';
			case 5018:
				return 'DIAMETER_RADIUS_AVP_UNTRANSLATABLE';
	// <!-- 5019-5023 Unassigned -->
			case 5024:
				return 'DIAMETER_ERROR_NO_FOREIGN_HA_SERVICE';
			case 5025:
				return 'DIAMETER_ERROR_END_TO_END_MIP_KEY_ENCRYPTION';
	// <!-- 5026-5029 Unassigned -->
			case 5030:
				return 'DIAMETER_USER_UNKNOWN';
			case 5031:
				return 'DIAMETER_RATING_FAILED';
			case 5032:
				return 'DIAMETER_ERROR_USER_UNKNOWN';
			case 5033:
				return 'DIAMETER_ERROR_IDENTITIES_DONT_MATCH';
			case 5034:
				return 'DIAMETER_ERROR_IDENTITY_NOT_REGISTERED';
			case 5035:
				return 'DIAMETER_ERROR_ROAMING_NOT_ALLOWED';
			case 5036:
				return 'DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED';
			case 5037:
				return 'DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED';
			case 5038:
				return 'DIAMETER_ERROR_IN_ASSIGNMENT_TYPE';
			case 5039:
				return 'DIAMETER_ERROR_TOO_MUCH_DATA';
			case 5040:
				return 'DIAMETER_ERROR_NOT SUPPORTED_USER_DATA';
			case 5041:
				return 'DIAMETER_ERROR_MIP6_AUTH_MODE';
			default:
				return $code;
		}
	}
	return;
}

function getExperimentalResultCode($code) {
	if(strlen($code) > 0) {
		switch($code) {
			case 2001:
				return "DIAMETER_FIRST_REGISTRATION";
			case 2002:
				return "DIAMETER_SUBSEQUENT_REGISTRATION";
			case 2003:
				return "DIAMETER_UNREGISTERED_SERVICE";
			case 2004:
				return "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED";
			case 2005:
				return "DIAMETER_SERVER_SELECTION(Deprecated value)";
			case 2021:
				return "DIAMETER_PDP_CONTEXT_DELETION_INDICATION";
			case 4100:
				return "DIAMETER_USER_DATA_NOT_AVAILABLE";
			case 4101:
				return "DIAMETER_PRIOR_UPDATE_IN_PROGRESS";
			case 4121:
				return "DIAMETER_ERROR_OUT_OF_RESOURCES";
			case 4141:
				return "DIAMETER_PCC_BEARER_EVENT";
			case 4181:
				return "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE";
			case 4201:
				return "DIAMETER_ERROR_ABSENT_USER";
			case 4221:
				return "DIAMETER_ERROR_UNREACHABLE_USER";
			case 4222:
				return "DIAMETER_ERROR_SUSPENDED_USER";
			case 4223:
				return "DIAMETER_ERROR_DETACHED_USER";
			case 4224:
				return "DIAMETER_ERROR_POSITIONING_DENIED";
			case 4225:
				return "DIAMETER_ERROR_POSITIONING_FAILED";
			case 4226:
				return "DIAMETER_ERROR_UNKNOWN_UNREACHABLE LCS_CLIENT";
			case 5001:
				return "DIAMETER_ERROR_USER_UNKNOWN";
			case 5002:
				return "DIAMETER_ERROR_IDENTITIES_DONT_MATCH";
			case 5003:
				return "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED";
			case 5004:
				return "DIAMETER_ERROR_ROAMING_NOT_ALLOWED";
			case 5005:
				return "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED";
			case 5006:
				return "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED";
			case 5007:
				return "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE";
			case 5008:
				return "DIAMETER_ERROR_TOO_MUCH_DATA";
			case 5009:
				return "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA";
			case 5010:
				return "DIAMETER_MISSING_USER_ID";
			case 5011:
				return "DIAMETER_ERROR_FEATURE_UNSUPPORTED";
			case 5041:
				return "DIAMETER_ERROR_USER_NO_WLAN_SUBSCRIPTION";
			case 5042:
				return "DIAMETER_ERROR_W-APN_UNUSED_BY_USER";
			case 5043:
				return "DIAMETER_ERROR_W-DIAMETER_ERROR_NO_ACCESS_INDEPENDENT_SUBSCRIPTION";
			case 5044:
				return "DIAMETER_ERROR_USER_NO_W-APN_SUBSCRIPTION";
			case 5045:
				return "DIAMETER_ERROR_UNSUITABLE_NETWORK";
			case 5061:
				return "INVALID_SERVICE_INFORMATION";
			case 5062:
				return "FILTER_RESTRICTIONS";
			case 5063:
				return "REQUESTED_SERVICE_NOT_AUTHORIZED";
			case 5064:
				return "DUPLICATED_AF_SESSION";
			case 5065:
				return "IP-CAN_SESSION_NOT_AVAILABLE";
			case 5066:
				return "UNAUTHORIZED_NON_EMERGENCY_SESSION";
			case 5100:
				return "DIAMETER_ERROR_USER_DATA_NOT_RECOGNIZED";
			case 5101:
				return "DIAMETER_ERROR_OPERATION_NOT_ALLOWED";
			case 5102:
				return "DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ";
			case 5103:
				return "DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED";
			case 5104:
				return "DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED";
			case 5105:
				return "DIAMETER_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC";
			case 5106:
				return "DIAMETER_ERROR_SUBS_DATA_ABSENT";
			case 5107:
				return "DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA";
			case 5108:
				return "DIAMETER_ERROR_DSAI_NOT_AVAILABLE";
			case 5120:
				return "DIAMETER_ERROR_START_INDICATION";
			case 5121:
				return "DIAMETER_ERROR_STOP_INDICATION";
			case 5122:
				return "DIAMETER_ERROR_UNKNOWN_MBMS_BEARER_SERVICE";
			case 5123:
				return "DIAMETER_ERROR_SERVICE_AREA";
			case 5140:
				return "DIAMETER_ERROR_INITIAL_PARAMETERS";
			case 5141:
				return "DIAMETER_ERROR_TRIGGER_EVENT";
			case 5142:
				return "DIAMETER_BEARER_EVENT";
			case 5143:
				return "DIAMETER_ERROR_BEARER_NOT_AUTHORIZED";
			case 5144:
				return "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED";
			case 5145:
				return "DIAMETER_QOS_RULE_EVENT";
			case 5146:
				return "DIAMETER_ERROR_TRAFFIC_MAPPING_INFO_REJECTED";
			case 5147:
				return "DIAMETER_ERROR_CONFLICTING_REQUEST";
			case 5401:
				return "DIAMETER_ERROR_IMPI_UNKNOWN";
			case 5402:
				return "DIAMETER_ERROR_NOT_AUTHORIZED";
			case 5403:
				return "DIAMETER_ERROR_TRANSACTION_IDENTIFIER_INVALID";
			case 5420:
				return "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION";
			case 5421:
				return "DIAMETER_ERROR_RAT_NOT_ALLOWED";
			case 5422:
				return "DIAMETER_ERROR_EQUIPMENT_UNKNOWN";
			case 5423:
				return "DIAMETER_ERROR_UNKNOWN_SERVING_NODE";
			case 5450:
				return "DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION";
			case 5451:
				return "DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION";
			case 5452:
				return "DIAMETER_ERROR_RAT_TYPE_NOT_ALLOWED";
			case 5470:
				return "DIAMETER_ERROR_SUBSESSION";
			case 5490:
				return "DIAMETER_ERROR_UNAUTHORIZED_REQUESTING_NETWORK";
			case 5510:
				return "DIAMETER_ERROR_UNAUTHORIZED_REQUESTING_ENTITY";
			case 5511:
				return "DIAMETER_ERROR_UNAUTHORIZED_SERVICE";
			case 5530:
				return "DIAMETER_ERROR_INVALID_SME_ADDRESS";
			case 5531:
				return "DIAMETER_ERROR_SC_CONGESTION";
			case 5532:
				return "DIAMETER_ERROR_SM_PROTOCOL";
			default:
				return $code;
		}
	}
	return;
}

function getDNSReplyCode($code) {
	if(strlen($code) > 0) {
		switch($code) {
		 case 0:
		   return 'No Error';
		 case 1:
		   return 'Format Error';
		 case 2:
		   return 'Server Failure';
		 case 3:
		   return 'No Such Name';
		 case 4:
		   return 'Not Implemented';
		 case 5:
		   return 'Refused';
		 case 6:
		   return 'Name Exists';
		 case 7:
		   return 'RRset Exist';
		 case 8:
		   return 'RRset Does Not Exist';
		 case 9:
		   return 'Not Authoritative';
		 case 10:
		   return 'Name Out Of Zone';
		 default:
		   return $code;
		}
	}
	return;
}

function getISUPMessageType($code) {
	if(strlen($code) > 0) {
		switch($code) {
			case 1:
				return 'INITIAL_ADDR';
			case 2:
				return 'SUBSEQ_ADDR';
			case 3:
				return 'INFO_REQ';
			case 4:
				return 'INFO';
			case 5:
				return 'CONTINUITY';
			case 6:
				return 'ADDR_CMPL';
			case 7:
				return 'CONNECT';
			case 8:
				return 'FORW_TRANS';
			case 9:
				return 'ANSWER';
			case 12:
				return 'RELEASE';
			case 13:
				return 'SUSPEND';
			case 14:
				return 'RESUME';
			case 16:
				return 'REL_CMPL';
			case 17:
				return 'CONT_CHECK_REQ';
			case 18:
				return 'RESET_CIRCUIT';
			case 19:
				return 'BLOCKING';
			case 20:
				return 'UNBLOCKING';
			case 21:
				return 'BLOCK_ACK';
			case 22:
				return 'UNBLOCK_ACK';
			case 23:
				return 'CIRC_GRP_RST';
			case 24:
				return 'CIRC_GRP_BLCK';
			case 25:
				return 'CIRC_GRP_UNBL';
			case 26:
				return 'CIRC_GRP_BL_ACK';
			case 27:
				return 'CIRC_GRP_UNBL_ACK';
			case 31:
				return 'FACILITY_REQ';
			case 32:
				return 'FACILITY_ACC';
			case 33:
				return 'FACILITY_REJ';
			case 36:
				return 'LOOP_BACK_ACK';
			case 40:
				return 'PASS_ALONG';
			case 41:
				return 'CIRC_GRP_RST_ACK';
			case 42:
				return 'CIRC_GRP_QRY';
			case 43:
				return 'CIRC_GRP_QRY_RSP';
			case 44:
				return 'CALL_PROGRSS';
			case 45:
				return 'USER2USER_INFO';
			case 46:
				return 'UNEQUIPPED_CIC';
			case 47:
				return 'CONFUSION';
			case 48:
				return 'OVERLOAD';
			case 49:
				return 'CHARGE_INFO';
			case 50:
				return 'NETW_RESRC_MGMT';
			case 51:
				return 'FACILITY';
			case 52:
				return 'USER_PART_TEST';
			case 53:
				return 'USER_PART_AVAIL';
			case 54:
				return 'IDENT_REQ';
			case 55:
				return 'IDENT_RSP';
			case 56:
				return 'SEGMENTATION';
			case 64:
				return 'LOOP_PREVENTION';
			case 65:
				return 'APPLICATION_TRANS';
			case 66:
				return 'PRE_RELEASE_INFO';
			case 67:
				return 'SUBSEQUENT_DIR_NUM';
		 default:
		   return $code;
		}
	}
	return;
}

function getISUPMessageTypeAbbrev($code) {
	if(strlen($code) > 0) {
		switch($code) {
			case 1:
				return 'IAM';
			case 2:
				return 'SAM';
			case 3:
				return 'INR';
			case 4:
				return 'INF';
			case 5:
				return 'COT';
			case 6:
				return 'ACM';
			case 7:
				return 'CON';
			case 8:
				return 'FOT';
			case 9:
				return 'ANM';
			case 12:
				return 'REL';
			case 13:
				return 'SUS';
			case 14:
				return 'RES';
			case 16:
				return 'RLC';
			case 17:
				return 'CCR';
			case 18:
				return 'RSC';
			case 19:
				return 'BLO';
			case 20:
				return 'UBL';
			case 21:
				return 'BLA';
			case 22:
				return 'UBLA';
			case 23:
				return 'GRS';
			case 24:
				return 'CGB';
			case 25:
				return 'CGU';
			case 26:
				return 'CGBA';
			case 27:
				return 'CGUA';
			case 31:
				return 'FAR';
			case 32:
				return 'FAA';
			case 33:
				return 'FRJ';
			case 36:
				return 'LPA';
			case 40:
				return 'PAM';
			case 41:
				return 'GRA';
			case 42:
				return 'CQM';
			case 43:
				return 'CQR';
			case 44:
				return 'CPG';
			case 45:
				return 'UUI';
			case 46:
				return 'UCIC';
			case 47:
				return 'CFN';
			case 48:
				return 'OLM';
			case 49:
				return 'CRG';
			case 50:
				return 'NRM';
			case 51:
				return 'FAC';
			case 52:
				return 'UPT';
			case 53:
				return 'UPA';
			case 54:
				return 'IDR';
			case 55:
				return 'IDS';
			case 56:
				return 'SGM';
			case 64:
				return 'LOP';
			case 65:
				return 'APM';
			case 66:
				return 'PRI';
			case 67:
				return 'SDN';
		 default:
		   return $code;
		}
	}
	return;
}

function logProc($accessTitle, $queryInfo, $runTime) {

	$mysql_table_name = 'user_behaviors';

	require("config/config.my");

  // disable this to prevent: "Cannot send session cache limiter
  //if(!isset($_SESSION)) session_start();

	// 2015/08/22 加入 session timeout 登出機制
	if(!isset($_SESSION)) session_start();
	if(empty($_SESSION['Username'])) {
		return -1;
	}
	$Username = $_SESSION['Username'];

  // Connecting, selecting database
	$db_host = preg_split('/:/',$my_mysql_host); # for PDO
	# 檢查連線
  try {
  	$pdo = new PDO("mysql:host=$db_host[0];port=$db_host[1]", $my_mysql_user, $my_mysql_pass);
		$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		// http://www.woiit.net/archives/388.html
		//$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
  	$pdo->query("set character set 'utf8'"); // read db
  	$pdo->query("set names 'utf8'"); // write db
  	$pdo->query("use $my_mysql_db");
	  $sql_str = "insert into $mysql_table_name ";
	  $sql_str .= '(`log_time`,`username`,`query_site`,`access_title`,`access_page`,`query_info`,`run_time`,`run_state`)';
	  $sql_str .= ' values '.'(?, ?, ?, ?, ?, ?, ?, ?)';
	  $stmt = $pdo->prepare($sql_str);
	  $pdo->beginTransaction();

	  # 檢查字串長度
	  $queryInfo = str_replace("'","\"",$queryInfo);
	  $queryInfo = strlen($queryInfo) > 2048 ? substr($queryInfo,0,2045).'...' : $queryInfo;

	  $replace_arr = array(date('Y/m/d H:i:s'),
	                       $Username,
	                       get_client_ip(),
	                       $accessTitle,
	                       basename($_SERVER['PHP_SELF']),
	                       $queryInfo,
	                       round((float)$runTime,3),
	                       get_conn_state());
	  $stmt->execute( $replace_arr);
  	# http://www.kitebird.com/articles/php-pdo.html
	  #$count = $pdo->exec($sql_str);
	  $stmt->closeCursor();
	  $pdo->commit();
  } catch (PDOException $e) {
	  if(count($replace_arr) > 0) {
	    // 取代 pdo 查詢字串
	    $sql_str = replace_arr($sql_str, $replace_arr);
	  }
  	$sql_err = '<p><font color=red>logProc fail!<br>'.$e->getMessage().'</font><br>'.
  	           'Site: '.$my_mysql_host.'; DB: '.$my_mysql_db.".".$mysql_table_name.'<br>'.
	             '<font color=blue>'.$sql_str.'</font>';
  	echo $sql_err;
  	$pdo = null;
  	return 0;
  }
  $pdo = null;
  return 1;
}

?>