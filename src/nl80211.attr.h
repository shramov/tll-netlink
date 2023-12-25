std::string_view nl80211_attr_string(nl80211_attrs attr)
{
	switch (attr) {
		case NL80211_ATTR_UNSPEC: return "NL80211_ATTR_UNSPEC";

		case NL80211_ATTR_WIPHY: return "NL80211_ATTR_WIPHY";
		case NL80211_ATTR_WIPHY_NAME: return "NL80211_ATTR_WIPHY_NAME";

		case NL80211_ATTR_IFINDEX: return "NL80211_ATTR_IFINDEX";
		case NL80211_ATTR_IFNAME: return "NL80211_ATTR_IFNAME";
		case NL80211_ATTR_IFTYPE: return "NL80211_ATTR_IFTYPE";

		case NL80211_ATTR_MAC: return "NL80211_ATTR_MAC";

		case NL80211_ATTR_KEY_DATA: return "NL80211_ATTR_KEY_DATA";
		case NL80211_ATTR_KEY_IDX: return "NL80211_ATTR_KEY_IDX";
		case NL80211_ATTR_KEY_CIPHER: return "NL80211_ATTR_KEY_CIPHER";
		case NL80211_ATTR_KEY_SEQ: return "NL80211_ATTR_KEY_SEQ";
		case NL80211_ATTR_KEY_DEFAULT: return "NL80211_ATTR_KEY_DEFAULT";

		case NL80211_ATTR_BEACON_INTERVAL: return "NL80211_ATTR_BEACON_INTERVAL";
		case NL80211_ATTR_DTIM_PERIOD: return "NL80211_ATTR_DTIM_PERIOD";
		case NL80211_ATTR_BEACON_HEAD: return "NL80211_ATTR_BEACON_HEAD";
		case NL80211_ATTR_BEACON_TAIL: return "NL80211_ATTR_BEACON_TAIL";

		case NL80211_ATTR_STA_AID: return "NL80211_ATTR_STA_AID";
		case NL80211_ATTR_STA_FLAGS: return "NL80211_ATTR_STA_FLAGS";
		case NL80211_ATTR_STA_LISTEN_INTERVAL: return "NL80211_ATTR_STA_LISTEN_INTERVAL";
		case NL80211_ATTR_STA_SUPPORTED_RATES: return "NL80211_ATTR_STA_SUPPORTED_RATES";
		case NL80211_ATTR_STA_VLAN: return "NL80211_ATTR_STA_VLAN";
		case NL80211_ATTR_STA_INFO: return "NL80211_ATTR_STA_INFO";

		case NL80211_ATTR_WIPHY_BANDS: return "NL80211_ATTR_WIPHY_BANDS";

		case NL80211_ATTR_MNTR_FLAGS: return "NL80211_ATTR_MNTR_FLAGS";

		case NL80211_ATTR_MESH_ID: return "NL80211_ATTR_MESH_ID";
		case NL80211_ATTR_STA_PLINK_ACTION: return "NL80211_ATTR_STA_PLINK_ACTION";
		case NL80211_ATTR_MPATH_NEXT_HOP: return "NL80211_ATTR_MPATH_NEXT_HOP";
		case NL80211_ATTR_MPATH_INFO: return "NL80211_ATTR_MPATH_INFO";

		case NL80211_ATTR_BSS_CTS_PROT: return "NL80211_ATTR_BSS_CTS_PROT";
		case NL80211_ATTR_BSS_SHORT_PREAMBLE: return "NL80211_ATTR_BSS_SHORT_PREAMBLE";
		case NL80211_ATTR_BSS_SHORT_SLOT_TIME: return "NL80211_ATTR_BSS_SHORT_SLOT_TIME";

		case NL80211_ATTR_HT_CAPABILITY: return "NL80211_ATTR_HT_CAPABILITY";

		case NL80211_ATTR_SUPPORTED_IFTYPES: return "NL80211_ATTR_SUPPORTED_IFTYPES";

		case NL80211_ATTR_REG_ALPHA2: return "NL80211_ATTR_REG_ALPHA2";
		case NL80211_ATTR_REG_RULES: return "NL80211_ATTR_REG_RULES";

		case NL80211_ATTR_MESH_CONFIG: return "NL80211_ATTR_MESH_CONFIG";

		case NL80211_ATTR_BSS_BASIC_RATES: return "NL80211_ATTR_BSS_BASIC_RATES";

		case NL80211_ATTR_WIPHY_TXQ_PARAMS: return "NL80211_ATTR_WIPHY_TXQ_PARAMS";
		case NL80211_ATTR_WIPHY_FREQ: return "NL80211_ATTR_WIPHY_FREQ";
		case NL80211_ATTR_WIPHY_CHANNEL_TYPE: return "NL80211_ATTR_WIPHY_CHANNEL_TYPE";

		case NL80211_ATTR_KEY_DEFAULT_MGMT: return "NL80211_ATTR_KEY_DEFAULT_MGMT";

		case NL80211_ATTR_MGMT_SUBTYPE: return "NL80211_ATTR_MGMT_SUBTYPE";
		case NL80211_ATTR_IE: return "NL80211_ATTR_IE";

		case NL80211_ATTR_MAX_NUM_SCAN_SSIDS: return "NL80211_ATTR_MAX_NUM_SCAN_SSIDS";

		case NL80211_ATTR_SCAN_FREQUENCIES: return "NL80211_ATTR_SCAN_FREQUENCIES";
		case NL80211_ATTR_SCAN_SSIDS: return "NL80211_ATTR_SCAN_SSIDS";
		case NL80211_ATTR_GENERATION: return "NL80211_ATTR_GENERATION"; /* replaces old SCAN_GENERATION */
		case NL80211_ATTR_BSS: return "NL80211_ATTR_BSS";

		case NL80211_ATTR_REG_INITIATOR: return "NL80211_ATTR_REG_INITIATOR";
		case NL80211_ATTR_REG_TYPE: return "NL80211_ATTR_REG_TYPE";

		case NL80211_ATTR_SUPPORTED_COMMANDS: return "NL80211_ATTR_SUPPORTED_COMMANDS";

		case NL80211_ATTR_FRAME: return "NL80211_ATTR_FRAME";
		case NL80211_ATTR_SSID: return "NL80211_ATTR_SSID";
		case NL80211_ATTR_AUTH_TYPE: return "NL80211_ATTR_AUTH_TYPE";
		case NL80211_ATTR_REASON_CODE: return "NL80211_ATTR_REASON_CODE";

		case NL80211_ATTR_KEY_TYPE: return "NL80211_ATTR_KEY_TYPE";

		case NL80211_ATTR_MAX_SCAN_IE_LEN: return "NL80211_ATTR_MAX_SCAN_IE_LEN";
		case NL80211_ATTR_CIPHER_SUITES: return "NL80211_ATTR_CIPHER_SUITES";

		case NL80211_ATTR_FREQ_BEFORE: return "NL80211_ATTR_FREQ_BEFORE";
		case NL80211_ATTR_FREQ_AFTER: return "NL80211_ATTR_FREQ_AFTER";

		case NL80211_ATTR_FREQ_FIXED: return "NL80211_ATTR_FREQ_FIXED";


		case NL80211_ATTR_WIPHY_RETRY_SHORT: return "NL80211_ATTR_WIPHY_RETRY_SHORT";
		case NL80211_ATTR_WIPHY_RETRY_LONG: return "NL80211_ATTR_WIPHY_RETRY_LONG";
		case NL80211_ATTR_WIPHY_FRAG_THRESHOLD: return "NL80211_ATTR_WIPHY_FRAG_THRESHOLD";
		case NL80211_ATTR_WIPHY_RTS_THRESHOLD: return "NL80211_ATTR_WIPHY_RTS_THRESHOLD";

		case NL80211_ATTR_TIMED_OUT: return "NL80211_ATTR_TIMED_OUT";

		case NL80211_ATTR_USE_MFP: return "NL80211_ATTR_USE_MFP";

		case NL80211_ATTR_STA_FLAGS2: return "NL80211_ATTR_STA_FLAGS2";

		case NL80211_ATTR_CONTROL_PORT: return "NL80211_ATTR_CONTROL_PORT";

		case NL80211_ATTR_TESTDATA: return "NL80211_ATTR_TESTDATA";

		case NL80211_ATTR_PRIVACY: return "NL80211_ATTR_PRIVACY";

		case NL80211_ATTR_DISCONNECTED_BY_AP: return "NL80211_ATTR_DISCONNECTED_BY_AP";
		case NL80211_ATTR_STATUS_CODE: return "NL80211_ATTR_STATUS_CODE";

		case NL80211_ATTR_CIPHER_SUITES_PAIRWISE: return "NL80211_ATTR_CIPHER_SUITES_PAIRWISE";
		case NL80211_ATTR_CIPHER_SUITE_GROUP: return "NL80211_ATTR_CIPHER_SUITE_GROUP";
		case NL80211_ATTR_WPA_VERSIONS: return "NL80211_ATTR_WPA_VERSIONS";
		case NL80211_ATTR_AKM_SUITES: return "NL80211_ATTR_AKM_SUITES";

		case NL80211_ATTR_REQ_IE: return "NL80211_ATTR_REQ_IE";
		case NL80211_ATTR_RESP_IE: return "NL80211_ATTR_RESP_IE";

		case NL80211_ATTR_PREV_BSSID: return "NL80211_ATTR_PREV_BSSID";

		case NL80211_ATTR_KEY: return "NL80211_ATTR_KEY";
		case NL80211_ATTR_KEYS: return "NL80211_ATTR_KEYS";

		case NL80211_ATTR_PID: return "NL80211_ATTR_PID";

		case NL80211_ATTR_4ADDR: return "NL80211_ATTR_4ADDR";

		case NL80211_ATTR_SURVEY_INFO: return "NL80211_ATTR_SURVEY_INFO";

		case NL80211_ATTR_PMKID: return "NL80211_ATTR_PMKID";
		case NL80211_ATTR_MAX_NUM_PMKIDS: return "NL80211_ATTR_MAX_NUM_PMKIDS";

		case NL80211_ATTR_DURATION: return "NL80211_ATTR_DURATION";

		case NL80211_ATTR_COOKIE: return "NL80211_ATTR_COOKIE";

		case NL80211_ATTR_WIPHY_COVERAGE_CLASS: return "NL80211_ATTR_WIPHY_COVERAGE_CLASS";

		case NL80211_ATTR_TX_RATES: return "NL80211_ATTR_TX_RATES";

		case NL80211_ATTR_FRAME_MATCH: return "NL80211_ATTR_FRAME_MATCH";

		case NL80211_ATTR_ACK: return "NL80211_ATTR_ACK";

		case NL80211_ATTR_PS_STATE: return "NL80211_ATTR_PS_STATE";

		case NL80211_ATTR_CQM: return "NL80211_ATTR_CQM";

		case NL80211_ATTR_LOCAL_STATE_CHANGE: return "NL80211_ATTR_LOCAL_STATE_CHANGE";

		case NL80211_ATTR_AP_ISOLATE: return "NL80211_ATTR_AP_ISOLATE";

		case NL80211_ATTR_WIPHY_TX_POWER_SETTING: return "NL80211_ATTR_WIPHY_TX_POWER_SETTING";
		case NL80211_ATTR_WIPHY_TX_POWER_LEVEL: return "NL80211_ATTR_WIPHY_TX_POWER_LEVEL";

		case NL80211_ATTR_TX_FRAME_TYPES: return "NL80211_ATTR_TX_FRAME_TYPES";
		case NL80211_ATTR_RX_FRAME_TYPES: return "NL80211_ATTR_RX_FRAME_TYPES";
		case NL80211_ATTR_FRAME_TYPE: return "NL80211_ATTR_FRAME_TYPE";

		case NL80211_ATTR_CONTROL_PORT_ETHERTYPE: return "NL80211_ATTR_CONTROL_PORT_ETHERTYPE";
		case NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT: return "NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT";

		case NL80211_ATTR_SUPPORT_IBSS_RSN: return "NL80211_ATTR_SUPPORT_IBSS_RSN";

		case NL80211_ATTR_WIPHY_ANTENNA_TX: return "NL80211_ATTR_WIPHY_ANTENNA_TX";
		case NL80211_ATTR_WIPHY_ANTENNA_RX: return "NL80211_ATTR_WIPHY_ANTENNA_RX";

		case NL80211_ATTR_MCAST_RATE: return "NL80211_ATTR_MCAST_RATE";

		case NL80211_ATTR_OFFCHANNEL_TX_OK: return "NL80211_ATTR_OFFCHANNEL_TX_OK";

		case NL80211_ATTR_BSS_HT_OPMODE: return "NL80211_ATTR_BSS_HT_OPMODE";

		case NL80211_ATTR_KEY_DEFAULT_TYPES: return "NL80211_ATTR_KEY_DEFAULT_TYPES";

		case NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION: return "NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION";

		case NL80211_ATTR_MESH_SETUP: return "NL80211_ATTR_MESH_SETUP";

		case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX: return "NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX";
		case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX: return "NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX";

		case NL80211_ATTR_SUPPORT_MESH_AUTH: return "NL80211_ATTR_SUPPORT_MESH_AUTH";
		case NL80211_ATTR_STA_PLINK_STATE: return "NL80211_ATTR_STA_PLINK_STATE";

		case NL80211_ATTR_WOWLAN_TRIGGERS: return "NL80211_ATTR_WOWLAN_TRIGGERS";
		case NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED: return "NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED";

		case NL80211_ATTR_SCHED_SCAN_INTERVAL: return "NL80211_ATTR_SCHED_SCAN_INTERVAL";

		case NL80211_ATTR_INTERFACE_COMBINATIONS: return "NL80211_ATTR_INTERFACE_COMBINATIONS";
		case NL80211_ATTR_SOFTWARE_IFTYPES: return "NL80211_ATTR_SOFTWARE_IFTYPES";

		case NL80211_ATTR_REKEY_DATA: return "NL80211_ATTR_REKEY_DATA";

		case NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS: return "NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS";
		case NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN: return "NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN";

		case NL80211_ATTR_SCAN_SUPP_RATES: return "NL80211_ATTR_SCAN_SUPP_RATES";

		case NL80211_ATTR_HIDDEN_SSID: return "NL80211_ATTR_HIDDEN_SSID";

		case NL80211_ATTR_IE_PROBE_RESP: return "NL80211_ATTR_IE_PROBE_RESP";
		case NL80211_ATTR_IE_ASSOC_RESP: return "NL80211_ATTR_IE_ASSOC_RESP";

		case NL80211_ATTR_STA_WME: return "NL80211_ATTR_STA_WME";
		case NL80211_ATTR_SUPPORT_AP_UAPSD: return "NL80211_ATTR_SUPPORT_AP_UAPSD";

		case NL80211_ATTR_ROAM_SUPPORT: return "NL80211_ATTR_ROAM_SUPPORT";

		case NL80211_ATTR_SCHED_SCAN_MATCH: return "NL80211_ATTR_SCHED_SCAN_MATCH";
		case NL80211_ATTR_MAX_MATCH_SETS: return "NL80211_ATTR_MAX_MATCH_SETS";

		case NL80211_ATTR_PMKSA_CANDIDATE: return "NL80211_ATTR_PMKSA_CANDIDATE";

		case NL80211_ATTR_TX_NO_CCK_RATE: return "NL80211_ATTR_TX_NO_CCK_RATE";

		case NL80211_ATTR_TDLS_ACTION: return "NL80211_ATTR_TDLS_ACTION";
		case NL80211_ATTR_TDLS_DIALOG_TOKEN: return "NL80211_ATTR_TDLS_DIALOG_TOKEN";
		case NL80211_ATTR_TDLS_OPERATION: return "NL80211_ATTR_TDLS_OPERATION";
		case NL80211_ATTR_TDLS_SUPPORT: return "NL80211_ATTR_TDLS_SUPPORT";
		case NL80211_ATTR_TDLS_EXTERNAL_SETUP: return "NL80211_ATTR_TDLS_EXTERNAL_SETUP";

		case NL80211_ATTR_DEVICE_AP_SME: return "NL80211_ATTR_DEVICE_AP_SME";

		case NL80211_ATTR_DONT_WAIT_FOR_ACK: return "NL80211_ATTR_DONT_WAIT_FOR_ACK";

		case NL80211_ATTR_FEATURE_FLAGS: return "NL80211_ATTR_FEATURE_FLAGS";

		case NL80211_ATTR_PROBE_RESP_OFFLOAD: return "NL80211_ATTR_PROBE_RESP_OFFLOAD";

		case NL80211_ATTR_PROBE_RESP: return "NL80211_ATTR_PROBE_RESP";

		case NL80211_ATTR_DFS_REGION: return "NL80211_ATTR_DFS_REGION";

		case NL80211_ATTR_DISABLE_HT: return "NL80211_ATTR_DISABLE_HT";
		case NL80211_ATTR_HT_CAPABILITY_MASK: return "NL80211_ATTR_HT_CAPABILITY_MASK";

		case NL80211_ATTR_NOACK_MAP: return "NL80211_ATTR_NOACK_MAP";

		case NL80211_ATTR_INACTIVITY_TIMEOUT: return "NL80211_ATTR_INACTIVITY_TIMEOUT";

		case NL80211_ATTR_RX_SIGNAL_DBM: return "NL80211_ATTR_RX_SIGNAL_DBM";

		case NL80211_ATTR_BG_SCAN_PERIOD: return "NL80211_ATTR_BG_SCAN_PERIOD";

		case NL80211_ATTR_WDEV: return "NL80211_ATTR_WDEV";

		case NL80211_ATTR_USER_REG_HINT_TYPE: return "NL80211_ATTR_USER_REG_HINT_TYPE";

		case NL80211_ATTR_CONN_FAILED_REASON: return "NL80211_ATTR_CONN_FAILED_REASON";

		case NL80211_ATTR_AUTH_DATA: return "NL80211_ATTR_AUTH_DATA";

		case NL80211_ATTR_VHT_CAPABILITY: return "NL80211_ATTR_VHT_CAPABILITY";

		case NL80211_ATTR_SCAN_FLAGS: return "NL80211_ATTR_SCAN_FLAGS";

		case NL80211_ATTR_CHANNEL_WIDTH: return "NL80211_ATTR_CHANNEL_WIDTH";
		case NL80211_ATTR_CENTER_FREQ1: return "NL80211_ATTR_CENTER_FREQ1";
		case NL80211_ATTR_CENTER_FREQ2: return "NL80211_ATTR_CENTER_FREQ2";

		case NL80211_ATTR_P2P_CTWINDOW: return "NL80211_ATTR_P2P_CTWINDOW";
		case NL80211_ATTR_P2P_OPPPS: return "NL80211_ATTR_P2P_OPPPS";

		case NL80211_ATTR_LOCAL_MESH_POWER_MODE: return "NL80211_ATTR_LOCAL_MESH_POWER_MODE";

		case NL80211_ATTR_ACL_POLICY: return "NL80211_ATTR_ACL_POLICY";

		case NL80211_ATTR_MAC_ADDRS: return "NL80211_ATTR_MAC_ADDRS";

		case NL80211_ATTR_MAC_ACL_MAX: return "NL80211_ATTR_MAC_ACL_MAX";

		case NL80211_ATTR_RADAR_EVENT: return "NL80211_ATTR_RADAR_EVENT";

		case NL80211_ATTR_EXT_CAPA: return "NL80211_ATTR_EXT_CAPA";
		case NL80211_ATTR_EXT_CAPA_MASK: return "NL80211_ATTR_EXT_CAPA_MASK";

		case NL80211_ATTR_STA_CAPABILITY: return "NL80211_ATTR_STA_CAPABILITY";
		case NL80211_ATTR_STA_EXT_CAPABILITY: return "NL80211_ATTR_STA_EXT_CAPABILITY";

		case NL80211_ATTR_PROTOCOL_FEATURES: return "NL80211_ATTR_PROTOCOL_FEATURES";
		case NL80211_ATTR_SPLIT_WIPHY_DUMP: return "NL80211_ATTR_SPLIT_WIPHY_DUMP";

		case NL80211_ATTR_DISABLE_VHT: return "NL80211_ATTR_DISABLE_VHT";
		case NL80211_ATTR_VHT_CAPABILITY_MASK: return "NL80211_ATTR_VHT_CAPABILITY_MASK";

		case NL80211_ATTR_MDID: return "NL80211_ATTR_MDID";
		case NL80211_ATTR_IE_RIC: return "NL80211_ATTR_IE_RIC";

		case NL80211_ATTR_CRIT_PROT_ID: return "NL80211_ATTR_CRIT_PROT_ID";
		case NL80211_ATTR_MAX_CRIT_PROT_DURATION: return "NL80211_ATTR_MAX_CRIT_PROT_DURATION";

		case NL80211_ATTR_PEER_AID: return "NL80211_ATTR_PEER_AID";

		case NL80211_ATTR_COALESCE_RULE: return "NL80211_ATTR_COALESCE_RULE";

		case NL80211_ATTR_CH_SWITCH_COUNT: return "NL80211_ATTR_CH_SWITCH_COUNT";
		case NL80211_ATTR_CH_SWITCH_BLOCK_TX: return "NL80211_ATTR_CH_SWITCH_BLOCK_TX";
		case NL80211_ATTR_CSA_IES: return "NL80211_ATTR_CSA_IES";
		case NL80211_ATTR_CNTDWN_OFFS_BEACON: return "NL80211_ATTR_CNTDWN_OFFS_BEACON";
		case NL80211_ATTR_CNTDWN_OFFS_PRESP: return "NL80211_ATTR_CNTDWN_OFFS_PRESP";

		case NL80211_ATTR_RXMGMT_FLAGS: return "NL80211_ATTR_RXMGMT_FLAGS";

		case NL80211_ATTR_STA_SUPPORTED_CHANNELS: return "NL80211_ATTR_STA_SUPPORTED_CHANNELS";

		case NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES: return "NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES";

		case NL80211_ATTR_HANDLE_DFS: return "NL80211_ATTR_HANDLE_DFS";

		case NL80211_ATTR_SUPPORT_5_MHZ: return "NL80211_ATTR_SUPPORT_5_MHZ";
		case NL80211_ATTR_SUPPORT_10_MHZ: return "NL80211_ATTR_SUPPORT_10_MHZ";

		case NL80211_ATTR_OPMODE_NOTIF: return "NL80211_ATTR_OPMODE_NOTIF";

		case NL80211_ATTR_VENDOR_ID: return "NL80211_ATTR_VENDOR_ID";
		case NL80211_ATTR_VENDOR_SUBCMD: return "NL80211_ATTR_VENDOR_SUBCMD";
		case NL80211_ATTR_VENDOR_DATA: return "NL80211_ATTR_VENDOR_DATA";
		case NL80211_ATTR_VENDOR_EVENTS: return "NL80211_ATTR_VENDOR_EVENTS";

		case NL80211_ATTR_QOS_MAP: return "NL80211_ATTR_QOS_MAP";

		case NL80211_ATTR_MAC_HINT: return "NL80211_ATTR_MAC_HINT";
		case NL80211_ATTR_WIPHY_FREQ_HINT: return "NL80211_ATTR_WIPHY_FREQ_HINT";

		case NL80211_ATTR_MAX_AP_ASSOC_STA: return "NL80211_ATTR_MAX_AP_ASSOC_STA";

		case NL80211_ATTR_TDLS_PEER_CAPABILITY: return "NL80211_ATTR_TDLS_PEER_CAPABILITY";

		case NL80211_ATTR_SOCKET_OWNER: return "NL80211_ATTR_SOCKET_OWNER";

		case NL80211_ATTR_CSA_C_OFFSETS_TX: return "NL80211_ATTR_CSA_C_OFFSETS_TX";
		case NL80211_ATTR_MAX_CSA_COUNTERS: return "NL80211_ATTR_MAX_CSA_COUNTERS";

		case NL80211_ATTR_TDLS_INITIATOR: return "NL80211_ATTR_TDLS_INITIATOR";

		case NL80211_ATTR_USE_RRM: return "NL80211_ATTR_USE_RRM";

		case NL80211_ATTR_WIPHY_DYN_ACK: return "NL80211_ATTR_WIPHY_DYN_ACK";

		case NL80211_ATTR_TSID: return "NL80211_ATTR_TSID";
		case NL80211_ATTR_USER_PRIO: return "NL80211_ATTR_USER_PRIO";
		case NL80211_ATTR_ADMITTED_TIME: return "NL80211_ATTR_ADMITTED_TIME";

		case NL80211_ATTR_SMPS_MODE: return "NL80211_ATTR_SMPS_MODE";

		case NL80211_ATTR_OPER_CLASS: return "NL80211_ATTR_OPER_CLASS";

		case NL80211_ATTR_MAC_MASK: return "NL80211_ATTR_MAC_MASK";

		case NL80211_ATTR_WIPHY_SELF_MANAGED_REG: return "NL80211_ATTR_WIPHY_SELF_MANAGED_REG";

		case NL80211_ATTR_EXT_FEATURES: return "NL80211_ATTR_EXT_FEATURES";

		case NL80211_ATTR_SURVEY_RADIO_STATS: return "NL80211_ATTR_SURVEY_RADIO_STATS";

		case NL80211_ATTR_NETNS_FD: return "NL80211_ATTR_NETNS_FD";

		case NL80211_ATTR_SCHED_SCAN_DELAY: return "NL80211_ATTR_SCHED_SCAN_DELAY";

		case NL80211_ATTR_REG_INDOOR: return "NL80211_ATTR_REG_INDOOR";

		case NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS: return "NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS";
		case NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL: return "NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL";
		case NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS: return "NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS";
		case NL80211_ATTR_SCHED_SCAN_PLANS: return "NL80211_ATTR_SCHED_SCAN_PLANS";

		case NL80211_ATTR_PBSS: return "NL80211_ATTR_PBSS";

		case NL80211_ATTR_BSS_SELECT: return "NL80211_ATTR_BSS_SELECT";

		case NL80211_ATTR_STA_SUPPORT_P2P_PS: return "NL80211_ATTR_STA_SUPPORT_P2P_PS";

		case NL80211_ATTR_PAD: return "NL80211_ATTR_PAD";

		case NL80211_ATTR_IFTYPE_EXT_CAPA: return "NL80211_ATTR_IFTYPE_EXT_CAPA";

		case NL80211_ATTR_MU_MIMO_GROUP_DATA: return "NL80211_ATTR_MU_MIMO_GROUP_DATA";
		case NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR: return "NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR";

		case NL80211_ATTR_SCAN_START_TIME_TSF: return "NL80211_ATTR_SCAN_START_TIME_TSF";
		case NL80211_ATTR_SCAN_START_TIME_TSF_BSSID: return "NL80211_ATTR_SCAN_START_TIME_TSF_BSSID";
		case NL80211_ATTR_MEASUREMENT_DURATION: return "NL80211_ATTR_MEASUREMENT_DURATION";
		case NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY: return "NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY";

		case NL80211_ATTR_MESH_PEER_AID: return "NL80211_ATTR_MESH_PEER_AID";

		case NL80211_ATTR_NAN_MASTER_PREF: return "NL80211_ATTR_NAN_MASTER_PREF";
		case NL80211_ATTR_BANDS: return "NL80211_ATTR_BANDS";
		case NL80211_ATTR_NAN_FUNC: return "NL80211_ATTR_NAN_FUNC";
		case NL80211_ATTR_NAN_MATCH: return "NL80211_ATTR_NAN_MATCH";

		case NL80211_ATTR_FILS_KEK: return "NL80211_ATTR_FILS_KEK";
		case NL80211_ATTR_FILS_NONCES: return "NL80211_ATTR_FILS_NONCES";

		case NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED: return "NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED";

		case NL80211_ATTR_BSSID: return "NL80211_ATTR_BSSID";

		case NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI: return "NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI";
		case NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST: return "NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST";

		case NL80211_ATTR_TIMEOUT_REASON: return "NL80211_ATTR_TIMEOUT_REASON";

		case NL80211_ATTR_FILS_ERP_USERNAME: return "NL80211_ATTR_FILS_ERP_USERNAME";
		case NL80211_ATTR_FILS_ERP_REALM: return "NL80211_ATTR_FILS_ERP_REALM";
		case NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM: return "NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM";
		case NL80211_ATTR_FILS_ERP_RRK: return "NL80211_ATTR_FILS_ERP_RRK";
		case NL80211_ATTR_FILS_CACHE_ID: return "NL80211_ATTR_FILS_CACHE_ID";

		case NL80211_ATTR_PMK: return "NL80211_ATTR_PMK";

		case NL80211_ATTR_SCHED_SCAN_MULTI: return "NL80211_ATTR_SCHED_SCAN_MULTI";
		case NL80211_ATTR_SCHED_SCAN_MAX_REQS: return "NL80211_ATTR_SCHED_SCAN_MAX_REQS";

		case NL80211_ATTR_WANT_1X_4WAY_HS: return "NL80211_ATTR_WANT_1X_4WAY_HS";
		case NL80211_ATTR_PMKR0_NAME: return "NL80211_ATTR_PMKR0_NAME";
		case NL80211_ATTR_PORT_AUTHORIZED: return "NL80211_ATTR_PORT_AUTHORIZED";

		case NL80211_ATTR_EXTERNAL_AUTH_ACTION: return "NL80211_ATTR_EXTERNAL_AUTH_ACTION";
		case NL80211_ATTR_EXTERNAL_AUTH_SUPPORT: return "NL80211_ATTR_EXTERNAL_AUTH_SUPPORT";

		case NL80211_ATTR_NSS: return "NL80211_ATTR_NSS";
		case NL80211_ATTR_ACK_SIGNAL: return "NL80211_ATTR_ACK_SIGNAL";

		case NL80211_ATTR_CONTROL_PORT_OVER_NL80211: return "NL80211_ATTR_CONTROL_PORT_OVER_NL80211";

		case NL80211_ATTR_TXQ_STATS: return "NL80211_ATTR_TXQ_STATS";
		case NL80211_ATTR_TXQ_LIMIT: return "NL80211_ATTR_TXQ_LIMIT";
		case NL80211_ATTR_TXQ_MEMORY_LIMIT: return "NL80211_ATTR_TXQ_MEMORY_LIMIT";
		case NL80211_ATTR_TXQ_QUANTUM: return "NL80211_ATTR_TXQ_QUANTUM";

		case NL80211_ATTR_HE_CAPABILITY: return "NL80211_ATTR_HE_CAPABILITY";

		case NL80211_ATTR_FTM_RESPONDER: return "NL80211_ATTR_FTM_RESPONDER";

		case NL80211_ATTR_FTM_RESPONDER_STATS: return "NL80211_ATTR_FTM_RESPONDER_STATS";

		case NL80211_ATTR_TIMEOUT: return "NL80211_ATTR_TIMEOUT";

		case NL80211_ATTR_PEER_MEASUREMENTS: return "NL80211_ATTR_PEER_MEASUREMENTS";

		case NL80211_ATTR_AIRTIME_WEIGHT: return "NL80211_ATTR_AIRTIME_WEIGHT";
		case NL80211_ATTR_STA_TX_POWER_SETTING: return "NL80211_ATTR_STA_TX_POWER_SETTING";
		case NL80211_ATTR_STA_TX_POWER: return "NL80211_ATTR_STA_TX_POWER";

		case NL80211_ATTR_SAE_PASSWORD: return "NL80211_ATTR_SAE_PASSWORD";

		case NL80211_ATTR_TWT_RESPONDER: return "NL80211_ATTR_TWT_RESPONDER";

		case NL80211_ATTR_HE_OBSS_PD: return "NL80211_ATTR_HE_OBSS_PD";

		case NL80211_ATTR_WIPHY_EDMG_CHANNELS: return "NL80211_ATTR_WIPHY_EDMG_CHANNELS";
		case NL80211_ATTR_WIPHY_EDMG_BW_CONFIG: return "NL80211_ATTR_WIPHY_EDMG_BW_CONFIG";

		case NL80211_ATTR_VLAN_ID: return "NL80211_ATTR_VLAN_ID";

		case NL80211_ATTR_HE_BSS_COLOR: return "NL80211_ATTR_HE_BSS_COLOR";

		case NL80211_ATTR_IFTYPE_AKM_SUITES: return "NL80211_ATTR_IFTYPE_AKM_SUITES";

		case NL80211_ATTR_TID_CONFIG: return "NL80211_ATTR_TID_CONFIG";

		case NL80211_ATTR_CONTROL_PORT_NO_PREAUTH: return "NL80211_ATTR_CONTROL_PORT_NO_PREAUTH";

		case NL80211_ATTR_PMK_LIFETIME: return "NL80211_ATTR_PMK_LIFETIME";
		case NL80211_ATTR_PMK_REAUTH_THRESHOLD: return "NL80211_ATTR_PMK_REAUTH_THRESHOLD";

		case NL80211_ATTR_RECEIVE_MULTICAST: return "NL80211_ATTR_RECEIVE_MULTICAST";
		case NL80211_ATTR_WIPHY_FREQ_OFFSET: return "NL80211_ATTR_WIPHY_FREQ_OFFSET";
		case NL80211_ATTR_CENTER_FREQ1_OFFSET: return "NL80211_ATTR_CENTER_FREQ1_OFFSET";
		case NL80211_ATTR_SCAN_FREQ_KHZ: return "NL80211_ATTR_SCAN_FREQ_KHZ";

		case NL80211_ATTR_HE_6GHZ_CAPABILITY: return "NL80211_ATTR_HE_6GHZ_CAPABILITY";

		case NL80211_ATTR_FILS_DISCOVERY: return "NL80211_ATTR_FILS_DISCOVERY";

		case NL80211_ATTR_UNSOL_BCAST_PROBE_RESP: return "NL80211_ATTR_UNSOL_BCAST_PROBE_RESP";

		case NL80211_ATTR_S1G_CAPABILITY: return "NL80211_ATTR_S1G_CAPABILITY";
		case NL80211_ATTR_S1G_CAPABILITY_MASK: return "NL80211_ATTR_S1G_CAPABILITY_MASK";

		case NL80211_ATTR_SAE_PWE: return "NL80211_ATTR_SAE_PWE";
		case NL80211_ATTR_RECONNECT_REQUESTED: return "NL80211_ATTR_RECONNECT_REQUESTED";
		case NL80211_ATTR_SAR_SPEC: return "NL80211_ATTR_SAR_SPEC";
		case NL80211_ATTR_DISABLE_HE: return "NL80211_ATTR_DISABLE_HE";
		case NL80211_ATTR_OBSS_COLOR_BITMAP: return "NL80211_ATTR_OBSS_COLOR_BITMAP";
		case NL80211_ATTR_COLOR_CHANGE_COUNT: return "NL80211_ATTR_COLOR_CHANGE_COUNT";
		case NL80211_ATTR_COLOR_CHANGE_COLOR: return "NL80211_ATTR_COLOR_CHANGE_COLOR";
		case NL80211_ATTR_COLOR_CHANGE_ELEMS: return "NL80211_ATTR_COLOR_CHANGE_ELEMS";
		case NL80211_ATTR_MBSSID_CONFIG: return "NL80211_ATTR_MBSSID_CONFIG";
		case NL80211_ATTR_MBSSID_ELEMS: return "NL80211_ATTR_MBSSID_ELEMS";
		case NL80211_ATTR_RADAR_BACKGROUND: return "NL80211_ATTR_RADAR_BACKGROUND";
		case NL80211_ATTR_AP_SETTINGS_FLAGS: return "NL80211_ATTR_AP_SETTINGS_FLAGS";
		case NL80211_ATTR_EHT_CAPABILITY: return "NL80211_ATTR_EHT_CAPABILITY";
		case NL80211_ATTR_DISABLE_EHT: return "NL80211_ATTR_DISABLE_EHT";
		case NL80211_ATTR_MLO_LINKS: return "NL80211_ATTR_MLO_LINKS";
		case NL80211_ATTR_MLO_LINK_ID: return "NL80211_ATTR_MLO_LINK_ID";
		case NL80211_ATTR_MLD_ADDR: return "NL80211_ATTR_MLD_ADDR";
		case NL80211_ATTR_MLO_SUPPORT: return "NL80211_ATTR_MLO_SUPPORT";
		case NL80211_ATTR_MAX_NUM_AKM_SUITES: return "NL80211_ATTR_MAX_NUM_AKM_SUITES";
		case NL80211_ATTR_EML_CAPABILITY: return "NL80211_ATTR_EML_CAPABILITY";
		case NL80211_ATTR_MLD_CAPA_AND_OPS: return "NL80211_ATTR_MLD_CAPA_AND_OPS";
		case NL80211_ATTR_TX_HW_TIMESTAMP: return "NL80211_ATTR_TX_HW_TIMESTAMP";
		case NL80211_ATTR_RX_HW_TIMESTAMP: return "NL80211_ATTR_RX_HW_TIMESTAMP";
		case NL80211_ATTR_TD_BITMAP: return "NL80211_ATTR_TD_BITMAP";
		case NL80211_ATTR_PUNCT_BITMAP: return "NL80211_ATTR_PUNCT_BITMAP";
		case NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS: return "NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS";
		case NL80211_ATTR_HW_TIMESTAMP_ENABLED: return "NL80211_ATTR_HW_TIMESTAMP_ENABLED";
		case NL80211_ATTR_EMA_RNR_ELEMS: return "NL80211_ATTR_EMA_RNR_ELEMS";
		case NL80211_ATTR_MLO_LINK_DISABLED: return "NL80211_ATTR_MLO_LINK_DISABLED";

		case __NL80211_ATTR_AFTER_LAST: return "__NL80211_ATTR_AFTER_LAST";

	}
	return "Unknown";
}
