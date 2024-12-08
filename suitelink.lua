-- Suitelink protocol for Wireshark / Finngineering 2024

-- HANDLER FUNCTIONS
-- Each handler function below recieves the normal information about the packet
-- to dissect, and additionally the starting position of the message in the tcp
-- payload as well as an info object for the stream. Each handler should dis-
-- sect the message and return the length of the message / bytes handled. A negative
-- return value indicates the amount of missing bytes to decode the message. A
-- return value of 0 indicates that the message could not be handled. In case the
-- handler needs more bytes to decode the message but do not know how many, tough
-- luck. No such option available


local length_based_on_commtype = true

sl_protocol = Proto("Suitelink",  "Suitelink Protocol")

local streams

function sl_protocol.init()
  streams = {}
end

-- Register tcp stream. In case it already exists, update the name (only)
function stream_register(pinfo, name)
  -- Get client port
  local client_port = stream_client_port(pinfo)
  -- Dont reset stream information in case it has already been created
  if streams[client_port] == nil then
    streams[client_port] = {}
    streams[client_port].tags = {}
    streams[client_port].type = "unknown"
    streams[client_port].type_start_after = 1e9 -- TODO: should be handled in a nicer way (look for comparisons to .type_start_after)
  end
  streams[client_port].name = name
end

-- Add a mapping between a tag id and a tag name to the this stream
function stream_advise(pinfo, tag_id, tag_name)
  streams[pinfo.src_port].tags[tag_id] = tag_name
end

-- Set communication type for stream. At the time of writing, either "normal" or "alarmmgr" are used.
-- Only messages after this one will be marked with the provided type
function stream_set_type(pinfo, type)
  client_port = stream_client_port(pinfo)
  streams[client_port].type = type
  streams[client_port].type_start_after = pinfo.number
end

-- Same as stream_set_type, but set only incase pinfo.number is lower than where type was previously set
function stream_update_type(pinfo, type)
  client_port = stream_client_port(pinfo)
  if pinfo.number < streams[client_port].type_start_after then
    streams[client_port].type = type
    streams[client_port].type_start_after = pinfo.number
  end
end

-- Return the communication type for this message in the stream. If a message 
function stream_get_type(pinfo)
  client_port = stream_client_port(pinfo)

  -- Return Unknown in case no type is defined
  if streams[client_port] == nil or streams[client_port].type == nil then
    return "unknown"
  end

  -- Return define type in case pinfo.number is largr than type_start_after, and
  -- otherwise return Unknown
  start_after = streams[client_port].type_start_after
  if start_after == nil or pinfo.number <= start_after then
    return "unknown"
  else
    return streams[client_port].type
  end
end

-- Return tag_name based on provided tag_id for stream defined by pinfo
function stream_tagname(pinfo, tag_id)
  local client_port = stream_client_port(pinfo)

  local tag_name = "__UNKNOWN__"
  if streams[client_port] ~= nil then
    tag_name = streams[client_port].tags[tag_id]
    if tag_name == nil then
      tag_name = "__UNKNOWN__"
    end
  end

  return tag_name
end

-- Get client port (i.e. the port that is not 5413). Not 100% fool proof, but good enough.
function stream_client_port(pinfo)
  local client_port = pinfo.src_port
  if client_port == 5413 then
    client_port = pinfo.dst_port
  end
  return client_port
end

-- Get stream information (or create it if not yet available)
function stream_info(pinfo)
  local info = {}
  local client_port = stream_client_port(pinfo)

  if streams[client_port] == nil then
    stream_register(pinfo, "" .. client_port .. "")
  end

  -- Store the lowest message number found in this stream so far
  if streams[client_port].first_number == nil or pinfo.number < streams[client_port].first_number then
    streams[client_port].first_number = pinfo.number
  end

  info.client_port = client_port
  info.name = stream_name(pinfo)
  info.first_number = streams[client_port].first_number
  info.first_message = streams[client_port].first_number == pinfo.number
 
  if pinfo.src_port == 5413 then
    info.dir_name = ">" .. info.name
  else
    info.dir_name = info.name .. ">"
  end

  return info
end

-- Get the name of the stream
function stream_name(pinfo)
  local port = pinfo.src_port
  if port == 5413 then
    port = pinfo.dst_port
  end

  if not streams[port] then
    return ""
  end
  return streams[port].name
end

-- Convert suitelink time in TvbRange to NSTime
function sl_to_ns_time(range)
  -- Suitelink time is counted in 100 ns from 1601-01-01
  local sl_time_r = range(0, 8)
  local sl_time = sl_time_r:le_uint64()
  local sl_seconds = (sl_time / (1000*1000*10)):tonumber()
  local sl_nanoseconds = (sl_time % (1000*1000*10) * 100):tonumber()

  -- Nuber of seconds between suitelink time (same as Windows FILETIME) and unix epoch time is 11644473600
  -- Create a NSTime
  local nstime = NSTime.new(sl_seconds - 11644473600, sl_nanoseconds)

  return nstime
end

-- Lookup a value from a table, and return a specified default value in case not found
function table_lookup(table, lookup_value, default_value)
  local value = table[lookup_value]
  if value == nil then
    value = default_value
  end
  return value
end

-- ProtoField's table construction
f = {}

-- General/common suitelink fields
f.unknown_message = ProtoField.bytes("suitelink.unknown_message", "Unknown message type")
f.remaining_bytes = ProtoField.uint16("suitelink.remaining_bytes", "Message remaining bytes")
f.message_end = ProtoField.uint8("suitelink.message_end", "Message end magic", base.HEX)
f.remaining_bytes = ProtoField.uint16("suitelink.remaining_bytes", "Message remaining bytes")
f.unknown = ProtoField.bytes("suitelink.unknown", "Unknown suitelink data")
f.magic = ProtoField.bytes("suitelink.magic", "Magic bytes")
f.handshake = ProtoField.uint32("suitelink.handshake", "Handshake", base.HEX)
f.handshake_ack = ProtoField.bytes("suitelink.handshake_ack", "Handshake ack")
f.handshake_unknown1 = ProtoField.bytes("suitelink.handshake.unknown1", "handshake unknown1 data")
f.handshake_name = ProtoField.stringz("suitelink.handshake.client_name", "Target applicaiton name")
f.handshake_direct = ProtoField.uint32("suitelink.handshake.direct", "Direct connection")
f.handshake_srcnode = ProtoField.stringz("suitelink.handshake.srcnode", "Source node name")
f.handshake_srcuser = ProtoField.stringz("suitelink.handshake.srcuser", "Source user name")
f.handshake_type = ProtoField.uint32("suitelink.handshake.type", "Handshake type")
f.transfer = ProtoField.bytes("suitelink.transfer", "Transfer (magic)")
f.wsaprotocol_infoa = ProtoField.bytes("suitelink.wsaprotocol_infoa", "WSAPROTOCOL_INFOA (WinSock2 struct)")
f.png = ProtoField.uint16("suitelink.png", "Suitelink PNG (shorter P?NG message?)", base.HEX)

-- Suitelink data fields
f.connect = ProtoField.uint16("suitelink.connect", "Connect", base.HEX)
f.connect_application_len = ProtoField.uint8("suitelink.connect.application_len", "Requested application name length")
f.connect_application = ProtoField.string("suitelink.connect.application", "Requested application")
f.connect_topic_len = ProtoField.uint8("suitelink.connect.topic_len", "Requested topic name length")
f.connect_topic = ProtoField.string("suitelink.connect.topic", "Requested topic")
f.connect_unknown1 = ProtoField.bytes("suitelink.connect.unknown1", "Connect unknown1 data")
f.connect_client_len = ProtoField.uint8("suitelink.connect.client_len", "Client name length")
f.connect_client = ProtoField.string("suitelink.connect.client", "Client name")
f.connect_client_node_len = ProtoField.uint8("suitelink.connect.client_node_len", "Client node name length")
f.connect_client_node = ProtoField.string("suitelink.connect.client_node", "Client node name")
f.connect_username_len = ProtoField.uint8("suitelink.connect.username_len", "Client username length")
f.connect_username = ProtoField.string("suitelink.connect.username", "Client username")
f.connect_server_node_len = ProtoField.uint8("suitelink.connect.server_node_len", "Server node name length")
f.connect_server_node = ProtoField.string("suitelink.connect.server_node", "Server node name")
f.connect_unknown2 = ProtoField.bytes("suitelink.connect.unknown2", "Connect unknown2 data")
f.connect_timezone1 = ProtoField.string("suitelink.connect.timezone1", "Timezone1")
f.connect_unknown3 = ProtoField.bytes("suitelink.connect.unknown3", "Connect unknown3 data")
f.connect_timezone2 = ProtoField.string("suitelink.connect.timezone2", "Timezone2")
f.connect_unknown4 = ProtoField.bytes("suitelink.connect.unknown4", "Connect unknown4 data")
f.ping = ProtoField.uint16("suitelink.ping", "Ping", base.HEX)
f.peng = ProtoField.uint16("suitelink.peng", "Peng", base.HEX)
f.pong = ProtoField.uint16("suitelink.pong", "Pong", base.HEX)
f.pang = ProtoField.uint16("suitelink.pang", "Pang", base.HEX)
f.advise = ProtoField.uint16("suitelink.advise", "Advise", base.HEX)
f.advise_item = ProtoField.none("suitelink.advise.item", "Advise item")
f.advise_ack = ProtoField.uint16("suitelink.advise_ack", "Advise ACK", base.HEX)
f.advise_ack_item = ProtoField.none("suitelink.advise_ack.item", "Advise item")
f.advise_binary = ProtoField.uint32("suitelink.advise.binary", "Advise binary", base.HEX)
f.tag_id = ProtoField.uint32("suitelink.tag_id", "Tag id", base.HEX)
f.tag_name_len = ProtoField.uint8("suitelink.tag_name_len", "Tag name length")
f.tag_name = ProtoField.string("suitelink.tag_name", "Tag name", base.UNICODE)
f.tag_type = ProtoField.uint8("suitelink.tag_type", "Tag type", base.HEX)
f.advise_integer = ProtoField.uint32("suitelink.advise.integer", "Advise integer", base.HEX)
f.advise_real = ProtoField.uint32("suitelink.advise.real", "Advise real", base.HEX)
f.advise_ack_unknown1 = ProtoField.uint8("suitelink.advise_ack.unknown1", "Advise ack unknown1", base.HEX)
f.time = ProtoField.uint16("suitelink.time", "Time", base.HEX)
f.time_time = ProtoField.absolute_time("suitelink.time.time", "Time", base.UTC)
f.update = ProtoField.uint16("suitelink.update", "Update tag(s)", base.HEX)
f.update_item = ProtoField.none("suitelink.update.item", "Update item")
f.update_elapsed_ms = ProtoField.uint16("suitelink.update.elapsed_ms", "Elapsed milliseconds", base.DEC)
f.update_type = ProtoField.uint8("suitelink.update.type", "Variable type", base.HEX)
f.quality = ProtoField.uint16("suitelink.quality", "Quality", base.HEX)
f.value = ProtoField.bytes("suitelink.value", "Value")
f.unadvise = ProtoField.uint16("suitelink.unadvise", "Unadvise", base.HEX)
f.unadvise_ack = ProtoField.uint16("suitelink.unadvise_ack", "Unadvise ACK", base.HEX)
f.unadvise_ack_unknown1 = ProtoField.uint8("suitelink.unadvise_ack.unknown1", "Unadvise unknown1", base.HEX)
f.poke = ProtoField.uint16("suitelink.poke", "Poke", base.HEX)
f.poke_binary = ProtoField.uint32("suitelink.poke.binary", "Poke binary", base.HEX)
f.poke_integer = ProtoField.uint32("suitelink.poke.integer", "Poke integer", base.HEX)
f.poke_real = ProtoField.uint32("suitelink.poke.real", "Poke real", base.HEX)
f.poke_unknown1 = ProtoField.uint8("suitelink.poke.unknown1", "Poke unknown1", base.HEX)
f.poke_ack = ProtoField.uint16("suitelink.poke_ack", "Poke ACK", base.HEX)

-- AlarmMgr fields
f.alarmmgr = ProtoField.uint16("suitelink.alarmmgr", "AlarmMgr", base.HEX)
f.alarmmgr_header = ProtoField.bytes("suitelink.alarmmgr.header", "AlarmMgr header")
f.alarmmgr_magic = ProtoField.uint16("suitelink.alarmmgr.magic", "Alarmmgr magic", base.HEX)
f.alarmmgr_version = ProtoField.uint16("suitelink.alarmmgr.version", "Alarmmgr version", base.HEX)
f.alarmmgr_header_len = ProtoField.uint16("suitelink.alarmmgr.header_len", "Alarmmgr header length")
f.alarmmgr_data_len = ProtoField.uint16("suitelink.alarmmgr.data_len", "Alarmmgr data length")
f.alarmmgr_buffer_num = ProtoField.uint32("suitelink.alarmmgr.buffer_num", "Alarmmgr buffer number", base.HEX)
f.alarmmgr_record_cnt = ProtoField.uint16("suitelink.alarmmgr.record_cnt", "Alarmmgr record count")
f.alarmmgr_time_in_q = ProtoField.uint32("suitelink.alarmmgr.time_in_q", "Alarmmgr time in Q")
f.alarmmgr_status1 = ProtoField.uint8("suitelink.alarmmgr.status1", "Alarmmgr status 1")
f.alarmmgr_status2 = ProtoField.uint8("suitelink.alarmmgr.status2", "Alarmmgr status 2")
f.alarmmgr_status3 = ProtoField.uint8("suitelink.alarmmgr.status3", "Alarmmgr status 3")
f.alarmmgr_status4 = ProtoField.uint8("suitelink.alarmmgr.status4", "Alarmmgr status 4")
f.alarmmgr_reason = ProtoField.uint16("suitelink.alarmmgr.reason", "Alarmmgr reason")
f.alarmmgr_record = ProtoField.bytes("suitelink.alarmmgr.record", "AlarmMgr record")
f.alarmmgr_record_magic = ProtoField.uint32("suitelink.alarmmgr.record.magic", "Alarmmgr record magic", base.HEX)
f.alarmmgr_record_version = ProtoField.uint32("suitelink.alarmmgr.record.version", "Alarmmgr record version", base.HEX)
f.alarmmgr_record_reserved = ProtoField.uint32("suitelink.alarmmgr.record.reserved", "Alarmmgr record reserved (all zero)", base.HEX)
f.alarmmgr_record_len = ProtoField.uint16("suitelink.alarmmgr.record.len", "Alarmmgr record length")
f.alarmmgr_record_type = ProtoField.uint16("suitelink.alarmmgr.record.type", "Alarmmgr record type", base.HEX)
f.alarmmgr_record_buffer_num = ProtoField.uint32("suitelink.alarmmgr.record.buffer_num", "Alarmmgr record buffer number", base.HEX)
f.alarmmgr_record_global_name = ProtoField.string("suitelink.alarmmgr.record.global_name", "Alarmmgr record global name")
f.alarmmgr_record_local_name = ProtoField.string("suitelink.alarmmgr.record.local_name", "Alarmmgr record local name")
f.alarmmgr_record_lp_acc = ProtoField.uint32("suitelink.alarmmgr.record.lp_acc", "Alarmmgr record lpAcc", base.HEX)
f.alarmmgr_almbuf_spec = ProtoField.uint32("suitelink.alarmmgr.almbuf_spec", "Alarmmgr alarm buffer spec", base.HEX)
f.alarmmgr_record_almbuf_size = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_size", "Alarmmgr record AlmBuf size")
f.alarmmgr_record_almbuf_data = ProtoField.bytes("suitelink.alarmmgr.record.almbuf_data", "Alarmmgr record AlmBuf data")
f.alarmmgr_record_almbuf_version = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_version", "Alarmmgr record AlmBuf version", base.HEX)
f.alarmmgr_record_almbuf_activation = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_activation", "Alarmmgr record AlmBuf activation code", base.HEX)
f.alarmmgr_record_almbuf_client_hdisplay = ProtoField.uint32("suitelink.alarmmgr.record.almbuf_client_hdisplay", "Alarmmgr record AlmBuf client hDisplay", base.HEX)
f.alarmmgr_record_almbuf_hprovsubscription = ProtoField.uint32("suitelink.alarmmgr.record.almbuf_hprovsubscription", "Alarmmgr record AlmBuf hProvSubscription", base.HEX)
f.alarmmgr_record_almbuf_hupdaterec = ProtoField.uint32("suitelink.alarmmgr.record.almbuf_hupdaterec", "Alarmmgr record AlmBuf hUpdateRec", base.HEX)
f.alarmmgr_record_almbuf_hserverrec = ProtoField.uint32("suitelink.alarmmgr.record.almbuf_hserverrec", "Alarmmgr record AlmBuf client hServerRec", base.HEX)
f.alarmmgr_record_almbuf_wwhichalarmlist = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_wwhichalarmlist", "Alarmmgr record AlmBuf wWhichAlarmList", base.HEX)
f.alarmmgr_record_almbuf_di_hprovcacherec = ProtoField.uint32("suitelink.alarmmgr.record.almbuf_di_hprovcacherec", "Alarmmgr record AlmBuf di_hProvCacheRec", base.HEX)
f.alarmmgr_record_almbuf_di_wwhichalarmlist = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_di_wwhichalarmlist", "Alarmmgr record AlmBuf di_wWhichAlarmList", base.HEX)
f.alarmmgr_record_almbuf_version2 = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_version2", "Alarmmgr record AlmBuf version2", base.HEX)
f.alarmmgr_record_almbuf_queryversion = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_queryversion", "Alarmmgr record AlmBuf query version", base.HEX)
f.alarmmgr_record_almbuf_group_offset = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_group_offset", "Alarmmgr record AlmBuf group offset")
f.alarmmgr_record_almbuf_groupversion = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_groupversion", "Alarmmgr record AlmBuf group version", base.HEX)
f.alarmmgr_record_almbuf_statuscode = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_statuscode", "Alarmmgr record AlmBuf wStatusCode", base.HEX)
f.alarmmgr_record_almbuf_numqualifyingalarms = ProtoField.uint32("suitelink.alarmmgr.record.almbuf_numqualifyingalarms", "Alarmmgr record AlmBuf dwNumQualifyingAlarms", base.HEX)
f.alarmmgr_record_almbuf_newhistbufsize = ProtoField.uint32("suitelink.alarmmgr.record.almbuf_newhistbufsize", "Alarmmgr record AlmBuf sdwNewHistBufSize", base.HEX)
f.alarmmgr_record_almbuf_groupname = ProtoField.string("suitelink.alarmmgr.record.almbuf_groupname", "Alarmmgr record AlmBuf group name")
f.alarmmgr_alarm_record_size = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_rec_size", "Alarmmgr record AlmBuf record size")
f.alarmmgr_record_almbuf_type = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_type", "Alarmmgr record AlmBuf type")
f.alarmmgr_alarm_record_version = ProtoField.uint16("suitelink.alarmmgr.record.almbuf_rec_version", "Alarmmgr record AlmBuf record version", base.HEX)
f.alarmmgr_alarm_record = ProtoField.bytes("suitelink.alarmmgr.record", "AlarmMgr record")
f.alarmmgr_alarm_transition = ProtoField.uint16("suitelink.alarmmgr.alarm_transition", "Alarm transition")
f.alarmmgr_timezone_offset = ProtoField.int32("suitelink.alarmmgr.timezone_offset", "Timezone offset")
f.alarmmgr_alarm_record_header_size = ProtoField.uint16("suitelink.alarmmgr.alarm_record.header_size", "Alarm record header size")
f.alarmmgr_alarm_record_string_count = ProtoField.uint16("suitelink.alarmmgr.alarm_record.string_count", "Alarm record string count")
f.alarmmgr_alarm_record_tagname_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.tagname_offset", "Alarm record tagname offset")
f.alarmmgr_alarm_tagname = ProtoField.string("suitelink.alarmmgr.alarm.tagname", "Alarm tagname")
f.alarmmgr_alarm_record_class_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.class_offset", "Alarm record class offset")
f.alarmmgr_alarm_class = ProtoField.string("suitelink.alarmmgr.alarm.class", "Alarm class")
f.alarmmgr_alarm_record_typestr_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.typestr_offset", "Alarm record type offset")
f.alarmmgr_alarm_typestr = ProtoField.string("suitelink.alarmmgr.alarm.typestr", "Alarm type string")
f.alarmmgr_alarm_record_operatordomain_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.operatordomain_offset", "Alarm record operator domain offset")
f.alarmmgr_alarm_operatordomain = ProtoField.string("suitelink.alarmmgr.alarm.operatordomain", "Alarm operator domain")
f.alarmmgr_alarm_record_operatornode_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.operatornode_offset", "Alarm record operator node offset")
f.alarmmgr_alarm_operatornode = ProtoField.string("suitelink.alarmmgr.alarm.operatornode", "Alarm operator node")
f.alarmmgr_alarm_record_operatorname_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.operatorname_offset", "Alarm record operator name offset")
f.alarmmgr_alarm_operatorname = ProtoField.string("suitelink.alarmmgr.alarm.operatorname", "Alarm operator (full) name")
f.alarmmgr_alarm_record_operator_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.operator_offset", "Alarm record operator offset")
f.alarmmgr_alarm_operator = ProtoField.string("suitelink.alarmmgr.alarm.operator", "Alarm operator")
f.alarmmgr_alarm_record_alarmcomment_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.alarmcomment_offset", "Alarm record alarmcomment offset")
f.alarmmgr_alarm_alarmcomment = ProtoField.string("suitelink.alarmmgr.alarm.alarmcomment", "Alarm alarmcomment")
f.alarmmgr_alarm_record_comment_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.comment_offset", "Alarm record comment offset")
f.alarmmgr_alarm_comment = ProtoField.string("suitelink.alarmmgr.alarm.comment", "Alarm comment")
f.alarmmgr_alarm_record_onmsg_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.onmsg_offset", "Alarm On (off) message offset")
f.alarmmgr_alarm_onmsg = ProtoField.string("suitelink.alarmmgr.alarm.onmsg", "Alarm On (off) message")
f.alarmmgr_alarm_record_offmsg_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.offmsg_offset", "Alarm Off (on) message offset")
f.alarmmgr_alarm_offmsg = ProtoField.string("suitelink.alarmmgr.alarm.offmsg", "Alarm Off (on) message")
f.alarmmgr_alarm_record_user3_offset = ProtoField.uint16("suitelink.alarmmgr.alarm_record.user3_offset", "Alarm record user3 offset")
f.alarmmgr_alarm_user3 = ProtoField.string("suitelink.alarmmgr.alarm.user3", "Alarm user3 (user-defined string)")
f.alarmmgr_alarm_string_offset = ProtoField.uint16("suitelink.alarmmgr.alarm.string_offset", "Alarm (unknown) string offset")
f.alarmmgr_alarm_string = ProtoField.string("suitelink.alarmmgr.alarm.string", "Alarm (unknown) string")

f.alarmmgr_alarm_type = ProtoField.uint16("suitelink.alarmmgr.alarm.type", "Alarm type")
f.alarmmgr_alarm_value = ProtoField.float("suitelink.alarmmgr.alarm.value", "Alarm value")
f.alarmmgr_alarm_limit = ProtoField.float("suitelink.alarmmgr.alarm.limit", "Alarm limit")
f.alarmmgr_alarm_outstandingacks = ProtoField.uint16("suitelink.alarmmgr.alarm.outstandingacks", "Alarm outstanding acks")
f.alarmmgr_alarm_timedelay = ProtoField.uint32("suitelink.alarmmgr.alarm.timedelay", "Alarm time delay")
f.alarmmgr_alarm_user1 = ProtoField.float("suitelink.alarmmgr.alarm.user1", "Alarm user1 (user-defined number 1)")
f.alarmmgr_alarm_user2 = ProtoField.float("suitelink.alarmmgr.alarm.user2", "Alarm user2 (user-defined number 2)")
f.alarmmgr_alarm_group = ProtoField.string("suitelink.alarmmgr.alarm.group", "Alarm group")
f.alarmmgr_alarm_guid = ProtoField.bytes("suitelink.alarmmgr.alarm.guid", "Alarm GUID")
f.alarmmgr_alarm_priority = ProtoField.uint16("suitelink.alarmmgr.alarm.priority", "Alarm priority")
f.alarmmgr_alarm_handle = ProtoField.uint16("suitelink.alarmmgr.alarm.handle", "Alarm handle", base.HEX)

sl_protocol.fields = f


-- Shamelessly copied from:
-- https://stackoverflow.com/questions/18886447/convert-signed-ieee-754-float-to-hexadecimal-representation
function hex2float (c)
  if c == 0 then return 0.0 end
  local c = string.gsub(string.format("%X", c),"(..)",function (x) return string.char(tonumber(x, 16)) end)
  local b1,b2,b3,b4 = string.byte(c, 1, 4)
  local sign = b1 > 0x7F
  local expo = (b1 % 0x80) * 0x2 + math.floor(b2 / 0x80)
  local mant = ((b2 % 0x80) * 0x100 + b3) * 0x100 + b4

  if sign then
      sign = -1
  else
      sign = 1
  end

  local n

  if mant == 0 and expo == 0 then
      n = sign * 0.0
  elseif expo == 0xFF then
      if mant == 0 then
          n = sign * math.huge
      else
          n = 0.0/0.0
      end
  else
      n = sign * math.ldexp(1.0 + mant / 0x800000, expo - 0x7F)
  end

  return n
end

-- Advise acknowledge message item
function handle_advise_ack_item(buffer, pinfo, tree, slinfo, pos)
  local start_pos = pos

  local tag_id_r = buffer(pos, 4)
  local tag_id = tag_id_r:le_uint()
  local tag_id_str = string.format("0x%08x", tag_id)
  local unknown1_r = buffer(pos + 4, 1)
  local unknown1 = unknown1_r:le_uint()
  local unknown1_str = string.format("0x%02x", unknown1)

  local tag_name = stream_tagname(pinfo, tag_id)

  -- Add subtree for the item
  pos = pos + 5
  itemtree = tree:add(f.advise_ack_item, buffer(start_pos, pos - start_pos)):append_text(": " ..
    "tag_id=" .. tag_id_str .. " (name=" .. tag_name .. ")" ..
    " unknown01=" .. unknown1_str )
  
  itemtree:add_le(f.tag_id, tag_id_r)
  itemtree:add_le(f.advise_ack_unknown1, unknown1_r)

  pinfo.cols.info = slinfo.stream.dir_name .. " ADVISE ACK" ..
  " tag_id=" .. tag_id_str .. " (name=" .. tag_name .. ")" ..
  " unknown1=" .. unknown1_str

  return pos - start_pos
end

-- Advise acknowledge message
function handle_advise_ack(buffer, pinfo, tree, slinfo)
  local len = slinfo.msg_len
  local pos = slinfo.pos

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add message type
  tree:add_le(f.advise_ack, buffer(pos + 2, 2))

  -- Loop through all items
  pos = pos + 4
  local count = 0
  while pos < buffer:len() - 1 do
    count = count + 1
    pos = pos + handle_advise_ack_item(buffer, pinfo, tree, slinfo, pos)
  end

  tree:add_le(f.message_end, buffer(pos, 1))

  if count > 1 then
    pinfo.cols.info = slinfo.stream.dir_name .. " ADVISE ACK (multiple items)"
  end

  return slinfo.msg_len
end

-- Unadvise acknowledge mesage
function handle_unadvise_ack(buffer, pinfo, tree, slinfo)
  local len = slinfo.msg_len
  local pos = slinfo.pos

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add type
  tree:add_le(f.unadvise_ack, buffer(pos + 2, 2))

  local tag_id_r = buffer(4, 4)
  local tag_id = tag_id_r:le_uint()
  local tag_id_str = string.format("0x%08x", tag_id)

  tree:add_le(f.tag_id, tag_id_r)
  tree:add_le(f.unadvise_ack_unknown1, buffer(8, 1))
  tree:add_le(f.message_end, buffer(9, 1))

  local tag_name = stream_tagname(pinfo, tag_id)

  pinfo.cols.info = slinfo.stream.dir_name .. " UNADVISE ACK" ..
    " tag_id=" .. tag_id_str .. " (name=" .. tag_name .. ")" ..
    " unknown1=" .. string.format("0x%02x", buffer(8, 1):le_uint())
  
  return slinfo.msg_len
end

-- Unadvise message
function handle_unadvise(buffer, pinfo, tree, slinfo)
  local pos = slinfo.pos
  local len = slinfo.msg_len

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add message type
  tree:add_le(f.unadvise, buffer(pos + 2, 2))

  -- TODO: presumably there might be multiple items, so should be handled as e.g. handle_advise
  local tag_id_r = buffer(4, 4)
  local tag_id = tag_id_r:le_uint()
  local tag_id_str = string.format("0x%08x", tag_id)

  tree:add_le(f.tag_id, tag_id_r)
  tree:add_le(f.message_end, buffer(8, 1))

  local tag_name = stream_tagname(pinfo, tag_id)

  pinfo.cols.info = slinfo.stream.dir_name .. " UNADVISE" ..
    " tag_id=" .. tag_id_str .. " (name=" .. tag_name .. ")"

  return slinfo.msg_len
end

-- Handle time message
function handle_time(buffer, pinfo, tree, slinfo)
  -- TODO: Stray decimals in info column and not "UTC" datetime
  local pos = slinfo.pos
  local len = slinfo.msg_len

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add message type
  tree:add_le(f.time, buffer(pos + 2, 2))

  -- Suitelink time is counted in 100 ns from 1601-01-01
  local sl_time_r = buffer(pos + 4, 8)
  local sl_time = sl_time_r:le_uint64()

  -- Nuber of seconds between suitelink time (same as Windows FILETIME) and unix epoch time is 11644473600
  local epoch = sl_time:tonumber() / (1000*1000*10) - 11644473600

  -- Create a NSTime
  local nstime = sl_to_ns_time(sl_time_r)
  tree:add_le(f.time_time, sl_time_r, nstime):append_text(" (SL timestamp: " .. sl_time .. ")")
  tree:add(f.message_end, buffer(pos + 12, 1))
  pinfo.cols.info = slinfo.stream.dir_name .. " TIME " ..
    format_date(epoch) .. " (SL timestamp: " .. sl_time .. ")"

  return slinfo.msg_len
end

-- Handle update message item
function handle_update_item(buffer, pinfo, tree, slinfo, pos)
  local start_pos = pos

  local tag_id_r = buffer(pos, 4)
  local tag_id_str = string.format("0x%08x", tag_id_r:le_uint())
  local elapsed_ms_r = buffer(pos + 4, 2)
  local quality_r = buffer(pos + 6, 2)
  local quality_str = string.format("0x%04x", quality_r:le_uint())
  local type_r = buffer(pos + 8, 1)
  local type_str
  if type_r:le_uint() == 1 then
    type_str = "binary"
  elseif type_r:le_uint() == 2 then
    type_str = "integer"
  elseif type_r:le_uint() == 3 then
    type_str = "real"
  elseif type_r:le_uint() == 4 then
    type_str = "message"
  else
    type_str = string.format("0x%02x", type_r:uint())
  end
  pos = pos + 9
  local value_r
  local value
  local value_str
  if type_str == "binary" then
    value_r = buffer(pos, 1)
    value_str = string.format("%d", value_r:le_uint())
    pos = pos + 1
  elseif type_str == "integer" then
    value_r = buffer(pos, 4)
    value_str = string.format("%d", value_r:le_uint())
    pos = pos + 4
  elseif type_str == "real" then 
    value_r = buffer(pos, 4)
    value_str = hex2float(value_r:le_uint())
    pos = pos + 4
  elseif type_str == "message" then
    local msg_len_r = buffer(pos, 2)
    local msg_len = msg_len_r:le_uint()
    print("Message length: " .. msg_len)
    if msg_len > 0 then
      value_r = buffer(pos + 2, msg_len)
      value_str = value_r:string()
    else
      value_r = buffer(pos, 2)
      value_str =" "
    end
    pos = pos + 2 + msg_len
  else
    value_r = buffer(pos, 4)
    value_str = string.format("0x%08x", value_r:le_uint())
    pos = pos + 4
  end

  local tag_name = stream_tagname(pinfo, tag_id_r:le_uint())
  if tag_name == nil then
    tag_name = "__Unknown__"
  end

  itemtree = tree:add(f.update_item, buffer(start_pos, pos - start_pos)):append_text(": " ..
    "tag_id=" .. tag_id_str .. " (name=" .. tag_name .. ")" ..
    " elapsed_ms=" .. elapsed_ms_r:le_uint() ..
    " quality=" .. quality_str ..
    " type=" .. type_str ..
    " value=" .. value_str )
  itemtree:add_le(f.tag_id, tag_id_r)
  itemtree:add_le(f.update_elapsed_ms, elapsed_ms_r)
  itemtree:add(f.quality, quality_r)
  itemtree:add_le(f.update_type, type_r):append_text(" (" .. type_str .. ")")
  itemtree:add_le(f.value, value_r)

  pinfo.cols.info = slinfo.stream.dir_name .. " UPDATE" ..
    " tag_id=" .. tag_id_str .. " (name=" .. tag_name .. ")" ..
    " elapsed_ms=" .. elapsed_ms_r:le_uint() ..
    " quality=" .. quality_str ..
    " type=" .. type_str ..
    " value=" .. value_str

  return pos - start_pos
end

-- Handle update message
function handle_update(buffer, pinfo, tree, slinfo)
  local pos = slinfo.pos
  local len = slinfo.msg_len

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)
  
  -- Add message type
  tree:add_le(f.update, buffer(pos + 2, 2))

  -- Loop through and add all items
  local count = 0
  pos = pos + 4
  while pos < buffer:captured_len() - 1 do
    count = count + 1
    pos = pos + handle_update_item(buffer, pinfo, tree, slinfo, pos)
  end
  tree:add_le(f.message_end, buffer(pos, 1))

  if count > 1 then
    pinfo.cols.info = slinfo.stream.dir_name .. " UPDATE (multiple items)"
  end

  return slinfo.msg_len
end

-- Handle poke ack message
function handle_poke_ack(buffer, pinfo, tree, slinfo)
  -- TODO: complete implementation

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add message type
  tree:add_le(f.poke_ack, buffer(pos + 2, 2))

  pinfo.cols.info = slinfo.stream.dir_name .. "POKE ACK"

  return slinfo.msg_len
end

-- Handle poke message
function handle_poke(buffer, pinfo, tree, slinfo)
  -- TODO: fix info column
  -- TODO: handle multiple pokes in one message

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add message type
  tree:add_le(f.poke, buffer(pos + 2, 2))

  local tag_id_r = buffer(pos + 4, 4)
  local type_r = buffer(pos + 8, 1)
  local type_str
  if type_r:le_uint() == 1 then
    type_str = "binary"
  elseif type_r:le_uint() == 2 then
    type_str = "integer"
  elseif type_r:le_uint() == 3 then
    type_str = "real"
  else
    type_str = string.format("0x%02x", type_r:uint())
  end

  tree:add_le(f.tag_id, tag_id_r)
  tree:add_le(f.tag_type, type_r)

  local pos = pos + 9
  if type_str == "binary" then
    value_r = buffer(pos, 1)
    value_str = string.format("%d", value_r:le_uint())
    pos = pos + 1
  elseif type_str == "integer" then
    value_r = buffer(pos, 4)
    value_str = string.format("%d", value_r:le_uint())
    pos = pos + 4
  elseif type_str == "real" then 
    value_r = buffer(pos, 4)
    value_str = hex2float(value_r:le_uint())
    pos = pos + 4
  else
    value_r = buffer(pos, 4)
    value_str = string.format("0x%08x", value_r:le_uint())
    pos = pos + 4
  end
  value = value_r:le_uint()
  tree:add_le(f.value, value_r)
  tree:add_le(f.message_end, buffer(pos, 1))

  pinfo.cols.info = slinfo.stream.dir_name .. " POKE"

  return slinfo.msg_len
end

-- Pong message
function handle_pong(buffer, pinfo, tree, slinfo)
  local pos = slinfo.pos
  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  tree:add_le(f.pong, buffer(pos + 2, 2))
  tree:add_le(f.message_end, buffer(pos + 4, 1))
  pinfo.cols.info = slinfo.stream.dir_name .. " PONG"
  return slinfo.msg_len
end

-- Ping message
function handle_ping(buffer, pinfo, tree, slinfo)
  local pos = slinfo.pos
  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  tree:add_le(f.ping, buffer(pos + 2, 2))
  tree:add_le(f.message_end, buffer(pos + 4, 1))
  pinfo.cols.info = slinfo.stream.dir_name .. " PING"
  return slinfo.msg_len
end

-- Peng message
function handle_peng(buffer, pinfo, tree, slinfo)
  local pos = slinfo.pos
  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  tree:add_le(f.peng, buffer(pos + 2, 2))
  tree:add_le(f.message_end, buffer(pos + 4, 1))
  pinfo.cols.info = slinfo.stream.dir_name .. " PENG"
  return slinfo.msg_len
end

-- Pang message
function handle_pang(buffer, pinfo, tree, slinfo)
  local pos = slinfo.pos
  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  tree:add_le(f.pang, buffer(pos + 2, 2))
  tree:add_le(f.message_end, buffer(pos + 4, 1))
  pinfo.cols.info = slinfo.stream.dir_name .. " PANG"
  return slinfo.msg_len
end

-- Handle advise message item
function handle_advise_item(buffer, pinfo, tree, slinfo, pos)
  local start_pos = pos
  local errmsg = ""
  -- We need at least 5 bytes for a semi-valid advise item
  if buffer:len() - pos < 5 then
    tree:add_le(f.unknown, buffer(pos)):append_text(string.format("handle_advise_item: need at least 5 bytes to advise item"))
    return buffer:len() - pos
  end

  -- Tag ID
  local tag_id_r = buffer(pos, 4)
  local tag_id_str = string.format("0x%08x", tag_id_r:le_uint())

  -- Tagname length
  local str_len_r = buffer(pos + 4, 1)
  local str_len = str_len_r:le_uint()

  -- Check that we have enough bytes for the whole tagname string
  if buffer:len() < pos + 5 + str_len * 2 then
    tree:add_le(f.unknown, buffer(pos)):append_text(string.format("handle_advise_item: need %d bytes for tagname string", str_len * 2))
    return buffer:len() - pos
  end

  -- Tagname
  local tag_name_r = buffer(pos + 5, str_len * 2)
  local tag_name = tag_name_r:le_ustring()
  pos = pos + 5 + str_len * 2

  -- Create advise item tree
  itemtree = tree:add(f.advise_item, buffer(start_pos, pos - start_pos)):append_text(": " ..
    "tag_id=" .. tag_id_str .. " tag_name=" .. tag_name)

  -- Populate tree
  itemtree:add_le(f.tag_id, tag_id_r)
  itemtree:add_le(f.tag_name_len, str_len_r)
  itemtree:add_packet_field(f.tag_name, tag_name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)

  -- Map tag ID <==> tag name
  stream_advise(pinfo, tag_id_r:le_uint(), tag_name)

  pinfo.cols.info = slinfo.stream.dir_name .. " ADVISE" ..
    " tag_id=" .. tag_id_str ..
    " tag_name=" .. tag_name

  return pos - start_pos
end

-- Handle advise message
function handle_advise(buffer, pinfo, tree, slinfo)
  -- Remember starting position
  local start_pos = slinfo.pos
  local pos = slinfo.pos
  local msg_len = slinfo.msg_len

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add message type
  tree:add_le(f.advise, buffer(pos + 2, 2))
  
  pos = pos + 4
  -- Loop as long as we have more than one byte left in the TCP buffer
  local count = 0
  while buffer:len() > pos + 1 do
    -- Also check that we have more than one byte left in the message
    local remaining_bytes = msg_len - (pos - start_pos)
    if remaining_bytes < 2 then
      break
    end
    count = count + 1
    pos = pos + handle_advise_item(buffer, pinfo, tree, slinfo, pos)
  end
  tree:add_le(f.message_end, buffer(pos, 1))

  if count > 1 then
    pinfo.cols.info = slinfo.stream.dir_name .. " ADVISE (multiple items)"
  end

  return pos - start_pos + 1
end

function handle_alarmmgr_alarm_record(buffer, pinfo, tree, pos, sinfo)
  -- String length variable for later
  local str_len

  -- Alarm record length
  local record_len_r = buffer(pos, 2)
  local record_len = record_len_r:le_uint()

  -- Create subtree
  local subtree = tree:add(f.alarmmgr_alarm_record, buffer(pos, record_len))

  -- Record length
  subtree:add_le(f.alarmmgr_alarm_record_size, record_len_r)

  -- Version
  subtree:add_le(f.alarmmgr_alarm_record_version, buffer(pos + 2, 2))

  -- Handle
  subtree:add_le(f.alarmmgr_alarm_handle, buffer(pos + 4, 4))

  -- GUID
  -- TODO: fix (byte) order to make the displayed value match logged GUID
  subtree:add_le(f.alarmmgr_alarm_guid, buffer(pos + 8, 16)):append_text(" (Needs byte order change to display logged GUID)")

  -- Origination time and timezone offset
  local origination_time_r = buffer(pos + 0x18, 8)
  local origination_tz_offset_r = buffer(pos + 0x20, 4) -- 4 bytes reserved in the message
  local origination_tz_offset = -buffer(pos + 0x20, 2):le_int() -- but only 2 bytes used for the value
  subtree:add_le(f.time_time, origination_time_r, sl_to_ns_time(origination_time_r)):prepend_text("Origination ")
  subtree:add_le(f.alarmmgr_timezone_offset, origination_tz_offset_r, origination_tz_offset):prepend_text("Origination ")

  -- Other time 1 and timezone offset
  local other1_time_r = buffer(pos + 0x30, 8)
  local other1_tz_offset_r = buffer(pos + 0x38, 4)
  local other1_tz_offset = -buffer(pos + 0x38, 2):le_int()
  subtree:add_le(f.time_time, other1_time_r, sl_to_ns_time(other1_time_r)):prepend_text("Other 1 ")
  subtree:add_le(f.alarmmgr_timezone_offset, other1_tz_offset_r, other1_tz_offset):prepend_text("Other 1 ")

  -- Other time 2 and timezone offset
  local other2_time_r = buffer(pos + 0x3c, 8)
  local other2_tz_offset_r = buffer(pos + 0x44, 4)
  local other2_tz_offset = -buffer(pos + 0x44, 2):le_int()
  subtree:add_le(f.time_time, other2_time_r, sl_to_ns_time(other2_time_r)):prepend_text("Other 2 ")
  subtree:add_le(f.alarmmgr_timezone_offset, other2_tz_offset_r, other2_tz_offset):prepend_text("Other 2 ")

  -- Other time 3 and timezone offset
  local other3_time_r = buffer(pos + 0x48, 8)
  local other3_tz_offset_r = buffer(pos + 0x50, 4)
  local other3_tz_offset = -buffer(pos + 0x50, 2):le_int()
  subtree:add_le(f.time_time, other3_time_r, sl_to_ns_time(other3_time_r)):prepend_text("Other 3 ")
  subtree:add_le(f.alarmmgr_timezone_offset, other3_tz_offset_r, other3_tz_offset):prepend_text("Other 3 ")

  -- Alarm transition type
  local transition_r = buffer(pos + 0x5a, 2)
  local transition = transition_r:le_uint()
  -- TODO: Not quite sure if the below transition descriptions are correct
  local transition_map = {
    [0] = "SUB",
    [1] = "ALM",
    [2] = "RTN",
    [4] = "ACK",
    [6] = "ARTN",
    [8] = "SUB",
  }
  local transition_text = transition_map[transition]
  if transition_text == nil then
    transition_text = "UNKNOWN"
  end
  subtree:add_le(f.alarmmgr_alarm_transition, transition_r):append_text(" (" .. transition_text .. ")")

  -- Outstanding acks
  subtree:add_le(f.alarmmgr_alarm_outstandingacks, buffer(pos + 0x5c, 2))

  -- Some 4 byte value at 0x5e

  -- Priority
  subtree:add_le(f.alarmmgr_alarm_priority, buffer(pos + 0x64, 2))

  -- Alarm type
  local alarm_type_map = {
    [1] = "D",
    [2] = "I",
    [3] = "R",
    [4] = "S",
  }
  local alarm_type_r = buffer(pos + 0x6e, 2)
  local alarm_type = alarm_type_r:le_uint()
  subtree:add_le(f.alarmmgr_alarm_type, alarm_type_r):append_text(" (" .. table_lookup(alarm_type_map, alarm_type, "UNKNOWN") .. ")")

  -- Alarm value
  subtree:add_le(f.alarmmgr_alarm_value, buffer(pos + 0x70, 4))

  -- Alarm limit
  subtree:add_le(f.alarmmgr_alarm_limit, buffer(pos + 0x74, 4))

  -- Timedelay
  subtree:add_le(f.alarmmgr_alarm_timedelay, buffer(pos + 0x78, 4))

  -- User1
  subtree:add_le(f.alarmmgr_alarm_user1, buffer(pos + 0x80, 4))

  -- User2
  subtree:add_le(f.alarmmgr_alarm_user2, buffer(pos + 0x84, 4))

  -- Header size
  local header_size_r = buffer(pos + 0x88, 2)
  local header_size = header_size_r:le_uint()
  subtree:add_le(f.alarmmgr_alarm_record_header_size, header_size_r)

  -- String count
  local string_count_r = buffer(pos + header_size, 2)
  local string_count = string_count_r:le_uint()
  subtree:add_le(f.alarmmgr_alarm_record_string_count, string_count_r)

  -- Position from when string offsets are given
  local str_pos = pos + header_size + string_count * 2 + 2

  -- Ordered mapping between string offset and the actual string fields
  local string_map = {
    {f.alarmmgr_alarm_record_tagname_offset, f.alarmmgr_alarm_tagname},
    {f.alarmmgr_alarm_record_class_offset, f.alarmmgr_alarm_class},
    {f.alarmmgr_alarm_record_typestr_offset, f.alarmmgr_alarm_typestr},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
    {f.alarmmgr_alarm_record_offmsg_offset, f.alarmmgr_alarm_offmsg},
    {f.alarmmgr_alarm_record_operatornode_offset, f.alarmmgr_alarm_operatornode},
    {f.alarmmgr_alarm_record_operator_offset, f.alarmmgr_alarm_operator},
    {f.alarmmgr_alarm_record_alarmcomment_offset, f.alarmmgr_alarm_alarmcomment},
    {f.alarmmgr_alarm_record_onmsg_offset, f.alarmmgr_alarm_onmsg},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
    {f.alarmmgr_alarm_record_user3_offset, f.alarmmgr_alarm_user3},
    {f.alarmmgr_alarm_record_operatorname_offset, f.alarmmgr_alarm_operatorname},
    {f.alarmmgr_alarm_record_operatordomain_offset, f.alarmmgr_alarm_operatordomain},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
    {f.alarmmgr_alarm_record_comment_offset, f.alarmmgr_alarm_comment},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
    {f.alarmmgr_alarm_string_offset, f.alarmmgr_alarm_string},
  }

  -- We first add the offsets to the dissector tree, and push the string ranges to a buffer
  local string_ranges = {}
  for i, map_line in ipairs(string_map) do
    local offset_field = map_line[1]

    -- Add the string offset field
    local offset_r = buffer(pos + header_size + i * 2, 2)
    local offset = offset_r:le_uint()
    subtree:add_le(offset_field, offset_r)

    -- Determine the range for the string and put it in the buffer
    local string_pos = str_pos + offset
    str_len = buffer(string_pos):stringz():len()
    range = buffer(string_pos, str_len + 1)
    string_ranges[i] = range
  end

  -- Add the strings from the buffer to the dissector tree
  for i, map_line in ipairs(string_map) do
    local string_field = map_line[2]
    subtree:add_le(string_field, string_ranges[i])
  end

end

-- Handle alarmmgr message
function handle_alarmmgr(buffer, pinfo, tree, slinfo)
  local record_type_map = {
    [0x21] = "Connect",
    [0x22] = "Connected",
    [0x23] = "Terminate",
    [0x24] = "Terminated",
    [0x25] = "Alarmbuf",
    [0x26] = "Heartbeat"
  }

  local pos = slinfo.pos
  local len = slinfo.msg_len
  local msg_len_size= slinfo.msg_len_size
  
  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  pos = pos + msg_len_size

  -- Need header length field to add header subtree
  local header_len_r = buffer(pos + 8, 2)
  local header_len = header_len_r:le_uint()

  -- Header subtree
  local header_tree = tree:add(f.alarmmgr_header, buffer(pos, header_len))

  header_tree:add_le(f.unknown, buffer(pos, 4))
  header_tree:add_le(f.alarmmgr_magic, buffer(pos + 4, 2))
  header_tree:add_le(f.alarmmgr_version, buffer(pos + 6, 2))
  header_tree:add_le(f.alarmmgr_header_len, header_len_r)


  -- Data length
  local data_len_r = buffer(pos + 10, 2)
  local data_len = data_len_r:le_uint()
  header_tree:add_le(f.alarmmgr_data_len, data_len_r)

  -- Record count
  local record_cnt_r = buffer(pos + 12, 2)
  local record_cnt = record_cnt_r:le_uint()
  header_tree:add_le(f.alarmmgr_record_cnt, record_cnt_r)

  header_tree:add_le(f.alarmmgr_buffer_num, buffer(pos + 16, 4))
  header_tree:add_le(f.alarmmgr_time_in_q, buffer(pos + 20, 4))

  -- TODO: remove this hack to offset activation_code 0x6b length
  local add_processed = 0


  local record_type = 0 -- Needed outside the while loop below
  -- Iterate through all records
  pos = pos + header_len -- Should point to the first record
  while record_cnt > 0 do

    local record_magic_r = buffer(pos, 4)
    local record_version_r = buffer(pos + 4, 4)

    -- Record type
    local record_type_r = buffer(pos + 8, 2)
    record_type = record_type_r:le_uint()
    local record_type_str = record_type_map[record_type]
    if record_type_str == nil then
      record_type_str = "Unknown"
    end

    local record_len_r = buffer(pos + 10, 2)
    local record_len = record_len_r:le_uint()
    local record_reserved_r = buffer(pos + 12, 4)
    local record_buffer_num_r = buffer(pos + 16, 4)

    -- Record subtree
    local record_subtree = tree:add(f.alarmmgr_record, buffer(pos, record_len))


    record_subtree:add_le(f.alarmmgr_record_magic, record_magic_r)
    record_subtree:add_le(f.alarmmgr_record_version, record_version_r)
    record_subtree:add_le(f.alarmmgr_record_type, record_type_r):append_text(" (" .. record_type_str .. ")")
    record_subtree:add_le(f.alarmmgr_record_len, record_len_r)
    record_subtree:add_le(f.alarmmgr_record_reserved, record_reserved_r)
    record_subtree:add_le(f.alarmmgr_record_buffer_num, record_buffer_num_r)

    if record_type == 0x21 then


      local status_1_r = buffer(pos + 0x20, 1)
      local status_2_r = buffer(pos + 0x21, 1)
      local status_3_r = buffer(pos + 0x22, 1)
      local status_4_r = buffer(pos + 0x23, 1)
      record_subtree:add_le(f.alarmmgr_status1, status_1_r)
      record_subtree:add_le(f.alarmmgr_status2, status_2_r)
      record_subtree:add_le(f.alarmmgr_status3, status_3_r)
      record_subtree:add_le(f.alarmmgr_status4, status_4_r)

      record_subtree:add_le(f.alarmmgr_almbuf_spec, buffer(pos + 0x20, 4))

      local record_global_name_len = buffer(pos + 40):stringz():len()
      local record_global_name_r = buffer(pos + 40, record_global_name_len)

      local local_name_start_pos = pos + 41 + record_global_name_len
      local record_local_name_len = buffer(local_name_start_pos):stringz():len()
      local record_local_name_r = buffer(local_name_start_pos, record_local_name_len)

      record_subtree:add(f.alarmmgr_record_global_name, record_global_name_r)
      record_subtree:add(f.alarmmgr_record_local_name, record_local_name_r)
    elseif record_type == 0x22 then
      local record_lp_acc_r = buffer(pos + 32, 4)

      local status_1_r = buffer(pos + 0x28, 1)
      local status_2_r = buffer(pos + 0x29, 1)
      local status_3_r = buffer(pos + 0x2a, 1)
      local status_4_r = buffer(pos + 0x2b, 1)
      local reason_r = buffer(pos + 0x30, 2)

      record_subtree:add_le(f.alarmmgr_record_lp_acc, record_lp_acc_r)      
      record_subtree:add_le(f.alarmmgr_status1, status_1_r)
      record_subtree:add_le(f.alarmmgr_status2, status_2_r)
      record_subtree:add_le(f.alarmmgr_status3, status_3_r)
      record_subtree:add_le(f.alarmmgr_status4, status_4_r)
      record_subtree:add_le(f.alarmmgr_reason, reason_r)

    elseif record_type == 0x25 then
      local record_lp_acc_r = buffer(pos + 24, 4)

      local record_almbuf_size_r = buffer(pos + 32, 2)
      local record_almbuf_size = record_almbuf_size_r:le_uint()

      local record_almbuf_data_r = buffer(pos + 34, record_almbuf_size)
      local almbuf_pos = pos + 34

      record_subtree:add_le(f.alarmmgr_record_lp_acc, record_lp_acc_r)      
      record_subtree:add_le(f.alarmmgr_record_almbuf_size, record_almbuf_size_r)  
      local subtree = record_subtree:add_le(f.alarmmgr_record_almbuf_data, record_almbuf_data_r)

      local almbuf_size_r = buffer(pos + 34, 2)
      local almbuf_version_r = buffer(pos + 36, 2)
      local almbuf_activation_r = buffer(pos + 38, 2)
      local almbuf_activation = almbuf_activation_r:le_uint()
      -- Changed to almbuf_pos offsets
      local almbuf_client_hdisplay_r = buffer(almbuf_pos + 0x6, 4)
      local almbuf_hprovsubscription_r = buffer(almbuf_pos + 0xa, 4)
      local almbuf_hupdaterec_r = buffer(almbuf_pos + 0xe, 4)
      local almbuf_hserverrec_r = buffer(almbuf_pos + 0x12, 4)
      local almbuf_wwhichalarmlist_r = buffer(almbuf_pos + 0x16, 2)
      -- Normal pos offsets resume
      subtree:add_le(f.alarmmgr_record_almbuf_size, almbuf_size_r)
      subtree:add_le(f.alarmmgr_record_almbuf_version, almbuf_version_r)
      if almbuf_activation == 0x01 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALARM_ADDED)")
      elseif almbuf_activation == 0x02 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALARM_DELETED)")
      elseif almbuf_activation == 0x03 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALARM_MODIFIED)")
      elseif almbuf_activation == 0x04 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (GROUP_ADDED)")
      elseif almbuf_activation == 0x05 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (GROUP_MODIFIED)")
      elseif almbuf_activation == 0x65 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALM_NEW_QUERY)")
      elseif almbuf_activation == 0x66 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALM_TERMINATE_QUERY)")
      elseif almbuf_activation == 0x67 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALM_TERMINATE_QUERY_ACK)")
      elseif almbuf_activation == 0x68 then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALM_ACK_ALARM)")
      elseif almbuf_activation == 0x6b then
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (ALM_ABAL_CONNECT_UPDATE)")
      else
        subtree:add_le(f.alarmmgr_record_almbuf_activation, almbuf_activation_r):append_text(" (UNKNOWN)")
      end
      subtree:add_le(f.alarmmgr_record_almbuf_client_hdisplay, almbuf_client_hdisplay_r)
      subtree:add_le(f.alarmmgr_record_almbuf_hprovsubscription, almbuf_hprovsubscription_r)
      subtree:add_le(f.alarmmgr_record_almbuf_hupdaterec, almbuf_hupdaterec_r)
      subtree:add_le(f.alarmmgr_record_almbuf_hserverrec, almbuf_hserverrec_r)
      local whichalarmlist = almbuf_wwhichalarmlist_r:le_uint()
      local whichalarmlist_map = {
        [1] = "SUMMARY",
        [2] = "HISTORICAL",
      }
      whichalarmlist_text = table_lookup(whichalarmlist_map, whichalarmlist, "UNKNOWN")
      subtree:add_le(f.alarmmgr_record_almbuf_wwhichalarmlist, almbuf_wwhichalarmlist_r):append_text(" (" .. whichalarmlist_text .. ")")
      if almbuf_activation == 0x01 then
        local almbuf_type_r = buffer(almbuf_pos + 22, 2)
        local almbuf_type = almbuf_type_r:le_uint()
        if almbuf_type == 1 then
          subtree:add_le(f.alarmmgr_record_almbuf_type, almbuf_type_r):append_text(" (SUMMARY)")
        elseif almbuf_type == 2 then
          subtree:add_le(f.alarmmgr_record_almbuf_type, almbuf_type_r):append_text(" (HISTORY)")
        else
          subtree:add_le(f.alarmmgr_record_almbuf_type, almbuf_type_r):append_text(" (UNKNOWN)")
        end

        handle_alarmmgr_alarm_record(buffer, pinfo, subtree, almbuf_pos + 24, sinfo)
      elseif almbuf_activation == 0x04 then
        local almbuf_groupversion_r = buffer(pos + 60, 2)

        subtree:add_le(f.alarmmgr_record_almbuf_groupversion, almbuf_groupversion_r)

        local almbuf_groupname = buffer(pos + 82):stringz()
        local str_len = almbuf_groupname:len()
        local almbuf_groupname_r = buffer(pos + 82, str_len + 1)
        subtree:add(f.alarmmgr_record_almbuf_groupname, almbuf_groupname_r)

      elseif almbuf_activation == 0x65 then
        local almbuf_version2_r = buffer(pos + 58, 2)
        local di_hprovcacherec_r = buffer(almbuf_pos + 0x1a, 4)
        local di_hwwhichalarmlist_r = buffer(almbuf_pos + 0x1e, 2)
        local almbuf_queryversion_r = buffer(pos + 82, 2)

        -- Groupe name (and offset to it)
        local group_offset_r = buffer(almbuf_pos + 0x58, 2)
        local group_offset = group_offset_r:le_uint()
        local group = buffer(almbuf_pos + 0x5a + group_offset):stringz()
        local str_len = group:len()
        local group_r = buffer(almbuf_pos + 0x5a + group_offset, str_len + 1)

        subtree:add_le(f.alarmmgr_record_almbuf_version2, almbuf_version2_r)
        subtree:add_le(f.alarmmgr_record_almbuf_di_hprovcacherec, di_hprovcacherec_r)
        subtree:add_le(f.alarmmgr_record_almbuf_di_wwhichalarmlist, di_hwwhichalarmlist_r)
        subtree:add_le(f.alarmmgr_record_almbuf_queryversion, almbuf_queryversion_r)
        subtree:add_le(f.alarmmgr_record_almbuf_group_offset, group_offset_r)
        subtree:add_le(f.alarmmgr_alarm_group, group_r)
      elseif almbuf_activation == 0x6b then
        local almbuf_statuscode_r = buffer(almbuf_pos + 26, 2)
        local almbuf_statuscode = almbuf_statuscode_r:le_uint()
        local almbuf_numqualifyingalarms_r = buffer(almbuf_pos + 32, 4)

        subtree:add_le(f.alarmmgr_record_almbuf_statuscode, almbuf_statuscode_r)
        subtree:add_le(f.alarmmgr_record_almbuf_numqualifyingalarms, almbuf_numqualifyingalarms_r)

        if almbuf_statuscode == 0x20 then
          local almbuf_newhistbufsize_r = buffer(almbuf_pos + 36, 4)
          subtree:add_le(f.alarmmgr_record_almbuf_newhistbufsize, almbuf_newhistbufsize_r)
        end

        add_processed = add_processed + 1
      end
    end

    record_cnt = record_cnt - 1

  end

  if record_cnt_r:le_uint() > 1 then
    pinfo.cols.info = slinfo.stream.dir_name .. " ALARMMGR (multiple records)"
  else
    pinfo.cols.info = slinfo.stream.dir_name .. " ALARMMGR " .. table_lookup(record_type_map, record_type, "UNKNOWN"):upper()
  end

  return len
end

-- Handle connect message
function handle_connect(buffer, pinfo, tree, slinfo)
  local pos = slinfo.pos

  local len = slinfo.msg_len

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add message type
  tree:add_le(f.connect, buffer(pos + 2, 2))
  pos = pos + 4
  local str_len

  -- Application name
  str_len = buffer(pos, 1):int()
  local application_name_r = buffer(pos + 1, str_len*2)
  tree:add_le(f.connect_application_len, buffer(pos, 1))
  tree:add_packet_field(f.connect_application, application_name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  pos = pos + 1 + str_len * 2

  -- Topic name
  str_len = buffer(pos, 1):int()
  local topic_name_r = buffer(pos + 1, str_len*2)
  tree:add_le(f.connect_topic_len, buffer(pos, 1))
  tree:add_packet_field(f.connect_topic, topic_name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  pos = pos + 1 + str_len * 2

  -- Unknown1
  tree:add_le(f.connect_unknown1, buffer(pos, 3))
  pos = pos + 3

  -- Client name
  str_len = buffer(pos, 1):int()
  local client_name_r = buffer(pos + 1, str_len*2)
  tree:add_le(f.connect_client_len, buffer(pos, 1))
  tree:add_packet_field(f.connect_client, client_name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  -- Register stream client name
  -- TODO: should probably use a different function than stream_register for this, since
  -- that is already called for the first message encountered in the (suitelink) tcp stream
  stream_register(pinfo, client_name_r:le_ustring())
  pos = pos + 1 + str_len * 2

  -- Client node name
  str_len = buffer(pos, 1):int()
  local client_node_name_r = buffer(pos + 1, str_len*2)
  tree:add_le(f.connect_client_node_len, buffer(pos, 1))
  tree:add_packet_field(f.connect_client_node, client_node_name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  pos = pos + 1 + str_len * 2

  -- Client username
  str_len = buffer(pos, 1):int()
  local client_username_r = buffer(pos + 1, str_len*2)
  tree:add_le(f.connect_username_len, buffer(pos, 1))
  tree:add_packet_field(f.connect_username, client_username_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  pos = pos + 1 + str_len * 2

  -- Server node name
  str_len = buffer(pos, 1):int()
  local node_name_r = buffer(pos + 1, str_len*2)
  tree:add_le(f.connect_server_node_len, buffer(pos, 1))
  tree:add_packet_field(f.connect_server_node, node_name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  pos = pos + 1 + str_len * 2

  -- Unknown2
  tree:add_le(f.connect_unknown2, buffer(pos, 20))
  pos = pos + 20

  -- Timezone1
  str_len = buffer(pos):le_ustringz():len()
  local timezone1_r = buffer(pos, str_len*2)
  tree:add_packet_field(f.connect_timezone1, timezone1_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  pos = pos + str_len * 2

  -- Unknown3
  tree:add_le(f.connect_unknown3, buffer(pos, 38))
  pos = pos + 38

  -- Timezone2
  str_len = buffer(pos):le_ustringz():len()
  local timezone2_r = buffer(pos, str_len*2)
  tree:add_packet_field(f.connect_timezone2, timezone2_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
  pos = pos + str_len * 2

  -- Unknown4
  tree:add_le(f.connect_unknown4, buffer(pos))

  -- Need to get new stream info since we updated the information for it
  local sinfo = stream_info(pinfo)

  pinfo.cols.info = slinfo.stream.dir_name .. " CONNECT" ..
    " application=" .. application_name_r:le_ustring() ..
    " topic=" .. topic_name_r:le_ustring() ..
    " node=" .. node_name_r:le_ustring()

  return len + 2
end

-- Needed for message_length and handshake functions
local handshake_magic_query1 = "605fc3b12d05d111bf0800a0c9723e82"
local handshake_magic_query2 = "cafe8bbafe8bd311aa0500a0c9ecfd9f"
local handshake_magic_register = "d5cfc7f80bcdd311aa1000a0c9ecfd9f"

local handshake_legacy_magic = handshake_magic_query1
local handshake_normal_magics = {
  handshake_magic_query2,
  handshake_magic_register,
  "d4cfc7f80bcdd311aa1000a0c9ecfd9f",
}

-- Handle handshake, which should be the first message in the conversation
function handle_handshake(buffer, pinfo, tree, slinfo)
  -- Ensure we have enough bytes
  local pos = slinfo.pos
  local available_bytes = buffer:len() - pos

  local msg_len = slinfo.msg_len

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- In case of QUERY1, the magic starts already from the first message byte (implied length of 48)
  local magic_r = buffer(pos, 16)
  if magic_r:bytes() == ByteArray.new(handshake_magic_query1) then
    -- QUERY1, "legacy" handshake(?)
    tree:add(f.magic, magic_r):append_text(" (QUERY1)")
    local application_name = buffer(pos + 16):stringz()
    tree:add(f.handshake_name, buffer(pos + 16, 32))
    pinfo.cols.info = slinfo.stream.dir_name .. " HANDSHAKE" ..
    " application=" .. application_name
  else
    -- Not QUERY1, so magic starts after message length bytes
    -- TODO: In case more than one byte message length is used, the below offsets will likely be wrong
    magic_r = buffer(pos + 1, 16)
    if magic_r:bytes() == ByteArray.new(handshake_magic_query2) then
      -- QUERY2
      tree:add(f.magic, magic_r):append_text(" (QUERY2)")
      tree:add(f.magic, buffer(pos + 17, 16)):append_text( " (UNKNOWN, possibly request specific)")
      tree:add_le(f.handshake_direct, buffer(pos + 33, 4))
      pos = pos + 37

      local str_len

      -- Target application name
      local application_name = buffer(pos):le_ustringz()
      str_len = (application_name:len() + 1) * 2
      local application_name_r = buffer(pos, str_len)
      tree:add_packet_field(f.handshake_name, application_name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
      pos = pos + str_len

      -- Source node name
      local srcnode = buffer(pos):le_ustringz()
      str_len = (srcnode:len() + 1) * 2
      local srcnode_r = buffer(pos, str_len)
      tree:add_packet_field(f.handshake_srcnode, srcnode_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
      pos = pos + str_len

      -- Source user name
      local srcuser = buffer(pos):le_ustringz()
      str_len = (srcuser:len() + 1) * 2
      local srcuser_r = buffer(pos, str_len)
      tree:add_packet_field(f.handshake_srcuser, srcuser_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
      pos = pos + str_len

    elseif magic_r:bytes() == ByteArray.new(handshake_magic_register) then
      -- REGISTER
      tree:add(f.magic, magic_r):append_text(" (REGISTER)")
      tree:add(f.magic, buffer(pos + 17, 16)):append_text(" (UNKNOWN, at least sometimes legacy magic)")
      tree:add_le(f.handshake_type, buffer(pos + 33, 4)):append_text(" (an educated guess)")
      local name = buffer(pos + 37):le_ustringz()
      str_len = (name:len() + 1) * 2
      local name_r = buffer(pos + 37, str_len)
      tree:add_packet_field(f.handshake_name, name_r, ENC_UTF_16 + ENC_LITTLE_ENDIAN)
      stream_set_type(pinfo, "alarmmgr")
    else
      tree:add(f.magic, magic_r):append_text(" (UNKNOWN)")
    end
    pinfo.cols.info = slinfo.stream.dir_name .. " HANDSHAKE"
  end

  return msg_len
end

-- Handle handshake ack
function handle_handshake_ack(buffer, pinfo, tree, slinfo)
  -- Ensure we have enough bytes
  local pos = slinfo.pos
  local msg_len = slinfo.msg_len
  local msg_len_bytecount = slinfo.msg_len_size
  local available_bytes = slinfo.available_bytes

  -- Add main suitelink tree and remaining bytes field
  subtree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Check against special magics
  local alarmmgr_handshake_ack_magic = ByteArray.new("d4cfc7f80bcdd311aa1000a0c9ecfd9f")
  local register_handshake_ack_magic = ByteArray.new("96e27844fccdd311aa1000a0c9ecfd9f")
  local remaining_bytes = available_bytes - msg_len_bytecount
  if remaining_bytes >= 16 then
    -- Check if this has the AlarmMgr handshake ack magic
    if buffer(pos + msg_len_bytecount, 16):bytes() == alarmmgr_handshake_ack_magic then
      -- This is the acknowledge for the handshake to the AlarmMgr
      subtree:add(f.handshake_ack, buffer(pos + msg_len_bytecount, 16)):append_text(" (magic for AlarmMgr)")
      pinfo.cols.info = slinfo.stream.dir_name .. " HANDSHAKE ACK (AlarmMgr)"
    elseif buffer(pos + msg_len_bytecount, 16):bytes() == register_handshake_ack_magic then
      -- Thick is the acknowledge for register handshake
      subtree:add(f.handshake_ack, buffer(pos + msg_len_bytecount, 16)):append_text(" (magic for register)")
      pinfo.cols.info = slinfo.stream.dir_name .. " HANDSHAKE ACK (Register)"
    end
    subtree:add_le(f.magic, buffer(pos + msg_len_bytecount, 16))
    subtree:add_le(f.handshake_type, buffer(pos + msg_len_bytecount + 16, 4))
  else
    -- This is a "normal" handshake ack
    subtree:add(f.handshake_ack, buffer(pos + msg_len_bytecount, 2)):append_text(" (actually 0x0001)")

    -- Not much known about this handshake
    local consumed_bytes = msg_len_bytecount + 2
    subtree:add(f.unknown, buffer(pos + consumed_bytes, available_bytes - consumed_bytes - 1))
    subtree:add(f.message_end, buffer(pos + available_bytes - 1, 1))
    stream_set_type(pinfo, "normal")
    pinfo.cols.info = slinfo.stream.dir_name .. " HANDSHAKE ACK (Normal)"
  end

  return msg_len
end

-- Handle transfer message
function handle_transfer(buffer, pinfo, tree, slinfo)
  -- Ensure we have enough bytes
  local pos = slinfo.pos
  local available_bytes = slinfo.available_bytes
  local msg_len = slinfo.msg_len

  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- This tcp stream has variable message length field
  stream_update_type(pinfo, "alarmmgr")

  -- Add transfer (magic)
  tree:add(f.transfer, buffer(pos + slinfo.msg_len_size, 16))
  tree:add(f.magic, buffer(pos + slinfo.msg_len_size, 16))

  -- Add WSAPROTOCOL_INFOA struct
  tree:add(f.wsaprotocol_infoa, buffer(pos + 19, 372))

  pinfo.cols.info = slinfo.stream.dir_name .. " TRANSFER"

  return msg_len
end

-- Handle png (short ping?) message
function handle_png(buffer, pinfo, tree, slinfo)
  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add PNG
  tree:add_le(f.png, buffer(slinfo.pos + 1, 2))

  pinfo.cols.info = slinfo.stream.dir_name .. " PNG"

  return slinfo.msg_len
end

-- Handle unknown messages. Mainly to mark them so we can filter them out
function handle_unknown(buffer, pinfo, tree, slinfo)
  -- Add main suitelink tree and remaining bytes field
  tree = message_tree_header(buffer, pinfo, tree, slinfo)

  -- Add unknown message type
  tree:add_le(f.unknown_message, buffer(slinfo.pos, slinfo.msg_len))

  pinfo.cols.info = slinfo.stream.dir_name .. " UNKNOWN"

  return slinfo.msg_len
end

-- Create the main suitelink tree for this message, and insert remaining length field
function message_tree_header(buffer, pinfo, tree, slinfo)
  -- Create main suitelink tree
  tree = tree:add(sl_protocol, buffer(slinfo.pos, slinfo.msg_len))
  if slinfo.available_bytes >= slinfo.msg_len_size then
    if slinfo.msg_len_size == 0 then
      -- Special first message which does not explicitly contain remaining bytes field
      tree:add_le(f.remaining_bytes, buffer(slinfo.pos, 0), 48):append_text(" (Fixed length message)")
    elseif slinfo.msg_len_size == 1 then
      -- Remaining bytes determined by first byte
      tree:add_le(f.remaining_bytes, buffer(slinfo.pos, 1))
    elseif slinfo.msg_len_size == 2 then
      -- Remaining bytes determined by first two bytes (this is used for data exchange)
      tree:add_le(f.remaining_bytes, buffer(slinfo.pos, 2))
    elseif slinfo.msg_len_size == 3 then
      -- Remaining bytes determined by bytes two and three, because the first byte was zero
      tree:add_le(f.remaining_bytes, buffer(slinfo.pos + 1, 2))
    elseif slinfo.msg_len_size == 7 then
      -- Remaining bytes determined by bytes four through seven, because the first three bytes were zero
      tree:add_le(f.remaining_bytes, buffer(slinfo.pos + 3, 4))
    else
      tree:add_le(f.remaining_bytes, buffer(slinfo.pos, slinfo.msg_len_size)):append_text( " (UNEXPECTED REMAINING BYTES FORMAT)")
    end
  else
    tree:add_le(f.remaining_bytes, buffer(slinfo.pos, slinfo.msg_len_size)):append_text( " (NOT ENOUGH BYTES TO MARK REMAINING BYTES FIELD)")
  end

  return tree
end

-- Determine the message length and bytes needed to determine it from variable length message length field
function message_length_variable(buffer, pinfo, tree, pos, sinfo)
  local available_bytes = buffer:len() - pos

  -- Need at least one byte to decode length
  if available_bytes < 1 then
    return -DESEGMENT_ONE_MORE_SEGMENT, 0
  end

  -- If first byte is not zero, then that defines the length, and we used 1 byte to determine it
  if buffer(pos, 1):le_uint() ~= 0 then
    return buffer(pos, 1):le_uint() + 1, 1
  end

  -- If first byte was zero, we need at least 3 bytes to determine the length
  if available_bytes < 3 then
    return -DESEGMENT_ONE_MORE_SEGMENT, 0
  end
  -- If the two following bytes are not zero, then those define the length, and we used 3 bytes to determine the length
  if buffer(pos + 1, 2):le_uint() ~= 0 then
    return buffer(pos + 1, 2):le_uint() + 3, 3
  end

  -- Need 7 bytes to determine the length
  if available_bytes < 7 then
    return -DESEGMENT_ONE_MORE_SEGMENT, 0
  end
  -- The three first bytes are zero, and the following four define the length, and we used 7 bytes to determine the length
  return buffer(pos + 3, 4):le_uint() + 7, 7
end

-- Determine the message lenght. Return the length and how many bytes were "consumed" to determine that
function message_length(buffer, pinfo, tree, pos, sinfo)
  local available_bytes = buffer:len() - pos
  -- We need at least one byte to do anything, but make sure we have at least two to simplify things later
  if available_bytes < 2 then
    return -DESEGMENT_ONE_MORE_SEGMENT, 0
  end

  -- Way might want to use detemined communication type to help determine length (simplifies the heuristics)
  local communication_type = stream_get_type(pinfo)
  if length_based_on_commtype == true then
    -- Determine length based on previously determined type
    if communication_type == "normal" then
      return buffer(pos, 2):le_uint() + 2, 2
    elseif communication_type == "alarmmgr" then
      return message_length_variable(buffer, pinfo, tree, pos, sinfo)
    end
  end

  -- AlarmMgr messages can have varying length fields, and leading zero(es) indicate multi-byte length field
  -- TODO: Also normal "data" message can start with zero, for instance if the length is 0x0100 bytes, and
  -- this is not handled properly with the below heuristic
  if buffer(pos, 1):le_uint() == 0 then
    -- The first byte is 0, so the message length field is (most likely = one in 256) multi-byte
    return message_length_variable(buffer, pinfo, tree, pos, sinfo)
  else
    -- In case this is the first message and the leading bytes maches hex 605fc3b12d05d111bf0800a0c9723e82,
    -- the message length is defined as 48 bytes. We don't know if this is the first message, so we handle
    -- the situation as best we can.
    local first_magic = ByteArray.new(handshake_legacy_magic)
    local compare_len = math.min(available_bytes, 16)
    -- Compare the leading bytes to the first magic
    if buffer(pos, compare_len):bytes() == first_magic:subset(0, compare_len) then
      if compare_len == 16 then
        -- Complete magic matches, so have indeed identified this special case first message (hopefully correctly)
        return 48, 0
      end
      -- Need more data to compare the whole first magic
      return -DESEGMENT_ONE_MORE_SEGMENT, 0
    end

    -- Check for other handshake magics
    for _, magic in ipairs(handshake_normal_magics) do
      compare_len = math.min(available_bytes - 1, 16)
      if buffer(pos + 1, compare_len):bytes() == ByteArray.new(magic):subset(0, compare_len) then
        if compare_len == 16 then
          -- This is a normal handshake with the first byte inicating the length
          return buffer(pos, 1):le_uint() + 1, 1
        end
        -- Need more data to compare the whole first magic
        return -DESEGMENT_ONE_MORE_SEGMENT, 0
      end
    end

    -- Check whether this appears to be an AlarmMgr message
    -- Length needs to be at least 0x14 bytes, because that is the shortest (close to AlarmMgr) header we have seen, and the
    -- following byte needs to be 0
    if buffer(pos, 1):le_uint() >= 0x14 and buffer(pos + 1, 1):le_uint() == 0x0 then
      -- Ensure we have enough bytes to perform the following checks
      if available_bytes < 11 then
        return -DESEGMENT_ONE_MORE_SEGMENT, 0
      end

      -- Check for AlarmMgr magic and header length (to be 0x20)
      if buffer(pos + 5, 2):le_uint() == 0x2dde and buffer(pos + 9, 2):le_uint() == 0x20 then
        -- We are reasonably satisfied that this is an AlarmMgr message...
        return buffer(pos, 1):le_uint() + 1, 1
      end
    end

    -- Not AlarmMgr, so we assume "normal" data with a two-byte length field
    return buffer(pos, 2):le_uint() + 2, 2
  end
end

-- Handler mapping. The table will be checked in order (first to last) and the handler function
-- of the first matching magic values will be returned. The magic values for each handler are
-- defined in a list with the index providing the offset for the magic and the value the actual
-- magic. This allows a type of wildcard mathing by defining several magics with different offsets.
local handler_map = {
  -- Handshakes
  {handle_handshake, {[0] = "605fc3b12d05d111bf0800a0c9723e82"}},
  {handle_handshake, {[0] = "cafe8bbafe8bd311aa0500a0c9ecfd9f"}},
  {handle_handshake, {[0] = "d5cfc7f80bcdd311aa1000a0c9ecfd9f"}},
  {handle_handshake_ack, {[0] = "d4cfc7f80bcdd311aa1000a0c9ecfd9f"}}, -- AlarmMgr handshake ack
  {handle_handshake_ack, {[0] = "96e27844fccdd311aa1000a0c9ecfd9f"}}, -- Register(?) handshake ack
  {handle_handshake_ack, {[0] = "0100"}}, -- "Normal" handshake ack
  -- Transfer
  {handle_transfer, {[0] = "bc7a006164dbd311aa1600a0c9ecfd9f"}},
  -- AlarmMgr
  {handle_alarmmgr, {[0] = "00", [4] = "de2d"}},
  {handle_png, {[0] = "0500"}},
  -- Normal data exchange
  {handle_advise_ack, {[0] = "0300"}},
  {handle_unadvise_ack, {[0] = "0400"}},
  {handle_time, {[0] = "0800"}},
  {handle_update, {[0] = "0900"}},
  {handle_poke_ack, {[0] = "0b00"}},
  {handle_connect, {[0] = "0180"}},
  {handle_advise, {[0] = "1080"}},
  {handle_pong, {[0] = "2340"}},
  {handle_ping, {[0] = "2440"}},
  {handle_peng, {[0] = "2540"}},
  {handle_pang, {[0] = "2640"}},
  {handle_unadvise, {[0] = "0480"}},
  {handle_poke, {[0] = "0b08"}},
  -- Also handle unknown messages
  {handle_unknown, {[0] = ""}}
}

-- Find the handler for the message at hand, or return nil if not found
function find_handler(buffer, pinfo, tree, pos, sinfo)
  -- Determine message length and available bytes
  local msg_len, msg_len_bytecount = message_length(buffer, pinfo, tree, pos, sinfo)
  local available_bytes = buffer:len() - pos - msg_len_bytecount

  -- Go through list of handlers and predefined magic sequences
  for i, handler_row in ipairs(handler_map) do
    handler = handler_row[1]
    magic_list = handler_row[2]

    -- Check whether all magics for this handler matches the message
    local still_matching = true
    for offset, magic in pairs(magic_list) do

      -- Magic length. Two ascii charachters per magic byte
      local magic_len = magic:len() / 2

      -- Only check the magic in case there is enough bytes in the message to do so
      if offset + magic_len > available_bytes then
        still_matching = false
        break
      end

      -- Check if the message is (still) matching the magic
      if buffer(pos + msg_len_bytecount + offset, magic_len):bytes() ~= ByteArray.new(magic) then
        still_matching = false
        break
      end
    end

    -- Return the handler is all defined magics were matching
    if still_matching then
      return handler
    end
  end

  -- No handler found
  return nil  
end

-- Dissect the following suitelink message in the tcp payload
function handle_message(buffer, pinfo, tree, pos, sinfo)

  local available_bytes = buffer:len() - pos

  local msg_len, msg_len_bytecount = message_length(buffer, pinfo, tree, pos, sinfo)
  -- A negative message length means more data is needed to decode the length
  if msg_len < 0 then
    return msg_len
  end

  -- Create a slinfo (suitelink info) table which then handlers can use to simplify processing
  local slinfo = {}
  slinfo.msg_len = msg_len -- Total size of the message in bytes
  slinfo.msg_len_size = msg_len_bytecount -- Amount of bytes that defines message size
  slinfo.pos = pos
  slinfo.stream = sinfo
  slinfo.available_bytes = buffer:len() - pos

  -- Ensure that we have enough bytes to decode the message
  if available_bytes < msg_len then
    return -DESEGMENT_ONE_MORE_SEGMENT
  end

  local handler = find_handler(buffer, pinfo, tree, pos, sinfo, slinfo)
  if handler ~= nil then
    -- TODO: take into account how many bytes were actually handled...
    handler(buffer, pinfo, tree, slinfo)

    local handled_bytes = slinfo.msg_len
    return handled_bytes
  else
    -- Just mark the rest of the packet as suitelink data in case we don't have a handler for it
    print("NO HANDLER FOUND")
    tree:add(sl_protocol, buffer(pos))
    return buffer(pos):len()
  end
end

-- Main dissector function
function sl_protocol.dissector(buffer, pinfo, tree)
  print("============================")
  print(string.format("Decoding packet: %d", pinfo.number))

  -- Don't process empty or cut off payloads
  if buffer:len() == 0 or buffer:len() ~= buffer:reported_len() then
    return
  end

  -- Loop to process all complete suitelink messages in this tcp packet
  local pos = 0
  local tcp_remaining_bytes = buffer:len()
  while pos < buffer:len() - 1 do
    print(string.format("Current pos=%d, remaining bytes=%d", pos, tcp_remaining_bytes))

    -- Set protocol column name
    pinfo.cols.protocol = sl_protocol.name

    -- Stream info to keep track of client names, tag names, etc...
    local sinfo = stream_info(pinfo)

    local handled_bytes
    handled_bytes = handle_message(buffer, pinfo, tree, pos, sinfo)
    if handled_bytes > 0 then
      pos = pos + handled_bytes
    elseif handled_bytes < 0 then
      pinfo.desegment_len = -handled_bytes
      pinfo.desegment_offset = pos
      return
    else
      -- Should not end up here...
      print("ERROR: handle_message() returned 0")
      pos = buffer:len() - 1
    end
  end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(5413, sl_protocol)
