

import socket
import struct
import math
import datetime

HOST = "127.0.0.1"
PORT = 5413

# Convert filetime to datetime
def filetime_to_datetime_and_micros(filetime):

    seconds = math.floor(filetime / 10_000_000)
    microseconds = (filetime % 10_000_000) / 10

    # Nuber of seconds between suitelink time (same as Windows FILETIME) and unix epoch time is 11644473600
    dt = datetime.datetime.fromtimestamp(seconds - 11644473600)

    return dt, microseconds

# Unpack a null-terminated string from the data
def stringz(data):
    str = ""
    endz = 0
    for endz in range(len(data)):
        if data[endz] == 0:
            break
    return data[:endz].decode("utf-8")
        

class AlarmManager:
    def __init__(self):
        self.lpAcc = 0
        self.application = "AlarmMgr"
        self.nodename = "WORKGROUP"
        self.username = "Superuser"
        self.whichalarmlist = 2 # Historical alarms
    
    def send_handshake(self):
        payload = bytearray()
        payload += b'\x00' # Packet length, update later
        payload += b'\xca\xfe\x8b\xba\xfe\x8b\xd3\x11\xaa\x05\x00\xa0\xc9\xec\xfd\x9f' # Query magic
        payload += b'\xff\x98\x55\xc8\x3d\x25\xd4\x11\xaa\x27\x00\xa0\xc9\xec\xfd\x9f' # Some other magic, possibly fairly arbitrary
        payload += struct.pack("<I", 1) # Connection type, 1 is what we need
        payload += self.application.encode("utf_16_le") + b'\x00\x00' # Target application
        payload += self.nodename.encode("utf_16_le") + b'\x00\x00' # Local node name
        payload += self.username.encode("utf_16_le") + b'\x00\x00' # Local user name
        payload[0:1] = struct.pack("<B", len(payload) - 1) # Packet length
        
        self.sock.send(payload)

    def send_connect(self):
        payload = bytearray()
        # Header
        payload += b'\x00' # Packet length, update later
        payload += b'\x00\x20\x04\xc3' # Unknown bytes
        payload += struct.pack("<H", 0x2dde) # Magic magic
        payload += struct.pack("<H", 1) # Version
        payload += struct.pack("<H", 32) # Header length. This is pretty much fixed
        payload += struct.pack("<H", 0) # Data length, update later
        payload += struct.pack("<H", 1) # Record count
        payload += b'\x00\x00' # Unknown bytes
        payload += struct.pack("<I", 1) # Buffer number
        payload += struct.pack("<I", 0) # Time in Q
        payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Unknown bytes
        # Data
        payload += struct.pack("<I", 0x2345eaea) # Record magic
        payload += struct.pack("<I", 0x01060103) # Record version
        payload += struct.pack("<H", 0x21) # Record type, 0x21 = CONNECT
        payload += struct.pack("<H", 0) # Record length, same as data length above, update later
        payload += b'\x00\x00\x00\x00' # Reserved, all zeroes
        payload += struct.pack("<I", 0) # Buffer number
        payload += b'\x00\x00\x00\x00\x96\x71\x00\x00\x00\x00\x00\x00' # Unknown
        payload += struct.pack("<B", 0) # Status 1
        payload += struct.pack("<B", 32) # Status 2
        payload += struct.pack("<B", 1) # Status 3
        payload += struct.pack("<B", 0) # Status 4
        payload += b'\x00\x00\x00\x00' # Unknown
        payload += "\intouch".encode() + b'\x00' # Global name
        payload += "intouch".encode() + b'\x00' # Local name
        payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Unknown
        payload[0:1] = struct.pack("<B", len(payload) - 1) # Packet length ("remaining bytes")
        payload[11:13] = struct.pack("<H", len(payload) - 1 - 32) # Data length
        payload[43:45] = struct.pack("<H", len(payload) - 1 - 32) # Record length
        self.sock.send(payload)

    def alarmmgr_almbuf_alm_new_query(self, whichalarmlist=0x02, query="$system"):
        payload = bytearray()
        payload += struct.pack('<H', 0) # Almbuf size, update later
        payload += struct.pack('<H', 0x0101) # Almbuf version
        payload += struct.pack('<H', 0x0065) # Activation code, 0x65 is ALM_NEW_QUERY
        payload += struct.pack('<I', 0xffffffff) # Client hDisplay
        payload += struct.pack('<I', 0xffffffff) # hProvSubscription
        payload += struct.pack('<I', 0xffffffff) # hUpdateRec
        payload += struct.pack('<I', 0xffffffff) # Client hServerRec
        payload += struct.pack('<H', whichalarmlist) # 0x01 is SUMMARY, 0x02 is HISTORICAL
        payload += struct.pack('<H', 0x0101) # Version
        payload += struct.pack('<I', 0x00000200) # di_hProvCacheRec
        payload += struct.pack('<H', whichalarmlist) # di_wWhichAlarmList
        payload += b'\x00\x03\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x40\x00\x36\x00' # Unknown
        payload += struct.pack('<H', 0x0104) # Query version
        payload += b'\x00\x00\x01\x00\xe7\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Unknown, continues on next line
        payload += b'\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00' # Unknown, continues on next line
        payload += b'\x36\x29\x00\x00\x0c\x00' # Unknown
        payload += struct.pack('<H', 0x0001) # Group offset
        payload += b'\x00' # Unknown
        payload += query.encode() + b'\x00'
        payload += b'\x00' # Unknown
        payload[0:2] = struct.pack('<H', len(payload)) # Update almbuf size
        return payload
    
    def alarmmgr_almbuf(self, buffernumber, lpacc, data):
        payload = bytearray()
        payload += struct.pack("<I", 0x2345eaea) # Record magic
        payload += struct.pack("<I", 0x01060103) # Record version
        payload += struct.pack("<H", 0x25) # Record type, 0x21 = ALARMBUF
        payload += struct.pack("<H", 35 + len(data)) # Record length, we make up 35 bytes here
        payload += b'\x00\x00\x00\x00' # Reserved, all zeroes
        payload += struct.pack("<I", buffernumber) # Buffer number
        payload += b'\x00\x00\x00\x00' # Unknown
        payload += struct.pack("<I", lpacc) # lpAcc
        payload += b'\x00\x00\x00\x00' # Unknown
        payload += struct.pack("<H", len(data)) # Almbuf length
        payload += data
        payload += b'\x00' # Unknown, end byte(?)
        return payload

    def alarmmgr_header(self, buffernumber, data):
        payload = bytearray()
        # Header
        payload += struct.pack("<B", 32 + len(data)) # Packet length, update later
        payload += b'\x00\x20\x04\xc3' # Unknown bytes
        payload += struct.pack("<H", 0x2dde) # Magic magic
        payload += struct.pack("<H", 1) # Version
        payload += struct.pack("<H", 32) # Header length. This is pretty much fixed
        payload += struct.pack("<H", len(data)) # Data length
        payload += struct.pack("<H", 1) # Record count
        payload += b'\x00\x00' # Unknown bytes
        payload += struct.pack("<I", buffernumber) # Buffer number
        payload += struct.pack("<I", 0) # Time in Q
        payload += b'\x00\x00\x00\x00\x00\x00\x00\x00' # Unknown bytes
        payload += data
        return payload

    # Return the message length in case we have the complete message, otherwise minus how many more bytes are needed
    def almmgr_length(self, data):
        # Need at least one byte
        if len(data) < 1:
            return -1, 0
        
        # If first byte is non-zero, that defines the remaining length
        remaining_bytes, = struct.unpack("<B", data[0:1])
        if remaining_bytes != 0:
            if len(data) >= remaining_bytes + 1:
                return remaining_bytes + 1, 1
            else:
                return len(data) - remaining_bytes - 1, 0
        
        # First byte zero and we need at least three bytes
        if len(data) < 3:
            return len(data) - 3, 0
        
        # If byte two and three are non-zero, they define the remaining length
        remaining_bytes, = struct.unpack("<H", data[1:3])
        if remaining_bytes != 0:
            if len(data) >= remaining_bytes + 3:
                return remaining_bytes + 3, 3
            else:
                return len(data) - remaining_bytes - 3, 0
        
        # First three bytes are zero, so we need at least seven bytes
        if len(data) < 7:
            return len(data) - 7, 0
        
        # Bytes four through seven define the length
        remaining_bytes, = struct.unpack("<I", data[3:7])
        if len(data) >= remaining_bytes + 7:
            return remaining_bytes + 7, 7
        else:
            return len(data) - remaining_bytes - 7, 0
        
    def handle_message(self, data):
        msglen, lensize = self.almmgr_length(data)
        # print("Message length: {}".format(msglen))

        # Strip message length bytes
        data = data[lensize:]

        if msglen < 32:
            print("Incomplete AlarmMgr message header, discarding message")
            return
        
        magic, = struct.unpack("<H", data[4:6])
        if magic != 0x2dde:
            print("Incorrect AlarmMgr magic \"0x{:x}\", discarding message".format(magic))
            return
        
        hdrlen, datalen = struct.unpack("<HH", data[8:12])
        if msglen < hdrlen + datalen:
            print("Message length {} is shorter data header length {} plus data length {}".format(msglen, hdrlen, datalen))
        # print("Header length: {}, data length: {}".format(hdrlen, datalen))

        rectype, reclen = struct.unpack("<HH", data[40:44])
        if rectype != 0x25:
            # print("Message record not AlmBuf, discarding")
            return
        
        actcode, = struct.unpack("<H", data[70:72])
        if actcode != 0x01:
            # print("Not ALARM_ADDED, skipping message")
            return
        
        alarm_offset = 90
        alarm_data = data[alarm_offset:]

        # Origination filetime
        origination_filetime, = struct.unpack("<Q", alarm_data[0x18:0x20])
        origination_time, origination_micros = filetime_to_datetime_and_micros(origination_filetime)

        # Last change time(?)
        lastchange_filetime, = struct.unpack("<Q", alarm_data[0x48:0x50])
        lastchange_time, lastchange_micros = filetime_to_datetime_and_micros(lastchange_filetime)

        # Alarm transition
        transition_map = {
            0: "SUB",
            1: "ALM",
            2: "RTN",
            4: "ACK",
            6: "ARTN",
            8: "SUB"
        }
        transition, = struct.unpack("<H", alarm_data[0x5a:0x5c])

        almhdr_size, = struct.unpack("<H", alarm_data[0x88:0x8a])
        string_count, = struct.unpack("<H", alarm_data[almhdr_size:almhdr_size+2])

        strings_start = almhdr_size + string_count * 2 + 2

        tagname_offset, = struct.unpack("<H", alarm_data[almhdr_size+2:almhdr_size+4])
        tagname_start = strings_start + tagname_offset
        tagname = stringz(alarm_data[tagname_start:])

        print("{:4s}  {}.{:03d}    {}.{:03d}   {}".format(transition_map.get(transition, "???"),
            lastchange_time.strftime("%Y-%m-%d %H:%M:%S"), math.floor(lastchange_micros/1000),
            origination_time.strftime("%Y-%m-%d %H:%M:%S"), math.floor(origination_micros/1000),
            tagname))


    def send_query(self):
        almbuf_new_query = self.alarmmgr_almbuf_alm_new_query(whichalarmlist=self.whichalarmlist)
        almbuf = self.alarmmgr_almbuf(self.bufNum + 1, self.lpAcc, almbuf_new_query)
        message = self.alarmmgr_header(0x00000002, almbuf)
        self.sock.send(message)

    def recv_handshake_ack(self):
        # We don't really need anything from the handshake ack, so we simply discard it
        data = self.sock.recv(1024)
        return data
        
    def recv_connect_ack(self):
        data = self.sock.recv(1024)
        self.lpAcc, = struct.unpack("<I", data[0x41:0x45])
        self.bufNum, = struct.unpack("<I", data[0x31:0x35])
        print("Received bufNum: 0x{:08x} and lpAcc: 0x{:08x}".format(self.bufNum, self.lpAcc))
        
    def recv_data(self):
        self.sock.settimeout(1)
        data = []
        while len(data) == 0:
            try:
                data = self.sock.recv(1024)
            except socket.error:
                pass
        return data
    
    def query(self, server, query):
        print("Connecting")
    
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(server)
        
        print("Sending handshake")
        self.send_handshake()
        
        print("Waiting for handshake ACK")
        self.recv_handshake_ack()
        
        print("Sending connect")
        self.send_connect()
        
        print("Waiting for connect ACK")
        self.recv_connect_ack()
        
        print("Sending query")
        self.send_query()
        
        print("Waiting for updates")

        data = bytearray()
        while True:
            data = data + self.recv_data()
            # print("Received data...")
            while True:
                msglen, _ = self.almmgr_length(data)
                if msglen < 0:
                    break

#                print("Handling data")
                self.handle_message(data)
                data = data[msglen:]

if __name__ == "__main__":
    almmgr = AlarmManager()
    
    almmgr.query((HOST, PORT), "$system")