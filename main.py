import struct


crc16_table= [
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48,
    0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, 0x1081, 0x0108,
    0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x6440, 0x9CC9, 0x8D40, 0xBFDB,
    0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876, 0x2102, 0x308B, 0x0210, 0x1399,
    0x6726, 0x76AF, 0x4434, 0x55BD, 0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E,
    0xFAE7, 0xC87C, 0xD9F5, 0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E,
    0x54B5, 0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD,
    0xC974, 0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3, 0x5285,
    0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDECD, 0xCF44,
    0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72, 0x6306, 0x728F, 0x4014,
    0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5,
    0xA96A, 0xB8E3, 0x8A78, 0x9BF1, 0x7387, 0x620E, 0x5095, 0x411C, 0x35A3,
    0x242A, 0x16B1, 0x0738, 0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862,
    0x9AF9, 0x8B70, 0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E,
    0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036, 0x18C1,
    0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E, 0xA50A, 0xB483,
    0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5, 0x2942, 0x38CB, 0x0A50,
    0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD, 0xB58B, 0xA402, 0x9699, 0x8710,
    0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7,
    0x6E6E, 0x5CF5, 0x4D7C, 0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1,
    0xA33A, 0xB2B3, 0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72,
    0x3EFB, 0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A, 0xE70E,
    0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1, 0x6B46, 0x7ACF,
    0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9, 0xF78F, 0xE606, 0xD49D,
    0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E, 0x58D5, 0x495C,
    0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
]
# crc16_buffer = bytearray(struct.pack('H', x) for x in crc16_table)
def get_crc16(data: bytes) -> bytes:
    fcs = 0xFFFF
    for byte in data:
        index = ((fcs ^ byte) & 0xFF) * 2
        fcs = (fcs >> 8) ^ CRC16_TABLE[index]

    fcs = (~fcs) & 0xFFFF
    return struct.pack('>H', fcs)

def parse_login(data: bytes) -> dict:
    imei = int(data[4:12].hex(), 16)
    serial_number = int.from_bytes(data[12:14], byteorder='big')
    return {
        "imei": imei,
        "serial_number": serial_number
    }


def get_crc16(data):
    fcs = 0xFFFF
    for byte in data:
        index = ((fcs ^ byte) & 0xFF) * 2
        fcs = (fcs >> 8) ^ struct.unpack('<H', crc16_buffer[index:index + 2])[0]
    return struct.pack('>H', (~fcs) & 0xFFFF)

class Gt06:
    def __init__(self):
        self.msg_buffer_raw = []
        self.msg_buffer = []
        self.imei = None

    def parse(self, data):
        self.msg_buffer_raw = self.slice_msgs_in_buff(data)
        parsed_messages = []

        for idx, msg in enumerate(self.msg_buffer_raw):
            parsed = {}
            event_type = self.select_event(msg)
            if event_type == 0x01:
                parsed.update(self.parse_login(msg))
                parsed['expects_response'] = True
                parsed['response_msg'] = self.create_response(msg)
            elif event_type == 0x12:
                parsed.update(self.parse_location(msg))
            elif event_type == 0x13:
                parsed.update(self.parse_status(msg))
                parsed['expects_response'] = True
                parsed['response_msg'] = self.create_response(msg)
            elif event_type == 0x16:
                parsed.update(self.parse_alarm(msg))
            else:
                raise ValueError(f"Unknown message type: {event_type}")

            parsed['event'] = event_type
            parsed['parse_time'] = datetime.now()
            if idx == len(self.msg_buffer_raw) - 1:
                self.imei = parsed.get('imei')
            self.msg_buffer.append(parsed)
            parsed_messages.append(parsed)

        return parsed_messages

    def clear_msg_buffer(self):
        self.msg_buffer = []

    def slice_msgs_in_buff(self, data):
        start_pattern = b'\x78\x78'
        next_start = data.find(start_pattern)
        msg_array = []

        while next_start != -1:
            msg_array.append(data[:next_start])
            data = data[next_start:]
            next_start = data.find(start_pattern)

        msg_array.append(data)
        return msg_array

    def select_event(self, data):
        event_str = 'unknown'
        event_number = data[3]
        if event_number == 0x01:
            event_str = 'login'
        elif event_number == 0x12:
            event_str = 'location'
        elif event_number == 0x13:
            event_str = 'status'
        elif event_number == 0x16:
            event_str = 'alarm'
        return event_number

    def parse_login(self, data):
        imei = int(data[4:12].hex(), 16)
        serial_number = int.from_bytes(data[12:14], 'big')
        return {'imei': imei, 'serial_number': serial_number}

    def parse_status(self, data):
        status_info = data[4:9]
        terminal_info = status_info[0]
        voltage_level = status_info[1]
        gsm_sig_strength = status_info[2]

        alarm = (terminal_info & 0x38) >> 3
        alarm_type = {
            1: 'shock',
            2: 'power cut',
            3: 'low battery',
            4: 'sos'
        }.get(alarm, 'normal')

        term_obj = {
            'status': bool(terminal_info & 0x01),
            'ignition': bool(terminal_info & 0x02),
            'charging': bool(terminal_info & 0x04),
            'alarm_type': alarm_type,
            'gps_tracking': bool(terminal_info & 0x40),
            'relay_state': bool(terminal_info & 0x80)
        }

        voltage_level_str = {
            1: 'extremely low battery',
            2: 'very low battery (low battery alarm)',
            3: 'low battery (can be used normally)',
            4: 'medium',
            5: 'high',
            6: 'very high'
        }.get(voltage_level, 'no power (shutting down)')

        gsm_sig_strength_str = {
            1: 'extremely weak signal',
            2: 'very weak signal',
            3: 'good signal',
            4: 'strong signal'
        }.get(gsm_sig_strength, 'no signal')

        return {
            'terminal_info': term_obj,
            'voltage_level': voltage_level_str,
            'gsm_sig_strength': gsm_sig_strength_str
        }

    def parse_location(self, data):
        fix_time = datetime.utcfromtimestamp(int.from_bytes(data[4:10], 'big'))
        quantity = data[10]
        lat = int.from_bytes(data[11:15], 'big')
        lon = int.from_bytes(data[15:19], 'big')
        speed = data[19]
        course = int.from_bytes(data[20:22], 'big')
        mcc = int.from_bytes(data[22:24], 'big')
        mnc = data[24]
        lac = int.from_bytes(data[25:27], 'big')
        cell_id = int.from_bytes(data[27:30], 'big')

        return {
            'fix_time': fix_time,
            'sat_cnt': (quantity & 0xF0) >> 4,
            'sat_cnt_active': (quantity & 0x0F),
            'lat': self.decode_lat(lat, course),
            'lon': self.decode_lon(lon, course),
            'speed': speed,
            'course': course,
            'mcc': mcc,
            'mnc': mnc,
            'lac': lac,
            'cell_id': cell_id
        }

    def parse_alarm(self, data):
        fix_time = datetime.utcfromtimestamp(int.from_bytes(data[4:10], 'big'))
        quantity = data[10]
        lat = int.from_bytes(data[11:15], 'big')
        lon = int.from_bytes(data[15:19], 'big')
        speed = data[19]
        course = int.from_bytes(data[20:22], 'big')
        mcc = int.from_bytes(data[22:24], 'big')
        mnc = data[24]
        lac = int.from_bytes(data[25:27], 'big')
        cell_id = int.from_bytes(data[27:30], 'big')
        terminal_info = data[31]
        voltage_level = data[32]
        gps_signal = data[33]
        alarm_lang = int.from_bytes(data[34:36], 'big')
        serial_nr = int.from_bytes(data[36:38], 'big')

        return {
            'fix_time': fix_time,
            'sat_cnt': (quantity & 0xF0) >> 4,
            'sat_cnt_active': (quantity & 0x0F),
            'lat': self.decode_lat(lat, course),
            'lon': self.decode_lon(lon, course),
            'speed': speed,
            'course': course,
            'mcc': mcc,
            'mnc': mnc,
            'lac': lac,
            'cell_id': cell_id,
            'terminal_info': terminal_info,
            'voltage_level': voltage_level,
            'gps_signal': gps_signal,
            'alarm_lang': alarm_lang,
            'serial_nr': serial_nr
        }

    def create_response(self, data):
        response_raw = b'\x78\x78\x05\xFF\x00\x01\xd9\xdc\x0d\x0a'
        response_raw = bytearray(response_raw)
        response_raw[3] = data[3]  # Set the protocol number to match the received message
        crc = self.get_crc16(response_raw[2:6])
        response_raw[-4:-2] = crc
        return bytes(response_raw)

    def decode_lat(self, lat, course):
        latitude = lat / 60.0 / 30000.0
        if not (course & 0x0400):
            latitude = -latitude
        return round(latitude, 6)

    def decode_lon(self, lon, course):
        longitude = lon / 60.0 / 30000.0
        if course & 0x0800:
            longitude = -longitude
        return round(longitude, 6)


data = b'\x78\x78\x05\x01' + b'\x00' * 10  # Replace with real data to parse
gt06 = Gt06()
parsed = gt06.parse(data)
print(parsed)
