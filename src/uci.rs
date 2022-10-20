use std::fmt;
use std::num::ParseIntError;
use std::collections::HashMap;
use lazy_static::lazy_static;
use byteorder::{ByteOrder, LittleEndian};

/* Packet type */
struct Packet{
    bytes: Vec<u8>,
}

impl Packet {
    fn new(bytes: Vec<u8>) -> Packet {
        Packet {
            bytes: bytes,
        }
    }
    fn mt(&self) -> u8 {
        self.bytes[0] >> 5
    }
    fn gid(&self) -> u8 {
        self.bytes[0] & 0xf
    }
    fn oid(&self) -> u8 {
        self.bytes[1]
    }
    fn len(&self) -> u8 {
        self.bytes[3]
    }

    /* get(), slice(): for payload accesses */
    fn get(&self, idx: usize) -> u8 {
        self.bytes[idx + 4]
    }
    fn slice<'a>(&'a self, idx: usize, len: usize) -> &'a [u8] {
        &self.bytes[idx + 4..idx + len + 4]
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mt:{:#3x} gid:{:#3x} oid:{:#3x} len:{:#4x}",
               self.mt(), self.gid(), self.oid(), self.len())
    }
}

/* Error types */
pub struct UciPacketParseError {
    msg: String,
}

impl UciPacketParseError {
    fn new(msg: &str) -> UciPacketParseError {
        UciPacketParseError { msg: msg.to_string() }
    }
}

impl fmt::Display for UciPacketParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

/*
 * UCI protocol definitions
 */
#[allow(dead_code)]
mod mt {
    pub const CMD   :u8 = 1;
    pub const RSP   :u8 = 2;
    pub const NTF   :u8 = 3;
}

#[allow(dead_code)]
mod gid {
    pub const CORE                      :u8 = 0x00;
    pub const SESSION                   :u8 = 0x01;
    pub const RANGING                   :u8 = 0x02;
    pub const PROPRIETARY               :u8 = 0x0e;
    pub const PROPRIETARY_A             :u8 = 0x0a;
    pub const TEST                      :u8 = 0x0d;
}

#[allow(dead_code)]
mod oid {
    pub const CORE_DEVICE_RESET         :u8 = 0;
    pub const CORE_DEVICE_STATUS        :u8 = 1;
    pub const CORE_GET_DEVICE_INFO      :u8 = 2;
    pub const CORE_GET_CAPS_INFO        :u8 = 3;
    pub const CORE_SET_CONFIG           :u8 = 4;
    pub const CORE_GET_CONFIG           :u8 = 5;
    pub const CORE_GENERIC_ERROR        :u8 = 7;

    pub const SESSION_INIT              :u8 = 0;
    pub const SESSION_DEINIT            :u8 = 1;
    pub const SESSION_STATUS            :u8 = 2;
    pub const SESSION_SET_APP_CONFIG    :u8 = 3;
    pub const SESSION_GET_APP_CONFIG    :u8 = 4;
    pub const SESSION_GET_COUNT         :u8 = 5;
    pub const SESSION_GET_STATE         :u8 = 6;

    pub const RANGE_START               :u8 = 0;
    pub const RANGE_DATA_NTF            :u8 = 0;
    pub const RANGE_STOP                :u8 = 1;
    pub const GET_RANGING_COUNT         :u8 = 3;
    pub const BLINK_DATA_TX             :u8 = 4;

    pub const TEST_CONFIG_SET           :u8 = 0;
    pub const TEST_CONFIG_GET           :u8 = 1;
    pub const TEST_PERIODIC_TX          :u8 = 2;
    pub const TEST_PER_RX               :u8 = 3;
    pub const TEST_RX                   :u8 = 5;
    pub const TEST_LOOPBACK             :u8 = 6;
    pub const TEST_STOP_SESSION         :u8 = 7;
    pub const TEST_SS_TWR               :u8 = 8;

    pub const NXP_CORE_DEVICE_INIT      :u8 = 0x00;
    pub const NXP_SE_DO_BIND            :u8 = 0x01;
    pub const NXP_SE_GET_BINDING_CNT    :u8 = 0x0a;
    pub const NXP_SE_GET_BINDING_STAT   :u8 = 0x0c;
    pub const NXP_TEST_LOOP             :u8 = 0x0d;
    pub const NXP_TEST_CONNECTIVITY     :u8 = 0x0e;
    pub const NXP_SE_COMM_ERROR         :u8 = 0x10;
    pub const NXP_SET_CALIBRATION       :u8 = 0x11;
    pub const NXP_GET_CALIBRATION       :u8 = 0x12;
    pub const NXP_BINDING_STAT          :u8 = 0x13;
    pub const NXP_GET_INTF_STAT         :u8 = 0x21;
    pub const NXP_WRITE_CALIB_DATA      :u8 = 0;
    pub const NXP_READ_CALIB_DATA       :u8 = 1;
}

#[derive(PartialEq)]
enum ParamType {
    Hex8,
    Hex16,
    Hex32,
    Dec8,
    Dec16,
    Dec32,
    HexArray(i16),
    CharArray(u16),
    Table8(&'static [(u8, &'static str)]),
}

#[derive(PartialEq)]
struct Field(&'static str, ParamType);

impl Field {
    fn size(&self) -> usize {
        match self.1 {
            ParamType::Hex8  | ParamType::Dec8  => 1,
            ParamType::Hex16 | ParamType::Dec16 => 2,
            ParamType::Hex32 | ParamType::Dec32 => 4,
            ParamType::HexArray(x) => x as usize,
            ParamType::CharArray(x) => x as usize,
            ParamType::Table8(_x) => 1,
        }
    }
    fn length_compatible(&self, len: usize) -> bool {
        match self.size() {
            0 => true,
            x => x as usize == len,
        }
    }
}

lazy_static! {
    static ref STATUS_CODES: HashMap<u8, &'static str> = {
        HashMap::from([
            ( 0x00u8, "OK"),
            ( 0x01u8, "REJECTED"),
            ( 0x02u8, "FAILED"),
            ( 0x03u8, "SYNTAX_ERROR"),
            ( 0x04u8, "INVALID_PARAM"),
            ( 0x05u8, "INVALID_RANGE"),
            ( 0x06u8, "INVALID_MESSAGE_SIZE"),
            ( 0x07u8, "UNKNOWN_GID"),
            ( 0x08u8, "UNKNOWN_OID"),
            ( 0x09u8, "READ_ONLY"),
            ( 0x0Au8, "COMMAND_RETRY"),
            ( 0x11u8, "ERROR_SESSION_NOT_EXIST"),
            ( 0x12u8, "ERROR_SESSION_DUPLICATE"),
            ( 0x13u8, "ERROR_SESSION_ACTIVE"),
            ( 0x14u8, "ERROR_MAX_SESSIONS_EXCEEDED"),
            ( 0x15u8, "ERROR_SESSION_NOT_CONFIGURED"),
            ( 0x16u8, "ERROR_ACTIVE_SESSIONS_ONGOING"),
            ( 0x17u8, "ERROR_MULTICAST_LIST_FULL"),
            ( 0x18u8, "ERROR_ADDRESS_NOT_FOUND"),
            ( 0x19u8, "ERROR_ADDRESS_ALREADY_PRESENT"),
            ( 0x20u8, "RANGING_TX_FAILED"),
            ( 0x21u8, "RANGING_RX_TIMEOUT"),
            ( 0x22u8, "RANGING_RX_PHY_DEC_FAILED"),
            ( 0x23u8, "RANGING_RX_PHY_TOA_FAILED"),
            ( 0x24u8, "RANGING_RX_PHY_STS_FAILED"),
            ( 0x25u8, "RANGING_RX_MAC_DEC_FAILED"),
            ( 0x26u8, "RANGING_RX_MAC_IE_DEC_FAILED"),
            ( 0x27u8, "RANGING_RX_MAC_IE_MISSING"),
            ( 0x50u8, "BINDING_SUCCESS" ),
            ( 0x51u8, "BINDING_FAILURE" ),
            ( 0x52u8, "BINDING_LIMIT_REACHED" ),
            ( 0x53u8, "CALIBRATION_IN_PROGRESS" ),
            ( 0x54u8, "DEVICE_TEMP_REACHED_THERMAL_RUNAWAY" ),
            ( 0x55u8, "FEATURE_NOT_SUPPORTED" ),
            ( 0x56u8, "NUM_PACKET_EXCEEDS_1000_FOR_TEST_PER_RX" ),
            ( 0x57u8, "CAILBRATION_NOT_CONFIGURED" ),
            ( 0x70u8, "NO_SE" ),
            ( 0x72u8, "SE_RECOVERY_FAILURE" ),
            ( 0x73u8, "SE_RECOVERY_SUCCESS" ),
            ( 0x74u8, "SE_APDU_CMD_FAIL" ),
            ( 0x75u8, "SE_AUTH_FAIL" ),
            ( 0x81u8, "RANGING_PHY_RX_SECDEC_FAILED" ),
            ( 0x82u8, "RANGING_PHY_RX_RSDEC_FAILED" ),
            ( 0x83u8, "RANGING_PHY_RX_DEC_FAILED" ),
            ( 0x84u8, "RANGING_PHY_RX_ERR_FAILED" ),
            ( 0x85u8, "RANGING_PHY_RX_PHR_DECODE_FAILED" ),
            ( 0x86u8, "RANGING_PHY_RX_SYNC_SFD_TIMEOUT" ),
            ( 0x87u8, "RANGING_PHY_RX_PHR_DATA_RATE_ERROR" ),
            ( 0x88u8, "RANGING_PHY_RX_PHR_RANGING_ERROR" ),
            ( 0x89u8, "RANGING_PHY_RX_PHR_PREAMBLE_DUR_ERROR" ),
            ( 0x8au8, "MAX_ACTIVE_GRANT_DURATION_EXCEEDED" ),
            ( 0x8bu8, "RANGING_SUSPENDED" ),
            ( 0x90u8, "DATA_TRANSFER_ERROR" ),
            ( 0x91u8, "DATA_NO_CREDIT_AVAILABLE" ),
            ( 0x92u8, "DATA_TRANSFER_STOPPED" ),
            ( 0xa0u8, "COEX_WLAN_UART_RSP_TIMEOUT_OR_INVALID" ),
            ( 0xa1u8, "COEX_WLAN_UART_RSP_INVALID" ),
        ])
    };

    static ref DEVICE_STATUS_CODES: HashMap<u8, &'static str> = {
        HashMap::from([
            ( 0x01u8, "DEVICE_STATE_READY" ),
            ( 0x02u8, "DEVICE_STATE_ACTIVE" ),
            ( 0xffu8, "DEVICE_STATE_ERROR" ),
        ])
    };

    static ref DEVICE_CONF_PARAMS: HashMap<u8, Field> = {
        HashMap::from([
            ( 0x00u8, Field("DEVICE_STATE", ParamType::Hex8) ),
            ( 0x01u8, Field("LOW_POWER_MODE", ParamType::Hex8) ),
        ])
    };
    
    static ref DEVICE_CONF_PARAMS_NXP: HashMap<(u8, u8), Field> = {
        HashMap::from([
            ( (0xe4u8, 0x02u8), Field("DPD_WAKEUP_SRC", ParamType::Hex8) ),
            ( (0xe4u8, 0x03u8), Field("WTX_COUNT_CONFIG", ParamType::Dec8) ),
            ( (0xe4u8, 0x04u8), Field("DPD_ENTRY_TIMEOUT", ParamType::Dec16) ),
            ( (0xe4u8, 0x05u8), Field("WIFI_COEX_FEATURE", ParamType::HexArray(4)) ),
            ( (0xe4u8, 0x26u8), Field("TX_BASE_BAND_CONFIG", ParamType::Hex8) ),
            ( (0xe4u8, 0x27u8), Field("DDFS_TONE_CONFIG", ParamType::HexArray(72)) ),
            ( (0xe4u8, 0x28u8), Field("TX_PULSE_SHAPE_CONFIG", ParamType::HexArray(3)) ),
            ( (0xe4u8, 0x30u8), Field("CLK_CONFIG_CTRL", ParamType::HexArray(2)) ),
            ( (0xe4u8, 0x33u8), Field("NXP_EXTENDED_NTF_CONFIG", ParamType::Dec8) ),
            ( (0xe4u8, 0x34u8), Field("CLOCK_PRESENT_WAITING_TIME", ParamType::Dec16) ),
            ( (0xe4u8, 0x60u8), Field("ANTENNA_RX_IDX_DEFINE", ParamType::HexArray(0)) ),
            ( (0xe4u8, 0x61u8), Field("ANTENNA_TX_IDX_DEFINE", ParamType::HexArray(0)) ),
            ( (0xe4u8, 0x62u8), Field("ANTENNAS_RX_PAIR_DEFINE", ParamType::HexArray(0)) ),
        ])
    };

    static ref APP_CONF_PARAMS: HashMap<u8, Field> = {
        HashMap::from([
            ( 0x00u8, Field("DEVICE_TYPE", ParamType::Table8(&[(0u8, "Controlee"), (1u8, "Controller")])) ),
            ( 0x01u8, Field("RANGING_ROUND_USAGE", ParamType::Table8(&[
                (0u8, "TDoA"),
                (1u8, "SS-TWR"), (2u8, "DS-TWR"),
                (3u8, "SS-TWR non-deferred"), (4u8, "DS-TWR non-deferred"),
                (5u8, "Downlink TDOA"),
            ])) ),
            ( 0x02u8, Field("STS_CONFIG", ParamType::Table8(&[(0u8, "Static STS"), (1u8, "Dynamic STS"), (2u8, "Dynamic STS with sub-session key"),])) ),
            ( 0x03u8, Field("MULTI_NODE_MODE", ParamType::Hex8) ),
            ( 0x04u8, Field("CHANNEL_NUMBER", ParamType::Hex8) ),
            ( 0x05u8, Field("NUMBER_OF_CONTROLEES", ParamType::Dec8) ),
            ( 0x06u8, Field("DEVICE_MAC_ADDRESS", ParamType::Hex16) ),
            ( 0x07u8, Field("DST_MAC_ADDRESS", ParamType::Hex16) ),
            ( 0x08u8, Field("SLOT_DURATION", ParamType::Dec16) ),
            ( 0x09u8, Field("RANGING_INTERVAL", ParamType::Dec32) ),
            ( 0x0Au8, Field("STS_INDEX", ParamType::Hex32) ),
            ( 0x0Bu8, Field("MAC_FCS_TYPE", ParamType::Hex8) ),
            ( 0x0Cu8, Field("RANGING_ROUND_CONTROL", ParamType::Hex8) ),
            ( 0x0Du8, Field("AOA_RESULT_REQ", ParamType::Hex8) ),
            ( 0x0Eu8, Field("RANGE_DATA_NTF_CONFIG", ParamType::Hex8) ),
            ( 0x0Fu8, Field("RANGE_DATA_NTF_PROXIMITY_NEAR", ParamType::Dec16) ),
            ( 0x10u8, Field("RANGE_DATA_NTF_PROXIMITY_FAR", ParamType::Dec16) ),
            ( 0x11u8, Field("DEVICE_ROLE", ParamType::Table8(&[
                (0u8, "Responder"), (1u8, "Initiator"),
                (2u8, "Master Anchor"), (3u8, "Initiator & Responder"),
                (4u8, "Receiver"),
            ])) ),
            ( 0x12u8, Field("RFRAME_CONFIG", ParamType::Hex8) ),
            ( 0x14u8, Field("PREAMBLE_CODE_INDEX", ParamType::Hex8) ),
            ( 0x15u8, Field("SFD_ID", ParamType::Hex8) ),
            ( 0x16u8, Field("PSDU_DATA_RATE", ParamType::Hex8) ),
            ( 0x17u8, Field("PREAMBLE_DURATION", ParamType::Hex8) ),
            ( 0x1Au8, Field("RANGING_TIME_STRUCT", ParamType::Hex8) ),
            ( 0x1Bu8, Field("SLOTS_PER_RR", ParamType::Hex8) ),
            ( 0x1Cu8, Field("TX_ADAPTIVE_PAYLOAD_POWER", ParamType::Hex8) ),
            ( 0x1Eu8, Field("RESPONDER_SLOT_INDEX", ParamType::Hex8) ),
            ( 0x1Fu8, Field("PRF_MODE", ParamType::Hex8) ),
            ( 0x22u8, Field("SCHEDULED_MODE", ParamType::Hex8) ),
            ( 0x23u8, Field("KEY_ROTATION", ParamType::Hex8) ),
            ( 0x24u8, Field("KEY_ROTATION_RATE", ParamType::Hex8) ),
            ( 0x25u8, Field("SESSION_PRIORITY", ParamType::Dec8) ),
            ( 0x26u8, Field("MAC_ADDRESS_MODE", ParamType::Hex8) ),
            ( 0x27u8, Field("VENDOR_ID", ParamType::HexArray(2)) ),
            ( 0x28u8, Field("STATIC_STS_IV", ParamType::HexArray(6)) ),
            ( 0x29u8, Field("NUMBER_OF_STS_SEGMENTS", ParamType::Dec8) ),
            ( 0x2Au8, Field("MAX_RR_RETRY", ParamType::Dec16) ),
            ( 0x2Bu8, Field("UWB_INITIATION_TIME", ParamType::Dec32) ),
            ( 0x2Cu8, Field("HOPPING_MODE", ParamType::Hex8) ),
            ( 0x2Du8, Field("BLOCK_STRIDE_LENGTH", ParamType::Dec8) ),
            ( 0x2Eu8, Field("RESULT_REPORT_CONFIG", ParamType::Hex8) ),
            ( 0x2Fu8, Field("IN_BAND_TERMINATION_ATTEMPT_COUNT", ParamType::Hex8) ),
            ( 0x30u8, Field("SUB_SESSION_ID", ParamType::Hex32) ),
            ( 0x31u8, Field("BPRF_PHR_DATA_RATE", ParamType::Hex8) ),
            ( 0x32u8, Field("MAX_NUMBER_OF_MEASUREMENTS", ParamType::Dec16) ),
            ( 0x33u8, Field("BLINK_RANDOM_INTERVAL", ParamType::Dec16) ),
            ( 0x34u8, Field("TDOA_REPORT_FREQUENCY", ParamType::Dec16) ),
            ( 0x35u8, Field("STS_LENGTH", ParamType::Dec8) ),
        ]) }; static ref SESSION_STATE_CODES: HashMap<u8, &'static str> = { HashMap::from([
            ( 0x00u8, "SESSION_STATE_INIT" ),
            ( 0x01u8, "SESSION_STATE_DEINIT" ),
            ( 0x02u8, "SESSION_STATE_ACTIVE" ),
            ( 0x03u8, "SESSION_STATE_IDLE" ),
        ])
    };

    static ref DEVCAL_PARAMS_NXP: HashMap<u8, Field> = {
        HashMap::from([
            ( 0x00u8, Field("VCO_PLL", ParamType::HexArray(2)) ),
            ( 0x01u8, Field("TX_POWER", ParamType::HexArray(0)) ),
            ( 0x02u8, Field("38.4MHz_XTAL_CAP_GM_CTRL", ParamType::HexArray(3)) ),
            ( 0x03u8, Field("RSSI_CALIB_CONSTANT1", ParamType::HexArray(0)) ),
            ( 0x04u8, Field("RSSI_CALIB_CONSTANT2", ParamType::HexArray(0)) ),
            ( 0x05u8, Field("SNR_CALIB_CONSTANT", ParamType::HexArray(0)) ),
            ( 0x06u8, Field("MANUAL_TX_POW_CTRL", ParamType::HexArray(4)) ),
            ( 0x07u8, Field("PDOA1_OFFSET", ParamType::HexArray(0)) ),
            ( 0x08u8, Field("PA_PPA_CALIB_CTRL", ParamType::HexArray(2)) ),
            ( 0x09u8, Field("TX_TEMPERATURE_COMP", ParamType::HexArray(0)) ),
            ( 0x0Au8, Field("PDOA2_OFFSET", ParamType::HexArray(0)) ),
            ( 0x0Bu8, Field("AOA_MULTIPOINT_PDOA_CALIB", ParamType::HexArray(0)) ),
            ( 0x0Cu8, Field("AOA_MULTIPOINT_PDOA_CALIB", ParamType::HexArray(0)) ),
            ( 0x0Du8, Field("AOA_ANTENNAS_MULTIPOINT_CALIB", ParamType::HexArray(0)) ),
            ( 0x0Fu8, Field("RX_ANT_DELAY_CALIB", ParamType::HexArray(0)) ),
            ( 0x10u8, Field("PDOA_OFFSET_CALIB", ParamType::HexArray(0)) ),
            ( 0x11u8, Field("PDOA_MANUFACT_ZERO_OFFSET_CALIB", ParamType::HexArray(0)) ),
            ( 0x12u8, Field("AOA_THRESHOLD_PDOA", ParamType::HexArray(0)) ),
            ( 0x13u8, Field("RSSI_CALIB_CONSTANT_HIGH_PWR", ParamType::HexArray(0)) ),
            ( 0x14u8, Field("RSSI_CALIB_CONSTANT_LOW_PWR", ParamType::HexArray(0)) ),
            ( 0x15u8, Field("SNR_CALIB_CONSTANT_PER_ANTENNA", ParamType::HexArray(0)) ),
            ( 0x17u8, Field("TX_POWER_PER_ANTENNA", ParamType::HexArray(0)) ),
            ( 0x18u8, Field("TX_TEMPERATURE_COMP_PER_ANTENNA", ParamType::HexArray(0)) ),
        ])
    };
}

macro_rules! lookup_string {
    ($table: ident, $id: expr) => {
        match $table.get($id) {
            Some(x) => format!("{:#x}:{}", $id, x).to_string(),
            None => format!("{:#x}:Unknown", $id).to_string(),
        }
    }
}

#[allow(unused_macros)]
macro_rules! lookup_string_ext {
    ($table: ident, $id0: expr, $id1: expr) => {
        match $table.get(($id0, $id1)) {
            Some(x) => format!("{:#4x}:{:#4x}:{}", $id0, $id1, x).to_string(),
            None => format!("{:#x}:Unknown", $id).to_string(),
        }
    }
}

fn print_hexarr(pkt: &Packet, offset: usize, len: usize) -> String {
    (offset..offset + len).fold(String::from("{"), |arr, i| arr + format!(" {:#04x}", pkt.get(i)).as_str()) + " }"
}

/*
 * Packet Printers
 */
struct PacketPrinter {
    name: String,
    handler: fn((u8, u8, u8), &'static PacketPrinter, Packet) -> Result<String, UciPacketParseError>,
}

fn print_packet_base(_type: (u8, u8, u8), printer: &'static PacketPrinter, _pkt: Packet) -> Result<String, UciPacketParseError> {
    Ok(format!("{}", printer.name))
}

fn _print_packet_statusonly<'a>(name: &String, pkt: Packet, offset: usize, table: &HashMap<u8, &'static str>) -> Result<String, UciPacketParseError> {
    match pkt.len() {
        0 => Err(UciPacketParseError::new(format!("payload len mismatch, expected=1 actual={}", pkt.len()).as_str())),
        _ => Ok(format!("{}: {}", name, lookup_string!(table, &pkt.get(offset))).to_string()),
    }
}

fn print_packet_statusonly(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {
    _print_packet_statusonly(&printer.name, pkt, 0, &*STATUS_CODES)
}

fn print_packet_devicestatus(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {
    _print_packet_statusonly(&printer.name, pkt, 0, &*DEVICE_STATUS_CODES)
}


/* e.g. "DPD_WAKEUP_SRC = 0x0" */
fn _print_field(field: &Field, pkt: &Packet, offset: usize, len: usize) -> String {

    macro_rules! printf {
        ($pkt: ident, $fmt: expr, $offset: expr, $len: ident) => {
            format!($fmt,
                if $len == 1 {
                    $pkt.get($offset).into()
                } else if $len == 2 {
                    LittleEndian::read_u16(&$pkt.slice($offset, 2)).into()
                } else {
                    LittleEndian::read_u32(&$pkt.slice($offset, 4))
                })
        }
    }

    let value = if !field.length_compatible(len) {
        format!("length mismatch expected={}, actual={}", field.size(), len)
    } else {
        match field.1 {
            ParamType::Hex8 => printf!(pkt, "{:#x}", offset, len),
            ParamType::Hex16 => printf!(pkt, "{:#x}", offset, len),
            ParamType::Hex32 => printf!(pkt, "{:#x}", offset, len),
            ParamType::Dec8 => printf!(pkt, "{}", offset, len),
            ParamType::Dec16 => printf!(pkt, "{}", offset, len),
            ParamType::Dec32 => printf!(pkt, "{}", offset, len),
            ParamType::CharArray(_n) => String::from_utf8_lossy(&pkt.bytes[offset..offset + len]).into_owned(),
            ParamType::Table8(t) => {
                let mut v = None;
                for x in t {
                    if x.0 == pkt.get(offset) {
                        v = Some(x);
                        break;
                    }
                }
                match v {
                    Some(x) => format!("{:#04x} ({})", x.0, x.1),
                    None => format!("{:#04x}(Unknown)", pkt.get(offset)),
                }
            },
            _ => print_hexarr(pkt, offset, len),
        }
    };
    format!("{} = {}", field.0, value)
}

fn _print_config(pkt: Packet, off: usize,
                table: &HashMap<u8, Field>,
                ext_table: Option<&HashMap<(u8, u8), Field>>) -> Result<String, UciPacketParseError> {

    if pkt.len() < 5 {
        return Err(UciPacketParseError::new("payload len is zero"));
    }

    let num:u8 = pkt.get(off);
    let mut s = format!("{} parameters:", num);
    let mut n = 0;
    let mut offset: usize = off + 1;

    while n < num {
        if (offset + 2) > pkt.len().into() {
            s = s + "\n - Error marker";
            break;
        }

        let id0 = pkt.get(offset);
        let len: usize;

        /* field id */
        let field = if id0 < 0xe0u8 || (offset + 3) > pkt.len().into() || ext_table == None {
            /* standard TLV */
            len = pkt.get(offset + 1).into();
            s = s + &format!("\n - {:#04x} ", id0);
            offset = offset + 2;
            table.get(&id0)
        } else {
            /* NXP extended TLV: id0 + id1 + len + value */
            let id1 = pkt.get(offset + 1);
            len = pkt.get(offset + 2).into();
            s = s + &format!("\n - {:#04x}:{:#04x} ", id0, id1);
            offset = offset + 3;
            ext_table.unwrap().get(&(id0, id1))
        };

        /* field name = value */
        let param_tail = match field {
            Some(f) => _print_field(f, &pkt, offset, len),
            None => format!("Unknown = {}", print_hexarr(&pkt, offset, len))
        };
        s.push_str(&param_tail);

        offset = offset + len;
        n = n + 1;
    }
    Ok(s)
}

fn print_set_config(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {
    let mut s = format!("{} ", printer.name);
    let ret = match _print_config(pkt, 0, &*DEVICE_CONF_PARAMS, Some(&*DEVICE_CONF_PARAMS_NXP)) {
        Ok(x) => x,
        Err(e) => return Err(e),
    };
    s.push_str(&ret);
    Ok(s)
}

fn print_set_appconfig(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {
    if pkt.len() < 4 {
        return Err(UciPacketParseError::new("Can't get session id"));
    }

    let mut s = format!("{} ", printer.name);
    s = s + &format!("SessionID = {:#010x}, ", LittleEndian::read_u16(&pkt.slice(0, 4)));

    let ret = match _print_config(pkt, 4, &*APP_CONF_PARAMS, None) {
        Ok(x) => x,
        Err(e) => return Err(e),
    };
    s.push_str(&ret);
    Ok(s)
}

fn _print_static<'a>(name: &'a str, pkt: Packet, fields: &[Field])-> Result<String, UciPacketParseError> {
    let mut offset = 0;
    let mut s = String::from(name);

    for field in fields {
        let len = field.size();
        if (offset + len) > pkt.len().into() {
            return Err(UciPacketParseError::new("length mismatch"));
        }
        let x = _print_field(field, &pkt, offset, len);
        s = s + " ";
        s.push_str(&x);
        offset = offset + len;
    }
    Ok(s)
}

fn print_session_init_cmd(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {
    let field_arr = [
          Field("SESSION_ID", ParamType::Hex32),
          Field("SESSION_TYPE", ParamType::Hex8),
    ];
    _print_static(&printer.name, pkt, &field_arr)
}

fn print_session_init_ntf(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {
    if pkt.len() < 6 {
        return Err(UciPacketParseError::new("payload len mismatch"));
    }

    let session_id = _print_field(&Field("SESSION_ID", ParamType::Hex32), &pkt, 0, 4);
    let state = format!("SESSION_STATE = {}", lookup_string!(SESSION_STATE_CODES, &pkt.get(4)));
    let reason = _print_field(&Field("REASON_CODE", ParamType::Hex8), &pkt, 5, 1);

    Ok(format!("{}\n - {}\n - {}\n - {}", printer.name, session_id, state, reason))
}

fn print_core_device_init_cmd(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {
    let field_arr = [
          Field("Major Version", ParamType::Hex8),
          Field("Minor Version", ParamType::Hex8),
    ];
    _print_static(&printer.name, pkt, &field_arr)
}

fn print_set_calibration(_type: (u8, u8, u8), printer: &'static PacketPrinter, pkt: Packet) -> Result<String, UciPacketParseError> {

    if pkt.len() < 3 {
        return Err(UciPacketParseError::new("payload len mismatch"));
    }
  
    let ch = pkt.get(0);
    let id = pkt.get(1);
    let param = match DEVCAL_PARAMS_NXP.get(&id) {
        Some(field) => _print_field(field, &pkt, 2, (pkt.len() - 2).into()),
        None => format!("{:#4x}:Unknown = {}", id, print_hexarr(&pkt, 2, (pkt.len() - 2).into())),
    };

    Ok(format!("{} Channel={} {}", printer.name, ch, param))
}

lazy_static! {
    static ref PRINTERS: HashMap<(u8, u8, u8), PacketPrinter> = {

        macro_rules! insert_printer{
            ($h: ident, $gid: ident, $oid: ident, $mt: ident, $func: ident) => {
                $h.insert((gid::$gid, oid::$oid, mt::$mt),
                    PacketPrinter {
                        name: concat!(stringify!($oid), "_", stringify!($mt)).to_string(),
                        handler: $func,
                    });
            }
        }
        let mut table = HashMap::new();

        insert_printer!(table, CORE, CORE_DEVICE_RESET, CMD, print_packet_base);
        insert_printer!(table, CORE, CORE_DEVICE_RESET, RSP, print_packet_statusonly);
        insert_printer!(table, CORE, CORE_DEVICE_STATUS, NTF, print_packet_devicestatus);
        insert_printer!(table, CORE, CORE_GET_DEVICE_INFO, CMD, print_packet_base);
        insert_printer!(table, CORE, CORE_SET_CONFIG, CMD, print_set_config);
        insert_printer!(table, CORE, CORE_SET_CONFIG, RSP, print_packet_statusonly);    /* skip other fields */

        insert_printer!(table, SESSION, SESSION_INIT, CMD, print_session_init_cmd);
        insert_printer!(table, SESSION, SESSION_INIT, RSP, print_packet_statusonly);
        insert_printer!(table, SESSION, SESSION_STATUS, NTF, print_session_init_ntf);

        insert_printer!(table, SESSION, SESSION_SET_APP_CONFIG, CMD, print_set_appconfig);
        insert_printer!(table, SESSION, SESSION_SET_APP_CONFIG, RSP, print_packet_statusonly); /* skip other fields */

        insert_printer!(table, PROPRIETARY, NXP_CORE_DEVICE_INIT, CMD, print_core_device_init_cmd);
        insert_printer!(table, PROPRIETARY, NXP_CORE_DEVICE_INIT, RSP, print_packet_statusonly);

        insert_printer!(table, PROPRIETARY, NXP_SET_CALIBRATION, CMD, print_set_calibration);
        insert_printer!(table, PROPRIETARY, NXP_SET_CALIBRATION, RSP, print_packet_statusonly);
        table
    };
}


fn to_packet(s: String) -> Result<Packet, UciPacketParseError> {
    fn parse_hexstr(s: String) -> Result<Vec<u8>, ParseIntError> {
        let n = if s.len() % 2 == 1 { s.len() - 1 } else { s.len() };
        (0..n)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    let bytes = match parse_hexstr(s) {
        Ok(bytes) => bytes,
        Err(_e) => return Err(UciPacketParseError::new("Failed to parse hex string"))
    };
  
    if bytes.len() < 4 {
        return Err(UciPacketParseError::new("packet length is less than 4 bytes"))
    }

    let packet_len = bytes[3];
    if (bytes.len() - 4) != packet_len.into() {
        return Err(UciPacketParseError::new(format!("payload length mismatch: packet_len={} actual={}", packet_len, bytes.len() - 4).as_str()));
    }

    Ok(Packet::new(bytes))
}

pub fn print(s: String) {
    match to_packet(s) {
        Ok(pkt) => {
            let id = (pkt.gid(), pkt.oid(), pkt.mt());
            let ret = PRINTERS.get(&id);
            match ret {
                Some(printer) => {
                    let s = match (printer.handler)(id, printer, pkt) {
                        Ok(s) => s,
                        Err(e) => e.msg,
                    };
                    println!("{}", s);
                }
                None => {
                    println!("{}", pkt);
                }
            };
        }
        Err(e) => {
            println!("{}", e);
        }
    }
}

