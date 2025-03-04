#[derive(Clone)]
pub struct PacketInfo {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub total_len: u16,
    pub protocol: u8,
}