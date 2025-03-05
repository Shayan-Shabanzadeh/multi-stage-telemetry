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

impl PacketInfo {
    pub fn get(&self, field: &str) -> Option<String> {
        match field {
            "src_ip" => Some(self.src_ip.clone()),
            "dst_ip" => Some(self.dst_ip.clone()),
            "src_port" => Some(self.src_port.to_string()),
            "dst_port" => Some(self.dst_port.to_string()),
            "tcp_flags" => Some(self.tcp_flags.to_string()),
            "total_len" => Some(self.total_len.to_string()),
            "protocol" => Some(self.protocol.to_string()),
            _ => None,
        }
    }
}