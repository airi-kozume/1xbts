//! PPP HDLC-like framing per RFC 1662.
//!
//! Provides frame/deframe for PPP packets carried over the RLP byte stream.
//! The RLP session delivers arbitrary byte chunks; this module accumulates
//! them in a reassembly buffer until a complete HDLC frame (delimited by
//! 0x7E flags) is found, then validates FCS-16 and extracts the PPP packet.

/// HDLC flag byte — frame delimiter.
const FLAG: u8 = 0x7E;
/// HDLC escape byte — the next byte is XOR'd with 0x20.
const ESCAPE: u8 = 0x7D;
/// PPP Address field (all-stations).
const ADDRESS: u8 = 0xFF;
/// PPP Control field (unnumbered information).
const CONTROL: u8 = 0x03;

/// FCS-16 lookup table per RFC 1662 Appendix C.
const FCS16_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0u16;
    while i < 256 {
        let mut fcs = i;
        let mut bit = 0;
        while bit < 8 {
            if fcs & 1 != 0 {
                fcs = (fcs >> 1) ^ 0x8408;
            } else {
                fcs >>= 1;
            }
            bit += 1;
        }
        table[i as usize] = fcs;
        i += 1;
    }
    table
};

/// Initial FCS-16 value.
const FCS16_INIT: u16 = 0xFFFF;
/// Good final FCS-16 value (residue when FCS is included in the check).
const FCS16_GOOD: u16 = 0xF0B8;

/// Compute FCS-16 over a byte slice.
fn fcs16(data: &[u8]) -> u16 {
    let mut fcs = FCS16_INIT;
    for &b in data {
        fcs = (fcs >> 8) ^ FCS16_TABLE[((fcs ^ b as u16) & 0xFF) as usize];
    }
    fcs
}

/// A deframed PPP packet: protocol field + information/padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppPacket {
    /// PPP protocol number (e.g. 0xC021 for LCP, 0x8021 for IPCP, 0x0021 for IP).
    pub protocol: u16,
    /// Information field (payload after protocol).
    pub payload: Vec<u8>,
}

/// Reassembly buffer for accumulating RLP byte chunks into complete HDLC frames.
#[derive(Debug, Default)]
pub struct HdlcDeframer {
    buf: Vec<u8>,
}

impl HdlcDeframer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Feed raw bytes (from RLP data delivery) into the reassembly buffer.
    /// Returns zero or more complete, validated PPP packets.
    pub fn feed(&mut self, data: &[u8]) -> Vec<PppPacket> {
        self.buf.extend_from_slice(data);
        let mut packets = Vec::new();

        loop {
            // Find the first flag byte — start of a frame.
            let start = match self.buf.iter().position(|&b| b == FLAG) {
                Some(pos) => pos,
                None => {
                    // No flag at all — discard everything (inter-frame garbage).
                    self.buf.clear();
                    break;
                }
            };

            // Discard anything before the first flag.
            if start > 0 {
                self.buf.drain(..start);
            }

            // Skip consecutive flags to find the frame start.
            let frame_start = match self.buf.iter().position(|&b| b != FLAG) {
                Some(pos) => pos,
                None => break, // Only flags in the buffer — wait for more data.
            };

            // Find the closing flag after frame content.
            let frame_end = match self.buf[frame_start..].iter().position(|&b| b == FLAG) {
                Some(pos) => frame_start + pos,
                None => break, // No closing flag yet — wait for more data.
            };

            // Extract the raw frame content (between flags) and remove from buffer.
            let raw_frame: Vec<u8> = self.buf[frame_start..frame_end].to_vec();
            // Drain up to and including the closing flag.
            self.buf.drain(..frame_end);
            // Don't drain the closing flag — it may be the opening flag of the next frame.

            if raw_frame.is_empty() {
                continue;
            }

            // Unescape the frame.
            let mut unescaped = match unescape(&raw_frame) {
                Some(data) => data,
                None => continue, // Malformed escape sequence.
            };

            // Minimum: address(1) + control(1) + protocol(1 or 2) + FCS(2) = 5 bytes.
            if unescaped.len() < 5 {
                continue;
            }

            // Validate FCS-16: compute over entire unescaped content including the FCS bytes.
            // Result should equal FCS16_GOOD.
            if fcs16(&unescaped) != FCS16_GOOD {
                if recover_single_byte_ipv4_tcp_corruption(&mut unescaped) {
                    log::warn!(
                        "PPP HDLC: recovered a single-byte IPv4/TCP payload corruption after FCS failure"
                    );
                } else {
                    log::debug!("PPP HDLC: FCS check failed, discarding frame");
                    continue;
                }
            }

            // Strip address + control header.
            let payload_with_fcs = if unescaped[0] == ADDRESS && unescaped[1] == CONTROL {
                &unescaped[2..unescaped.len() - 2] // strip addr+ctrl and FCS
            } else {
                // Address/control field compression — not expected in our MVP but handle gracefully.
                &unescaped[..unescaped.len() - 2]
            };

            if payload_with_fcs.is_empty() {
                continue;
            }

            // Extract protocol field (1 or 2 bytes per RFC 1661 protocol field compression).
            let (protocol, info) = if payload_with_fcs[0] & 0x01 != 0 {
                // Protocol field compression: single byte, LSB is 1.
                (payload_with_fcs[0] as u16, &payload_with_fcs[1..])
            } else {
                if payload_with_fcs.len() < 2 {
                    continue;
                }
                let proto = ((payload_with_fcs[0] as u16) << 8) | payload_with_fcs[1] as u16;
                (proto, &payload_with_fcs[2..])
            };

            packets.push(PppPacket {
                protocol,
                payload: info.to_vec(),
            });
        }

        packets
    }
}

/// Attempts to recover the known femto bearer failure mode where exactly one
/// byte of an IPv4/TCP payload changes after PPP and TCP checksums are written.
///
/// A recovery is accepted only when it is unique and makes both the original
/// PPP FCS and the inner TCP checksum valid. This deliberately does not relax
/// FCS validation for arbitrary PPP frames.
fn recover_single_byte_ipv4_tcp_corruption(frame: &mut [u8]) -> bool {
    let frame_end = match frame.len().checked_sub(2) {
        Some(end) => end,
        None => return false,
    };

    let mut cursor = 0;
    if frame.get(..2) == Some(&[ADDRESS, CONTROL]) {
        cursor = 2;
    }
    let (protocol, ip_start) = match frame.get(cursor) {
        Some(protocol) if protocol & 1 != 0 => (*protocol as u16, cursor + 1),
        Some(_) if cursor + 2 <= frame_end => (
            u16::from_be_bytes([frame[cursor], frame[cursor + 1]]),
            cursor + 2,
        ),
        _ => return false,
    };
    if protocol != 0x0021 {
        return false;
    }

    let ip = &frame[ip_start..frame_end];
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return false;
    }
    let ip_header_len = usize::from(ip[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ip_header_len < 20
        || ip_header_len > ip.len()
        || total_len != ip.len()
        || total_len < ip_header_len + 20
        || ip[9] != 6
        || !internet_checksum_valid(&ip[..ip_header_len])
    {
        return false;
    }

    let tcp_start = ip_start + ip_header_len;
    let tcp_len = total_len - ip_header_len;
    let tcp_header_len = usize::from(frame[tcp_start + 12] >> 4) * 4;
    if tcp_header_len < 20 || tcp_header_len > tcp_len {
        return false;
    }
    let tcp_end = ip_start + total_len;
    let tcp_payload_start = tcp_start + tcp_header_len;
    if tcp_payload_start == tcp_end {
        return false;
    }

    let checksum_sum = tcp_checksum_sum(ip, &frame[tcp_start..tcp_end]);
    if checksum_sum == u16::MAX {
        return false;
    }

    let mut repair = None;
    for word_start in (tcp_payload_start..tcp_end).step_by(2) {
        let old_high = frame[word_start];
        let old_low = frame.get(word_start + 1).copied().unwrap_or(0);
        let old_word = u16::from_be_bytes([old_high, old_low]);
        let checksum_without_word =
            fold_checksum_sum(u32::from(checksum_sum) + u32::from(!old_word));
        let replacement_word = !checksum_without_word;
        let [new_high, new_low] = replacement_word.to_be_bytes();

        let candidate = if new_high != old_high && new_low == old_low {
            Some((word_start, new_high))
        } else if word_start + 1 < tcp_end && new_high == old_high && new_low != old_low {
            Some((word_start + 1, new_low))
        } else {
            None
        };
        let Some((offset, replacement)) = candidate else {
            continue;
        };

        let original = frame[offset];
        frame[offset] = replacement;
        let valid = fcs16(frame) == FCS16_GOOD
            && internet_checksum_valid(&frame[ip_start..ip_start + ip_header_len])
            && tcp_checksum_sum(&frame[ip_start..tcp_end], &frame[tcp_start..tcp_end]) == u16::MAX;
        frame[offset] = original;
        if valid {
            if repair.is_some() {
                return false;
            }
            repair = Some((offset, replacement));
        }
    }

    let Some((offset, replacement)) = repair else {
        return false;
    };
    frame[offset] = replacement;
    true
}

fn fold_checksum_sum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    sum as u16
}

fn internet_checksum_valid(data: &[u8]) -> bool {
    fold_checksum_sum(checksum_words(data)) == u16::MAX
}

fn checksum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    sum
}

fn tcp_checksum_sum(ip: &[u8], tcp: &[u8]) -> u16 {
    let mut sum = checksum_words(&ip[12..20]);
    sum += u32::from(ip[9]);
    sum += tcp.len() as u32;
    sum += checksum_words(tcp);
    fold_checksum_sum(sum)
}

/// Unescape HDLC: replace 0x7D XX with XX^0x20.
fn unescape(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == ESCAPE {
            i += 1;
            if i >= data.len() {
                return None; // Truncated escape.
            }
            out.push(data[i] ^ 0x20);
        } else {
            out.push(data[i]);
        }
        i += 1;
    }
    Some(out)
}

/// Check if a byte needs HDLC escaping given the negotiated ACCM.
/// FLAG (0x7E) and ESCAPE (0x7D) are always escaped regardless of ACCM.
fn needs_escape_accm(b: u8, accm: u32) -> bool {
    if b == FLAG || b == ESCAPE {
        return true;
    }
    if b < 0x20 {
        // Check the corresponding bit in the ACCM.
        (accm >> b) & 1 != 0
    } else {
        false
    }
}

/// PPP TX framing options derived from LCP negotiation.
#[derive(Debug, Clone, Copy)]
pub struct FrameOptions {
    /// ACCM to use when escaping (from peer's negotiated receive ACCM).
    /// Default: 0xFFFFFFFF (escape all 0x00-0x1F).
    pub tx_accm: u32,
    /// Whether the peer accepts Address/Control field compression.
    /// If true, omit FF 03 on non-LCP packets.
    pub acfc: bool,
    /// Whether the peer accepts Protocol field compression.
    /// If true, use 1-byte protocol when the high byte is 0x00.
    pub pfc: bool,
}

impl Default for FrameOptions {
    fn default() -> Self {
        Self {
            tx_accm: 0xFFFFFFFF,
            acfc: false,
            pfc: false,
        }
    }
}

/// Frame a PPP packet into HDLC-like format per RFC 1662.
///
/// Returns the complete HDLC frame including opening/closing flags.
/// Uses default framing options (no compression, full ACCM).
pub fn frame(packet: &PppPacket) -> Vec<u8> {
    frame_with_options(packet, &FrameOptions::default())
}

/// Frame a PPP packet with negotiated LCP options.
pub fn frame_with_options(packet: &PppPacket, opts: &FrameOptions) -> Vec<u8> {
    let is_lcp = packet.protocol == super::lcp::LCP_PROTOCOL;

    // Build the unescaped frame content.
    let mut content = Vec::new();

    // Address + Control: omit if ACFC negotiated and not LCP.
    // RFC 1661 §6.6: "This option MUST NOT be negotiated for LCP."
    // Meaning: LCP frames always include A/C even if ACFC is negotiated.
    if !opts.acfc || is_lcp {
        content.push(ADDRESS);
        content.push(CONTROL);
    }

    // Protocol field: use 1-byte if PFC negotiated, not LCP, and high byte is 0.
    // RFC 1661 §6.5: compressible when high byte is 0x00 (LSB of low byte is 1).
    if opts.pfc && !is_lcp && (packet.protocol >> 8) == 0 && (packet.protocol & 0x01) != 0 {
        content.push(packet.protocol as u8);
    } else {
        content.push((packet.protocol >> 8) as u8);
        content.push((packet.protocol & 0xFF) as u8);
    }

    content.extend_from_slice(&packet.payload);

    // Compute FCS-16 over the content (including any A/C and protocol bytes).
    let fcs = fcs16(&content) ^ FCS16_INIT; // complement
    content.push((fcs & 0xFF) as u8); // FCS low byte first
    content.push((fcs >> 8) as u8);

    // Use default ACCM for LCP frames (RFC 1662 §4.2: LCP frames are always
    // sent with the default ACCM until negotiation completes).
    let accm = if is_lcp { 0xFFFFFFFF } else { opts.tx_accm };

    // Escape and wrap in flags.
    let mut out = Vec::new();
    out.push(FLAG);
    for &b in &content {
        if needs_escape_accm(b, accm) {
            out.push(ESCAPE);
            out.push(b ^ 0x20);
        } else {
            out.push(b);
        }
    }
    out.push(FLAG);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fcs16_known_value() {
        // RFC 1662 Appendix C example: FCS of "123456789" = 0x906E (before complement).
        // The good-FCS check is over the data + appended FCS, yielding FCS16_GOOD.
        let data = b"123456789";
        let fcs = fcs16(data) ^ FCS16_INIT;
        // Append FCS to data and verify residue.
        let mut check = data.to_vec();
        check.push((fcs & 0xFF) as u8);
        check.push((fcs >> 8) as u8);
        assert_eq!(fcs16(&check), FCS16_GOOD);
    }

    #[test]
    fn round_trip_lcp_packet() {
        let pkt = PppPacket {
            protocol: 0xC021,
            payload: vec![0x01, 0x01, 0x00, 0x04], // Configure-Request, ID=1, length=4
        };
        let framed = frame(&pkt);

        // First and last bytes should be flags.
        assert_eq!(framed[0], FLAG);
        assert_eq!(*framed.last().unwrap(), FLAG);

        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&framed);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], pkt);
    }

    #[test]
    fn round_trip_ip_packet() {
        // Simulated IP packet (just some bytes).
        let pkt = PppPacket {
            protocol: 0x0021,
            payload: vec![
                0x45, 0x00, 0x00, 0x1C, 0xAB, 0xCD, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0A, 0x00,
                0x00, 0x01, 0x0A, 0x00, 0x00, 0x02,
            ],
        };
        let framed = frame(&pkt);
        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&framed);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], pkt);
    }

    #[test]
    fn escape_sequences_handled() {
        // Create a packet with payload that forces escaping.
        let pkt = PppPacket {
            protocol: 0xC021,
            payload: vec![0x7E, 0x7D, 0x00, 0x01, 0x1F], // Contains FLAG, ESCAPE, and control chars.
        };
        let framed = frame(&pkt);

        // Verify no raw FLAG or ESCAPE bytes appear in the frame body.
        for &b in &framed[1..framed.len() - 1] {
            assert!(b != FLAG, "raw FLAG found in frame body");
        }

        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&framed);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], pkt);
    }

    #[test]
    fn multiple_frames_in_one_buffer() {
        let pkt1 = PppPacket {
            protocol: 0xC021,
            payload: vec![0x01, 0x01, 0x00, 0x04],
        };
        let pkt2 = PppPacket {
            protocol: 0x8021,
            payload: vec![0x01, 0x02, 0x00, 0x0A, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00],
        };

        let mut buf = frame(&pkt1);
        buf.extend_from_slice(&frame(&pkt2));

        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&buf);
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], pkt1);
        assert_eq!(packets[1], pkt2);
    }

    #[test]
    fn partial_frame_reassembly() {
        let pkt = PppPacket {
            protocol: 0xC021,
            payload: vec![0x01, 0x01, 0x00, 0x04],
        };
        let framed = frame(&pkt);

        // Split in the middle.
        let mid = framed.len() / 2;
        let part1 = &framed[..mid];
        let part2 = &framed[mid..];

        let mut deframer = HdlcDeframer::new();

        // First chunk: no complete frame yet.
        let packets = deframer.feed(part1);
        assert!(packets.is_empty());

        // Second chunk: frame completes.
        let packets = deframer.feed(part2);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], pkt);
    }

    #[test]
    fn partial_frame_across_three_chunks() {
        let pkt = PppPacket {
            protocol: 0x0021,
            payload: vec![
                0x45, 0x00, 0x00, 0x1C, 0xAB, 0xCD, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0A, 0x00,
                0x00, 0x01,
            ],
        };
        let framed = frame(&pkt);

        let split1 = framed.len() / 3;
        let split2 = 2 * framed.len() / 3;

        let mut deframer = HdlcDeframer::new();
        assert!(deframer.feed(&framed[..split1]).is_empty());
        assert!(deframer.feed(&framed[split1..split2]).is_empty());
        let packets = deframer.feed(&framed[split2..]);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], pkt);
    }

    #[test]
    fn garbage_before_frame_is_discarded() {
        let pkt = PppPacket {
            protocol: 0xC021,
            payload: vec![0x01, 0x01, 0x00, 0x04],
        };
        let framed = frame(&pkt);

        let mut buf = vec![0xAA, 0xBB, 0xCC]; // garbage
        buf.extend_from_slice(&framed);

        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&buf);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], pkt);
    }

    #[test]
    fn bad_fcs_frame_discarded() {
        let pkt = PppPacket {
            protocol: 0xC021,
            payload: vec![0x01, 0x01, 0x00, 0x04],
        };
        let mut framed = frame(&pkt);

        // Corrupt a byte in the frame body (between the flags).
        let mid = framed.len() / 2;
        framed[mid] ^= 0xFF;

        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&framed);
        assert!(packets.is_empty());
    }

    #[test]
    fn recovers_unique_single_byte_tcp_payload_corruption() {
        let payload = vec![0x5c; 600];
        let ip = ipv4_tcp_packet(&payload);
        let pkt = PppPacket {
            protocol: 0x0021,
            payload: ip,
        };
        let opts = FrameOptions {
            tx_accm: 0,
            acfc: true,
            pfc: true,
        };
        let mut framed = frame_with_options(&pkt, &opts);

        // The test payload contains only unescaped 0x5c octets. Corrupt one
        // of them after the checksums have been written, matching the FAP
        // bearer failure observed in the field capture.
        let payload_offset = framed.len() - 64;
        assert_eq!(framed[payload_offset], 0x5c);
        framed[payload_offset] = 0x78;

        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&framed);
        assert_eq!(packets, vec![pkt]);
    }

    fn ipv4_tcp_packet(payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 55, 0, 2]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..28].copy_from_slice(&1u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[34..36].copy_from_slice(&4096u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);

        let ip_checksum = !fold_checksum_sum(checksum_words(&packet[..20]));
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        let tcp_checksum = !tcp_checksum_sum(&packet[..], &packet[20..]);
        packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
        packet
    }

    #[test]
    fn empty_frame_between_flags_is_ignored() {
        // Two flags with nothing between them.
        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&[FLAG, FLAG]);
        assert!(packets.is_empty());
    }

    #[test]
    fn protocol_field_compression() {
        // Build a frame manually with 1-byte protocol field (0x21 for IP, LSB=1).
        let mut content = Vec::new();
        content.push(ADDRESS);
        content.push(CONTROL);
        content.push(0x21); // compressed protocol
        content.extend_from_slice(&[0x45, 0x00]); // payload

        let fcs = fcs16(&content) ^ FCS16_INIT;
        content.push((fcs & 0xFF) as u8);
        content.push((fcs >> 8) as u8);

        let mut framed = vec![FLAG];
        for &b in &content {
            if needs_escape_accm(b, 0xFFFFFFFF) {
                framed.push(ESCAPE);
                framed.push(b ^ 0x20);
            } else {
                framed.push(b);
            }
        }
        framed.push(FLAG);

        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&framed);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].protocol, 0x21);
        assert_eq!(packets[0].payload, vec![0x45, 0x00]);
    }

    #[test]
    fn frame_output_has_no_raw_special_bytes_in_body() {
        // Brute-force: frame a packet and verify no unescaped specials in the body.
        let pkt = PppPacket {
            protocol: 0xC021,
            payload: (0..=255).collect(),
        };
        let framed = frame(&pkt);
        assert_eq!(framed[0], FLAG);
        assert_eq!(*framed.last().unwrap(), FLAG);

        let body = &framed[1..framed.len() - 1];
        let mut i = 0;
        while i < body.len() {
            if body[i] == ESCAPE {
                // Next byte must be XOR'd form.
                i += 2;
            } else {
                assert!(
                    !needs_escape_accm(body[i], 0xFFFFFFFF),
                    "unescaped byte 0x{:02X} at position {}",
                    body[i],
                    i + 1
                );
                i += 1;
            }
        }
    }

    #[test]
    fn round_trip_all_byte_values_in_payload() {
        let pkt = PppPacket {
            protocol: 0xC021,
            payload: (0..=255).collect(),
        };
        let framed = frame(&pkt);
        let mut deframer = HdlcDeframer::new();
        let packets = deframer.feed(&framed);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], pkt);
    }
}
