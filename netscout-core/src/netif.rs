//! Network interface enumeration.
//!
//! Lists all network interfaces on the system with their addresses,
//! status, and metadata. Uses platform-native APIs via `libc`.

use serde::Serialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::output::HumanReadable;
use colored::Colorize;

/// Information about a single network interface.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub is_up: bool,
    pub is_loopback: bool,
    pub addresses: Vec<InterfaceAddress>,
    pub mtu: Option<u32>,
}

/// An address bound to an interface.
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub prefix_len: Option<u8>,
    pub scope: String,
}

/// Result of listing interfaces.
#[derive(Debug, Clone, Serialize)]
pub struct NetifResult {
    pub interfaces: Vec<NetworkInterface>,
    pub total: usize,
    pub up_count: usize,
}

/// Enumerate all network interfaces on the system.
pub fn list_interfaces() -> Result<NetifResult, String> {
    let raw = gather_interfaces().map_err(|e| format!("Failed to enumerate interfaces: {e}"))?;

    let up_count = raw.iter().filter(|i| i.is_up).count();
    let total = raw.len();

    Ok(NetifResult {
        interfaces: raw,
        total,
        up_count,
    })
}

#[cfg(unix)]
fn gather_interfaces() -> Result<Vec<NetworkInterface>, std::io::Error> {
    use std::ffi::CStr;

    // Use getifaddrs
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    let ret = unsafe { libc::getifaddrs(&mut ifaddrs) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut map: BTreeMap<String, NetworkInterface> = BTreeMap::new();

    let mut cur = ifaddrs;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .to_string();

        let is_up = (entry.ifa_flags & libc::IFF_UP as u32) != 0;
        let is_loopback = (entry.ifa_flags & libc::IFF_LOOPBACK as u32) != 0;

        let iface = map.entry(name.clone()).or_insert_with(|| {
            let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
            NetworkInterface {
                name: name.clone(),
                index,
                is_up,
                is_loopback,
                addresses: Vec::new(),
                mtu: None,
            }
        });

        // Extract address if present
        if !entry.ifa_addr.is_null() {
            let sa_family = unsafe { (*entry.ifa_addr).sa_family } as i32;

            if sa_family == libc::AF_INET {
                let sockaddr_in = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.s_addr));
                let prefix_len = if !entry.ifa_netmask.is_null() {
                    let mask = unsafe { &*(entry.ifa_netmask as *const libc::sockaddr_in) };
                    Some(u32::from_be(mask.sin_addr.s_addr).count_ones() as u8)
                } else {
                    None
                };
                iface.addresses.push(InterfaceAddress {
                    ip: IpAddr::V4(ip),
                    prefix_len,
                    scope: scope_for_v4(ip),
                });
            } else if sa_family == libc::AF_INET6 {
                let sockaddr_in6 = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(sockaddr_in6.sin6_addr.s6_addr);
                let prefix_len = if !entry.ifa_netmask.is_null() {
                    let mask = unsafe { &*(entry.ifa_netmask as *const libc::sockaddr_in6) };
                    Some(count_v6_prefix(&mask.sin6_addr.s6_addr))
                } else {
                    None
                };
                iface.addresses.push(InterfaceAddress {
                    ip: IpAddr::V6(ip),
                    prefix_len,
                    scope: scope_for_v6(ip),
                });
            }
        }

        cur = entry.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifaddrs) };

    // Try to get MTU via ioctl for each interface
    #[cfg(target_os = "macos")]
    {
        for iface in map.values_mut() {
            if let Ok(mtu) = get_mtu_ioctl(&iface.name) {
                iface.mtu = Some(mtu);
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        for iface in map.values_mut() {
            if let Ok(mtu) = get_mtu_ioctl(&iface.name) {
                iface.mtu = Some(mtu);
            }
        }
    }

    Ok(map.into_values().collect())
}

#[cfg(unix)]
fn get_mtu_ioctl(name: &str) -> Result<u32, std::io::Error> {
    use std::os::unix::io::AsRawFd;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let mut ifreq = [0u8; 40]; // struct ifreq is at most 40 bytes
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(15);
    ifreq[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    #[cfg(target_os = "macos")]
    const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
    #[cfg(target_os = "linux")]
    const SIOCGIFMTU: libc::c_ulong = 0x8921;

    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFMTU, ifreq.as_mut_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // MTU is at offset 16 as an i32 on both platforms
    let mtu_bytes: [u8; 4] = ifreq[16..20].try_into().unwrap();
    let mtu = i32::from_ne_bytes(mtu_bytes);
    Ok(mtu as u32)
}

fn scope_for_v4(ip: Ipv4Addr) -> String {
    if ip.is_loopback() {
        "loopback".into()
    } else if ip.is_link_local() {
        "link-local".into()
    } else if ip.is_private() {
        "private".into()
    } else {
        "global".into()
    }
}

fn scope_for_v6(ip: Ipv6Addr) -> String {
    if ip.is_loopback() {
        "loopback".into()
    } else if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        "link-local".into()
    } else if (ip.segments()[0] & 0xfe00) == 0xfc00 {
        "unique-local".into()
    } else {
        "global".into()
    }
}

fn count_v6_prefix(mask: &[u8; 16]) -> u8 {
    let mut bits = 0u8;
    for &byte in mask {
        if byte == 0xff {
            bits += 8;
        } else {
            bits += byte.leading_ones() as u8;
            break;
        }
    }
    bits
}

impl HumanReadable for NetifResult {
    fn to_csv(&self) -> String {
        let mut out = String::from("name,state,type,mtu,addresses\n");
        for iface in &self.interfaces {
            let state = if iface.is_up { "UP" } else { "DOWN" };
            let kind = if iface.is_loopback { "lo" } else { "eth" };
            let mtu = iface.mtu.map(|m| m.to_string()).unwrap_or_default();
            let addrs: Vec<String> = iface
                .addresses
                .iter()
                .map(|a| {
                    let prefix = a.prefix_len.map(|p| format!("/{p}")).unwrap_or_default();
                    format!("{}{}", a.ip, prefix)
                })
                .collect();
            out.push_str(&format!(
                "{},{},{},{},\"{}\"\n",
                iface.name,
                state,
                kind,
                mtu,
                addrs.join(";")
            ));
        }
        out
    }

    fn to_table(&self) -> String {
        let mut out = format!("Interfaces: {} total, {} up\n\n", self.total, self.up_count,);
        out.push_str(&format!(
            "{:<12} {:<6} {:<8} {:<6} {}\n",
            "NAME", "STATE", "TYPE", "MTU", "ADDRESSES"
        ));
        out.push_str(&format!("{}\n", "-".repeat(65)));
        for iface in &self.interfaces {
            let state = if iface.is_up { "UP" } else { "DOWN" };
            let kind = if iface.is_loopback { "lo" } else { "eth" };
            let mtu = iface
                .mtu
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".into());
            let addrs: Vec<String> = iface
                .addresses
                .iter()
                .map(|a| {
                    let prefix = a.prefix_len.map(|p| format!("/{p}")).unwrap_or_default();
                    format!("{}{}", a.ip, prefix)
                })
                .collect();
            let addr_str = if addrs.is_empty() {
                "-".to_string()
            } else {
                addrs.join(", ")
            };
            out.push_str(&format!(
                "{:<12} {:<6} {:<8} {:<6} {}\n",
                iface.name, state, kind, mtu, addr_str,
            ));
        }
        out
    }

    fn to_human(&self) -> String {
        use crate::output::status_icon;

        let mut out = format!(
            "{} {} interfaces ({} up)\n\n",
            "INTERFACES".blue().bold(),
            self.total,
            self.up_count,
        );
        for iface in &self.interfaces {
            let status = if iface.is_up {
                "UP".green().bold().to_string()
            } else {
                "DOWN".red().bold().to_string()
            };
            let lo = if iface.is_loopback { " (loopback)" } else { "" };
            let mtu_str = iface.mtu.map(|m| format!(" mtu {m}")).unwrap_or_default();
            out.push_str(&format!(
                "  {} {}{} [{}]{}\n",
                status_icon(iface.is_up),
                iface.name.bold(),
                lo,
                status,
                mtu_str,
            ));
            for addr in &iface.addresses {
                let prefix = addr.prefix_len.map(|p| format!("/{p}")).unwrap_or_default();
                out.push_str(&format!("    {}{} ({})\n", addr.ip, prefix, addr.scope,));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_for_v4() {
        assert_eq!(scope_for_v4(Ipv4Addr::LOCALHOST), "loopback");
        assert_eq!(scope_for_v4(Ipv4Addr::new(192, 168, 1, 1)), "private");
        assert_eq!(scope_for_v4(Ipv4Addr::new(169, 254, 1, 1)), "link-local");
        assert_eq!(scope_for_v4(Ipv4Addr::new(8, 8, 8, 8)), "global");
    }

    #[test]
    fn test_scope_for_v4_private_ranges() {
        // Test all RFC 1918 private ranges
        assert_eq!(scope_for_v4(Ipv4Addr::new(10, 0, 0, 1)), "private");
        assert_eq!(scope_for_v4(Ipv4Addr::new(10, 255, 255, 254)), "private");
        assert_eq!(scope_for_v4(Ipv4Addr::new(172, 16, 0, 1)), "private");
        assert_eq!(scope_for_v4(Ipv4Addr::new(172, 31, 255, 254)), "private");
        assert_eq!(scope_for_v4(Ipv4Addr::new(192, 168, 0, 1)), "private");
        assert_eq!(scope_for_v4(Ipv4Addr::new(192, 168, 255, 254)), "private");
    }

    #[test]
    fn test_scope_for_v4_link_local() {
        // Test link-local range (169.254.0.0/16)
        assert_eq!(scope_for_v4(Ipv4Addr::new(169, 254, 0, 1)), "link-local");
        assert_eq!(scope_for_v4(Ipv4Addr::new(169, 254, 100, 200)), "link-local");
        assert_eq!(scope_for_v4(Ipv4Addr::new(169, 254, 255, 254)), "link-local");
    }

    #[test]
    fn test_scope_for_v4_global() {
        // Test various global addresses
        assert_eq!(scope_for_v4(Ipv4Addr::new(8, 8, 8, 8)), "global");
        assert_eq!(scope_for_v4(Ipv4Addr::new(1, 1, 1, 1)), "global");
        assert_eq!(scope_for_v4(Ipv4Addr::new(93, 184, 216, 34)), "global"); // example.com
        assert_eq!(scope_for_v4(Ipv4Addr::new(208, 67, 222, 222)), "global"); // OpenDNS
    }

    #[test]
    fn test_scope_for_v4_loopback_variants() {
        assert_eq!(scope_for_v4(Ipv4Addr::new(127, 0, 0, 1)), "loopback");
        assert_eq!(scope_for_v4(Ipv4Addr::new(127, 0, 0, 2)), "loopback");
        assert_eq!(scope_for_v4(Ipv4Addr::new(127, 255, 255, 254)), "loopback");
    }

    #[test]
    fn test_scope_for_v6() {
        assert_eq!(scope_for_v6(Ipv6Addr::LOCALHOST), "loopback");
        assert_eq!(scope_for_v6("fe80::1".parse().unwrap()), "link-local");
        assert_eq!(scope_for_v6("fd00::1".parse().unwrap()), "unique-local");
        assert_eq!(scope_for_v6("2001:db8::1".parse().unwrap()), "global");
    }

    #[test]
    fn test_scope_for_v6_link_local_range() {
        // Test various link-local addresses (fe80::/10)
        assert_eq!(scope_for_v6("fe80::1234:5678:9abc:def0".parse().unwrap()), "link-local");
        assert_eq!(scope_for_v6("fe80::dead:beef".parse().unwrap()), "link-local");
        assert_eq!(scope_for_v6("feb0::1".parse().unwrap()), "link-local");
        assert_eq!(scope_for_v6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()), "link-local");
    }

    #[test]
    fn test_scope_for_v6_unique_local_range() {
        // Test unique local addresses (fc00::/7)
        assert_eq!(scope_for_v6("fc00::1".parse().unwrap()), "unique-local");
        assert_eq!(scope_for_v6("fd00::1".parse().unwrap()), "unique-local");
        assert_eq!(scope_for_v6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()), "unique-local");
    }

    #[test]
    fn test_scope_for_v6_global() {
        // Test various global unicast addresses
        assert_eq!(scope_for_v6("2001:4860:4860::8888".parse().unwrap()), "global"); // Google DNS
        assert_eq!(scope_for_v6("2606:4700:4700::1111".parse().unwrap()), "global"); // Cloudflare DNS
        assert_eq!(scope_for_v6("2001:db8::1".parse().unwrap()), "global"); // Documentation
    }

    #[test]
    fn test_count_v6_prefix() {
        let mask_64 = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(count_v6_prefix(&mask_64), 64);
        let mask_128 = [0xff; 16];
        assert_eq!(count_v6_prefix(&mask_128), 128);
    }

    #[test]
    fn test_count_v6_prefix_various() {
        // Test /48
        let mask_48 = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(count_v6_prefix(&mask_48), 48);
        
        // Test /56
        let mask_56 = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(count_v6_prefix(&mask_56), 56);
        
        // Test /0 (all zeros)
        let mask_0 = [0; 16];
        assert_eq!(count_v6_prefix(&mask_0), 0);
    }

    #[test]
    fn test_count_v6_prefix_partial_bytes() {
        // Test partial byte masks
        let mask_partial = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, // 60 bits
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(count_v6_prefix(&mask_partial), 60);
        
        let mask_partial2 = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, // 58 bits
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(count_v6_prefix(&mask_partial2), 58);
    }

    #[test]
    fn test_network_interface_serialization() {
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            index: 2,
            is_up: true,
            is_loopback: false,
            addresses: vec![],
            mtu: Some(1500),
        };
        let json = serde_json::to_string(&interface).unwrap();
        assert!(json.contains("eth0"));
        assert!(json.contains("true"));
        assert!(json.contains("1500"));
    }

    #[test]
    fn test_interface_address_serialization() {
        let addr = InterfaceAddress {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            prefix_len: Some(24),
            scope: "private".to_string(),
        };
        let json = serde_json::to_string(&addr).unwrap();
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("24"));
        assert!(json.contains("private"));
    }

    #[test]
    fn test_interface_address_ipv6() {
        let addr = InterfaceAddress {
            ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
            prefix_len: Some(64),
            scope: "global".to_string(),
        };
        assert!(matches!(addr.ip, IpAddr::V6(_)));
        assert_eq!(addr.prefix_len, Some(64));
        assert_eq!(addr.scope, "global");
    }

    #[test]
    fn test_netif_result_serialization() {
        let result = NetifResult {
            interfaces: vec![],
            total: 5,
            up_count: 3,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("5"));
        assert!(json.contains("3"));
    }

    #[test]
    fn test_list_interfaces_works() {
        // Should succeed on any system
        let result = list_interfaces().unwrap();
        assert!(result.total > 0, "Should have at least one interface");
        // Should have at least loopback
        assert!(
            result.interfaces.iter().any(|i| i.is_loopback),
            "Should have a loopback interface"
        );
        
        // Verify counts match
        let actual_up_count = result.interfaces.iter().filter(|i| i.is_up).count();
        assert_eq!(result.up_count, actual_up_count);
        assert_eq!(result.total, result.interfaces.len());
    }

    #[test]
    fn test_network_interface_properties() {
        let interface = NetworkInterface {
            name: "lo".to_string(),
            index: 1,
            is_up: true,
            is_loopback: true,
            addresses: vec![
                InterfaceAddress {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    prefix_len: Some(8),
                    scope: "loopback".to_string(),
                },
                InterfaceAddress {
                    ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    prefix_len: Some(128),
                    scope: "loopback".to_string(),
                },
            ],
            mtu: Some(65536),
        };
        
        assert_eq!(interface.name, "lo");
        assert!(interface.is_loopback);
        assert!(interface.is_up);
        assert_eq!(interface.addresses.len(), 2);
        assert_eq!(interface.mtu, Some(65536));
    }

    #[test]
    fn test_interface_without_mtu() {
        let interface = NetworkInterface {
            name: "dummy0".to_string(),
            index: 10,
            is_up: false,
            is_loopback: false,
            addresses: vec![],
            mtu: None,
        };
        
        assert!(interface.mtu.is_none());
        assert!(!interface.is_up);
        assert!(interface.addresses.is_empty());
    }
}
