use std::{path::PathBuf, net::SocketAddr, time::Duration};

use argh::FromArgs;
use base64::Engine;
use boringtun::{x25519::{PublicKey, StaticSecret}, noise::TunnResult};
use tracing::error;

/// Expose internet access without root using Wireguard
#[derive(FromArgs)]
pub struct Opts {
    /// main private key of this Wireguard node, base64-encoded
    #[argh(option,short='k')]
    pub private_key : Option<String>,

    /// main private key of this Wireguard node (content of a specified file), base64-encoded
    #[argh(option,short='f')]
    pub private_key_file: Option<PathBuf>,

    /// peer's public key
    #[argh(option,short='K')]
    pub peer_key : String,

    /// address of the peer's UDP socket, where to send keepalives
    #[argh(option,short='p')]
    pub wg_peer_endpoint : Option<SocketAddr>,

    /// wireguard keepalive interval, in seconds
    #[argh(option,short='a')]
    pub wg_keepalive_interval : Option<u16>,

    /// where to bind UDP socket for Wireguard connection
    #[argh(option, short='b')]
    pub wg_bind_ip_port: SocketAddr,

    /// where to bind UDP socket for GUE/FOU
    #[argh(option, short='g')]
    pub gue_bind_ip_port: SocketAddr,

    /// send GUE/FOU datagrams to that socket address, not use remembered recvfrom address.
    #[argh(option, short='G')]
    pub gue_peer_endpoint: Option<SocketAddr>,

    /// send empty UDP datagrams to the GUE/FOU peer with this interval, in seconds
    #[argh(option,short='A')]
    pub gue_keepalive_interval : Option<u16>,
}

#[tokio::main(flavor="current_thread")]
async fn main() -> anyhow::Result<()> {
    #[cfg(feature="tracing-subscriber")]
    tracing_subscriber::fmt::init();
    let opts : Opts = argh::from_env();

    let privkey = match (opts.private_key, opts.private_key_file) {
        (None, Some(path)) => {
            std::fs::read_to_string(path)?
        }
        (Some(s), None) => s,
        _ => anyhow::bail!("Set exactly one of --private-key or --private-key-file")
    };

    let private_key : StaticSecret = parsebase64_32(&privkey)?.into();
    let peer_key : PublicKey = parsebase64_32(&opts.peer_key)?.into();

    let mut wg = boringtun::noise::Tunn::new(
        private_key,
        peer_key,
        None,
        opts.wg_keepalive_interval,
        0,
        None,
    )
    .map_err(|e| anyhow::anyhow!(e))?;


    let wg_udp = tokio::net::UdpSocket::bind(opts.wg_bind_ip_port).await?;

    let mut wg_current_peer_addr = opts.wg_peer_endpoint;
    let wg_static_peer_addr = opts.wg_peer_endpoint;

    let mut each_second = tokio::time::interval(Duration::from_secs(1));

    let mut wg_udp_recv_buf = [0; 4096 - 32];
    let mut wg_scratch_buf = [0; 4096];
    let mut gue_recv_buf = [0; 4096];

    let gue_udp = tokio::net::UdpSocket::bind(opts.gue_bind_ip_port).await?;
    let mut gue_current_peer_addr = opts.gue_peer_endpoint;
    let mut gue_timer = {
        let mut i = tokio::time::interval(Duration::from_secs(opts.gue_keepalive_interval.unwrap_or(1 /* unused*/) as u64));
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    };

    loop {
        let mut wg_last_seen_recv_address = None;
        let mut tr: Option<TunnResult> = tokio::select! {
            _instant = each_second.tick() => {
                Some(wg.update_timers(&mut wg_scratch_buf))
            }
            ret = wg_udp.recv_from(&mut wg_udp_recv_buf[..]) => {
                let ret = ret?;
                let buf : &[u8] = &wg_udp_recv_buf[0..(ret.0)];
                let from : SocketAddr = ret.1;

                wg_last_seen_recv_address = Some(from);

                Some(wg.decapsulate(None, buf, &mut wg_scratch_buf))
            }
            ret = gue_udp.recv_from(&mut gue_recv_buf[..]) => {
                let ret = ret?;
                let mut buf : &[u8] = &gue_recv_buf[0..(ret.0)];
                if buf.len() >= 4 {
                    // Skip over simple GUE header
                    if &buf[..4] == [0,4,0,0] {
                        buf=&buf[4..];
                    }
                    if &buf[..4] == [0,0x29,0,0] {
                        buf=&buf[4..];
                    }
                }
                let from = ret.1;
                if opts.gue_peer_endpoint.is_none() {
                    gue_current_peer_addr = Some(from);
                }
                Some(wg.encapsulate(buf, &mut wg_scratch_buf))
            }
            _ = gue_timer.tick() , if opts.gue_keepalive_interval.is_some() => {
                if let Some(cpa) = gue_current_peer_addr {
                    match gue_udp.send_to(b"", cpa).await {
                        Ok(_n) => (),
                        Err(e) => {
                            error!("Failed to send empty packet to peer: {e}")
                        }
                    }
                } else {
                    error!("Keepalive interval set without destination address?");
                }
                continue
            }
        };
        loop {
            if let Some(tr_inner) = tr {
                if !matches!(tr_inner, TunnResult::Err(..)) {
                    if wg_last_seen_recv_address.is_some()
                        && wg_current_peer_addr.is_none()
                        && wg_static_peer_addr.is_none()
                    {
                        wg_current_peer_addr = wg_last_seen_recv_address;
                    }
                }
                match tr_inner {
                    TunnResult::Done => (),
                    TunnResult::Err(e) => {
                        error!("boringturn error: {:?}", e);
                    }
                    TunnResult::WriteToNetwork(b) => {
                        if let Some(cpa) = wg_current_peer_addr {
                            match wg_udp.send_to(b, cpa).await {
                                Ok(_n) => (),
                                Err(e) => {
                                    error!("Failed to send wiregaurd packet to peer: {e}")
                                }
                            }
                            tr = Some(wg.decapsulate(None, b"", &mut wg_scratch_buf));
                            continue;
                        } else {
                            error!("Trying to send a wireguard packet without configured peer address");
                        }
                    }
                    TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                        // Send "Variant 1" GUE, which is the same as FOU.
                        if let Some(cpa) = gue_current_peer_addr {
                            match gue_udp.send_to(b, cpa).await {
                                Ok(_n) => (),
                                Err(e) => {
                                    error!("Failed to send gue packet to peer: {e}")
                                }
                            }
                        } else {
                            error!("Trying to send a gue packet without configured peer address");
                        }
                    }
                }
            }
            break;
        }
    }
}

fn parsebase64_32(x: &str) -> anyhow::Result<[u8; 32]> {
    let b = base64::engine::general_purpose::STANDARD.decode(x)?;
    Ok(b[..].try_into()?)
}
