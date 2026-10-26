//! Outbound (client) direction: we initiate, send-only.
use {
    crate::{
        METRICS_INTERVAL, PeerListReceiver, close_codes,
        endpoint::KeyUpdateListener,
        error::Error,
        stats::{self, ClientStats, record_client_error},
        transport::new_client_config,
    },
    bytes::Bytes,
    log::{Level, debug, error, info, log, warn},
    quinn::{Connection, Endpoint, SendDatagramError},
    solana_keypair::{Keypair, Signer},
    solana_pubkey::{Pubkey, PubkeyHasherBuilder},
    solana_tls_utils::{get_remote_pubkey, socket_addr_to_quic_server_name},
    std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    },
    tokio::{
        sync::mpsc,
        task::JoinSet,
        time::{MissedTickBehavior, interval, sleep, timeout},
    },
    tokio_util::sync::CancellationToken,
};

/// How often the outbound loop reconciles its connection table against the
/// peer_list.
pub(crate) const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

/// Delay before redialing a peer after a failed connect, doubled after each
/// further failure up to `MAX_RETRY_DELAY`.
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Longest wait between connects to a peer that keeps failing. A peer can fail
/// for a long time, e.g. when its gossip address still points at a host that now
/// runs another identity, so this keeps such peers to one connect every 10 s.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);

/// Once a connection has been up this long, losing it redials the peer right
/// away and resets its retry delay. A peer that keeps closing connections sooner
/// is redialed no more often than one that rejects every connect.
const HEALTHY_CONNECTION_AGE: Duration = MAX_RETRY_DELAY;

/// Upper bound on a single handshake attempt, enforced inside the connect task.
/// Accommodates any plausible RTT with margin.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// State of a peer's entry in the outbound table.
#[derive(Debug)]
pub(crate) enum PeerState {
    /// Handshake in progress.
    Connecting {
        // If the peer moves before the handshake resolves, reconcile dials the
        // new address and this handshake's outcome is discarded.
        target_address: SocketAddr,
        // How long to wait before redialing if this handshake fails.
        retry_delay: Duration,
        // Failed connects to `target_address` since the last success.
        failed_connects: u32,
    },
    /// Live send-only connection.
    Established {
        connection: Connection,
        // This is cached at install so reconcile can
        // detect an address change without locking quinn state.
        target_address: SocketAddr,
        established_at: Instant,
        // How long to wait before redialing if this connection is lost early.
        retry_delay: Duration,
    },
    /// Waiting to redial after a failed connect or an early lost connection.
    Retrying {
        target_address: SocketAddr,
        // Identifies the retry timer that redials the peer.
        retry_id: u64,
        // How long to wait before redialing again if the next attempt fails.
        retry_delay: Duration,
        // Failed connects to `target_address` since the last success.
        failed_connects: u32,
    },
}

/// `Ok` carries the peer, the address dialed and the newly established
/// connection; `Err` carries the peer and address we failed to connect to.
type HandshakeOutcome = Result<(Pubkey, SocketAddr, Connection), (Pubkey, SocketAddr)>;

/// Enforce the send-only contract of an outbound connection. Returns, with the
/// peer and the connection's `stable_id`, once the connection is closed.
async fn reject_reverse_datagrams(peer: Pubkey, connection: Connection) -> (Pubkey, usize) {
    if connection.read_datagram().await.is_ok() {
        warn!("Peer {peer} sent a datagram on a send-only connection; closing.");
        close_codes::FLOODING.close(&connection);
    }
    (peer, connection.stable_id())
}

/// Open and authenticate a new connection to `peer` at `addr`. A failure is
/// logged at `failure_log_level`.
async fn connect(
    endpoint: Endpoint,
    peer: Pubkey,
    addr: SocketAddr,
    stats: Arc<ClientStats>,
    failure_log_level: Level,
) -> HandshakeOutcome {
    let attempt = async {
        let server_name = socket_addr_to_quic_server_name(addr);
        let connection = endpoint.connect(addr, &server_name)?.await?;
        let attested = get_remote_pubkey(&connection).ok_or(Error::InvalidIdentity(addr))?;
        if attested != peer {
            close_codes::INVALID_IDENTITY.close(&connection);
            return Err(Error::InvalidIdentity(addr));
        }
        Ok(connection)
    };
    match timeout(HANDSHAKE_TIMEOUT, attempt).await {
        Ok(Ok(connection)) => Ok((peer, addr, connection)),
        Ok(Err(e)) => {
            log!(
                failure_log_level,
                "Connection attempt to ({peer}, {addr}) failed: {e:?}"
            );
            record_client_error(&e, &stats);
            Err((peer, addr))
        }
        Err(_elapsed) => {
            log!(
                failure_log_level,
                "Connection attempt to ({peer}, {addr}) timed out after {HANDSHAKE_TIMEOUT:?}"
            );
            stats.connect_failed.fetch_add(1, Ordering::Relaxed);
            Err((peer, addr))
        }
    }
}

/// Outbound control loop for the egress direction (we-connect, send-only).
/// Strives to ensure open connections to everyone in the peer_list.
pub(crate) struct OutboundLoop {
    endpoint: Endpoint,
    local_pubkey: Pubkey,
    /// Channel for outbound messages to be broadcast
    egress_receiver: mpsc::Receiver<Bytes>,
    key_updates: KeyUpdateListener,
    peer_list_receiver: PeerListReceiver,
    /// Per-peer send-only connection state.
    /// Size is limited to the peer_list size by reconcile task.
    peer_state: HashMap<Pubkey, PeerState, PubkeyHasherBuilder>,
    in_flight_handshakes: JoinSet<HandshakeOutcome>,
    reverse_datagram_readers: JoinSet<(Pubkey, usize)>,
    /// Fire when a peer in `Retrying` is due to be redialed.
    retry_timers: JoinSet<(Pubkey, u64)>,
    next_retry_id: u64,
    cancel: CancellationToken,
    stats: Arc<ClientStats>,
    max_datagrams_per_second_per_peer: usize,
}

impl OutboundLoop {
    pub(crate) fn new(
        endpoint: Endpoint,
        local_pubkey: Pubkey,
        egress_receiver: mpsc::Receiver<Bytes>,
        key_updates: KeyUpdateListener,
        peer_list_receiver: PeerListReceiver,
        cancel: CancellationToken,
        max_datagrams_per_second_per_peer: usize,
    ) -> Self {
        Self {
            endpoint,
            local_pubkey,
            egress_receiver,
            key_updates,
            peer_list_receiver,
            peer_state: HashMap::with_hasher(PubkeyHasherBuilder::default()),
            in_flight_handshakes: JoinSet::new(),
            reverse_datagram_readers: JoinSet::new(),
            retry_timers: JoinSet::new(),
            next_retry_id: 0,
            cancel,
            stats: Arc::default(),
            max_datagrams_per_second_per_peer,
        }
    }

    pub(crate) async fn run(mut self) {
        let mut metrics_timer = interval(METRICS_INTERVAL);
        metrics_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut reconcile_timer = interval(RECONCILE_INTERVAL);
        reconcile_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // A receiver clone is needed to drive change notifications, as they call for &mut.
        let mut peer_list_receiver = self.peer_list_receiver.clone();

        info!("Votor QUIC transport client ready.");
        loop {
            tokio::select! {
                changed = self.key_updates.receiver.changed() => {
                    if changed.is_err() {
                        // Unreachable: endpoint holds the identity sender for this loop's lifetime.
                        error!("OutboundLoop: identity channel closed while running, exiting.");
                        debug_assert!(false, "identity channel closed while running");
                        break;
                    }
                    let new_keypair = self.key_updates.receiver.borrow_and_update().insecure_clone();
                    self.apply_identity_change(new_keypair);
                    self.reconcile();
                }
                // The peer set changed: reconcile the connection table right away.
                changed = peer_list_receiver.changed() => {
                    if changed.is_err() {
                        // Unreachable: PeerListService only drops sender when we drop the receiver.
                        error!("OutboundLoop: peer_list channel closed while running, exiting.");
                        debug_assert!(false, "peer_list channel closed while running");
                        break;
                    }
                    self.reconcile();
                }
                Some(joined) = self.in_flight_handshakes.join_next() => {
                    // we never abort these (without also wiping in_flight_handshakes)
                    // and panics are fatal in the validator.
                    let outcome = joined.expect("outbound handshake task panicked or was aborted");
                    self.handle_handshake_outcome(outcome);
                }
                Some(joined) = self.reverse_datagram_readers.join_next() => {
                    let (peer, stable_id) = joined
                        .expect("outbound reverse-datagram reader task panicked or was aborted");
                    self.handle_connection_closed(peer, stable_id);
                }
                Some(joined) = self.retry_timers.join_next() => {
                    let (peer, retry_id) =
                        joined.expect("outbound retry timer task panicked or was aborted");
                    self.handle_retry_timer(peer, retry_id);
                }
                maybe_message = self.egress_receiver.recv() => {
                    let Some(message) = maybe_message else {
                        debug_assert!(
                            self.cancel.is_cancelled(),
                            "egress channel closed before cancel signal is given"
                        );
                        error!("OutboundLoop: egress channel closed, exiting.");
                        break;
                    };
                    self.perform_broadcast(message);
                }
                // Periodic reconcile: connect to missing peers, drop departed peers.
                _ = reconcile_timer.tick() => self.reconcile(),
                _ = metrics_timer.tick() => {
                    debug!("OutboundLoop: running bookkeeping tasks");
                    self.stats.report(self.total_peers());
                }
                _ = self.cancel.cancelled() => break,
            }
        }
    }

    /// Counts the number of established connections
    fn total_peers(&self) -> u64 {
        // scan is not ideal but is simple and correct, and we have < 2000 entries
        self.peer_state
            .values()
            .filter(|entry| matches!(entry, PeerState::Established { .. }))
            .count() as u64
    }

    /// Rebuild the client TLS config against the new identity, swap it into the
    /// quinn endpoint, close every existing connection (since they use old ID),
    /// and adopt the new pubkey. The next reconcile will reconnect to everyone.
    fn apply_identity_change(&mut self, new_keypair: Keypair) {
        let client_config = new_client_config(&new_keypair, self.max_datagrams_per_second_per_peer);
        self.local_pubkey = new_keypair.pubkey();
        self.endpoint.set_default_client_config(client_config);
        // Dropping the JoinSet aborts every in-flight handshake. We do not
        // want them as they began under the old identity.
        self.in_flight_handshakes = JoinSet::new();
        self.reverse_datagram_readers = JoinSet::new();
        self.retry_timers = JoinSet::new();
        let closed = self
            .peer_state
            .drain()
            .filter(|(_peer, entry)| {
                if let PeerState::Established { connection, .. } = entry {
                    close_codes::IDENTITY_CHANGED.close(connection);
                    true
                } else {
                    false
                }
            })
            .count() as u64;
        self.stats
            .connection_closed_identity_changed
            .fetch_add(closed, Ordering::Relaxed);
        // Never blocks, and a dropped ack only matters at shutdown, when the
        // updater is gone anyway.
        let _ = self.key_updates.ack.try_send(());
        info!(
            "outbound identity changed to {} ({} connection(s) closed)",
            self.local_pubkey, closed
        );
    }

    /// Reconcile the connection table against the current peer_list.
    fn reconcile(&mut self) {
        debug!("OutboundLoop: running reconcile");
        let peer_list = self.peer_list_receiver.borrow().clone();
        // With pushing off every peer we hold counts as departed.
        let push_enabled = peer_list.push_enabled;

        // 1. Close connections for departed peers.
        let mut closed_not_in_peer_list = 0u64;
        self.peer_state.retain(|peer, state| {
            if push_enabled && peer_list.peers.contains_key(peer) {
                return true;
            }
            match state {
                PeerState::Established { connection, .. } => {
                    info!("OutboundLoop: closing connection to {peer}: no longer desired.");
                    close_codes::NOT_ADMITTED.close(connection);
                    closed_not_in_peer_list = closed_not_in_peer_list.saturating_add(1);
                    false
                }
                // A Connecting entry resolves within HANDSHAKE_TIMEOUT through
                // `handle_handshake_outcome` into an Established or a Retrying entry,
                // at which point we can wipe it.
                PeerState::Connecting { .. } => true,
                // Its retry timer finds the entry gone and does nothing.
                PeerState::Retrying { .. } => false,
            }
        });
        self.stats
            .connection_closed_not_in_peer_list
            .fetch_add(closed_not_in_peer_list, Ordering::Relaxed);

        if !push_enabled {
            return;
        }

        // 2. Ensure a connection for every addressable peer.
        for (peer, addr) in peer_list.peers.iter() {
            if *peer == self.local_pubkey {
                continue;
            }
            // No gossip address yet (or anymore)
            let Some(addr) = addr else {
                self.stats
                    .connect_failed_no_address
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // Whether to dial `addr` now. A connection found dead is handled like one
            // reported closed by its reader.
            let mut lost = false;
            let dial_now = match self.peer_state.get(peer) {
                // A handshake is already in flight; do not spawn a second task for this
                // peer unless it has moved. The handshake to the old address can take
                // up to HANDSHAKE_TIMEOUT if the old host is gone, so do not wait for it.
                Some(PeerState::Connecting { target_address, .. }) => target_address != addr,
                // The retry timer redials the peer, unless it has moved.
                Some(PeerState::Retrying { target_address, .. }) => target_address != addr,
                Some(PeerState::Established {
                    connection,
                    target_address: cur,
                    ..
                }) => {
                    // desired peer address has changed
                    if cur != addr {
                        info!(
                            "OutboundLoop: closing connection to {peer}: desired address changed \
                             from {cur} to {addr}."
                        );
                        close_codes::PEER_MOVED.close(connection);
                        self.stats
                            .connection_closed_peer_moved
                            .fetch_add(1, Ordering::Relaxed);
                        true
                    } else {
                        lost = connection.close_reason().is_some();
                        false
                    }
                }
                None => true,
            };
            if dial_now {
                self.dial(*peer, *addr, INITIAL_RETRY_DELAY, 0);
            } else if lost {
                self.handle_connection_lost(*peer);
            }
        }
    }

    /// Start a handshake to `peer` at `addr`, after `failed_connects` failed
    /// connects to it. If it fails, the peer is redialed after `retry_delay`.
    fn dial(
        &mut self,
        peer: Pubkey,
        addr: SocketAddr,
        retry_delay: Duration,
        failed_connects: u32,
    ) {
        // Only the first failure is a warning. A peer that keeps failing, e.g. one
        // that has gone down, would otherwise log a warning on every retry.
        let (log_level, failure_log_level) = if failed_connects == 0 {
            (Level::Info, Level::Warn)
        } else {
            (Level::Debug, Level::Debug)
        };
        log!(
            log_level,
            "OutboundLoop: initiating connection to {peer} ({addr})"
        );
        self.in_flight_handshakes.spawn(connect(
            self.endpoint.clone(),
            peer,
            addr,
            self.stats.clone(),
            failure_log_level,
        ));
        self.peer_state.insert(
            peer,
            PeerState::Connecting {
                target_address: addr,
                retry_delay,
                failed_connects,
            },
        );
    }

    /// Redial `peer` at `addr` after `retry_delay`, waiting twice as long (up to
    /// `MAX_RETRY_DELAY`) if that attempt fails as well.
    fn retry_later(
        &mut self,
        peer: Pubkey,
        addr: SocketAddr,
        retry_delay: Duration,
        failed_connects: u32,
    ) {
        let retry_id = self.next_retry_id;
        self.next_retry_id = self.next_retry_id.wrapping_add(1);
        self.retry_timers.spawn(async move {
            sleep(retry_delay).await;
            (peer, retry_id)
        });
        self.peer_state.insert(
            peer,
            PeerState::Retrying {
                target_address: addr,
                retry_id,
                retry_delay: retry_delay.saturating_mul(2).min(MAX_RETRY_DELAY),
                failed_connects,
            },
        );
    }

    /// Redial a peer whose retry timer fired.
    fn handle_retry_timer(&mut self, peer: Pubkey, retry_id: u64) {
        // The peer may have been redialed or dropped since this timer started.
        if let Some(&PeerState::Retrying {
            target_address,
            retry_id: current_retry_id,
            retry_delay,
            failed_connects,
        }) = self.peer_state.get(&peer)
            && current_retry_id == retry_id
        {
            self.dial(peer, target_address, retry_delay, failed_connects);
        }
    }

    /// Handle the reader of a connection to `peer` exiting, which it does once
    /// the connection is closed.
    fn handle_connection_closed(&mut self, peer: Pubkey, stable_id: usize) {
        // Connections we replaced or dropped ourselves are not redialed here.
        if matches!(
            self.peer_state.get(&peer),
            Some(PeerState::Established { connection, .. }) if connection.stable_id() == stable_id
        ) {
            self.handle_connection_lost(peer);
        }
    }

    /// Redial `peer`, whose established connection was lost: right away if the
    /// connection was healthy, otherwise after its retry delay.
    fn handle_connection_lost(&mut self, peer: Pubkey) {
        let Some(PeerState::Established {
            connection,
            target_address,
            established_at,
            retry_delay,
        }) = self.peer_state.get(&peer)
        else {
            return;
        };
        let (addr, healthy, retry_delay) = (
            *target_address,
            established_at.elapsed() >= HEALTHY_CONNECTION_AGE,
            *retry_delay,
        );
        match connection.close_reason() {
            Some(reason) => info!("OutboundLoop: connection to {peer} was closed: {reason}"),
            None => info!("OutboundLoop: connection to {peer} was lost."),
        }
        self.stats.connection_lost.fetch_add(1, Ordering::Relaxed);
        if healthy {
            self.dial(peer, addr, INITIAL_RETRY_DELAY, 0);
        } else {
            self.retry_later(peer, addr, retry_delay, 0);
        }
    }

    /// Broadcast one message to every live connection. Broken connections are
    /// redialed.
    fn perform_broadcast(&mut self, message: Bytes) {
        let mut sent = 0u64;
        let mut dead_peers = Vec::new();
        for (peer, state) in self.peer_state.iter() {
            let PeerState::Established { connection, .. } = state else {
                continue;
            };
            match connection.send_datagram(message.clone()) {
                Ok(()) => sent = sent.saturating_add(1),
                Err(SendDatagramError::ConnectionLost(reason)) => {
                    debug!("OutboundLoop: connection to {peer} lost while sending: {reason}.");
                    dead_peers.push(*peer);
                }
                // The peer either does not support datagrams or advertises max size below our
                // message size. Both are misconfigurations that reconnecting will not fix,
                // so keep the connection to avoid churn but report errors for visibility.
                Err(e @ (SendDatagramError::UnsupportedByPeer | SendDatagramError::TooLarge)) => {
                    debug!(
                        "OutboundLoop: peer {peer} refused a {} byte datagram: {e}",
                        message.len()
                    );
                    self.stats.peer_config_error.fetch_add(1, Ordering::Relaxed);
                }
                Err(SendDatagramError::Disabled) => {
                    unreachable!("By construction (we enable datagrams)");
                }
            }
        }
        self.stats.datagrams_sent.fetch_add(sent, Ordering::Relaxed);
        for peer in dead_peers {
            self.handle_connection_lost(peer);
        }
    }

    /// Handle a handshake task that ran to completion.
    fn handle_handshake_outcome(&mut self, outcome: HandshakeOutcome) {
        // Peer state is `Connecting` here: reconcile leaves `Connecting` entries in place
        // and identity rotation resets the JoinSet. Only a handshake superseded by one to
        // the peer's new address finds the peer elsewhere; discard its outcome.
        let (peer, addr) = match &outcome {
            Ok((peer, addr, _)) | Err((peer, addr)) => (*peer, *addr),
        };
        let (retry_delay, failed_connects) = match self.peer_state.get(&peer) {
            Some(PeerState::Connecting {
                target_address,
                retry_delay,
                failed_connects,
            }) if *target_address == addr => (*retry_delay, *failed_connects),
            _ => {
                debug!("OutboundLoop: discarding superseded handshake to ({peer}, {addr}).");
                if let Ok((_, _, connection)) = outcome {
                    close_codes::PEER_MOVED.close(&connection);
                }
                return;
            }
        };
        match outcome {
            Ok((peer, target_address, connection)) => {
                let reverse_datagram_reader = connection.clone();
                self.peer_state.insert(
                    peer,
                    PeerState::Established {
                        connection,
                        target_address,
                        established_at: Instant::now(),
                        retry_delay,
                    },
                );
                self.reverse_datagram_readers
                    .spawn(reject_reverse_datagrams(peer, reverse_datagram_reader));
                if failed_connects == 0 {
                    info!("OutboundLoop: established connection to {peer}.");
                } else {
                    info!(
                        "OutboundLoop: established connection to {peer} after {failed_connects} \
                         failed connects."
                    );
                }
                stats::record_connection_count(&self.stats.peak_connections, self.total_peers());
            }
            Err((peer, addr)) => {
                // an operator-visible message is printed in handshake task itself
                self.retry_later(peer, addr, retry_delay, failed_connects.saturating_add(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::PeerList, solana_net_utils::sockets::unique_port_range_for_tests,
        std::net::Ipv4Addr, tokio::sync::watch,
    };

    /// Recreates an edge case when client identity changes while a peer is in `Connecting`
    /// state, we must correctly terminate the handshake and leave things in a clean state.
    #[tokio::test]
    async fn identity_change_drops_handshakes() {
        let old_kp = Keypair::new();
        let old_pubkey = old_kp.pubkey();
        let port = unique_port_range_for_tests(1).next().unwrap();
        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .expect("bind client endpoint");
        endpoint.set_default_client_config(new_client_config(&old_kp, 50));

        let (_egress_tx, egress_rx) = mpsc::channel(1);
        let (_identity_tx, identity_rx) = watch::channel(Keypair::new());
        let (ack, _acks) = crossbeam_channel::unbounded();
        let (_peer_list_tx, peer_list_rx) = watch::channel(Arc::new(PeerList {
            peers: HashMap::default(),
            push_enabled: true,
        }));

        let mut outbound = OutboundLoop::new(
            endpoint,
            old_pubkey,
            egress_rx,
            KeyUpdateListener {
                receiver: identity_rx,
                ack,
            },
            peer_list_rx,
            CancellationToken::new(),
            50,
        );

        // Add a fake peer whose handshake is not finished at the moment of id change.
        let stuck_peer = Keypair::new().pubkey();
        outbound.peer_state.insert(
            stuck_peer,
            PeerState::Connecting {
                target_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                retry_delay: INITIAL_RETRY_DELAY,
                failed_connects: 0,
            },
        );
        outbound.in_flight_handshakes.spawn(async {
            sleep(Duration::from_secs(10)).await;
            unreachable!("This future should never resolve");
        });
        outbound.reverse_datagram_readers.spawn(async {
            sleep(Duration::from_secs(10)).await;
            unreachable!("This future should never resolve");
        });

        let new_kp = Keypair::new();
        let new_pubkey = new_kp.pubkey();
        outbound.apply_identity_change(new_kp);
        assert!(
            outbound.in_flight_handshakes.is_empty(),
            "identity change must clear in_flight_handshakes"
        );
        assert!(
            outbound.reverse_datagram_readers.is_empty(),
            "identity change must clear reverse_datagram_readers"
        );
        assert!(
            outbound.peer_state.is_empty(),
            "identity change must clear state",
        );
        assert_eq!(
            outbound
                .stats
                .connection_closed_identity_changed
                .load(Ordering::Relaxed),
            0,
            "a peer in `Connecting` state must not count as a closed connection",
        );
        assert_eq!(
            outbound.local_pubkey, new_pubkey,
            "identity change must adopt the new pubkey",
        );
    }

    /// A peer that moves while a handshake to its old address hangs is dialed at
    /// the new address right away, and the old handshake's outcome is discarded.
    #[tokio::test]
    async fn moved_peer_supersedes_in_flight_handshake() {
        use crate::transport::new_server_config;

        const MAX_DATAGRAMS_PER_SECOND: usize = 50;
        let mut ports = unique_port_range_for_tests(2);

        let peer_keypair = Keypair::new();
        let peer = peer_keypair.pubkey();
        let server = Endpoint::server(
            new_server_config(&peer_keypair, MAX_DATAGRAMS_PER_SECOND, 1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, ports.next().unwrap())),
        )
        .expect("bind server endpoint");
        let new_addr = server.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            connection.closed().await
        });

        let client_keypair = Keypair::new();
        let mut endpoint = Endpoint::client(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            ports.next().unwrap(),
        )))
        .expect("bind client endpoint");
        endpoint.set_default_client_config(new_client_config(
            &client_keypair,
            MAX_DATAGRAMS_PER_SECOND,
        ));
        let (_egress_tx, egress_rx) = mpsc::channel(1);
        let (_identity_tx, identity_rx) = watch::channel(Keypair::new());
        let (ack, _acks) = crossbeam_channel::unbounded();
        let (peer_list_tx, peer_list_rx) = watch::channel(Arc::new(PeerList {
            peers: HashMap::default(),
            push_enabled: true,
        }));
        let mut outbound = OutboundLoop::new(
            endpoint,
            client_keypair.pubkey(),
            egress_rx,
            KeyUpdateListener {
                receiver: identity_rx,
                ack,
            },
            peer_list_rx,
            CancellationToken::new(),
            MAX_DATAGRAMS_PER_SECOND,
        );

        // A handshake to the peer's old address hangs, as if the old host were gone.
        let old_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        outbound.peer_state.insert(
            peer,
            PeerState::Connecting {
                target_address: old_addr,
                retry_delay: INITIAL_RETRY_DELAY,
                failed_connects: 0,
            },
        );
        outbound.in_flight_handshakes.spawn(async {
            sleep(Duration::from_secs(10)).await;
            unreachable!("This future should never resolve");
        });

        // The peer moves.
        peer_list_tx.send_replace(Arc::new(PeerList {
            peers: HashMap::from([(peer, Some(new_addr))]),
            push_enabled: true,
        }));
        outbound.reconcile();
        assert!(matches!(
            outbound.peer_state.get(&peer),
            Some(PeerState::Connecting { target_address, .. }) if *target_address == new_addr
        ));

        // The old handshake failing does not affect the new one.
        outbound.handle_handshake_outcome(Err((peer, old_addr)));
        assert!(matches!(
            outbound.peer_state.get(&peer),
            Some(PeerState::Connecting { target_address, .. }) if *target_address == new_addr
        ));

        let outcome = timeout(HANDSHAKE_TIMEOUT, outbound.in_flight_handshakes.join_next())
            .await
            .expect("handshake to the new address did not complete")
            .unwrap()
            .unwrap();
        outbound.handle_handshake_outcome(outcome);
        assert!(matches!(
            outbound.peer_state.get(&peer),
            Some(PeerState::Established { target_address, .. }) if *target_address == new_addr
        ));
    }

    /// An outbound loop on a fresh localhost client endpoint, with `peers` as its
    /// peer list.
    fn new_test_outbound(
        peers: HashMap<Pubkey, Option<SocketAddr>>,
    ) -> (OutboundLoop, watch::Sender<Arc<PeerList>>) {
        let client_keypair = Keypair::new();
        let port = unique_port_range_for_tests(1).next().unwrap();
        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .expect("bind client endpoint");
        endpoint.set_default_client_config(new_client_config(&client_keypair, 50));
        let (_egress_tx, egress_rx) = mpsc::channel(1);
        let (_identity_tx, identity_rx) = watch::channel(Keypair::new());
        let (ack, _acks) = crossbeam_channel::unbounded();
        let (peer_list_tx, peer_list_rx) = watch::channel(Arc::new(PeerList {
            peers,
            push_enabled: true,
        }));
        let outbound = OutboundLoop::new(
            endpoint,
            client_keypair.pubkey(),
            egress_rx,
            KeyUpdateListener {
                receiver: identity_rx,
                ack,
            },
            peer_list_rx,
            CancellationToken::new(),
            50,
        );
        (outbound, peer_list_tx)
    }

    /// The retry delay and failed connect count of a `Retrying` peer.
    fn retry_of(outbound: &OutboundLoop, peer: &Pubkey) -> Option<(Duration, u32)> {
        match outbound.peer_state.get(peer)? {
            PeerState::Retrying {
                retry_delay,
                failed_connects,
                ..
            } => Some((*retry_delay, *failed_connects)),
            _ => None,
        }
    }

    /// A failed connect is retried after a delay that doubles with each further
    /// failure, up to MAX_RETRY_DELAY.
    #[tokio::test]
    async fn failed_connect_retries_with_backoff() {
        let peer = Keypair::new().pubkey();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let (mut outbound, peer_list_tx) = new_test_outbound(HashMap::from([(peer, Some(addr))]));

        outbound.reconcile();
        assert!(matches!(
            outbound.peer_state.get(&peer),
            Some(PeerState::Connecting {
                failed_connects: 0,
                ..
            })
        ));
        outbound.handle_handshake_outcome(Err((peer, addr)));
        assert_eq!(
            retry_of(&outbound, &peer),
            Some((2 * INITIAL_RETRY_DELAY, 1))
        );

        // The peer is redialed once INITIAL_RETRY_DELAY has passed, well before
        // the next reconcile tick.
        let (timer_peer, retry_id) =
            timeout(RECONCILE_INTERVAL / 2, outbound.retry_timers.join_next())
                .await
                .expect("retry timer did not fire")
                .unwrap()
                .unwrap();
        outbound.handle_retry_timer(timer_peer, retry_id);
        assert!(matches!(
            outbound.peer_state.get(&peer),
            Some(PeerState::Connecting { target_address, retry_delay, failed_connects: 1 })
                if *target_address == addr && *retry_delay == 2 * INITIAL_RETRY_DELAY
        ));
        outbound.handle_handshake_outcome(Err((peer, addr)));
        assert_eq!(
            retry_of(&outbound, &peer),
            Some((4 * INITIAL_RETRY_DELAY, 2))
        );

        // The delay never grows past MAX_RETRY_DELAY.
        outbound.peer_state.insert(
            peer,
            PeerState::Connecting {
                target_address: addr,
                retry_delay: MAX_RETRY_DELAY,
                failed_connects: 8,
            },
        );
        outbound.handle_handshake_outcome(Err((peer, addr)));
        assert_eq!(retry_of(&outbound, &peer), Some((MAX_RETRY_DELAY, 9)));

        // A move to a new address is dialed right away, as a first connect.
        let new_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 2));
        peer_list_tx.send_replace(Arc::new(PeerList {
            peers: HashMap::from([(peer, Some(new_addr))]),
            push_enabled: true,
        }));
        outbound.reconcile();
        assert!(matches!(
            outbound.peer_state.get(&peer),
            Some(PeerState::Connecting { target_address, retry_delay, failed_connects: 0 })
                if *target_address == new_addr && *retry_delay == INITIAL_RETRY_DELAY
        ));
    }

    /// A lost connection is redialed without waiting for the reconcile tick: at
    /// once if it was healthy, after its retry delay if it was lost early.
    #[tokio::test]
    async fn lost_connection_is_redialed() {
        use crate::transport::new_server_config;

        let peer_keypair = Keypair::new();
        let peer = peer_keypair.pubkey();
        let port = unique_port_range_for_tests(1).next().unwrap();
        let server = Endpoint::server(
            new_server_config(&peer_keypair, 50, 1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        )
        .expect("bind server endpoint");
        let addr = server.local_addr().unwrap();
        let (accepted_tx, mut accepted) = mpsc::unbounded_channel();
        let _server = tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                if let Ok(connection) = incoming.await {
                    accepted_tx.send(connection).unwrap();
                }
            }
        });
        let (mut outbound, _peer_list_tx) = new_test_outbound(HashMap::from([(peer, Some(addr))]));
        let mut establish = async |outbound: &mut OutboundLoop| {
            let outcome = timeout(HANDSHAKE_TIMEOUT, outbound.in_flight_handshakes.join_next())
                .await
                .expect("handshake did not complete")
                .unwrap()
                .unwrap();
            outbound.handle_handshake_outcome(outcome);
            assert!(matches!(
                outbound.peer_state.get(&peer),
                Some(PeerState::Established { .. })
            ));
            accepted.recv().await.unwrap()
        };
        let close = async |outbound: &mut OutboundLoop, server_connection: Connection| {
            server_connection.close(0u32.into(), b"");
            let (closed_peer, stable_id) = timeout(
                RECONCILE_INTERVAL / 2,
                outbound.reverse_datagram_readers.join_next(),
            )
            .await
            .expect("connection close was not noticed")
            .unwrap()
            .unwrap();
            outbound.handle_connection_closed(closed_peer, stable_id);
        };

        outbound.reconcile();
        let server_connection = establish(&mut outbound).await;
        // The connection has been up long enough to count as healthy.
        let Some(PeerState::Established { established_at, .. }) =
            outbound.peer_state.get_mut(&peer)
        else {
            unreachable!();
        };
        *established_at -= HEALTHY_CONNECTION_AGE;
        close(&mut outbound, server_connection).await;
        assert!(matches!(
            outbound.peer_state.get(&peer),
            Some(PeerState::Connecting { retry_delay, .. }) if *retry_delay == INITIAL_RETRY_DELAY
        ));

        // A connection lost right after it was made waits for its retry delay.
        let server_connection = establish(&mut outbound).await;
        close(&mut outbound, server_connection).await;
        assert_eq!(
            retry_of(&outbound, &peer),
            Some((2 * INITIAL_RETRY_DELAY, 0))
        );
    }

    #[tokio::test]
    async fn reverse_datagram_closes_connection() {
        use crate::transport::new_server_config;

        const MAX_DATAGRAMS_PER_SECOND: usize = 50;
        let mut ports = unique_port_range_for_tests(2);

        let server_keypair = Keypair::new();
        let server = Endpoint::server(
            new_server_config(&server_keypair, MAX_DATAGRAMS_PER_SECOND, 1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, ports.next().unwrap())),
        )
        .expect("bind server endpoint");
        let server_addr = server.local_addr().unwrap();

        let client_keypair = Keypair::new();
        let mut client = Endpoint::client(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            ports.next().unwrap(),
        )))
        .expect("bind client endpoint");
        client.set_default_client_config(new_client_config(
            &client_keypair,
            MAX_DATAGRAMS_PER_SECOND,
        ));

        let connecting = client
            .connect(server_addr, &socket_addr_to_quic_server_name(server_addr))
            .unwrap();
        let incoming = server.accept().await.unwrap();
        let (client_connection, server_connection) = tokio::join!(connecting, incoming);
        let client_connection = client_connection.unwrap();
        let server_connection = server_connection.unwrap();

        let reader = tokio::spawn(reject_reverse_datagrams(
            server_keypair.pubkey(),
            client_connection,
        ));
        server_connection
            .send_datagram(Bytes::new())
            .expect("client advertised datagram support");
        reader.await.unwrap();
        let reason = timeout(Duration::from_secs(5), server_connection.closed())
            .await
            .expect("client did not close after the reverse datagram");
        let quinn::ConnectionError::ApplicationClosed(close) = reason else {
            panic!("unexpected client close reason: {reason:?}");
        };
        assert_eq!(close.error_code, close_codes::FLOODING.code);
    }
}
