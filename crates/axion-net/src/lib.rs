use libp2p::futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::{
    gossipsub, kad, mdns, noise, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, StreamProtocol, Swarm,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use axion_core::{AxionBlock, GlobalState};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRequest {
    pub start_index: u64,
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<AxionBlock>,
}

#[derive(NetworkBehaviour)]
pub struct AxionBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub req_resp: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
}
pub struct AxionP2P {
    swarm: Swarm<AxionBehavior>,
    cmd_rx: mpsc::Receiver<AxionBlock>,
    event_tx: mpsc::Sender<AxionBlock>,
    sync_request_rx: mpsc::Receiver<PeerId>,
    state: Arc<GlobalState>,
}

impl AxionP2P {
    pub async fn new(
        topic_name: &str,
        cmd_rx: mpsc::Receiver<AxionBlock>,
        event_tx: mpsc::Sender<AxionBlock>,
        sync_request_rx: mpsc::Receiver<PeerId>,
        _bootstrap_peer: Option<String>,
        state: Arc<GlobalState>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let peer_id = key.public().to_peer_id();

                let gossip_msg_id = |message: &gossipsub::Message| {
                    let mut s = std::collections::hash_map::DefaultHasher::new();
                    message.data.hash(&mut s);
                    let hash_val = s.finish();
                    gossipsub::MessageId::from(hash_val.to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Permissive)
                    .message_id_fn(gossip_msg_id)
                    .build()
                    .map_err(|e| {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("{:?}", e),
                        )) as Box<dyn Error + Send + Sync>
                    })?;

                let mut gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{:?}", e),
                    )) as Box<dyn Error + Send + Sync>
                })?;

                let topic = gossipsub::IdentTopic::new(topic_name);

                gossipsub.subscribe(&topic).map_err(|e| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Subscription failed: {:?}", e),
                    )) as Box<dyn Error + Send + Sync>
                })?;

                let req_resp = request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new("/axion/sync/1"),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                let mut kademlia = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
                kademlia.set_mode(Some(kad::Mode::Server));

                let mdns =
                    mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id).map_err(|e| {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("{:?}", e),
                        )) as Box<dyn Error + Send + Sync>
                    })?;

                Ok(AxionBehavior {
                    gossipsub,
                    kademlia,
                    mdns,
                    req_resp,
                })
            })?
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        Ok(Self {
            swarm,
            cmd_rx,
            event_tx,
            sync_request_rx,
            state,
        })
    }

    pub async fn run(&mut self) {
        let topic = gossipsub::IdentTopic::new("axion-mainnet");

        loop {
            tokio::select! {
                // Outbound: Publish local block to the mesh
                Some(block) = self.cmd_rx.recv() => {
                    if let Ok(data) = bincode::serialize(&block) {
                        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                            eprintln!("⚠️ Gossipsub Publish Error: {:?}", e);
                        }
                    }
                },

                // Outbound: Request historical data from a specific peer
                Some(peer) = self.sync_request_rx.recv() => {
                    println!("🔄 Requesting block history from {}", peer);
                    let req = SyncRequest { start_index: 0, limit: 100 };
                    self.swarm.behaviour_mut().req_resp.send_request(&peer, req);
                },

                // Inbound: Handle all network behavior events
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("📡 Node local address: {:?}", address);
                    }

                    // Discovery via mDNS
                    SwarmEvent::Behaviour(AxionBehaviorEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, addr) in list {
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    },

                    // Inbound Gossip
                    SwarmEvent::Behaviour(AxionBehaviorEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Ok(block) = bincode::deserialize::<AxionBlock>(&message.data) {
                            let _ = self.event_tx.send(block).await;
                        }
                    },

                    // Req-Resp Sync Layer
                    SwarmEvent::Behaviour(AxionBehaviorEvent::ReqResp(request_response::Event::Message { message, .. })) => {
                        match message {
                            request_response::Message::Request { channel, request, .. } => {
                                let blocks = self.state.get_blocks_range(request.start_index, request.limit as usize)
                                    .unwrap_or_default();
                                let resp = SyncResponse { blocks };
                                let _ = self.swarm.behaviour_mut().req_resp.send_response(channel, resp);
                            },
                            request_response::Message::Response { response, .. } => {
                                println!("📥 Sync Complete: Received {} historical blocks", response.blocks.len());
                                for block in response.blocks {
                                    let _ = self.event_tx.send(block).await;
                                }
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}
