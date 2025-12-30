use libp2p::futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, noise, relay, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
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
    pub identify: identify::Behaviour,
    pub autonat: autonat::Behaviour,
    pub relay: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
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
        bootstrap_peers: Vec<String>,
        state: Arc<GlobalState>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true).port_reuse(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| {
                let peer_id = key.public().to_peer_id();

                let gossip_msg_id = |message: &gossipsub::Message| {
                    let mut s = std::collections::hash_map::DefaultHasher::new();
                    message.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::ConfigBuilder::default()
                        .heartbeat_interval(Duration::from_secs(1))
                        .validation_mode(gossipsub::ValidationMode::Permissive)
                        .message_id_fn(gossip_msg_id)
                        .build()?,
                )?;

                let mut kademlia = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
                kademlia.set_mode(Some(kad::Mode::Server));

                let req_resp = request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new("/axion/sync/1"),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                let identify = identify::Behaviour::new(identify::Config::new(
                    "/axion/1.0.0".into(),
                    key.public(),
                ));

                let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());

                let dcutr = dcutr::Behaviour::new(peer_id);

                Ok(AxionBehavior {
                    gossipsub,
                    kademlia,
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?,
                    req_resp,
                    identify,
                    autonat,
                    relay: relay_client,
                    dcutr,
                })
            })?
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        for addr in bootstrap_peers {
            if let Ok(ma) = addr.parse::<Multiaddr>() {
                let _ = swarm.dial(ma);
            }
        }

        let topic = gossipsub::IdentTopic::new(topic_name);
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

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
                Some(block) = self.cmd_rx.recv() => {
                    if let Ok(data) = bincode::serialize(&block) {
                         let _ = self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
                    }
                },
                Some(peer) = self.sync_request_rx.recv() => {
                    let req = SyncRequest { start_index: 0, limit: 100 };
                    self.swarm.behaviour_mut().req_resp.send_request(&peer, req);
                },
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("📡 Listening on: {:?}", address);
                    },
                    SwarmEvent::Behaviour(AxionBehaviorEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, addr) in list {
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    },
                    SwarmEvent::Behaviour(AxionBehaviorEvent::Identify(identify::Event::Received { peer_id, info })) => {
                        for addr in info.listen_addrs {
                            self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    },
                    SwarmEvent::Behaviour(AxionBehaviorEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Ok(block) = bincode::deserialize::<AxionBlock>(&message.data) {
                            let _ = self.event_tx.send(block).await;
                        }
                    },
                    SwarmEvent::Behaviour(AxionBehaviorEvent::ReqResp(request_response::Event::Message { message, .. })) => {
                        match message {
                             request_response::Message::Response { response, .. } => {
                                for block in response.blocks {
                                    let _ = self.event_tx.send(block).await;
                                }
                             },
                             request_response::Message::Request { channel, request, .. } => {
                                 let blocks = self.state.get_blocks_range(request.start_index, request.limit as usize).unwrap_or_default();
                                 let _ = self.swarm.behaviour_mut().req_resp.send_response(channel, SyncResponse { blocks });
                             }
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}
