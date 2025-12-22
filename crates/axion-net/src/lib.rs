use libp2p::{
    gossipsub, mdns, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, Multiaddr,
};
use libp2p::futures::StreamExt;
use tokio::sync::mpsc;
use std::time::Duration;
use std::error::Error;
use axion_core::AxionBlock;

#[derive(NetworkBehaviour)]
pub struct AxionBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub struct AxionP2P {
    swarm: libp2p::Swarm<AxionBehaviour>,
    cmd_rx: mpsc::Receiver<AxionBlock>,
    event_tx: mpsc::Sender<AxionBlock>,
}

impl AxionP2P {
    pub async fn new(
        topic_name: &str,
        cmd_rx: mpsc::Receiver<AxionBlock>,
        event_tx: mpsc::Sender<AxionBlock>,
        bootstrap_peer: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Permissive)
                    .build()?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;

                Ok(AxionBehaviour { gossipsub, mdns })
            })?
            .build();

        let topic = gossipsub::IdentTopic::new(topic_name);
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        if let Some(addr_str) = bootstrap_peer {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                println!("🔗 Dialing Bootstrap Node: {:?}", addr);
                swarm.dial(addr)?;
            }
        }

        Ok(Self {
            swarm,
            cmd_rx,
            event_tx,
        })
    }

    pub async fn run(mut self) {
        let topic = gossipsub::IdentTopic::new("axion-mainnet");
        let _ = self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap());

        loop {
            tokio::select! {
                Some(block) = self.cmd_rx.recv() => {
                    if let Ok(data) = bincode::serialize(&block) {
                        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                            println!("⚠️ Gossip Warning: {:?}", e);
                        }
                    }
                }
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("📡 Listening on {:?}", address);
                    }
                    SwarmEvent::Behaviour(AxionBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer, _) in list {
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                        }
                    }
                    SwarmEvent::Behaviour(AxionBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Ok(block) = bincode::deserialize::<AxionBlock>(&message.data) {
                            let _ = self.event_tx.send(block).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
