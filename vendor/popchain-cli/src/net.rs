#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::sleep,
};

use crate::{
    app::AppEventV0,
    chain::{BlockV1, Db},
    types::Hash32,
};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const BROADCAST_RETRIES: usize = 3;
const BROADCAST_RETRY_DELAY: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NetMessageV0 {
    /// Request peer tip state.
    GetTip,

    /// Peer tip reply.
    Tip {
        best_height: u64,
        best_tip_hash_hex: String,
    },

    /// Request one block by hash (hex).
    GetBlock { hash_hex: String },

    /// Send a full block.
    Block { block: BlockV1 },

    /// Submit an app event into mempool.
    Tx { tx: AppEventV0 },

    /// Simple ack for one-shot calls.
    Ok,

    /// Simple error reply.
    Err { msg: String },
}

#[derive(Debug, Default)]
struct OrphanPool {
    by_hash: BTreeMap<String, BlockV1>,
}

impl OrphanPool {
    fn insert(&mut self, block: BlockV1) -> bool {
        self.by_hash
            .insert(block.block_hash_hex.clone(), block)
            .is_none()
    }

    fn len(&self) -> usize {
        self.by_hash.len()
    }

    fn take_ready_blocks(&mut self, db: &Db) -> Result<Vec<BlockV1>> {
        let mut ready_keys: Vec<String> = Vec::new();

        for (hash_hex, block) in &self.by_hash {
            let parent = Hash32::from_hex(&block.header.prev_block_hash_hex)
                .context("orphan prev_block_hash_hex invalid")?;
            if db.has_block(&parent)? {
                ready_keys.push(hash_hex.clone());
            }
        }

        let mut out = Vec::with_capacity(ready_keys.len());
        for key in ready_keys {
            if let Some(block) = self.by_hash.remove(&key) {
                out.push(block);
            }
        }

        out.sort_by(|a, b| {
            a.header
                .height
                .cmp(&b.header.height)
                .then_with(|| a.block_hash_hex.cmp(&b.block_hash_hex))
        });

        Ok(out)
    }
}

fn orphan_pool() -> &'static Mutex<OrphanPool> {
    static ORPHANS: OnceLock<Mutex<OrphanPool>> = OnceLock::new();
    ORPHANS.get_or_init(|| Mutex::new(OrphanPool::default()))
}

fn is_missing_parent(db: &Db, block: &BlockV1) -> Result<bool> {
    let parent = Hash32::from_hex(&block.header.prev_block_hash_hex).context("bad parent hash")?;
    Ok(!db.has_block(&parent)?)
}

fn queue_orphan(block: BlockV1) -> usize {
    let pool = orphan_pool();
    let mut guard = pool.lock().unwrap();
    guard.insert(block);
    guard.len()
}

fn try_drain_orphans(db: &mut Db) -> Result<usize> {
    let mut imported_total = 0usize;

    loop {
        let ready_blocks = {
            let pool = orphan_pool();
            let mut guard = pool.lock().unwrap();
            guard.take_ready_blocks(db)?
        };

        if ready_blocks.is_empty() {
            break;
        }

        let mut imported_this_round = 0usize;

        for block in ready_blocks {
            match db.import_block(&block) {
                Ok(_) => {
                    imported_total += 1;
                    imported_this_round += 1;
                    eprintln!(
                        "[net] imported queued orphan height={} hash={}",
                        block.header.height, block.block_hash_hex
                    );
                }
                Err(e) => {
                    let queued = queue_orphan(block.clone());
                    eprintln!(
                        "[net] orphan retry failed height={} hash={} queued={} err={}",
                        block.header.height, block.block_hash_hex, queued, e
                    );
                }
            }
        }

        if imported_this_round == 0 {
            break;
        }
    }

    Ok(imported_total)
}

async fn read_one_line(r: tokio::net::tcp::OwnedReadHalf) -> Result<String> {
    let mut br = BufReader::new(r);
    let mut line = String::new();

    let n = tokio::time::timeout(READ_TIMEOUT, br.read_line(&mut line))
        .await
        .context("read timeout")?
        .context("read_line")?;

    if n == 0 {
        return Err(anyhow!("server closed"));
    }

    Ok(line.trim().to_string())
}

async fn write_one_line(w: &mut tokio::net::tcp::OwnedWriteHalf, msg: &NetMessageV0) -> Result<()> {
    let line = serde_json::to_string(msg).context("serialize")?;
    w.write_all(line.as_bytes()).await.context("write")?;
    w.write_all(b"\n").await.context("write nl")?;
    w.flush().await.context("flush")?;
    Ok(())
}

async fn request_once(addr: &str, msg: NetMessageV0) -> Result<NetMessageV0> {
    let sock = TcpStream::connect(addr).await.context("connect")?;
    let (r, mut w) = sock.into_split();

    write_one_line(&mut w, &msg).await.context("send request")?;

    let line = read_one_line(r).await.context("read reply")?;
    let reply: NetMessageV0 = serde_json::from_str(&line).context("parse reply")?;
    Ok(reply)
}

async fn fetch_tip_once(addr: &str) -> Result<(u64, String)> {
    let reply = request_once(addr, NetMessageV0::GetTip).await?;

    match reply {
        NetMessageV0::Tip {
            best_height,
            best_tip_hash_hex,
        } => Ok((best_height, best_tip_hash_hex)),
        NetMessageV0::Err { msg } => Err(anyhow!(msg)),
        other => Err(anyhow!("unexpected reply to GetTip: {:?}", other)),
    }
}

async fn fetch_block_once(addr: &str, hash_hex: &str) -> Result<BlockV1> {
    let reply = request_once(
        addr,
        NetMessageV0::GetBlock {
            hash_hex: hash_hex.to_string(),
        },
    )
    .await?;

    match reply {
        NetMessageV0::Block { block } => Ok(block),
        NetMessageV0::Err { msg } => Err(anyhow!(msg)),
        other => Err(anyhow!("unexpected reply to GetBlock: {:?}", other)),
    }
}

async fn fetch_missing_ancestor_chain(
    addr: &str,
    db: &Db,
    block: &BlockV1,
) -> Result<Vec<BlockV1>> {
    let mut missing: Vec<BlockV1> = Vec::new();
    let mut cursor = Hash32::from_hex(&block.header.prev_block_hash_hex)
        .context("block prev_block_hash_hex invalid")?;

    while !db.has_block(&cursor)? {
        let fetched = fetch_block_once(addr, &cursor.to_hex()).await?;
        cursor = Hash32::from_hex(&fetched.header.prev_block_hash_hex)
            .context("ancestor prev_block_hash_hex invalid")?;
        missing.push(fetched);
    }

    missing.reverse();
    Ok(missing)
}

async fn handle_peer(db: Arc<Mutex<Db>>, sock: TcpStream, peer: SocketAddr) -> Result<()> {
    let (r, mut w) = sock.into_split();

    let line = read_one_line(r).await.context("read request")?;
    let msg: NetMessageV0 = serde_json::from_str(&line).context("parse request")?;

    match msg {
        NetMessageV0::GetTip => {
            let st = {
                let dbh = db.lock().unwrap();
                dbh.read_state()?
            };

            write_one_line(
                &mut w,
                &NetMessageV0::Tip {
                    best_height: st.best_height,
                    best_tip_hash_hex: st.best_tip_hash_hex,
                },
            )
            .await?;
        }

        NetMessageV0::GetBlock { hash_hex } => {
            let h = Hash32::from_hex(&hash_hex).context("bad hash")?;

            let blk_opt = {
                let dbh = db.lock().unwrap();
                if dbh.has_block(&h)? {
                    Some(dbh.read_block_by_hash(&h)?)
                } else {
                    None
                }
            };

            match blk_opt {
                Some(block) => write_one_line(&mut w, &NetMessageV0::Block { block }).await?,
                None => {
                    write_one_line(
                        &mut w,
                        &NetMessageV0::Err {
                            msg: format!("no such block {}", hash_hex),
                        },
                    )
                    .await?
                }
            }
        }

        NetMessageV0::Block { block } => {
            let res = {
                let mut dbh = db.lock().unwrap();

                if is_missing_parent(&dbh, &block)? {
                    let queued = queue_orphan(block.clone());
                    Err(anyhow!(
                        "queued orphan block height={} hash={} missing_parent={} queued={}",
                        block.header.height,
                        block.block_hash_hex,
                        block.header.prev_block_hash_hex,
                        queued
                    ))
                } else {
                    dbh.import_block(&block)?;
                    let _ = try_drain_orphans(&mut dbh)?;
                    Ok(())
                }
            };

            match res {
                Ok(_) => {
                    eprintln!(
                        "[net] imported block height={} hash={}",
                        block.header.height, block.block_hash_hex
                    );
                    write_one_line(&mut w, &NetMessageV0::Ok).await?;
                }
                Err(e) => {
                    eprintln!("[net] reject/queue block from {}: {}", peer, e);
                    write_one_line(&mut w, &NetMessageV0::Err { msg: e.to_string() }).await?;
                }
            }
        }

        NetMessageV0::Tx { tx } => {
            let res = {
                let mut dbh = db.lock().unwrap();
                dbh.mempool_mut().insert_event(tx).map(|_inserted| ())
            };

            match res {
                Ok(_) => {
                    eprintln!("[net] tx accepted from {}", peer);
                    write_one_line(&mut w, &NetMessageV0::Ok).await?;
                }
                Err(e) => {
                    eprintln!("[net] tx rejected from {}: {}", peer, e);
                    write_one_line(&mut w, &NetMessageV0::Err { msg: e.to_string() }).await?;
                }
            }
        }

        NetMessageV0::Tip { .. } => {
            write_one_line(
                &mut w,
                &NetMessageV0::Err {
                    msg: "Tip is reply-only".to_string(),
                },
            )
            .await?;
        }

        NetMessageV0::Ok => {
            write_one_line(&mut w, &NetMessageV0::Ok).await?;
        }

        NetMessageV0::Err { msg } => {
            write_one_line(&mut w, &NetMessageV0::Err { msg }).await?;
        }
    }

    Ok(())
}

pub async fn serve(db: Arc<Mutex<Db>>, bind: &str) -> Result<()> {
    let addr: SocketAddr = bind.parse().context("bind parse")?;
    let lis = TcpListener::bind(addr).await.context("bind")?;
    eprintln!("[net] listening on {}", bind);

    loop {
        let (sock, peer) = lis.accept().await.context("accept")?;
        let db2 = db.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_peer(db2, sock, peer).await {
                eprintln!("[net] peer {} error: {}", peer, e);
            }
        });
    }
}

pub async fn connect_once(db: Arc<Mutex<Db>>, addr: &str) -> Result<()> {
    let (peer_height, peer_tip_hex) = fetch_tip_once(addr).await?;

    let peer_tip = Hash32::from_hex(&peer_tip_hex).context("peer best_tip_hash_hex invalid")?;

    {
        let dbh = db.lock().unwrap();
        let local_st = dbh.read_state()?;

        if local_st.best_tip_hash_hex == peer_tip_hex {
            eprintln!(
                "[net] already synced height={} from {}",
                local_st.best_height, addr
            );
            return Ok(());
        }

        if dbh.has_block(&peer_tip)? {
            eprintln!(
                "[net] already have peer tip at local height={} from {}",
                local_st.best_height, addr
            );
            return Ok(());
        }
    }

    let mut missing: Vec<BlockV1> = Vec::new();
    let mut cursor = peer_tip;

    loop {
        let already_have = {
            let dbh = db.lock().unwrap();
            dbh.has_block(&cursor)?
        };

        if already_have {
            break;
        }

        let block = fetch_block_once(addr, &cursor.to_hex()).await?;
        cursor = Hash32::from_hex(&block.header.prev_block_hash_hex)
            .context("block prev_block_hash_hex invalid")?;
        missing.push(block);

        if missing
            .last()
            .map(|b| b.header.height == 0)
            .unwrap_or(false)
        {
            break;
        }
    }

    missing.reverse();

    for block in missing {
        let mut dbh = db.lock().unwrap();

        if is_missing_parent(&dbh, &block)? {
            let queued = queue_orphan(block.clone());
            eprintln!(
                "[net] queued synced orphan height={} hash={} queued={}",
                block.header.height, block.block_hash_hex, queued
            );
            continue;
        }

        dbh.import_block(&block).context("import synced block")?;
        eprintln!(
            "[net] synced block height={} hash={}",
            block.header.height, block.block_hash_hex
        );

        let imported_orphans = try_drain_orphans(&mut dbh)?;
        if imported_orphans > 0 {
            eprintln!("[net] drained queued orphans count={}", imported_orphans);
        }
    }

    {
        let mut dbh = db.lock().unwrap();
        let imported_orphans = try_drain_orphans(&mut dbh)?;
        if imported_orphans > 0 {
            eprintln!("[net] drained queued orphans count={}", imported_orphans);
        }
    }

    eprintln!("[net] synced height={} from {}", peer_height, addr);
    Ok(())
}

/// One-shot: connect, request a block by hash, import into db if received.
pub async fn get_block_once(db: Arc<Mutex<Db>>, addr: &str, hash_hex: &str) -> Result<()> {
    let block = fetch_block_once(addr, hash_hex).await?;

    let ancestors = {
        let dbh = db.lock().unwrap();
        fetch_missing_ancestor_chain(addr, &dbh, &block).await?
    };

    {
        let mut dbh = db.lock().unwrap();

        for ancestor in ancestors {
            if !dbh.has_block(&Hash32::from_hex(&ancestor.block_hash_hex)?)? {
                dbh.import_block(&ancestor)
                    .context("import ancestor block")?;
                eprintln!(
                    "[net] imported ancestor block height={} hash={}",
                    ancestor.header.height, ancestor.block_hash_hex
                );
            }
        }

        if is_missing_parent(&dbh, &block)? {
            let queued = queue_orphan(block.clone());
            eprintln!(
                "[net] queued fetched orphan height={} hash={} queued={}",
                block.header.height, block.block_hash_hex, queued
            );
            return Ok(());
        }

        dbh.import_block(&block).context("import_block")?;
        let imported_orphans = try_drain_orphans(&mut dbh)?;
        if imported_orphans > 0 {
            eprintln!("[net] drained queued orphans count={}", imported_orphans);
        }
    }

    Ok(())
}

/// One-shot: connect, send tx, expect Ok.
pub async fn send_tx(_db: Arc<Mutex<Db>>, addr: &str, tx: AppEventV0) -> Result<()> {
    let reply = request_once(addr, NetMessageV0::Tx { tx }).await?;

    match reply {
        NetMessageV0::Ok => Ok(()),
        NetMessageV0::Err { msg } => Err(anyhow!(msg)),
        other => Err(anyhow!("unexpected ack: {:?}", other)),
    }
}

/// Broadcast a mined block to peers with retry.
pub async fn broadcast_block(peers: &[String], block: BlockV1) {
    for p in peers {
        let mut delivered = false;

        for attempt in 1..=BROADCAST_RETRIES {
            match request_once(
                p,
                NetMessageV0::Block {
                    block: block.clone(),
                },
            )
            .await
            {
                Ok(reply) => match reply {
                    NetMessageV0::Ok => {
                        eprintln!(
                            "[net] broadcast accepted by {} height={} hash={} attempt={}",
                            p, block.header.height, block.block_hash_hex, attempt
                        );
                        delivered = true;
                        break;
                    }
                    NetMessageV0::Err { msg } => {
                        eprintln!(
                            "[net] broadcast rejected by {} attempt={} msg={}",
                            p, attempt, msg
                        );
                    }
                    other => {
                        eprintln!(
                            "[net] broadcast unexpected reply from {} attempt={} reply={:?}",
                            p, attempt, other
                        );
                    }
                },
                Err(e) => {
                    eprintln!(
                        "[net] broadcast connect/send failed to {} attempt={} err={}",
                        p, attempt, e
                    );
                }
            }

            if attempt < BROADCAST_RETRIES {
                sleep(BROADCAST_RETRY_DELAY).await;
            }
        }

        if !delivered {
            eprintln!(
                "[net] broadcast permanently failed to {} height={} hash={}",
                p, block.header.height, block.block_hash_hex
            );
        }
    }
}
