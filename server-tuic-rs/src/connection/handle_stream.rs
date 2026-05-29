use bytes::Bytes;
use quinn::{RecvStream, SendStream};
use tokio::time;
use tracing::debug;
use tuic::quinn::Task;

use super::Connection;
use crate::{error::Error, utils::UdpRelayMode};

impl Connection {
	pub async fn handle_uni_stream(self, recv: RecvStream) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] incoming unidirectional stream",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		let pre_process = async {
			let task = time::timeout(self.ctx.cfg.task_negotiation_timeout, self.model.accept_uni_stream(recv))
				.await
				.map_err(|_| Error::TaskNegotiationTimeout)??;

			if let Task::Authenticate(auth) = &task {
				self.authenticate(auth).await?;
			}

			// Fast path: if already authenticated, skip the select
			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			let same_pkt_src =
				matches!(task, Task::Packet(_)) && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Native));
			if same_pkt_src {
				return Err(Error::UnexpectedPacketSource);
			}

			Ok(task)
		};

		match pre_process.await {
			Ok(Task::Authenticate(auth)) => self.handle_authenticate(auth).await,
			Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Quic).await,
			Ok(Task::Dissociate(assoc_id)) => self.handle_dissociate(assoc_id).await,
			Ok(_) => unreachable!(), // already filtered in `tuic_quinn`
			Err(err) => {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] handling incoming unidirectional stream error: {err}",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
				self.close();
			}
		}
	}

	pub async fn handle_bi_stream(self, (send, recv): (SendStream, RecvStream)) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] incoming bidirectional stream",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		let pre_process = async {
			let task = time::timeout(self.ctx.cfg.task_negotiation_timeout, self.model.accept_bi_stream(send, recv))
				.await
				.map_err(|_| Error::TaskNegotiationTimeout)??;

			// Fast path: if already authenticated, skip the select
			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			Ok(task)
		};

		match pre_process.await {
			Ok(Task::Connect(conn)) => self.handle_connect(conn).await,
			Ok(_) => unreachable!(), // already filtered in `tuic_quinn`
			Err(err) => {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] handling incoming bidirectional stream error: {err}",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
				self.close();
			}
		}
	}

	pub async fn handle_datagram(self, dg: Bytes) {
		debug!(
			"[{id:#010x}] [{addr}] [{user}] incoming datagram",
			id = self.id(),
			addr = self.inner.remote_address(),
			user = self.auth,
		);

		let pre_process = async {
			let task = self.model.accept_datagram(dg)?;

			// Fast path: if already authenticated, skip the select
			if !self.auth.is_authenticated() {
				tokio::select! {
					() = self.auth.wait() => {}
					err = self.inner.closed() => return Err(Error::from(err)),
				};
			}

			let same_pkt_src =
				matches!(task, Task::Packet(_)) && matches!(**self.udp_relay_mode.load(), Some(UdpRelayMode::Quic));
			if same_pkt_src {
				return Err(Error::UnexpectedPacketSource);
			}

			Ok(task)
		};

		match pre_process.await {
			Ok(Task::Packet(pkt)) => self.handle_packet(pkt, UdpRelayMode::Native).await,
			Ok(Task::Heartbeat) => self.handle_heartbeat().await,
			Ok(_) => unreachable!(),
			Err(err) => {
				debug!(
					"[{id:#010x}] [{addr}] [{user}] handling incoming datagram error: {err}",
					id = self.id(),
					addr = self.inner.remote_address(),
					user = self.auth,
				);
				self.close();
			}
		}
	}
}
