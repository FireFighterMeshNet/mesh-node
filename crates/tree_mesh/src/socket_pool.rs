use caches::{Cache, DefaultEvictCallback, DefaultHashBuilder, RawLRU};
use embassy_net::{
    tcp::{ConnectError, TcpSocket},
    IpEndpoint,
};
type LRU<K, V> = RawLRU<K, V, DefaultEvictCallback, DefaultHashBuilder>;

pub struct SocketPool<const N: usize> {
    // Socket pool for the underlay network.
    // Least recently used sockets should be in the `front` and more recent in the `back`
    pub used: LRU<IpEndpoint, TcpSocket<'static>>,
    pub unused: heapless::Vec<TcpSocket<'static>, N>,
}
impl<const N: usize> SocketPool<N> {
    /// Construct a new [`SocketPool`] with arbitrary recency with the given sockets.
    pub fn new(sockets: heapless::Vec<TcpSocket<'static>, N>) -> Self {
        Self {
            used: LRU::new(N).unwrap(),
            unused: sockets,
        }
    }

    /// Get a socket connected to the given if one already exists.
    pub fn socket_mut(&mut self, endpoint: IpEndpoint) -> Option<&mut TcpSocket<'static>> {
        self.used.get_mut(&endpoint)
    }

    /// Get a socket connected to the given endpoint.
    pub async fn socket_mut_or_connect(
        &mut self,
        endpoint: IpEndpoint,
    ) -> Result<&mut TcpSocket<'static>, ConnectError> {
        // Note: `if let` won't work because borrowchecker bug.
        if self.used.get_mut(&endpoint).is_some() {
            Ok(self.used.get_mut(&endpoint).unwrap())
        }
        // If there isn't one that can be re-used, try an unused one.
        else if !self.unused.is_empty() {
            let mut socket = self.unused.pop().unwrap();
            socket.connect(endpoint).await?;
            self.used.put(endpoint, socket);
            Ok(self.used.get_mut(&endpoint).unwrap())
        }
        // Otherwise have to re-use a socket.
        else {
            let socket = self.used.get_lru_mut().unwrap().1;
            socket.connect(endpoint).await?;
            Ok(socket)
        }
    }
}
