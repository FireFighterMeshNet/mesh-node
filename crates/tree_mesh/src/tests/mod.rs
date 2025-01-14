mod arbitrary_rng;
mod time;

pub fn get_two_mut<T>(slice: &mut [T], idx1: usize, idx2: usize) -> Option<(&mut T, &mut T)> {
    if idx1 == idx2 || idx1 >= slice.len() || idx2 >= slice.len() {
        return None; // Either indices are the same or out of bounds
    }

    if idx1 < idx2 {
        let (left, right) = slice.split_at_mut(idx2);
        Some((&mut left[idx1], &mut right[0]))
    } else {
        let (left, right) = slice.split_at_mut(idx1);
        Some((&mut right[0], &mut left[idx2]))
    }
}

#[cfg(feature = "arbitrary")]
mod arbitrary {
    mod imp;

    use super::{arbitrary_rng::RngUnstructured, time::MockDriver};
    use crate::{device::MeshDevice, tests::get_two_mut};
    use arbitrary::{Arbitrary, Unstructured};
    use common::LogFutExt;
    use core::{
        cell::RefCell,
        future::Future,
        ops::AsyncFn,
        pin::{pin, Pin},
        task::Context,
    };
    use embassy_futures::join::join;
    use embassy_net::{
        tcp::TcpSocket, IpEndpoint, IpListenEndpoint, Stack, StackResources, StaticConfigV6,
    };
    use embedded_io_async::Write;
    use imp::{Message, PhysicalChannel, SharedTestDriver, TestDriver, WifiError};
    use parking_lot::Mutex;
    use petgraph::{visit::EdgeRef, Graph};
    use rand::{distributions::uniform::SampleRange, seq::IteratorRandom, Rng};
    use std::{boxed::Box, rc::Rc, thread, vec::Vec};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Node {
        mac: [u8; 6],
    }
    impl arbitrary::Arbitrary<'_> for Node {
        fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
            // Keep track of previous macs to avoid generating the same one twice.
            static PREV: Mutex<Vec<[u8; 6]>> = Mutex::new(Vec::new());
            let mut prev = PREV.lock();

            // Start at random mac.
            let mut mac: [u8; 6] = u.arbitrary()?;
            // Note: Don't use entropy in the loop.
            let mac = loop {
                // Don't make multicast/broadcast address
                mac[0] &= !1;
                // Don't make all zero
                mac[1] |= 1;

                // Make sure the mac is unique. If it isn't, increment and check again.
                if prev.contains(&mac) {
                    let mut bytes = [0; 8];
                    bytes[0..6].copy_from_slice(&mac);
                    let mut x = u64::from_le_bytes(bytes);
                    // prime number > 2 to avoid getting stuck in loop where above increases/decreases by power of 2 then this adds the amount back.
                    x = x.wrapping_add(3);
                    mac = x.to_le_bytes()[0..6].try_into().unwrap();
                    continue;
                } else {
                    break mac;
                }
            };
            prev.push(mac);
            Ok(Self { mac })
        }
        fn size_hint(depth: usize) -> (usize, Option<usize>) {
            <[u8; 6] as Arbitrary>::size_hint(depth)
        }
    }

    /// Holding a mutable borrow to any `RefCells` in this structure, other than `nodes`, across an await point in the simulation will panic.
    /// This should be fine for the simulation, since the only thing it should need to await is the `TcpSockets` for IO operations.
    struct SimulationEnv {
        rng: Rc<RefCell<RngUnstructured>>,
        spawn: RefCell<Vec<Pin<Box<dyn Future<Output = ()>>>>>,
        nodes: RefCell<
            Vec<(
                Node,
                (Stack<'static>, TcpSocket<'static>),
                (Stack<'static>, TcpSocket<'static>),
            )>,
        >,
        // (ap, sta)
        drivers: Vec<(SharedTestDriver, SharedTestDriver)>,
        // Graph connects each interface. Though it is `petgraph::Directed` an edge is added in both directions for all edges.
        // This way the edge_weights can be a delaying physical channel with a clear target and source.
        graph: RefCell<Graph<(), PhysicalChannel, petgraph::Directed, usize>>,
        node_len: usize,
    }
    impl SimulationEnv {
        pub fn new(rng: Rc<RefCell<RngUnstructured>>) -> Self {
            Self {
                rng,
                spawn: RefCell::new(Vec::new()),
                nodes: RefCell::new(Vec::new()),
                drivers: Vec::new(),
                graph: RefCell::new(Graph::default()),
                node_len: 0,
            }
        }
    }
    impl core::fmt::Debug for SimulationEnv {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            struct VecLenDbg {
                len: usize,
            }
            impl core::fmt::Debug for VecLenDbg {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.debug_struct("Vec")
                        .field("len", &self.len)
                        .finish_non_exhaustive()
                }
            }
            struct RngDbg {
                len: usize,
            }
            impl core::fmt::Debug for RngDbg {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.debug_struct("RngDbg").field("len", &self.len).finish()
                }
            }

            let vec_dbg = VecLenDbg {
                len: self.spawn.borrow().len(),
            };
            f.debug_struct("SimulationEnv")
                .field(
                    "rng",
                    &self.rng.try_borrow().map(|x| RngDbg { len: x.len() }),
                )
                .field("spawn", &vec_dbg)
                .field(
                    "nodes",
                    &self
                        .nodes
                        .try_borrow()
                        .map(|x| x.iter().map(|x| x.0.clone()).collect::<Vec<_>>()),
                )
                .field("drivers", &self.drivers)
                .field("graph", &self.graph)
                .field("node_len", &self.node_len)
                .finish()
        }
    }

    /// Check for deadlock. If deadlock log and panic.
    fn panic_on_deadlock() {
        let deadlocks = parking_lot::deadlock::check_deadlock()
            .into_iter()
            .map(|x| {
                x.into_iter()
                    .for_each(|x| eprintln!("{:#?}", x.backtrace()))
            })
            .count();
        if deadlocks != 0 {
            panic!("deadlock occurred")
        }
    }

    /// Setup test.
    fn setup() {
        let _ = env_logger::Builder::from_default_env()
            .is_test(true)
            .filter_level(log::LevelFilter::Trace)
            .try_init();
        MockDriver::get().reset();
    }

    fn arbitrary_nodes(env: &mut SimulationEnv) -> Result<(), arbitrary::Error> {
        let node_len = (2..=8).sample_single(&mut *env.rng.borrow_mut());
        env.node_len = node_len;
        let nodes = env.rng.borrow_mut().with_unstructured(|u| {
            core::iter::repeat_with(|| u.arbitrary::<Node>())
                .take(node_len)
                .collect::<Result<Vec<_>, _>>()
        })?;
        // All nodes should be different.
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    assert_ne!(nodes[i].mac, nodes[j].mac)
                }
            }
        }

        let nodes = nodes
            .into_iter()
            .map(|node| {
                let (ap_driver, sta_driver) = (
                    MeshDevice::new({
                        SharedTestDriver(Rc::new(RefCell::new(TestDriver::new(node.mac))))
                    }),
                    MeshDevice::new({
                        SharedTestDriver(Rc::new(RefCell::new(TestDriver::new(node.mac))))
                    }),
                );
                env.drivers.push(
                    (
                        ap_driver.clone().into_inner(),
                        sta_driver.clone().into_inner(),
                    )
                        .clone(),
                );
                let (ap_stack, mut ap_runner) = embassy_net::new(
                    ap_driver,
                    embassy_net::Config::ipv6_static(StaticConfigV6 {
                        address: tree_mesh::consts::AP_CIDR,
                        gateway: Some(tree_mesh::consts::AP_CIDR.address()),
                        dns_servers: Default::default(),
                    }),
                    Box::leak(Box::new(StackResources::<16>::new())),
                    env.rng.borrow_mut().gen(),
                );
                env.spawn
                    .borrow_mut()
                    .push(Box::pin(async move { ap_runner.run().await }));
                let (sta_stack, mut sta_runner) = embassy_net::new(
                    sta_driver,
                    embassy_net::Config::ipv6_static(StaticConfigV6 {
                        address: tree_mesh::consts::sta_cidr_from_mac(node.mac.into()),
                        gateway: Some(tree_mesh::consts::AP_CIDR.address()),
                        dns_servers: Default::default(),
                    }),
                    Box::leak(Box::new(StackResources::<16>::new())),
                    env.rng.borrow_mut().gen(),
                );
                env.spawn
                    .borrow_mut()
                    .push(Box::pin(async move { sta_runner.run().await }));
                let ap_socket = TcpSocket::new(
                    ap_stack,
                    Box::leak(Box::new([0; { 2usize.pow(10) }])),
                    Box::leak(Box::new([0; { 2usize.pow(10) }])),
                );
                let sta_socket = TcpSocket::new(
                    sta_stack,
                    Box::leak(Box::new([0; { 2usize.pow(10) }])),
                    Box::leak(Box::new([0; { 2usize.pow(10) }])),
                );
                (node, (ap_stack, ap_socket), (sta_stack, sta_socket))
            })
            .collect::<Vec<_>>();
        *env.nodes.get_mut() = nodes;
        Ok(())
    }

    /// Initialize connection graph into `env`.
    fn arbitrary_connection_graph(env: &mut SimulationEnv) {
        let indices = 0..env.nodes.borrow().len();
        while env.graph.borrow().node_count() < env.nodes.borrow().len() {
            env.graph.borrow_mut().add_node(());
        }

        // Connect all nodes to and from 0.
        // TODO remove this.
        for i in 1..indices.end {
            env.graph
                .borrow_mut()
                .add_edge(0.into(), i.into(), PhysicalChannel::new());
            env.graph
                .borrow_mut()
                .add_edge(i.into(), 0.into(), PhysicalChannel::new());
        }

        // For each node.
        for i in indices.clone() {
            let other_indices = (i + 1)..env.nodes.borrow().len();
            if other_indices.clone().count() == 0 {
                continue;
            }

            // Add a random amount of edges to other nodes.
            let other_len = (0..other_indices.clone().count())
                .choose(&mut *env.rng.borrow_mut())
                .unwrap();
            let mut neighbors = vec![0; other_len];
            other_indices.choose_multiple_fill(&mut *env.rng.borrow_mut(), &mut neighbors);
            for j in neighbors {
                // To other nodes.
                if !env.graph.borrow().contains_edge(i.into(), j.into()) {
                    env.graph
                        .borrow_mut()
                        .add_edge(i.into(), j.into(), PhysicalChannel::new());
                }
                // Make sure to add the reverse direction if it is missing.
                if !env.graph.borrow().contains_edge(j.into(), i.into()) {
                    env.graph
                        .borrow_mut()
                        .add_edge(j.into(), i.into(), PhysicalChannel::new());
                }
            }
        }
    }

    async fn run_sim_test(
        rng: Rc<RefCell<RngUnstructured>>,
        sim: impl AsyncFn(&SimulationEnv) -> Result<(), WifiError>,
    ) -> arbitrary::Result<()> {
        // Detect deadlocks.
        thread::spawn(|| loop {
            thread::sleep(core::time::Duration::from_micros(1000));
            panic_on_deadlock();
        });

        let mut env = SimulationEnv::new(rng);
        arbitrary_nodes(&mut env)?;
        arbitrary_connection_graph(&mut env);

        let (waker, count) = futures_test::task::new_count_waker();
        let mut prev_count = count.get();
        let res = {
            let mut fut = pin!(sim(&env));
            loop {
                // Poll spawned tasks.
                if count.get() > prev_count || count.get() < env.spawn.borrow().len() {
                    for fut in env.spawn.borrow_mut().iter_mut() {
                        assert!(fut
                            .as_mut()
                            .poll(&mut Context::from_waker(&waker))
                            .is_pending());
                    }
                }

                // Poll if woke.
                if count.get() > prev_count || count.get() == 0 {
                    // Poll actual test
                    match fut.as_mut().poll(&mut Context::from_waker(&waker)) {
                        core::task::Poll::Ready(x) => break x,
                        core::task::Poll::Pending => (),
                    }
                }

                let no_alarms = !MockDriver::get().alarm_pending();
                let no_in_flight_msgs = env
                    .graph
                    .borrow()
                    .edge_weights()
                    .all(|x| x.in_air.is_empty());
                let no_new_wakes = count.get() == prev_count;
                // If nothing will happen again then break.
                if no_alarms && no_in_flight_msgs && no_new_wakes {
                    break Ok(());
                }

                prev_count = count.get();

                // Poll the simulation to move forward time and deliver messages from physical channel.
                let now = embassy_time::Instant::now();
                for i in 0..env.node_len {
                    let data = match (
                        env.drivers[i]
                            .0
                             .0
                            .borrow_mut()
                            .tx_queue
                            .borrow_mut()
                            .pop_front(),
                        env.drivers[i]
                            .1
                             .0
                            .borrow_mut()
                            .tx_queue
                            .borrow_mut()
                            .pop_front(),
                    ) {
                        (_, Some(x)) => x,
                        (Some(x), _) => x,
                        _ => continue,
                    };
                    let iter = env
                        .graph
                        .borrow()
                        .edges(i.into())
                        .map(|x| x.id())
                        .collect::<Vec<_>>();
                    for edge_id in iter {
                        let mut graph = env.graph.borrow_mut();
                        let weight = graph.edge_weight_mut(edge_id).unwrap();
                        weight.tx(Message {
                            delivery_time: now.as_ticks()
                                + env.rng.borrow_mut().arbitrary::<u16>()? as u64,
                            data: data.clone(),
                        });
                    }
                }
                let iter = env
                    .graph
                    .borrow_mut()
                    .edge_references()
                    .map(|x| (x.id(), x.target()))
                    .collect::<Vec<_>>();
                for (edge_id, to) in iter {
                    let mut graph = env.graph.borrow_mut();
                    let phy = graph.edge_weight_mut(edge_id).unwrap();
                    phy.poll(now.as_ticks(), &env.drivers[to.index()]);
                }
                MockDriver::get().advance(embassy_time::Duration::from_millis(1));
                println!("{:0>2X?}", env);
            }
        };
        match res {
            Ok(()) => Ok(()),
            Err(WifiError::Arbitrary(e)) => Err(e),
        }
    }

    #[test]
    #[serial_test::serial]
    fn deterministic_simulation_test() {
        setup();

        async fn sim(env: &SimulationEnv) -> Result<(), WifiError> {
            let max_iters: u8 = env.rng.borrow_mut().gen_range(1..=u8::MAX);
            let mut iter = 0u16;
            // Test communicate between nodes.
            loop {
                let [idx1, idx2] = {
                    let mut out = [0, 0];
                    (0..env.nodes.borrow().len())
                        .choose_multiple_fill(&mut *env.rng.borrow_mut(), &mut out);
                    out
                };
                // TODO remove this line
                let idx1 = 0;

                if iter > max_iters as u16 {
                    break;
                }
                iter += 1;

                // Connect node.
                let addr = crate::consts::sta_cidr_from_mac(env.nodes.borrow()[idx2].0.mac.into())
                    .address();
                let mut nodes = env.nodes.borrow_mut();
                let (node1, node2) = get_two_mut(&mut nodes, idx1, idx2).unwrap();

                // TODO crate::run(sniffer, controller, ap_rx_socket, sta_tx_socket, ap_mac)
                let (r1, r2) = join(
                    async {
                        let r = node2
                            .2
                             .1
                            .accept(IpListenEndpoint {
                                addr: None,
                                port: crate::consts::DATA_PORT,
                            })
                            .inspect("accepting")
                            .await;
                        println!("[{}:{}:{}] accept fin, {r:?}", file!(), line!(), column!());
                        r
                    },
                    async {
                        let r = node1
                            .2
                             .1
                            .connect(IpEndpoint {
                                addr: dbg!(addr.into()),
                                port: crate::consts::DATA_PORT,
                            })
                            .inspect("connecting")
                            .await;
                        println!("[{}:{}:{}] connect fin, {r:?}", file!(), line!(), column!(),);
                        r
                    },
                )
                .await;
                dbg!(r1.unwrap());
                dbg!(r2.unwrap());

                // Send some random data.
                let data: [u8; 2048] = env.rng.borrow_mut().arbitrary()?;
                let res = nodes[idx1].2 .1.write_all(&data).await;
                _ = dbg!(res);
            }

            Ok(())
        }

        arbtest::arbtest(|u| {
            let rng = Rc::new(RefCell::new(RngUnstructured::from(u)));
            let start = rng.borrow().len();
            let res = embassy_futures::block_on(run_sim_test(rng.clone(), sim));
            let end = rng.borrow().len();
            log::trace!("test completed using {}/{} entropy", start - end, start);
            res
        })
        .size_min(256)
        .seed(((0xffeeddccu32 as u64) << 32) | (u16::MAX as u64))
        .run();
    }
}
