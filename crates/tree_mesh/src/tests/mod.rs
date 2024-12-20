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
    use arbitrary::Unstructured;
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
    use imp::{PhysicalChannel, TestDriver, WifiError};
    use parking_lot::Mutex;
    use petgraph::Graph;
    use rand::{distributions::uniform::SampleRange, seq::IteratorRandom, Rng};
    use std::{collections::BinaryHeap, sync::Arc, thread};

    #[derive(Debug, PartialEq, Eq)]
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

    struct SimulationEnv {
        rng: RefCell<RngUnstructured>,
        spawn: RefCell<Vec<Pin<Box<dyn Future<Output = ()>>>>>,
        nodes: RefCell<
            Vec<(
                Node,
                (Stack<'static>, TcpSocket<'static>),
                (Stack<'static>, TcpSocket<'static>),
            )>,
        >,
        graph: Graph<(), (), petgraph::Undirected, usize>,
    }
    impl SimulationEnv {
        pub fn new(rng: RngUnstructured) -> Self {
            Self {
                rng: RefCell::new(rng),
                spawn: RefCell::new(Vec::new()),
                nodes: RefCell::new(Vec::new()),
                graph: Graph::default(),
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

            let vec_dbg = VecLenDbg {
                len: self.spawn.borrow().len(),
            };
            f.debug_struct("SimulationEnv")
                .field("rng", &self.rng)
                .field("spawn", &vec_dbg)
                .field(
                    "nodes",
                    &self.nodes.borrow().iter().map(|x| &x.0).collect::<Vec<_>>(),
                )
                .field("graph", &self.graph)
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

    fn arbitrary_nodes(
        env: &mut SimulationEnv,
        phy: Arc<Mutex<PhysicalChannel>>,
    ) -> Result<(), arbitrary::Error> {
        let node_len = (2..=8).sample_single(&mut env.rng.get_mut());
        let nodes = env.rng.get_mut().with_unstructured(|u| {
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
                let (ap_stack, mut ap_runner) = embassy_net::new(
                    MeshDevice::new({
                        let driver = TestDriver::new(node.mac, phy.clone());
                        phy.lock().connected.push(driver.local_msgs.clone());
                        driver
                    }),
                    embassy_net::Config::ipv6_static(StaticConfigV6 {
                        address: tree_mesh::consts::AP_CIDR,
                        gateway: Some(tree_mesh::consts::AP_CIDR.address()),
                        dns_servers: Default::default(),
                    }),
                    Box::leak(Box::new(StackResources::<16>::new())),
                    env.rng.get_mut().arbitrary()?,
                );
                env.spawn
                    .borrow_mut()
                    .push(Box::pin(async move { ap_runner.run().await }));
                let (sta_stack, mut sta_runner) = embassy_net::new(
                    MeshDevice::new({
                        let driver = TestDriver::new(node.mac, phy.clone());
                        phy.lock().connected.push(driver.local_msgs.clone());
                        driver
                    }),
                    embassy_net::Config::ipv6_static(StaticConfigV6 {
                        address: tree_mesh::consts::sta_cidr_from_mac(node.mac.into()),
                        gateway: Some(tree_mesh::consts::AP_CIDR.address()),
                        dns_servers: Default::default(),
                    }),
                    Box::leak(Box::new(StackResources::<16>::new())),
                    env.rng.get_mut().arbitrary()?,
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
                Ok((node, (ap_stack, ap_socket), (sta_stack, sta_socket)))
            })
            .collect::<Result<Vec<_>, arbitrary::Error>>()?;
        *env.nodes.get_mut() = nodes;
        Ok(())
    }

    /// Initialize connection graph into `env`.
    fn arbitrary_connection_graph(env: &mut SimulationEnv) {
        let indices = 0..env.nodes.borrow().len();
        while env.graph.node_count() < env.nodes.borrow().len() {
            env.graph.add_node(());
        }
        // For each node.
        for i in indices.clone() {
            let other_indices = indices.clone().filter(|x| *x != i);
            // Add a random amount of edges to other nodes.
            let mut neighbors = vec![
                0;
                other_indices
                    .clone()
                    .choose(&mut env.rng.get_mut())
                    .unwrap()
            ];
            other_indices.choose_multiple_fill(&mut env.rng.get_mut(), &mut neighbors);
            // To other nodes.
            for j in neighbors {
                env.graph.add_edge(i.into(), j.into(), ());
            }
        }
    }

    async fn run_sim_test(
        rng: &mut RngUnstructured,
        sim: impl AsyncFn(&SimulationEnv) -> Result<(), WifiError>,
    ) -> arbitrary::Result<()> {
        let phy = Arc::new(Mutex::new(PhysicalChannel {
            in_air: BinaryHeap::new(),
            rng: rng.clone(),
            connected: Vec::new(),
        }));

        // Detect deadlocks.
        thread::spawn(|| loop {
            thread::sleep(core::time::Duration::from_micros(1000));
            panic_on_deadlock();
        });

        let mut env = SimulationEnv::new(rng.clone());
        arbitrary_nodes(&mut env, phy.clone())?;
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
                let no_in_flight_msgs = phy.lock().in_air.is_empty();
                let no_new_wakes = count.get() == prev_count;
                // If nothing will happen again then break.
                if no_alarms && no_in_flight_msgs && no_new_wakes {
                    break Ok(());
                }

                prev_count = count.get();

                // Poll the simulation to move forward time and deliver messages from physical channel.
                let now = embassy_time::Instant::now();
                phy.lock().poll(now.as_ticks());
                MockDriver::get().advance(embassy_time::Duration::from_millis(1));
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
                panic!("TODO");
                dbg!(r1.unwrap());
                dbg!(r2.unwrap());

                // Send some random data.
                let data: [u8; 2048] = env.rng.borrow_mut().arbitrary()?;
                let res = env.nodes.borrow_mut()[idx1].1 .1.write_all(&data).await;
                _ = dbg!(res);
            }

            Ok(())
        }

        arbtest::arbtest(|u| {
            let rng = Rc::new(RefCell::new(RngUnstructured::from(u)));
            let start = rng.borrow().len();
            let res = embassy_futures::block_on(run_sim_test(rng.clone(), sim));
            let end = rng.borrow().len();
            log::trace!("test completed using {} entropy", start - end);
            res
        })
        .size_min(256)
        // .seed(((0xffeeddccu32 as u64) << 32) | (u16::MAX as u64))
        .run();
    }
}
