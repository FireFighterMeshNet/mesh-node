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
        Some((&mut left[idx2], &mut right[0]))
    }
}

#[cfg(feature = "arbitrary")]
mod arbitrary {
    mod imp;

    use crate::{device::MeshDevice, tests::get_two_mut};
    use arbitrary::Unstructured;
    use common::LogFutExt;
    use embassy_executor::{Executor, Spawner};
    use embassy_futures::join::join;
    use embassy_net::{
        tcp::TcpSocket, IpEndpoint, IpListenEndpoint, Runner, StackResources, StaticConfigV6,
    };
    use embedded_io_async::Write;
    use imp::{PhysicalChannel, TestDriver, WifiError};
    use parking_lot::Mutex;
    use std::{
        collections::BinaryHeap,
        sync::{
            mpsc::{self, SyncSender},
            Arc,
        },
        thread,
    };

    #[derive(Debug)]
    struct Node {
        mac: [u8; 6],
    }
    impl arbitrary::Arbitrary<'_> for Node {
        fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
            let mut mac: [u8; 6] = u.arbitrary()?;
            mac[0] &= !1; // don't make multicast address
            Ok(Self { mac })
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

    #[test]
    fn send() {
        env_logger::Builder::from_default_env()
            .is_test(true)
            .filter_level(log::LevelFilter::Trace)
            .try_init()
            .unwrap();

        #[embassy_executor::task(pool_size = 1024)]
        async fn runner_task(mut runner: Runner<'static, MeshDevice<TestDriver>>) {
            runner.run().await
        }
        #[embassy_executor::task(pool_size = 1024)]
        async fn async_inner(
            spawn: Spawner,
            mut u: arbitrary::Unstructured<'static>,
            tx: SyncSender<Result<(), WifiError>>,
        ) {
            thread::spawn(|| loop {
                thread::sleep(core::time::Duration::from_micros(1000));
                panic_on_deadlock();
            });
            let phy = Arc::new(Mutex::new(PhysicalChannel {
                in_air: BinaryHeap::new(),
                u: Unstructured::new(u.peek_bytes(u.len()).unwrap()),
                connected: Vec::new(),
            }));
            {
                // Poll the simulation to move forward time and deliver messages from physical channel.
                let phy = phy.clone();
                let driver = crate::tests::time::DRIVER
                    .inner
                    .get_or_init(Default::default)
                    .clone();
                thread::Builder::new()
                    .name("poll simulation".to_owned())
                    .spawn(move || loop {
                        thread::yield_now();
                        let now = embassy_time::Instant::now();
                        phy.lock().poll(now.as_ticks());
                        driver.poll(embassy_time::Duration::from_millis(1));
                    })
                    .unwrap();
            }
            tx.send(
                async {
                    let nodes = {
                        // at least 2 nodes
                        let mut out = std::iter::repeat_with(|| u.arbitrary())
                            .take(2)
                            .collect::<Vec<_>>();
                        // no more than 8 nodes
                        out.extend(u.arbitrary_iter::<Node>()?.take(6));
                        // remove errors
                        out.into_iter().collect::<Result<Vec<_>, _>>()?
                    };

                    let mut nodes = nodes
                        .into_iter()
                        .map(|node| {
                            let (ap_stack, ap_runner) = embassy_net::new(
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
                                u.arbitrary()?,
                            );
                            spawn.must_spawn(runner_task(ap_runner));
                            let (sta_stack, sta_runner) = embassy_net::new(
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
                                u.arbitrary()?,
                            );
                            spawn.must_spawn(runner_task(sta_runner));
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
                            Ok::<_, WifiError>((
                                node,
                                (ap_stack, ap_socket),
                                (sta_stack, sta_socket),
                            ))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let nodes_len = nodes.len();

                    let max_iters: u8 = u.int_in_range(1..=u8::MAX)?;
                    let mut iter = 0u16;
                    // Test communicate between nodes.
                    while let (Ok(idx1), Ok(idx2)) = (
                        u.int_in_range(0..=nodes_len - 1),
                        u.int_in_range(0..=nodes_len - 1),
                    ) {
                        if iter > max_iters as u16 {
                            break;
                        }
                        iter += 1;
                        if idx1 == idx2 {
                            // TODO connect to self instead of reselecting.
                            iter -= 1;
                            continue;
                        }

                        // Connect node.
                        let addr =
                            crate::consts::sta_cidr_from_mac(nodes[idx2].0.mac.into()).address();
                        let (node1, node2) = get_two_mut(&mut nodes, idx1, idx2).unwrap();

                        // TODO crate::run(sniffer, controller, ap_rx_socket, sta_tx_socket, ap_mac)
                        let (r1, r2) = join(
                            async {
                                let r = node2
                                    .1
                                     .1
                                    .accept(IpListenEndpoint {
                                        addr: None,
                                        port: crate::consts::DATA_PORT,
                                    })
                                    .inspect("accepting")
                                    .await;
                                println!(
                                    "[{}:{}:{}] accept fin, {r:?}",
                                    file!(),
                                    line!(),
                                    column!()
                                );
                                r
                            },
                            async {
                                let r = node1
                                    .1
                                     .1
                                    .connect(IpEndpoint {
                                        addr: dbg!(addr.into()),
                                        port: crate::consts::DATA_PORT,
                                    })
                                    .inspect("connecting")
                                    .await;
                                println!(
                                    "[{}:{}:{}] connect fin, {r:?}",
                                    file!(),
                                    line!(),
                                    column!(),
                                );
                                r
                            },
                        )
                        .await;
                        panic!("ah");
                        dbg!(r1.unwrap());
                        dbg!(r2.unwrap());

                        // Send some random data.
                        let res = nodes[idx1].1 .1.write_all(u.arbitrary()?).await;
                        _ = dbg!(res);
                    }

                    Ok(())
                }
                .await,
            )
            .unwrap();
        }
        fn inner(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<()> {
            let data: &'static [u8] = u.bytes(u.len()).unwrap().to_owned().leak(); // has to be static to spawn on executor
            let u = Unstructured::new(data);

            // `executor` never returns so spawn a new thread for it to run and signal completion with channel.
            let (tx, rx) = mpsc::sync_channel(0);

            // cancel whole test on any panic.
            {
                let prev = std::panic::take_hook();
                let tx = tx.clone();
                std::panic::set_hook(Box::new(move |info| {
                    prev(info);
                    let _ = tx.try_send(Err(WifiError::Panic)); // if send fails, nothing left to cancel
                }));
            }

            thread::Builder::new()
                .name("async test".to_owned())
                .spawn(|| {
                    let executor = Box::leak(Box::new(Executor::new()));
                    executor.run(move |spawn| {
                        spawn.must_spawn(async_inner(spawn, u, tx.clone()));
                    });
                })
                .unwrap();
            match rx.recv().unwrap() {
                Ok(()) => Ok(()),
                Err(WifiError::Arbitrary(e)) => Err(e),
                Err(WifiError::Panic) => {
                    panic!("async test fail");
                }
            }
        }
        arbtest::arbtest(inner)
            .seed(((0xffeeddccu32 as u64) << 32) | (u16::MAX as u64))
            .run();
        println!("done")
    }
}
