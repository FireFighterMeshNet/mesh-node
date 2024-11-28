#[derive(Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
struct Node {
    mac: [u8; 6],
}

struct TestTimeDriver;
impl embassy_time_driver::Driver for TestTimeDriver {
    fn now(&self) -> u64 {
        0
    }

    unsafe fn allocate_alarm(&self) -> Option<embassy_time_driver::AlarmHandle> {
        None
    }

    fn set_alarm_callback(
        &self,
        alarm: embassy_time_driver::AlarmHandle,
        callback: fn(*mut ()),
        ctx: *mut (),
    ) {
        todo!()
    }

    fn set_alarm(&self, alarm: embassy_time_driver::AlarmHandle, timestamp: u64) -> bool {
        todo!()
    }
}
embassy_time_driver::time_driver_impl! {static DRIVER: TestTimeDriver = TestTimeDriver}

#[cfg(feature = "arbitrary")]
mod arbitrary_test {
    use crate::{device::MeshDevice, imp::TestDriver, tests::Node};
    use arbitrary::Unstructured;
    use embassy_executor::{Executor, Spawner};
    use embassy_net::{tcp::TcpSocket, Config, Runner, Stack, StackResources, StaticConfigV6};

    #[test]
    fn send() {
        #[embassy_executor::task(pool_size = 256)]
        async fn runner_task(mut runner: Runner<'static, MeshDevice<TestDriver>>) {
            runner.run().await
        }
        #[embassy_executor::task(pool_size = 256)]
        async fn async_inner(
            spawn: Spawner,
            u: &'static mut arbitrary::Unstructured<'static>,
            tx: std::sync::mpsc::SyncSender<arbitrary::Result<()>>,
        ) {
            tx.send(
                async {
                    let nodes = u
                        .arbitrary_iter::<Node>()?
                        .map(Result::unwrap)
                        .take(8)
                        .collect::<Vec<_>>();
                    dbg!(nodes.len());
                    let nodes = nodes
                        .into_iter()
                        .map(|node| {
                            let (ap_stack, ap_runner) = embassy_net::new(
                                MeshDevice::new(TestDriver { mac: node.mac }),
                                embassy_net::Config::ipv6_static(StaticConfigV6 {
                                    address: tree_mesh::consts::AP_CIDR,
                                    gateway: Some(tree_mesh::consts::AP_CIDR.address()),
                                    dns_servers: Default::default(),
                                }),
                                Box::leak(Box::new(StackResources::<16>::new())),
                                u.arbitrary().unwrap(),
                            );
                            spawn.must_spawn(runner_task(ap_runner));
                            let (sta_stack, sta_runner) = embassy_net::new(
                                MeshDevice::new(TestDriver { mac: node.mac }),
                                embassy_net::Config::ipv6_static(StaticConfigV6 {
                                    address: tree_mesh::consts::sta_cidr_from_mac(node.mac.into()),
                                    gateway: Some(tree_mesh::consts::AP_CIDR.address()),
                                    dns_servers: Default::default(),
                                }),
                                Box::leak(Box::new(StackResources::<16>::new())),
                                u.arbitrary().unwrap(),
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
                            (node, (ap_stack, ap_socket), (sta_stack, sta_socket))
                        })
                        .collect::<Vec<_>>();
                    let nodes_len = nodes.len();
                    if nodes_len <= 1 {
                        // TODO test communicate with own node.
                        return dbg!(Ok(()));
                    }

                    let max_iters: u8 = u.arbitrary()?;
                    let mut iter = 0u16;
                    // Test communicate between nodes.
                    while let (Ok(idx1), Ok(idx2)) = (
                        u.int_in_range(0..=nodes_len - 1),
                        u.int_in_range(0..=nodes_len - 1),
                    ) {
                        iter += 1;
                        if iter > max_iters as u16 {
                            break;
                        }
                        // let (idx1, idx2) = (idx1.min(idx2), idx1.max(idx2)); // [a,b,c,d,..]
                        // dbg!(idx1, idx2);
                        // let (_, nodes) = nodes.split_at(idx1); // [b,c,d,..]
                        // let (node1, nodes) = nodes.split_first().unwrap(); // (b, [c,d,..])
                        // let (_, nodes) = nodes.split_at(idx2 - idx1 - 1); // (c,d,..)
                        // let (node2, _) = nodes.split_first().unwrap(); // [d,..]
                    }

                    Ok(())
                }
                .await,
            )
            .unwrap();
        }
        fn inner(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<()> {
            let data: &'static [u8] = u.bytes(u.len()).unwrap().to_owned().leak();
            let u = Box::leak(Box::new(Unstructured::new(data))); // has to be static to spawn

            // `executor` never returns so spawn a new thread for it to run and signal completion with channel.
            let (tx, rx) = std::sync::mpsc::sync_channel(0);
            std::thread::spawn(|| {
                let executor = Box::leak(Box::new(Executor::new()));
                executor.run(move |spawn| {
                    spawn.must_spawn(async_inner(spawn, u, tx));
                });
            });
            rx.recv().unwrap()
        }
        arbtest::arbtest(inner).run();
    }
}
