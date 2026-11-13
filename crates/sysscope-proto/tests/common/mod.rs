//! Shared test data: one hand-written example of every message type and
//! proptest strategies that generate arbitrary valid messages.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(dead_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use sysscope_proto::*;

pub fn key(tgid: u32, start: u64) -> ProcKey {
    ProcKey {
        tgid,
        start_ticks: start,
    }
}

pub fn sample_event() -> Event {
    Event {
        id: 18812,
        ts_ns: 5_000_000_000,
        proc: key(4312, 120034),
        tid: 4312,
        uid: 1000,
        kind: EventKind::Open {
            path: BStr::new(b"/home/u/.ssh/id_ed25519\x1b[2J\xff".to_vec()),
            dev: 66306,
            ino: 1234567,
            read: true,
            write: false,
            create: false,
            trunc: false,
            path_trunc: false,
        },
    }
}

pub fn sample_finding() -> Finding {
    Finding {
        id: 7,
        rule: "R001".into(),
        title: "Credential file read".into(),
        subject: "ssh_keys".into(),
        attack: Some("T1552".into()),
        proc: key(4312, 120034),
        exe: BStr::from("/tmp/x"),
        ts_ns: 5_000_000_000,
        weight: 0.6,
        confidence: 0.9,
        summary: "opened /home/u/.ssh/id_ed25519 for reading".into(),
        why: vec!["this file is a private SSH key".into()],
        benign: vec!["you ran a backup or key-management tool yourself".into()],
        evidence: vec![18812],
        evidence_events: vec![sample_event()],
    }
}

pub fn sample_row() -> ProcRow {
    ProcRow {
        key: key(4312, 120034),
        parent: Some(key(4100, 110000)),
        exe: BStr::from("/tmp/x"),
        comm: BStr::from("x"),
        uid: 1000,
        kthread: false,
        cpu_pct: 12.5,
        rss: 4_194_304,
        threads: 1,
        io_r: 4096,
        io_w: 0,
        n_open: 3,
        n_conn: 0,
        n_exec: 1,
        n_child: 0,
        n_sys: 120,
        score: 72,
        tree_score: 72,
        top_rule: Some("R001".into()),
        exited_ts: None,
        followed: false,
        ev_dropped: 0,
    }
}

pub fn sample_report() -> GhReport {
    GhReport {
        run_id: "20261113-0001".into(),
        sample: BStr::from("fake_malware.py"),
        args: vec![BStr::from("--demo")],
        timeout_s: 60,
        started_ts: 1_000,
        ended_ts: 2_000,
        exit_code: Some(0),
        timed_out: false,
        decoys: vec![DecoyStatus {
            path: BStr::from("/home/victim/Documents/a.docx"),
            dev: 50,
            ino: 9,
            states: vec![DecoyState::Modified, DecoyState::Renamed],
            new_path: Some(BStr::from("/home/victim/Documents/a.docx.locked")),
            size_before: 2048,
            size_after: Some(2048),
            entropy_before: 4.125,
            entropy_after: Some(7.875),
        }],
        created: vec![CreatedFile {
            path: BStr::from("/home/victim/README_RESTORE.txt"),
            size: 64,
            entropy: 4.5,
            preview: Some(BStr::from("your files are locked (demo)\n")),
        }],
        timeline: vec![sample_event()],
        connections: vec![ConnStat {
            family: Family::Inet,
            addr: "203.0.113.10".into(),
            port: 443,
            sock: SockType::Stream,
            count: 1,
            last_ts: 1_500,
        }],
        children: vec![key(2, 3)],
        findings: vec![sample_finding()],
        loss: Loss::default(),
        limitation:
            "Glasshouse is a behaviour-demonstration sandbox, not a malware containment system."
                .into(),
    }
}

/// One example per message type, named as the golden fixture file.
pub fn client_samples() -> Vec<(&'static str, ClientMsg)> {
    vec![
        (
            "Hello",
            ClientMsg::Hello {
                proto: 1,
                client: ClientKind::Gui,
                version: "0.0.1".into(),
            },
        ),
        (
            "Subscribe",
            ClientMsg::Subscribe {
                snapshots: true,
                alerts: true,
                events: EventSub::Proc {
                    proc: key(4312, 120034),
                },
            },
        ),
        (
            "Follow",
            ClientMsg::Follow {
                root: key(4100, 110000),
            },
        ),
        ("Unfollow", ClientMsg::Unfollow {}),
        (
            "GetDetail",
            ClientMsg::GetDetail {
                proc: key(4312, 120034),
                maps: true,
            },
        ),
        (
            "GhUploadBegin",
            ClientMsg::GhUploadBegin {
                name: BStr::from("sample.sh"),
                size: 1234,
            },
        ),
        (
            "GhUploadChunk",
            ClientMsg::GhUploadChunk {
                seq: 0,
                b64: "aGVsbG8=".into(),
            },
        ),
        (
            "GhRun",
            ClientMsg::GhRun {
                args: vec![BStr::from("-v")],
                timeout_s: 60,
            },
        ),
        ("GhCancel", ClientMsg::GhCancel {}),
        (
            "Act",
            ClientMsg::Act {
                proc: key(4312, 120034),
                action: ActAction::Pause,
                nonce: "n1".into(),
            },
        ),
        ("Ping", ClientMsg::Ping { n: 42 }),
    ]
}

pub fn daemon_samples() -> Vec<(&'static str, DaemonMsg)> {
    vec![
        (
            "Welcome",
            DaemonMsg::Welcome {
                proto: 1,
                daemon_version: "0.0.1".into(),
                kernel: "6.19.14+kali-amd64".into(),
                boot_to_wall_ns: 1_763_000_000_000_000_000,
                features: vec!["listen".into(), "syscalls".into()],
                act_enabled: false,
            },
        ),
        (
            "Snapshot",
            DaemonMsg::Snapshot {
                seq: 3,
                ts_ns: 5_500_000_000,
                mode: Mode::Follow {
                    follow: key(4100, 110000),
                },
                procs: vec![sample_row()],
                loss: Loss {
                    ringbuf: 0,
                    budget: 12,
                    scratch: 0,
                    decode: 0,
                    since_ts_ns: 1_000,
                },
            },
        ),
        (
            "Events",
            DaemonMsg::Events {
                events: vec![sample_event()],
                client_dropped: 0,
            },
        ),
        (
            "Alert",
            DaemonMsg::Alert {
                finding: sample_finding(),
            },
        ),
        (
            "Detail",
            DaemonMsg::Detail {
                proc: key(4312, 120034),
                series: Series {
                    t: vec![1, 2],
                    cpu: vec![0.5, 1.25],
                    rss: vec![100, 200],
                },
                recent: vec![sample_event()],
                files: vec![FileStat {
                    path: BStr::from("/etc/passwd"),
                    dev: 66306,
                    ino: 12,
                    opens: 2,
                    read: true,
                    write: false,
                    rbytes: 0,
                    wbytes: 0,
                    last_ts: 9,
                }],
                conns: vec![ConnStat {
                    family: Family::Inet6,
                    addr: "::1".into(),
                    port: 8080,
                    sock: SockType::Stream,
                    count: 3,
                    last_ts: 10,
                }],
                syscalls: vec![SysStat {
                    nr: 0,
                    name: "read".into(),
                    count: 10,
                    lat_count: 0,
                    lat_total_ns: 0,
                    lat_max_ns: 0,
                }],
                children: vec![key(4313, 120040)],
                maps: Some(vec![MapRow {
                    start: 0x400000,
                    end: 0x401000,
                    perms: "r-xp".into(),
                    offset: 0,
                    dev: "08:02".into(),
                    inode: 12,
                    path: BStr::from("/tmp/x"),
                }]),
                findings: vec![sample_finding()],
            },
        ),
        (
            "GhStatus",
            DaemonMsg::GhStatus {
                state: GhState::Running,
                run_id: "20261113-0001".into(),
                message: "sample started".into(),
            },
        ),
        (
            "GhReport",
            DaemonMsg::GhReport {
                report: sample_report(),
            },
        ),
        (
            "ActResult",
            DaemonMsg::ActResult {
                ok: false,
                message: "act mode is not enabled".into(),
            },
        ),
        (
            "Error",
            DaemonMsg::Error {
                code: "unknown_type".into(),
                message: "unknown message type \"Nope\"".into(),
            },
        ),
        ("Pong", DaemonMsg::Pong { n: 42 }),
    ]
}

// ---------------------------------------------------------------- strategies

pub fn arb_bstr() -> impl Strategy<Value = BStr> {
    vec(any::<u8>(), 0..48).prop_map(BStr)
}

/// Finite floats that survive a decimal round trip exactly (multiples of 1/8).
pub fn arb_f32() -> impl Strategy<Value = f32> {
    (-1_000_000i32..1_000_000).prop_map(|x| x as f32 / 8.0)
}

pub fn arb_key() -> impl Strategy<Value = ProcKey> {
    (any::<u32>(), any::<u64>()).prop_map(|(tgid, start_ticks)| ProcKey { tgid, start_ticks })
}

pub fn arb_family() -> impl Strategy<Value = Family> {
    prop_oneof![
        Just(Family::Inet),
        Just(Family::Inet6),
        Just(Family::Unix),
        Just(Family::Other)
    ]
}

pub fn arb_sock() -> impl Strategy<Value = SockType> {
    prop_oneof![
        Just(SockType::Stream),
        Just(SockType::Dgram),
        Just(SockType::Other)
    ]
}

pub fn arb_kind() -> impl Strategy<Value = EventKind> {
    prop_oneof![
        (
            arb_bstr(),
            arb_bstr(),
            any::<bool>(),
            any::<bool>(),
            any::<u64>(),
            any::<u64>()
        )
            .prop_map(
                |(exe, argv, argv_trunc, fileless, dev, ino)| EventKind::Exec {
                    exe,
                    argv,
                    argv_trunc,
                    fileless,
                    dev,
                    ino
                }
            ),
        arb_key().prop_map(|child| EventKind::Fork { child }),
        Just(EventKind::Exit {}),
        (arb_bstr(), any::<u64>(), any::<u64>(), any::<[bool; 5]>()).prop_map(
            |(path, dev, ino, f)| EventKind::Open {
                path,
                dev,
                ino,
                read: f[0],
                write: f[1],
                create: f[2],
                trunc: f[3],
                path_trunc: f[4]
            }
        ),
        (
            arb_bstr(),
            arb_bstr(),
            any::<u64>(),
            any::<u64>(),
            any::<bool>()
        )
            .prop_map(|(old, new, dev, ino, approx)| EventKind::Rename {
                old,
                new,
                dev,
                ino,
                approx
            }),
        (arb_bstr(), any::<u64>(), any::<u64>(), any::<bool>()).prop_map(
            |(path, dev, ino, approx)| EventKind::Unlink {
                path,
                dev,
                ino,
                approx
            }
        ),
        (arb_family(), ".{0,40}", any::<u16>(), arb_sock()).prop_map(
            |(family, addr, port, sock)| EventKind::Connect {
                family,
                addr,
                port,
                sock
            }
        ),
        (".{0,40}", any::<u16>()).prop_map(|(addr, port)| EventKind::Listen { addr, port }),
    ]
}

pub fn arb_event() -> impl Strategy<Value = Event> {
    (
        any::<u64>(),
        any::<u64>(),
        arb_key(),
        any::<u32>(),
        any::<u32>(),
        arb_kind(),
    )
        .prop_map(|(id, ts_ns, proc, tid, uid, kind)| Event {
            id,
            ts_ns,
            proc,
            tid,
            uid,
            kind,
        })
}

pub fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        (
            any::<u64>(),
            ".{0,8}",
            ".{0,20}",
            option::of(".{0,8}"),
            arb_key(),
            arb_bstr(),
            any::<u64>(),
        ),
        (
            arb_f32(),
            arb_f32(),
            ".{0,30}",
            vec(".{0,20}", 0..3),
            vec(".{0,20}", 0..3),
            vec(any::<u64>(), 0..5),
            vec(arb_event(), 0..3),
        ),
    )
        .prop_map(
            |(
                (id, rule, title, attack, proc, exe, ts_ns),
                (weight, confidence, summary, why, benign, evidence, evidence_events),
            )| Finding {
                id,
                rule,
                subject: title.clone(),
                title,
                attack,
                proc,
                exe,
                ts_ns,
                weight,
                confidence,
                summary,
                why,
                benign,
                evidence,
                evidence_events,
            },
        )
}

pub fn arb_row() -> impl Strategy<Value = ProcRow> {
    (
        (
            arb_key(),
            option::of(arb_key()),
            arb_bstr(),
            arb_bstr(),
            any::<u32>(),
            any::<bool>(),
            arb_f32(),
            any::<u64>(),
        ),
        (
            any::<u32>(),
            any::<[u64; 8]>(),
            any::<u8>(),
            any::<u8>(),
            option::of(".{0,8}"),
            option::of(any::<u64>()),
            any::<bool>(),
            any::<u64>(),
        ),
    )
        .prop_map(
            |(
                (key, parent, exe, comm, uid, kthread, cpu_pct, rss),
                (threads, n, score, tree_score, top_rule, exited_ts, followed, ev_dropped),
            )| ProcRow {
                key,
                parent,
                exe,
                comm,
                uid,
                kthread,
                cpu_pct,
                rss,
                threads,
                io_r: n[0],
                io_w: n[1],
                n_open: n[2],
                n_conn: n[3],
                n_exec: n[4],
                n_child: n[5],
                n_sys: n[6],
                score,
                tree_score,
                top_rule,
                exited_ts,
                followed,
                ev_dropped,
            },
        )
}

pub fn arb_loss() -> impl Strategy<Value = Loss> {
    any::<[u64; 5]>().prop_map(|a| Loss {
        ringbuf: a[0],
        budget: a[1],
        scratch: a[2],
        decode: a[4],
        since_ts_ns: a[3],
    })
}

pub fn arb_client() -> impl Strategy<Value = ClientMsg> {
    let sub = prop_oneof![
        Just(EventSub::Simple(EventSubMode::None)),
        Just(EventSub::Simple(EventSubMode::All)),
        arb_key().prop_map(|proc| EventSub::Proc { proc }),
    ];
    let action = prop_oneof![
        Just(ActAction::Pause),
        Just(ActAction::Resume),
        Just(ActAction::Kill)
    ];
    let kind = prop_oneof![Just(ClientKind::Gui), Just(ClientKind::Cli)];
    prop_oneof![
        (any::<u32>(), kind, ".{0,10}").prop_map(|(proto, client, version)| ClientMsg::Hello {
            proto,
            client,
            version
        }),
        (any::<bool>(), any::<bool>(), sub).prop_map(|(snapshots, alerts, events)| {
            ClientMsg::Subscribe {
                snapshots,
                alerts,
                events,
            }
        }),
        arb_key().prop_map(|root| ClientMsg::Follow { root }),
        Just(ClientMsg::Unfollow {}),
        (arb_key(), any::<bool>()).prop_map(|(proc, maps)| ClientMsg::GetDetail { proc, maps }),
        (arb_bstr(), any::<u64>()).prop_map(|(name, size)| ClientMsg::GhUploadBegin { name, size }),
        (any::<u32>(), "[A-Za-z0-9+/=]{0,40}")
            .prop_map(|(seq, b64)| ClientMsg::GhUploadChunk { seq, b64 }),
        (vec(arb_bstr(), 0..4), any::<u32>())
            .prop_map(|(args, timeout_s)| ClientMsg::GhRun { args, timeout_s }),
        Just(ClientMsg::GhCancel {}),
        (arb_key(), action, ".{0,10}").prop_map(|(proc, action, nonce)| ClientMsg::Act {
            proc,
            action,
            nonce
        }),
        any::<u64>().prop_map(|n| ClientMsg::Ping { n }),
    ]
}

pub fn arb_daemon() -> impl Strategy<Value = DaemonMsg> {
    let mode = prop_oneof![
        Just(Mode::System(SystemMode::System)),
        arb_key().prop_map(|follow| Mode::Follow { follow }),
    ];
    let state = prop_oneof![
        Just(GhState::Uploading),
        Just(GhState::Starting),
        Just(GhState::Running),
        Just(GhState::Finished),
        Just(GhState::Failed),
    ];
    let detail = (
        arb_key(),
        (
            vec(any::<u64>(), 0..4),
            vec(arb_f32(), 0..4),
            vec(any::<u64>(), 0..4),
        ),
        vec(arb_event(), 0..3),
        vec((arb_bstr(), any::<[u64; 5]>(), any::<[bool; 2]>()), 0..3),
        vec(
            (
                arb_family(),
                ".{0,20}",
                any::<u16>(),
                arb_sock(),
                any::<[u64; 2]>(),
            ),
            0..3,
        ),
        vec((any::<u32>(), ".{0,10}", any::<[u64; 4]>()), 0..3),
        vec(arb_key(), 0..3),
        option::of(vec(
            (any::<[u64; 4]>(), ".{0,4}", ".{0,5}", arb_bstr()),
            0..3,
        )),
        vec(arb_finding(), 0..2),
    )
        .prop_map(
            |(proc, (t, cpu, rss), recent, files, conns, syscalls, children, maps, findings)| {
                DaemonMsg::Detail {
                    proc,
                    series: Series { t, cpu, rss },
                    recent,
                    files: files
                        .into_iter()
                        .map(|(path, n, b)| FileStat {
                            path,
                            dev: n[0],
                            ino: n[1],
                            opens: n[2],
                            read: b[0],
                            write: b[1],
                            rbytes: n[3],
                            wbytes: n[4],
                            last_ts: n[0],
                        })
                        .collect(),
                    conns: conns
                        .into_iter()
                        .map(|(family, addr, port, sock, n)| ConnStat {
                            family,
                            addr,
                            port,
                            sock,
                            count: n[0],
                            last_ts: n[1],
                        })
                        .collect(),
                    syscalls: syscalls
                        .into_iter()
                        .map(|(nr, name, n)| SysStat {
                            nr,
                            name,
                            count: n[0],
                            lat_count: n[1],
                            lat_total_ns: n[2],
                            lat_max_ns: n[3],
                        })
                        .collect(),
                    children,
                    maps: maps.map(|m| {
                        m.into_iter()
                            .map(|(n, perms, dev, path)| MapRow {
                                start: n[0],
                                end: n[1],
                                perms,
                                offset: n[2],
                                dev,
                                inode: n[3],
                                path,
                            })
                            .collect()
                    }),
                    findings,
                }
            },
        );
    let decoy_state = prop_oneof![
        Just(DecoyState::Untouched),
        Just(DecoyState::Read),
        Just(DecoyState::Modified),
        Just(DecoyState::Renamed),
        Just(DecoyState::Deleted),
    ];
    let report = (
        (
            ".{0,10}",
            arb_bstr(),
            vec(arb_bstr(), 0..3),
            any::<u32>(),
            any::<u64>(),
            any::<u64>(),
            option::of(any::<i32>()),
            any::<bool>(),
        ),
        vec(
            (
                arb_bstr(),
                any::<[u64; 3]>(),
                vec(decoy_state, 0..3),
                option::of(arb_bstr()),
                option::of(any::<u64>()),
                arb_f32(),
                option::of(arb_f32()),
            ),
            0..3,
        ),
        vec(
            (arb_bstr(), any::<u64>(), arb_f32(), option::of(arb_bstr())),
            0..3,
        ),
        vec(arb_event(), 0..3),
        vec(arb_key(), 0..3),
        vec(arb_finding(), 0..2),
        arb_loss(),
        ".{0,40}",
    )
        .prop_map(
            |(
                (run_id, sample, args, timeout_s, started_ts, ended_ts, exit_code, timed_out),
                decoys,
                created,
                timeline,
                children,
                findings,
                loss,
                limitation,
            )| DaemonMsg::GhReport {
                report: GhReport {
                    run_id,
                    sample,
                    args,
                    timeout_s,
                    started_ts,
                    ended_ts,
                    exit_code,
                    timed_out,
                    decoys: decoys
                        .into_iter()
                        .map(
                            |(
                                path,
                                n,
                                states,
                                new_path,
                                size_after,
                                entropy_before,
                                entropy_after,
                            )| DecoyStatus {
                                path,
                                dev: n[0],
                                ino: n[1],
                                states,
                                new_path,
                                size_before: n[2],
                                size_after,
                                entropy_before,
                                entropy_after,
                            },
                        )
                        .collect(),
                    created: created
                        .into_iter()
                        .map(|(path, size, entropy, preview)| CreatedFile {
                            path,
                            size,
                            entropy,
                            preview,
                        })
                        .collect(),
                    timeline,
                    connections: Vec::new(),
                    children,
                    findings,
                    loss,
                    limitation,
                },
            },
        );
    prop_oneof![
        (
            any::<u32>(),
            ".{0,10}",
            ".{0,20}",
            any::<u64>(),
            vec(".{0,10}", 0..3),
            any::<bool>()
        )
            .prop_map(
                |(proto, daemon_version, kernel, boot_to_wall_ns, features, act_enabled)| {
                    DaemonMsg::Welcome {
                        proto,
                        daemon_version,
                        kernel,
                        boot_to_wall_ns,
                        features,
                        act_enabled,
                    }
                }
            ),
        (
            any::<u64>(),
            any::<u64>(),
            mode,
            vec(arb_row(), 0..4),
            arb_loss()
        )
            .prop_map(|(seq, ts_ns, mode, procs, loss)| DaemonMsg::Snapshot {
                seq,
                ts_ns,
                mode,
                procs,
                loss
            }),
        (vec(arb_event(), 0..5), any::<u64>()).prop_map(|(events, client_dropped)| {
            DaemonMsg::Events {
                events,
                client_dropped,
            }
        }),
        arb_finding().prop_map(|finding| DaemonMsg::Alert { finding }),
        detail,
        (state, ".{0,10}", ".{0,20}").prop_map(|(state, run_id, message)| DaemonMsg::GhStatus {
            state,
            run_id,
            message
        }),
        report,
        (any::<bool>(), ".{0,20}").prop_map(|(ok, message)| DaemonMsg::ActResult { ok, message }),
        (".{0,10}", ".{0,20}").prop_map(|(code, message)| DaemonMsg::Error { code, message }),
        any::<u64>().prop_map(|n| DaemonMsg::Pong { n }),
    ]
}
