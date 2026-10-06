//! Real issuer/device signatures, Profile preparation, encrypted checkpoint and
//! Guard matching. Test signing custody is not production G3 or forum evidence.
use ckmg::{
    SystemEntropy,
    passkey::{PrfOutput, store_cipher},
};
use cpfl::{DeviceSigner, Draft, PortableCodec};
use csgn::{Kind, SecretKey, Signer};
use csrh::{Error, Input, Verification, recheck};
use ed25519_dalek::{Digest, Sha512, Signer as _, SigningKey};
use serde_json::json;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg(not(target_arch="wasm32"))]
        #[test]
        fn $name() { futures_executor::block_on(async $body); }
        #[cfg(target_arch="wasm32")]
        #[wasm_bindgen_test::wasm_bindgen_test]
        async fn $name() $body
    };
}
struct Device(SigningKey);
impl DeviceSigner for Device {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn hpke_public_key(&self) -> Result<[u8; 32], cpfl::Error> {
        Ok(self.0.verifying_key().to_montgomery().to_bytes())
    }
    fn sign(&mut self, bytes: &[u8]) -> Result<[u8; 64], cpfl::Error> {
        Ok(self.0.sign(bytes).to_bytes())
    }
}
fn clean(_: &str) -> cshm::ContactCheck {
    cshm::ContactCheck::Clear
}
fn schema() -> cshm::Schema {
    serde_json::from_value(json!({
    "community":"garden","version":1,
    "public":[{"id":"age","label":"Age","kind":{"type":"integer","min":18,"max":120},"required":true,"filterable":true,"change_preset":"stable","no_contact_details":false}, {"id":"place","label":"Place","kind":{"type":"location"},"required":true,"filterable":true,"change_preset":"occasional","no_contact_details":false}],
    "private":[{"id":"secret","label":"Secret","kind":{"type":"yes_no"},"required":true,"filterable":false,"change_preset":"occasional","no_contact_details":false}]
})).unwrap()
}
struct Fixture {
    wire: Vec<u8>,
    keys: csgn::KeyRing,
    settings: Vec<u8>,
    schema: Vec<u8>,
    revocations: Vec<u8>,
}
impl Fixture {
    async fn new(member: &str, age: u64, rules: Vec<cgrd::Rule>) -> Self {
        Self::at(member, age, json!({"latitude":0,"longitude":0}), rules).await
    }
    async fn at(member: &str, age: u64, place: serde_json::Value, rules: Vec<cgrd::Rule>) -> Self {
        Self::at_revision(member, age, place, rules, 1).await
    }
    async fn at_revision(
        member: &str,
        age: u64,
        place: serde_json::Value,
        rules: Vec<cgrd::Rule>,
        revision: u64,
    ) -> Self {
        let mut device = Device(SigningKey::from_bytes(&[age as u8; 32]));
        let mut draft = Draft::new(
            member.into(),
            cshm::Profile {
                community: "garden".into(),
                schema_version: 1,
                public: [("age".into(), json!(age)), ("place".into(), place)].into(),
                private: [("secret".into(), json!(true))].into(),
            },
        )
        .unwrap();
        draft.set_rules(rules).unwrap();
        let pins = draft
            .prepare_pins(&schema(), &clean, &mut SystemEntropy)
            .unwrap();
        let mut issuer =
            Signer::new("garden", SecretKey::from_seed(&mut [11; 32]), 1000, 10000).unwrap();
        let credential = cgrd::Credential {
            community: "garden".into(),
            member: member.into(),
            handle: "mountain".into(),
            schema_version: 1,
            policy_epoch: 2,
            gates: vec![],
            pins,
            devices: vec![device.public_key()],
        };
        let mut sign = |kind, value: serde_json::Value| {
            issuer
                .sign(kind, &serde_json::to_vec(&value).unwrap(), 1000, 2000)
                .unwrap()
        };
        let credential = sign(Kind::Credential, serde_json::to_value(credential).unwrap());
        let signed_schema = sign(
            Kind::SchemaSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":schema()}),
        );
        let settings = sign(
            Kind::SettingsSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"action/admission":{"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]}}}),
        );
        let revocations = sign(
            Kind::RevocationListSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"members":[],"devices":[]}}),
        );
        let mut fixture = Self {
            wire: vec![],
            keys: issuer.key_ring().clone(),
            schema: signed_schema,
            settings,
            revocations,
        };
        let cipher = store_cipher(&PrfOutput::from_bytes(&[3; 32]).unwrap(), "garden").unwrap();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
            .await
            .unwrap();
        // Original maintained conversion for deterministic test device custody.
        // Production uses the fresh-authorized Keys lender, never caller keys.
        let hpke: [u8; 32] = Sha512::digest(device.0.as_bytes())[..32]
            .try_into()
            .unwrap();
        let custody =
            cnvl::Custodian::from_keys(&hpke, &[44; 32], "garden", member, device.public_key())
                .unwrap();
        draft
            .prepare_publication(
                &credential,
                &fixture.policy(),
                &fixture.schema,
                revision,
                1,
                vec![1],
                0,
                &mut device,
                &custody,
                &PortableCodec,
                &clean,
            )
            .unwrap()
            .commit_publication(
                &mut store,
                cpfl::Validation {
                    policy: fixture.policy(),
                    signed_schema: &fixture.schema,
                    contact: &clean,
                },
                [1; 32],
                vec![],
            )
            .await
            .unwrap();
        fixture.wire = store.load_pending().unwrap()[0].bytes.clone();
        fixture
    }
    fn policy(&self) -> cgrd::PublishedPolicy<'_> {
        cgrd::PublishedPolicy {
            policy: cgrd::Policy {
                community: "garden",
                keys: &self.keys,
                now: 1100,
                minimum_epoch: 2,
                minimum_settings_revision: 1,
                minimum_schema_revision: 1,
                maximum_snapshot_age: 300,
                settings: &self.settings,
            },
            revocations: &self.revocations,
            minimum_revocations_revision: 1,
            action: "admission",
        }
    }
    fn input<'a>(&'a self, member: &'a str) -> Input<'a> {
        Input {
            member,
            minimum_revision: 1,
            bytes: &self.wire,
        }
    }
}
fn range(min: &str, max: &str) -> cgrd::Rule {
    cgrd::Rule::NumberRange {
        field: "age".into(),
        min: min.into(),
        max: max.into(),
    }
}
shared!(both_signed_rules_use_the_real_guard_engine, {
    let alice = Fixture::new("alice", 34, vec![range("40", "60")]).await;
    let bob = Fixture::new("bob", 50, vec![range("30", "40")]).await;
    let policy = alice.policy();
    let verification = Verification {
        policy: &policy,
        signed_schema: &alice.schema,
    };
    let pair = recheck(
        alice.input("alice"),
        bob.input("bob"),
        &verification,
        &clean,
    )
    .unwrap();
    assert_eq!(pair.requester().transcript().member, "alice");
    assert_eq!(pair.owner().transcript().member, "bob");
    assert!(pair.decision().is_match());
    assert_eq!(
        serde_json::to_value(pair.discovery().unwrap()).unwrap(),
        json!({"community":"garden", "member":"bob", "profile_revision":1,
               "schema_version":1, "public":{"age":50}})
    );
    assert_eq!(
        *pair.decision(),
        cgrd::matches(pair.requester().participant(), pair.owner().participant())
    );
    let rejecting = Fixture::new("bob", 50, vec![range("40", "60")]).await;
    let refused = recheck(
        alice.input("alice"),
        rejecting.input("bob"),
        &verification,
        &clean,
    )
    .unwrap();
    assert!(!refused.decision().is_match());
    assert!(refused.discovery().is_none());
    assert_eq!(refused.decision().requester_fields(), ["age"]);
    assert!(
        !serde_json::to_string(&refused.decision().requester_fields())
            .unwrap()
            .contains("40")
    );
});
shared!(
    signed_blocks_in_either_direction_and_self_matching_refuse,
    {
        for side in [false, true] {
            let alice = Fixture::new(
                "alice",
                34,
                if side {
                    vec![cgrd::Rule::Block {
                        member: "bob".into(),
                    }]
                } else {
                    vec![]
                },
            )
            .await;
            let bob = Fixture::new(
                "bob",
                50,
                if side {
                    vec![]
                } else {
                    vec![cgrd::Rule::Block {
                        member: "alice".into(),
                    }]
                },
            )
            .await;
            let policy = alice.policy();
            let verification = Verification {
                policy: &policy,
                signed_schema: &alice.schema,
            };
            let pair = recheck(
                alice.input("alice"),
                bob.input("bob"),
                &verification,
                &clean,
            )
            .unwrap();
            assert!(!pair.decision().is_match());
            assert!(pair.decision().requester_fields().is_empty());
            let pair = recheck(
                alice.input("alice"),
                alice.input("alice"),
                &verification,
                &clean,
            )
            .unwrap();
            assert!(!pair.decision().is_match());
        }
    }
);
shared!(wrong_owner_revision_tampering_expiry_and_scope_refuse, {
    let alice = Fixture::new("alice", 34, vec![]).await;
    let bob = Fixture::new("bob", 50, vec![]).await;
    let policy = alice.policy();
    let verification = Verification {
        policy: &policy,
        signed_schema: &alice.schema,
    };
    for revision in [0, 2] {
        let mut input = bob.input("bob");
        input.minimum_revision = revision;
        assert!(matches!(
            recheck(alice.input("alice"), input, &verification, &clean),
            Err(Error::Binding | Error::Publication)
        ));
    }
    assert!(matches!(
        recheck(
            alice.input("alice"),
            bob.input("charlie"),
            &verification,
            &clean
        ),
        Err(Error::Binding)
    ));
    for bytes in [b"{".to_vec(), vec![0; cpfl::MAX_PROFILE_BYTES + 1]] {
        for swap in [false, true] {
            let malformed = Input {
                member: "alice",
                minimum_revision: 1,
                bytes: &bytes,
            };
            let result = if swap {
                recheck(alice.input("alice"), malformed, &verification, &clean)
            } else {
                recheck(malformed, bob.input("bob"), &verification, &clean)
            };
            assert!(matches!(result, Err(Error::Publication)));
        }
    }
    let mut forged = cpfl::Publication::from_bytes(&bob.wire).unwrap();
    forged.signature[0] ^= 1;
    let wire = forged.to_bytes().unwrap();
    assert!(matches!(
        recheck(
            alice.input("alice"),
            Input {
                member: "bob",
                minimum_revision: 1,
                bytes: &wire
            },
            &verification,
            &clean
        ),
        Err(Error::Publication)
    ));
    for now in [2000, 999] {
        let mut expired = alice.policy();
        expired.policy.now = now;
        assert!(
            recheck(
                alice.input("alice"),
                bob.input("bob"),
                &Verification {
                    policy: &expired,
                    signed_schema: &alice.schema
                },
                &clean
            )
            .is_err()
        );
    }
    let mut foreign = alice.policy();
    foreign.policy.community = "other";
    assert!(
        recheck(
            alice.input("alice"),
            bob.input("bob"),
            &Verification {
                policy: &foreign,
                signed_schema: &alice.schema
            },
            &clean
        )
        .is_err()
    );
});

// Link maintained profiling support only into the instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

shared!(
    distance_rules_are_rechecked_by_the_current_guard_in_both_directions,
    {
        let within = |max: &str| cgrd::Rule::DistanceRange {
            field: "place".into(),
            min_meters: "0".into(),
            max_meters: max.into(),
        };
        let alice = Fixture::at(
            "alice",
            34,
            json!({"latitude":0,"longitude":0}),
            vec![within("1500")],
        )
        .await;
        let policy = alice.policy();
        let verification = Verification {
            policy: &policy,
            signed_schema: &alice.schema,
        };
        for (owner_limit, expected) in [("1500", true), ("500", false)] {
            let bob = Fixture::at(
                "bob",
                50,
                json!({"latitude":0,"longitude":0.01}),
                vec![within(owner_limit)],
            )
            .await;
            let pair = recheck(
                alice.input("alice"),
                bob.input("bob"),
                &verification,
                &clean,
            )
            .unwrap();
            assert_eq!(pair.decision().is_match(), expected);
            assert_eq!(
                *pair.decision(),
                cgrd::matches(pair.requester().participant(), pair.owner().participant())
            );
            if !expected {
                assert_eq!(pair.decision().requester_fields(), ["place"]);
            }
        }
        let distant = Fixture::at(
            "bob",
            50,
            json!({"latitude":0,"longitude":1}),
            vec![within("200000")],
        )
        .await;
        let pair = recheck(
            alice.input("alice"),
            distant.input("bob"),
            &verification,
            &clean,
        )
        .unwrap();
        assert!(!pair.decision().is_match());
    }
);
shared!(
    signed_revocations_refuse_each_participant_without_mutation,
    {
        let alice = Fixture::new("alice", 34, vec![]).await;
        let bob = Fixture::new("bob", 50, vec![]).await;
        let alice_before = alice.wire.clone();
        let bob_before = bob.wire.clone();
        let control = alice.policy();
        let verification = Verification {
            policy: &control,
            signed_schema: &alice.schema,
        };
        assert!(
            recheck(
                alice.input("alice"),
                bob.input("bob"),
                &verification,
                &clean
            )
            .unwrap()
            .decision()
            .is_match()
        );
        let mut issuer =
            Signer::new("garden", SecretKey::from_seed(&mut [11; 32]), 1000, 10000).unwrap();
        for (member, age) in [("alice", 34u8), ("bob", 50u8)] {
            let device = SigningKey::from_bytes(&[age; 32])
                .verifying_key()
                .to_bytes();
            for content in [
                json!({"members":[member],"devices":[]}),
                json!({"members":[],"devices":[device]}),
            ] {
                let snapshot = json!({
                    "community": "garden",
                    "revision": 1,
                    "policy_epoch": 2,
                    "content": content,
                });
                let signed = issuer
                    .sign(
                        Kind::RevocationListSnapshot,
                        &serde_json::to_vec(&snapshot).unwrap(),
                        1000,
                        2000,
                    )
                    .unwrap();
                let mut policy = alice.policy();
                policy.revocations = &signed;
                let revoked = Verification {
                    policy: &policy,
                    signed_schema: &alice.schema,
                };
                assert!(matches!(
                    recheck(alice.input("alice"), bob.input("bob"), &revoked, &clean),
                    Err(Error::Publication)
                ));
                assert_eq!(alice.wire, alice_before);
                assert_eq!(bob.wire, bob_before);
                assert!(
                    recheck(
                        alice.input("alice"),
                        bob.input("bob"),
                        &verification,
                        &clean
                    )
                    .unwrap()
                    .decision()
                    .is_match()
                );
            }
        }
    }
);

fn view() -> csrh::View {
    csrh::View::new(csrh::ViewLimits {
        candidates: 2,
        publication_bytes: cpfl::MAX_PROFILE_BYTES * 3,
    })
    .unwrap()
}

shared!(bounded_view_rechecks_and_forgets_original_publications, {
    let alice = Fixture::new("alice", 34, vec![]).await;
    let bob = Fixture::new("bob", 50, vec![]).await;
    let carol = Fixture::new("carol", 42, vec![]).await;
    let policy = alice.policy();
    let verification = Verification {
        policy: &policy,
        signed_schema: &alice.schema,
    };
    let mut view = view();
    assert!(matches!(
        view.read(alice.input("alice"), &verification, &clean),
        Err(csrh::ViewError::ResetRequired)
    ));
    view.remove("bob");
    view.replace(
        alice.input("alice"),
        &[bob.input("bob"), carol.input("carol")],
        &verification,
        &clean,
    )
    .unwrap();
    let pairs = view
        .read(alice.input("alice"), &verification, &clean)
        .unwrap();
    assert_eq!(
        pairs
            .iter()
            .map(|pair| pair.owner().transcript().member.as_str())
            .collect::<Vec<_>>(),
        ["bob", "carol"]
    );
    view.remove("unknown");
    view.remove("bob");
    let pairs = view
        .read(alice.input("alice"), &verification, &clean)
        .unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].owner().transcript().member, "carol");
    view.remove("carol");
    assert!(
        view.read(alice.input("alice"), &verification, &clean)
            .unwrap()
            .is_empty()
    );
    view.clear();
    assert!(matches!(
        view.read(alice.input("alice"), &verification, &clean),
        Err(csrh::ViewError::ResetRequired)
    ));
    // An exact combined byte bound is accepted, without retaining a full roster.
    let mut bounded = csrh::View::new(csrh::ViewLimits {
        candidates: 1,
        publication_bytes: alice.wire.len() + bob.wire.len(),
    })
    .unwrap();
    bounded
        .replace(
            alice.input("alice"),
            &[bob.input("bob")],
            &verification,
            &clean,
        )
        .unwrap();
    assert_eq!(
        bounded
            .read(alice.input("alice"), &verification, &clean)
            .unwrap()
            .len(),
        1
    );
});

shared!(
    view_refuses_oversize_duplicate_and_unverified_candidates_atomically,
    {
        use csrh::{View, ViewError, ViewLimits};
        for (candidates, publication_bytes) in [(0, 1), (1, 0)] {
            assert!(matches!(
                View::new(ViewLimits {
                    candidates,
                    publication_bytes
                }),
                Err(ViewError::Capacity)
            ));
        }
        let alice = Fixture::new("alice", 34, vec![]).await;
        let bob = Fixture::new("bob", 50, vec![]).await;
        let refusing = Fixture::new(
            "bob",
            50,
            vec![cgrd::Rule::Block {
                member: "alice".into(),
            }],
        )
        .await;
        let policy = alice.policy();
        let verification = Verification {
            policy: &policy,
            signed_schema: &alice.schema,
        };
        for budget in [alice.wire.len() - 1, alice.wire.len() + bob.wire.len() - 1] {
            let mut bounded = View::new(ViewLimits {
                candidates: 1,
                publication_bytes: budget,
            })
            .unwrap();
            assert_eq!(
                bounded.replace(
                    alice.input("alice"),
                    &[bob.input("bob")],
                    &verification,
                    &clean
                ),
                Err(ViewError::Capacity)
            );
        }
        let mut view = view();
        for (candidates, expected) in [
            (vec![bob.input("bob"); 3], ViewError::Capacity),
            (vec![bob.input("bob"); 2], ViewError::Binding),
            (vec![bob.input("wrong")], ViewError::Rejected),
            (vec![refusing.input("bob")], ViewError::Rejected),
            (vec![alice.input("alice")], ViewError::Rejected),
        ] {
            view.replace(
                alice.input("alice"),
                &[bob.input("bob")],
                &verification,
                &clean,
            )
            .unwrap();
            assert_eq!(
                view.replace(alice.input("alice"), &candidates, &verification, &clean),
                Err(expected)
            );
            assert!(matches!(
                view.read(alice.input("alice"), &verification, &clean),
                Err(ViewError::ResetRequired)
            ));
        }
        let mut invalid = alice.input("alice");
        invalid.bytes = b"{}";
        assert_eq!(
            view.replace(invalid, &[], &verification, &clean),
            Err(ViewError::Rejected)
        );
    }
);

shared!(
    view_binding_trust_change_and_time_regression_reset_before_display,
    {
        use csrh::ViewError;
        let alice = Fixture::new("alice", 34, vec![]).await;
        let changed = Fixture::new(
            "alice",
            34,
            vec![cgrd::Rule::Block {
                member: "bob".into(),
            }],
        )
        .await;
        let bob = Fixture::new("bob", 50, vec![]).await;
        let policy = alice.policy();
        let verification = Verification {
            policy: &policy,
            signed_schema: &alice.schema,
        };
        let mut view = view();
        for input in [
            alice.input("wrong"),
            changed.input("alice"),
            Input {
                minimum_revision: 2,
                ..alice.input("alice")
            },
        ] {
            view.replace(
                alice.input("alice"),
                &[bob.input("bob")],
                &verification,
                &clean,
            )
            .unwrap();
            assert!(matches!(
                view.read(input, &verification, &clean),
                Err(ViewError::Binding)
            ));
            assert!(matches!(
                view.read(alice.input("alice"), &verification, &clean),
                Err(ViewError::ResetRequired)
            ));
        }
        for case in 0..4 {
            view.replace(
                alice.input("alice"),
                &[bob.input("bob")],
                &verification,
                &clean,
            )
            .unwrap();
            let mut policy = alice.policy();
            let mut signed_schema = alice.schema.as_slice();
            match case {
                0 => policy.policy.community = "other",
                1 => policy.policy.minimum_epoch += 1,
                2 => signed_schema = b"different",
                _ => policy.policy.now -= 1,
            }
            assert!(matches!(
                view.read(
                    alice.input("alice"),
                    &Verification {
                        policy: &policy,
                        signed_schema
                    },
                    &clean
                ),
                Err(ViewError::ResetRequired)
            ));
        }
        view.replace(
            alice.input("alice"),
            &[bob.input("bob")],
            &verification,
            &clean,
        )
        .unwrap();
        let mut later = alice.policy();
        later.policy.now += 1;
        assert_eq!(
            view.read(
                alice.input("alice"),
                &Verification {
                    policy: &later,
                    signed_schema: &alice.schema
                },
                &clean
            )
            .unwrap()
            .len(),
            1
        );
        assert!(matches!(
            view.read(alice.input("alice"), &verification, &clean),
            Err(ViewError::ResetRequired)
        ));
    }
);

shared!(
    view_rechecks_new_revocations_and_expiry_even_for_empty_pages,
    {
        use csrh::ViewError;
        let alice = Fixture::new("alice", 34, vec![]).await;
        let bob = Fixture::new("bob", 50, vec![]).await;
        let policy = alice.policy();
        let verification = Verification {
            policy: &policy,
            signed_schema: &alice.schema,
        };
        let mut issuer =
            Signer::new("garden", SecretKey::from_seed(&mut [11; 32]), 1000, 10000).unwrap();
        for member in ["alice", "bob"] {
            for empty in [false, true] {
                let candidates = if empty {
                    vec![]
                } else {
                    vec![bob.input("bob")]
                };
                let mut view = view();
                view.replace(alice.input("alice"), &candidates, &verification, &clean)
                    .unwrap();
                let signed = issuer
                    .sign(
                        Kind::RevocationListSnapshot,
                        &serde_json::to_vec(&json!({
                            "community":"garden", "revision":2, "policy_epoch":2,
                            "content":{"members":[member],"devices":[]}
                        }))
                        .unwrap(),
                        1000,
                        2000,
                    )
                    .unwrap();
                let mut current = alice.policy();
                current.revocations = &signed;
                current.minimum_revocations_revision = 2;
                let result = view.read(
                    alice.input("alice"),
                    &Verification {
                        policy: &current,
                        signed_schema: &alice.schema,
                    },
                    &clean,
                );
                if empty && member == "bob" {
                    assert!(result.unwrap().is_empty());
                } else {
                    assert!(matches!(result, Err(ViewError::Rejected)));
                    assert!(matches!(
                        view.read(alice.input("alice"), &verification, &clean),
                        Err(ViewError::ResetRequired)
                    ));
                }
            }
        }
        let mut view = view();
        view.replace(alice.input("alice"), &[], &verification, &clean)
            .unwrap();
        let mut expired = alice.policy();
        expired.policy.now = 2000;
        assert!(matches!(
            view.read(
                alice.input("alice"),
                &Verification {
                    policy: &expired,
                    signed_schema: &alice.schema
                },
                &clean
            ),
            Err(ViewError::Rejected)
        ));
        view.replace(alice.input("alice"), &[], &verification, &clean)
            .unwrap();
        assert!(matches!(
            view.read(
                Input {
                    minimum_revision: 0,
                    ..alice.input("alice")
                },
                &verification,
                &clean
            ),
            Err(ViewError::Rejected)
        ));
    }
);

shared!(
    bounded_deltas_recheck_add_update_remove_and_refuse_rollback,
    {
        let alice = Fixture::new("alice", 34, vec![]).await;
        let bob = Fixture::new("bob", 50, vec![]).await;
        let carol = Fixture::new("carol", 42, vec![]).await;
        let updated =
            Fixture::at_revision("bob", 51, json!({"latitude":0,"longitude":0}), vec![], 2).await;
        let equivocation = Fixture::new("bob", 51, vec![]).await;
        let policy = alice.policy();
        let verification = Verification {
            policy: &policy,
            signed_schema: &alice.schema,
        };
        let mut view = view();
        view.replace(
            alice.input("alice"),
            &[bob.input("bob")],
            &verification,
            &clean,
        )
        .unwrap();
        view.delta(
            alice.input("alice"),
            &[carol.input("carol")],
            &[],
            &verification,
            &clean,
        )
        .unwrap();
        assert_eq!(
            view.read(alice.input("alice"), &verification, &clean)
                .unwrap()
                .len(),
            2
        );
        view.delta(
            alice.input("alice"),
            &[updated.input("bob")],
            &["carol"],
            &verification,
            &clean,
        )
        .unwrap();
        let page = view
            .read(alice.input("alice"), &verification, &clean)
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].owner().transcript().revision, 2);
        assert!(
            view.delta(
                alice.input("alice"),
                &[bob.input("bob")],
                &[],
                &verification,
                &clean
            )
            .is_err()
        );
        assert!(matches!(
            view.read(alice.input("alice"), &verification, &clean),
            Err(csrh::ViewError::ResetRequired)
        ));
        view.replace(
            alice.input("alice"),
            &[bob.input("bob")],
            &verification,
            &clean,
        )
        .unwrap();
        assert!(matches!(
            view.delta(
                alice.input("alice"),
                &[equivocation.input("bob")],
                &[],
                &verification,
                &clean
            ),
            Err(csrh::ViewError::Binding)
        ));
        for removed in [vec!["unknown"], vec!["bob", "bob"]] {
            view.replace(
                alice.input("alice"),
                &[bob.input("bob")],
                &verification,
                &clean,
            )
            .unwrap();
            assert!(matches!(
                view.delta(alice.input("alice"), &[], &removed, &verification, &clean),
                Err(csrh::ViewError::Binding)
            ));
        }
        view.replace(
            alice.input("alice"),
            &[bob.input("bob")],
            &verification,
            &clean,
        )
        .unwrap();
        assert!(matches!(
            view.delta(
                alice.input("alice"),
                &[carol.input("carol"), carol.input("carol")],
                &[],
                &verification,
                &clean
            ),
            Err(csrh::ViewError::Binding)
        ));
    }
);
