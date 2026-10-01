//! Real issuer/device signatures, Profile preparation, encrypted checkpoint and
//! Guard matching. Test signing custody is not production G3 or forum evidence.
use ckmg::{
    SystemEntropy,
    passkey::{PrfOutput, store_cipher},
};
use cpfl::{DeviceSigner, Draft, PortableCodec};
use csgn::{Kind, SecretKey, Signer};
use csrh::{Error, Input, Verification, recheck};
use ed25519_dalek::{Signer as _, SigningKey};
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
    "public":[{"id":"age","label":"Age","kind":{"type":"integer","min":18,"max":120},"required":true,"filterable":true,"change_preset":"stable","no_contact_details":false}],
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
        let mut device = Device(SigningKey::from_bytes(&[age as u8; 32]));
        let mut draft = Draft::new(
            member.into(),
            cshm::Profile {
                community: "garden".into(),
                schema_version: 1,
                public: [("age".into(), json!(age))].into(),
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
        draft
            .prepare_publication(
                &credential,
                &fixture.policy(),
                &fixture.schema,
                1,
                1,
                vec![1],
                0,
                &mut device,
                &cipher,
                &PortableCodec,
                &mut SystemEntropy,
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
