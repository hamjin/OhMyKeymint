use super::*;
use crate::android::system::keystore2::IKeystoreOperation::BnKeystoreOperation;
use crate::hook::rewrite::{reply::tests::*, tests::*};
use rsbinder::{ExceptionCode, StatusCode};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

mod base;
mod metadata;
mod one_way;
mod operation_dispatch;

#[test]
fn synthetic_security_level_dispatch_preserves_system_namespace_routing() {
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x2239,
        cookie: 0x6683,
    };
    let level = crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel::TRUSTED_ENVIRONMENT;
    tracker::remember_security_level_target(
        target,
        SecurityLevelTargetInfo {
            security_level: level,
        },
    );
    for (domain, code) in [
        (Domain::BLOB, crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#convertStorageKeyToEphemeral),
        (Domain::SELINUX, crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey),
    ] {
        let mut parcel = request_parcel(identify::KEYSTORE_SECURITY_LEVEL_INTERFACE);
        parcel.write(&KeyDescriptor { domain, ..sample_key_descriptor() }).unwrap();
        let (mut tr, _data) = transaction_for_parcel(target, code, parcel);
        tr.sender_euid = 1000;
        let info = SyntheticTargetInfo { kind: SyntheticTargetKind::SecurityLevel, caller: None, native_generation: None };
        let reply = unsafe { build_synthetic_br_transaction_reply(&tr, target, info.clone(), Some("u:r:system_server:s0".into()), "test") }.unwrap();
        assert!(matches!(reply, SyntheticReply::SystemSecurityLevel(value) if value == level));
        if domain == Domain::SELINUX {
            tr.flags = super::super::super::super::binder::TF_ONE_WAY;
            let reply = unsafe { build_synthetic_br_transaction_reply(&tr, target, info, None, "test") }.unwrap();
            assert!(matches!(reply, SyntheticReply::SystemSecurityLevel(value) if value == level));
        }
    }
}

#[test]
fn untracked_native_target_is_not_intercepted() {
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let empty = rsbinder::Parcel::new();
    let (tr, _data) = transaction_for_parcel(target, rsbinder::FIRST_CALL_TRANSACTION, empty);
    assert!(unsafe { handle_synthetic_br_transaction(&tr, None, "BR_TRANSACTION") }.is_none());
}
