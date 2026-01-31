// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Aalivexy

use windows::{
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Win32::{
        System::WinRT::IUserConsentVerifierInterop,
        UI::WindowsAndMessaging::{GA_ROOT, GetAncestor, GetForegroundWindow},
    },
    core::{HSTRING, factory},
};
use windows_future::IAsyncOperation;

pub fn authenticate_with_biometrics() -> bool {
    unsafe {
        let fg_hwnd = GetForegroundWindow();
        let owner_hwnd = GetAncestor(fg_hwnd, GA_ROOT);
        factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .unwrap()
            .RequestVerificationForWindowAsync::<IAsyncOperation<UserConsentVerificationResult>>(
                owner_hwnd,
                &HSTRING::new(),
            )
            .is_ok_and(|async_op| async_op.get() == Ok(UserConsentVerificationResult::Verified))
    }
}

pub fn get_biometrics_status() -> i32 {
    UserConsentVerifier::CheckAvailabilityAsync().map_or(5, |async_op| {
        async_op.get().map_or(5, |availability| {
            #[allow(non_snake_case)]
            match availability {
                UserConsentVerifierAvailability::Available => 0,
                UserConsentVerifierAvailability::DeviceNotPresent => 2,
                UserConsentVerifierAvailability::NotConfiguredForUser => 7,
                UserConsentVerifierAvailability::DisabledByPolicy => 5,
                UserConsentVerifierAvailability::DeviceBusy => 2,
                _ => 5,
            }
        })
    })
}
