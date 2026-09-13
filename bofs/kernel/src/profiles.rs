//! Exact Windows build profiles generated from reviewed offline data.

include!("profiles_generated.rs");

pub const fn kernel_profile_count() -> usize {
    KERNEL_PROFILES.len()
}

pub const fn credential_profile_count() -> usize {
    CREDENTIAL_PROFILES.len()
}

pub fn find_kernel_profile(
    timestamp: u32,
    checksum: u32,
    image_size: u32,
) -> Option<&'static KernelProfile> {
    KERNEL_PROFILES.iter().find(|profile| {
        profile.value(KernelField::PeTimestamp) == timestamp
            && profile.value(KernelField::PeChecksum) == checksum
            && profile.value(KernelField::ImageSize) == image_size
    })
}

pub fn find_credential_profile(
    timestamp: u32,
    checksum: u32,
    image_size: u32,
) -> Option<&'static CredentialProfile> {
    CREDENTIAL_PROFILES.iter().find(|profile| {
        profile.lsasrv.pe_timestamp == timestamp
            && profile.lsasrv.pe_checksum == checksum
            && profile.lsasrv.image_size == image_size
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_profile_lookup_succeeds() {
        let expected = &KERNEL_PROFILES[0];
        let actual = find_kernel_profile(
            expected.value(KernelField::PeTimestamp),
            expected.value(KernelField::PeChecksum),
            expected.value(KernelField::ImageSize),
        );

        assert_eq!(actual.map(|profile| profile.id), Some(expected.id));
    }

    #[test]
    fn nearest_profile_fallback_is_absent() {
        assert!(find_kernel_profile(0, 0, 0).is_none());
    }

    #[test]
    fn exact_credential_profile_lookup_succeeds() {
        let expected = &CREDENTIAL_PROFILES[0];
        let actual = find_credential_profile(
            expected.lsasrv.pe_timestamp,
            expected.lsasrv.pe_checksum,
            expected.lsasrv.image_size,
        );

        assert_eq!(actual.map(|profile| profile.id), Some(expected.id));
    }
}
