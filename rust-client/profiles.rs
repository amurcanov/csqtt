// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use primp::{Impersonate, ImpersonateOS};
use rand::RngExt;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct Profile {
    pub impersonate: Impersonate,
    pub os: ImpersonateOS,
    pub user_agent: String,
    pub sec_ch_ua: String,
    pub sec_ch_ua_mobile: String,
    pub sec_ch_ua_platform: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            impersonate: Impersonate::Chrome,
            os: ImpersonateOS::Windows,
            user_agent: String::new(),
            sec_ch_ua: String::new(),
            sec_ch_ua_mobile: String::new(),
            sec_ch_ua_platform: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SavedProfile {
    #[serde(default)]
    #[allow(dead_code)]
    pub user_agent: String,
    pub device_json: String,
    pub browser_fp: String,
}

pub fn load_saved_profile() -> Option<SavedProfile> {
    let data = std::fs::read("vk_profile.json").ok()?;
    serde_json::from_slice(&data).ok()
}

struct WeightedProfile {
    impersonate: Impersonate,
    os: ImpersonateOS,
    weight: u32,
}

fn wp(impersonate: Impersonate, os: ImpersonateOS, weight: u32) -> WeightedProfile {
    WeightedProfile {
        impersonate,
        os,
        weight,
    }
}

fn pick_weighted(pool: &[WeightedProfile]) -> (Impersonate, ImpersonateOS) {
    let total: u32 = pool.iter().map(|entry| entry.weight).sum();
    let mut roll = rand::rng().random_range(0..total);
    for entry in pool {
        if roll < entry.weight {
            return (entry.impersonate, entry.os);
        }
        roll -= entry.weight;
    }
    let last = &pool[pool.len() - 1];
    (last.impersonate, last.os)
}

fn weighted_browser_pool(
    versions: &[(Impersonate, u32)],
    operating_systems: &[(ImpersonateOS, u32)],
) -> Vec<WeightedProfile> {
    versions
        .iter()
        .flat_map(|(impersonate, version_weight)| {
            operating_systems
                .iter()
                .map(move |(os, os_weight)| wp(*impersonate, *os, version_weight * os_weight))
        })
        .collect()
}

fn chrome_pool() -> Vec<WeightedProfile> {
    weighted_browser_pool(
        &[
            (Impersonate::ChromeV148, 35),
            (Impersonate::ChromeV147, 25),
            (Impersonate::ChromeV146, 18),
            (Impersonate::ChromeV145, 12),
            (Impersonate::ChromeV144, 10),
        ],
        &[
            (ImpersonateOS::Android, 55),
            (ImpersonateOS::Windows, 20),
            (ImpersonateOS::MacOS, 10),
            (ImpersonateOS::Linux, 10),
            (ImpersonateOS::IOS, 5),
        ],
    )
}

fn firefox_pool() -> Vec<WeightedProfile> {
    weighted_browser_pool(
        &[
            (Impersonate::FirefoxV148, 40),
            (Impersonate::FirefoxV147, 28),
            (Impersonate::FirefoxV146, 20),
            (Impersonate::FirefoxV140, 12),
        ],
        &[
            (ImpersonateOS::Android, 55),
            (ImpersonateOS::Windows, 20),
            (ImpersonateOS::MacOS, 10),
            (ImpersonateOS::Linux, 10),
            (ImpersonateOS::IOS, 5),
        ],
    )
}

fn safari_pool() -> Vec<WeightedProfile> {
    weighted_browser_pool(
        &[
            (Impersonate::SafariV26_3, 40),
            (Impersonate::SafariV26, 35),
            (Impersonate::SafariV18_5, 25),
        ],
        &[(ImpersonateOS::IOS, 70), (ImpersonateOS::MacOS, 30)],
    )
}

fn edge_pool() -> Vec<WeightedProfile> {
    weighted_browser_pool(
        &[
            (Impersonate::EdgeV148, 35),
            (Impersonate::EdgeV147, 25),
            (Impersonate::EdgeV146, 18),
            (Impersonate::EdgeV145, 12),
            (Impersonate::EdgeV144, 10),
        ],
        &[
            (ImpersonateOS::Android, 60),
            (ImpersonateOS::Windows, 20),
            (ImpersonateOS::MacOS, 8),
            (ImpersonateOS::Linux, 7),
            (ImpersonateOS::IOS, 5),
        ],
    )
}

fn opera_pool() -> Vec<WeightedProfile> {
    weighted_browser_pool(
        &[
            (Impersonate::OperaV131, 30),
            (Impersonate::OperaV130, 24),
            (Impersonate::OperaV129, 18),
            (Impersonate::OperaV128, 13),
            (Impersonate::OperaV127, 9),
            (Impersonate::OperaV126, 6),
        ],
        &[
            (ImpersonateOS::Android, 60),
            (ImpersonateOS::Windows, 20),
            (ImpersonateOS::MacOS, 8),
            (ImpersonateOS::Linux, 7),
            (ImpersonateOS::IOS, 5),
        ],
    )
}

pub fn random_profile(fingerprint: &str) -> Profile {
    let (impersonate, os) = match fingerprint {
        "safari" => pick_weighted(&safari_pool()),
        "firefox" => pick_weighted(&firefox_pool()),
        "edge" => pick_weighted(&edge_pool()),
        "opera" => pick_weighted(&opera_pool()),
        _ => pick_weighted(&chrome_pool()),
    };
    Profile {
        impersonate,
        os,
        user_agent: String::new(),
        sec_ch_ua: String::new(),
        sec_ch_ua_mobile: String::new(),
        sec_ch_ua_platform: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn saved_profile_accepts_go_partial_json() {
        let saved: SavedProfile =
            serde_json::from_str(r#"{"device_json":"{}","browser_fp":"0123456789abcdef"}"#)
                .unwrap();
        assert_eq!(saved.device_json, "{}");
        assert_eq!(saved.browser_fp, "0123456789abcdef");
        assert!(saved.user_agent.is_empty());
    }

    #[test]
    fn chrome_profiles_produce_diverse_versions_and_os_combinations() {
        assert_eq!(chrome_pool().len(), 25);
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            let profile = random_profile("chrome");
            seen.insert(format!("{:?}/{:?}", profile.impersonate, profile.os));
        }
        assert!(
            seen.len() >= 8,
            "Chrome diversity too low: only {} unique profiles: {:?}",
            seen.len(),
            seen
        );
    }

    #[test]
    fn firefox_profiles_produce_diverse_combinations() {
        assert_eq!(firefox_pool().len(), 20);
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            let profile = random_profile("firefox");
            seen.insert(format!("{:?}/{:?}", profile.impersonate, profile.os));
        }
        assert!(
            seen.len() >= 6,
            "Firefox diversity too low: only {} unique profiles: {:?}",
            seen.len(),
            seen
        );
    }

    #[test]
    fn safari_profiles_are_limited_to_apple_platforms() {
        assert_eq!(safari_pool().len(), 6);
        for _ in 0..1_000 {
            let profile = random_profile("safari");
            assert!(matches!(
                profile.os,
                ImpersonateOS::MacOS | ImpersonateOS::IOS
            ));
        }
    }

    #[test]
    fn edge_profiles_produce_diverse_combinations() {
        assert_eq!(edge_pool().len(), 25);
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            let profile = random_profile("edge");
            assert!(matches!(
                profile.impersonate,
                Impersonate::EdgeV144
                    | Impersonate::EdgeV145
                    | Impersonate::EdgeV146
                    | Impersonate::EdgeV147
                    | Impersonate::EdgeV148
            ));
            seen.insert(format!("{:?}/{:?}", profile.impersonate, profile.os));
        }
        assert!(seen.len() >= 8, "Edge diversity too low: {seen:?}");
    }

    #[test]
    fn opera_profiles_produce_diverse_combinations() {
        assert_eq!(opera_pool().len(), 30);
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            let profile = random_profile("opera");
            assert!(matches!(
                profile.impersonate,
                Impersonate::OperaV126
                    | Impersonate::OperaV127
                    | Impersonate::OperaV128
                    | Impersonate::OperaV129
                    | Impersonate::OperaV130
                    | Impersonate::OperaV131
            ));
            seen.insert(format!("{:?}/{:?}", profile.impersonate, profile.os));
        }
        assert!(seen.len() >= 8, "Opera diversity too low: {seen:?}");
    }

    #[test]
    fn default_fingerprint_is_chrome() {
        let profile = random_profile("anything");
        let name = format!("{:?}", profile.impersonate);
        assert!(
            name.contains("Chrome"),
            "Default fingerprint should be Chrome, got {name}"
        );
    }
}
