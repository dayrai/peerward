const CONSOLE_EN_US: &str = include_str!("../i18n/en-US.ftl");
const CONSOLE_ZH_CN: &str = include_str!("../i18n/zh-CN.ftl");

fn console_message(locale: Locale, key: &str) -> &'static str {
    let catalog = match locale {
        Locale::ZhCn => CONSOLE_ZH_CN,
        Locale::EnUs => CONSOLE_EN_US,
    };
    catalog
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(candidate, value)| (candidate.trim() == key).then(|| value.trim()))
        .unwrap_or("missing-translation")
}

#[cfg(test)]
fn console_catalog_complete() -> bool {
    let keys = |catalog: &'static str| {
        catalog
            .lines()
            .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim()))
            .collect::<std::collections::BTreeSet<_>>()
    };
    keys(CONSOLE_EN_US) == keys(CONSOLE_ZH_CN)
}
