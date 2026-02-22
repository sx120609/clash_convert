from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AclPreset:
    id: str
    label: str
    url: str


# Presets are aligned with ACL4SSR-sub common online options.
ACL_PRESETS: list[AclPreset] = [
    AclPreset(
        id="mesl_rules",
        label="MESL规则",
        url="https://em.mesl.cloud/ems/get?token=ffeafd47122ab3fe52682c39725b7ac5&flag=clash",
    ),
    AclPreset(
        id="acl4ssr_online_default",
        label="ACL4SSR_Online 默认版",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini",
    ),
    AclPreset(
        id="acl4ssr_online_adblockplus",
        label="ACL4SSR_Online_AdblockPlus 更多去广告",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_AdblockPlus.ini",
    ),
    AclPreset(
        id="acl4ssr_online_multicountry",
        label="ACL4SSR_Online_MultiCountry 多国分组",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_MultiCountry.ini",
    ),
    AclPreset(
        id="acl4ssr_online_noauto",
        label="ACL4SSR_Online_NoAuto 无自动测速",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoAuto.ini",
    ),
    AclPreset(
        id="acl4ssr_online_noreject",
        label="ACL4SSR_Online_NoReject 无广告拦截",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoReject.ini",
    ),
    AclPreset(
        id="acl4ssr_online_mini",
        label="ACL4SSR_Online_Mini 精简版",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini",
    ),
    AclPreset(
        id="acl4ssr_online_mini_adblockplus",
        label="ACL4SSR_Online_Mini_AdblockPlus 精简去广告",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_AdblockPlus.ini",
    ),
    AclPreset(
        id="acl4ssr_online_mini_noauto",
        label="ACL4SSR_Online_Mini_NoAuto 精简无测速",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_NoAuto.ini",
    ),
    AclPreset(
        id="acl4ssr_online_mini_fallback",
        label="ACL4SSR_Online_Mini_Fallback 精简故障转移",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_Fallback.ini",
    ),
    AclPreset(
        id="acl4ssr_online_mini_multimode",
        label="ACL4SSR_Online_Mini_MultiMode 精简多模式",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini",
    ),
    AclPreset(
        id="acl4ssr_online_mini_multicountry",
        label="ACL4SSR_Online_Mini_MultiCountry 精简多国",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiCountry.ini",
    ),
    AclPreset(
        id="acl4ssr_online_full",
        label="ACL4SSR_Online_Full 全分组",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini",
    ),
    AclPreset(
        id="acl4ssr_online_full_multimode",
        label="ACL4SSR_Online_Full_MultiMode 全分组多模式",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_MultiMode.ini",
    ),
    AclPreset(
        id="acl4ssr_online_full_noauto",
        label="ACL4SSR_Online_Full_NoAuto 全分组无测速",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini",
    ),
    AclPreset(
        id="acl4ssr_online_full_adblockplus",
        label="ACL4SSR_Online_Full_AdblockPlus 全分组去广告",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_AdblockPlus.ini",
    ),
    AclPreset(
        id="acl4ssr_online_full_netflix",
        label="ACL4SSR_Online_Full_Netflix 全分组奈飞",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Netflix.ini",
    ),
    AclPreset(
        id="acl4ssr_online_full_google",
        label="ACL4SSR_Online_Full_Google 全分组谷歌细分",
        url="https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_Google.ini",
    ),
]

ACL_PRESET_MAP: dict[str, AclPreset] = {item.id: item for item in ACL_PRESETS}
