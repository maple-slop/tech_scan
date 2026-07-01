from __future__ import annotations

from tech_scan.models import DIM_CMS

from .common import (
    Rule,
    any_detector,
    body_detector,
    cookie_name_detector,
    embedded_url_detector,
    global_detector,
    header_detector,
    meta_detector,
    script_url_detector,
)


RULES = [
    Rule("WordPress", DIM_CMS, 95, meta_detector("generator", r"^wordpress(?:\s|$)", "wordpress generator meta")),
    Rule("WordPress", DIM_CMS, 90, header_detector("link", r"api\.w\.org|wp-json")),
    Rule("WordPress", DIM_CMS, 90, header_detector("x-pingback", r"/xmlrpc\.php$")),
    Rule("WordPress", DIM_CMS, 90, header_detector("x-powered-by", r"\bwordpress\b")),
    Rule("WordPress", DIM_CMS, 90, cookie_name_detector(r"wordpress_(?:logged_in|sec|test_cookie)|wp-settings")),
    Rule("WordPress", DIM_CMS, 85, any_detector(
        body_detector(r"/wp-(?:content|includes)/|wp-embed(?:\.min)?\.js", "wordpress asset marker", True),
        script_url_detector(r"/wp-(?:content|includes)/|wp-embed(?:\.min)?\.js"),
    )),
    Rule("WordPress", DIM_CMS, 75, embedded_url_detector(r"/(?:wp-json|wp-admin|wp-content|wp-includes)/|/xmlrpc\.php(?:[?#]|$)")),
    Rule("Drupal", DIM_CMS, 95, meta_detector("generator", r"^drupal(?:\s|$)", "drupal generator meta")),
    Rule("Drupal", DIM_CMS, 95, header_detector("x-generator", r"^drupal(?:\s|$)")),
    Rule("Drupal", DIM_CMS, 90, header_detector("x-drupal-cache", r".*")),
    Rule("Drupal", DIM_CMS, 90, cookie_name_detector(r"S?SESS[a-f0-9]{32}")),
    Rule("Drupal", DIM_CMS, 85, any_detector(
        body_detector(r"drupalSettings|data-drupal-selector|/sites/(?:default|all)/(?:files|themes|modules)/|/core/misc/drupal", "drupal asset/settings marker", True),
        script_url_detector(r"/core/misc/drupal|drupal(?:\.min)?\.js"),
    )),
    Rule("Joomla", DIM_CMS, 95, meta_detector("generator", r"joomla!", "joomla generator meta")),
    Rule("Joomla", DIM_CMS, 95, header_detector("x-content-encoded-by", r"joomla!")),
    Rule("Joomla", DIM_CMS, 85, any_detector(
        body_detector(r"/components/com_|/media/system/js/|Joomla\.", "joomla asset marker", True),
        script_url_detector(r"/components/com_|/media/system/js/|joomla(?:\.min)?\.js"),
        global_detector(r"^Joomla$|jcomments"),
    )),
    Rule("TYPO3", DIM_CMS, 95, meta_detector("generator", r"typo3\s+(?:cms\s+)?", "typo3 generator meta")),
    Rule("TYPO3", DIM_CMS, 85, any_detector(
        body_detector(r"typo3(?:conf|temp)/|/typo3/sysext/|TYPO3\.settings", "typo3 asset/settings marker", True),
        script_url_detector(r"typo3(?:conf|temp)/|/typo3/sysext/"),
    )),
    Rule("Liferay", DIM_CMS, 95, header_detector("liferay-portal", r".+")),
    Rule("Liferay", DIM_CMS, 90, cookie_name_detector(r"GUEST_LANGUAGE_ID|COMPANY_ID|LFR_SESSION_STATE_")),
    Rule("Liferay", DIM_CMS, 90, global_detector(r"^Liferay$")),
    Rule("Liferay", DIM_CMS, 85, body_detector(r"Liferay\.(?:ThemeDisplay|currentURL|getCookie)|/o/(?:[^/]+/)?(?:css|js|combo)", "liferay marker", True)),
    Rule("Magento", DIM_CMS, 90, cookie_name_detector(r"mage-cache-|mage-translation-|x-magento-vary")),
    Rule("Magento", DIM_CMS, 90, any_detector(
        body_detector(r"text/x-magento-init|Mage\.Cookies|data-requiremodule=[\"'][^\"']*(?:mage/|Magento_)|/static/version\d+/frontend/", "magento marker", True),
        script_url_detector(r"/js/mage/|/static/_requirejs/|/static/version\d+/frontend/"),
        global_detector(r"^Mage$|^VarienForm$"),
    )),
    Rule("Shopware", DIM_CMS, 95, meta_detector("application-name", r"shopware", "shopware application meta")),
    Rule("Shopware", DIM_CMS, 90, header_detector("sw-context-token", r"^[a-f0-9]{32}$")),
    Rule("Shopware", DIM_CMS, 85, any_detector(
        body_detector(r"/engine/shopware/|/bundles/storefront/|Shopware\.", "shopware marker", True),
        script_url_detector(r"/engine/shopware/|/bundles/storefront/|jquery\.shopware(?:\.min)?\.js"),
    )),
    Rule("Adobe Experience Manager", DIM_CMS, 90, any_detector(
        body_detector(r"/etc(?:\.clientlibs|/clientlibs)/|/etc/designs/|data-component-path=[\"'][^\"']*jcr:|aem-grid|parbase", "aem marker", True),
        script_url_detector(r"/etc(?:\.clientlibs|/clientlibs)/|/etc/designs/"),
    )),
    Rule("Sitecore", DIM_CMS, 90, cookie_name_detector(r"sc_(?:analytics_global_cookie|expview|os_sessionid)|sxa_site")),
    Rule("Sitecore", DIM_CMS, 85, any_detector(
        body_detector(r"/-/media/|/_sitecore/|SitecoreUtilities", "sitecore marker", True),
        script_url_detector(r"/_sitecore/"),
        global_detector(r"SitecoreUtilities"),
    )),
    Rule("Umbraco", DIM_CMS, 95, header_detector("x-umbraco-version", r".+")),
    Rule("Umbraco", DIM_CMS, 95, meta_detector("generator", r"umbraco", "umbraco generator meta")),
    Rule("Umbraco", DIM_CMS, 85, any_detector(
        body_detector(r"/umbraco/(?:api|surface|backoffice)/|/UmbracoForms/|umb://", "umbraco marker", True),
        script_url_detector(r"/umbraco/(?:api|surface|backoffice)/|/UmbracoForms/"),
        global_detector(r"^Umbraco$|UC_(?:IMAGE_SERVICE|SETTINGS|ITEM_INFO_SERVICE)"),
    )),
    Rule("Ghost", DIM_CMS, 95, meta_detector("generator", r"ghost(?:\s|$)", "ghost generator meta")),
    Rule("Ghost", DIM_CMS, 95, header_detector("x-ghost-cache-status", r".*")),
    Rule("Webflow", DIM_CMS, 95, meta_detector("generator", r"webflow", "webflow generator meta")),
    Rule("Webflow", DIM_CMS, 90, any_detector(
        body_detector(r"<html[^>]+data-wf-(?:site|page)=|webflow(?:\.min)?\.js", "webflow marker", True),
        script_url_detector(r"webflow(?:\.min)?\.js"),
        global_detector(r"^Webflow$"),
    )),
    Rule("Craft CMS", DIM_CMS, 95, header_detector("x-powered-by", r"\bcraft cms\b")),
    Rule("Craft CMS", DIM_CMS, 90, cookie_name_detector(r"CraftSessionId|CRAFT_CSRF_TOKEN")),
    Rule("Sitefinity", DIM_CMS, 95, header_detector("x-powered-by", r"\bsitefinity\b")),
    Rule("Sitefinity", DIM_CMS, 90, any_detector(
        body_detector(r"Telerik\.Sitefinity|/Sitefinity/|sf_[a-z0-9_-]+", "sitefinity marker", True),
        script_url_detector(r"/Sitefinity/"),
    )),
]
