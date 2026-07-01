from __future__ import annotations

from tech_scan.models import DIM_FRONTEND

from .common import (
    Rule,
    any_detector,
    body_detector,
    global_detector,
    header_detector,
    meta_detector,
    script_body_detector,
    script_url_detector,
)


RULES = [
    Rule("React", DIM_FRONTEND, 80, any_detector(
        body_detector(r"data-reactroot|react-dom", "react script/html marker", True),
        script_body_detector(r"react-dom|React\.createElement|ReactDOM\.render|__REACT_DEVTOOLS_GLOBAL_HOOK__", "script body"),
        script_url_detector(r"react(?:\.production)?(?:\.min)?\.js|react-dom(?:\.production)?(?:\.min)?\.js"),
    )),
    Rule("React", DIM_FRONTEND, 75, global_detector(r"React")),
    Rule("Vue.js", DIM_FRONTEND, 80, any_detector(
        body_detector(r"data-v-[a-f0-9]+|__vue__", "vue script/html marker", True),
        script_body_detector(r"Vue\.config|Vue\.component|createApp\(|__VUE__", "script body"),
        script_url_detector(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js"),
    )),
    Rule("Vue.js", DIM_FRONTEND, 75, global_detector(r"Vue")),
    Rule("Preact", DIM_FRONTEND, 80, any_detector(
        body_detector(r"\bpreact/(?:hooks|compat|jsx-runtime)\b|@preact/|preact-render-to-string", "preact package marker", True),
        script_body_detector(r"\bpreact/(?:hooks|compat|jsx-runtime)\b|@preact/|__PREACT_DEVTOOLS__|options\.__[a-z]", "script body"),
        script_url_detector(r"(?:^|[/-])preact(?:[.-]|/)|@preact/"),
    )),
    Rule("Preact", DIM_FRONTEND, 75, global_detector(r"preact|__PREACT_DEVTOOLS__")),
    Rule("SolidJS", DIM_FRONTEND, 80, any_detector(
        body_detector(r"\bsolid-js/(?:web|store|html)\b|data-hk=", "solidjs marker", True),
        script_body_detector(r"\bsolid-js(?:/(?:web|store|html))?\b|_\$HY\b|_\$PROXY\b|delegateEvents\(|createComponent\(", "script body"),
        script_url_detector(r"solid-js(?:[./-]|$)|solid(?:[.-]js)?(?:[.-](?:web|store)|[./-])"),
    )),
    Rule("SolidJS", DIM_FRONTEND, 75, global_detector(r"Solid|_\$HY|_\$PROXY")),
    Rule("Angular", DIM_FRONTEND, 80, any_detector(
        body_detector(r"<[^>]+\sng-version(?:[\s=>]|$)|<[^>]+\sng-app(?:[\s=>]|$)", "angular html attribute marker", True),
        script_body_detector(r"@angular/core|ng\.core|platformBrowserDynamic", "script body"),
        script_url_detector(r"angular(?:\.min)?\.js"),
    )),
    Rule("Angular", DIM_FRONTEND, 75, global_detector(r"Angular")),
    Rule("AngularJS", DIM_FRONTEND, 85, any_detector(
        body_detector(r"<(?:div|html)[^>]+ng-app=|<ng-app", "angularjs marker", True),
        script_body_detector(r"angular\.module|angular\.element|ng-app", "script body"),
        script_url_detector(r"angular(?:\.min)?\.js"),
    )),
    Rule("AngularJS", DIM_FRONTEND, 75, global_detector(r"^angular$|angular\.version")),
    Rule("Alpine.js", DIM_FRONTEND, 80, any_detector(
        body_detector(r"\bx-data\b", "alpine marker", True),
        script_body_detector(r"Alpine\.data|Alpine\.store|x-data", "script body"),
        script_url_detector(r"alpine(?:\.min)?\.js"),
    )),
    Rule("Alpine.js", DIM_FRONTEND, 75, global_detector(r"Alpine")),
    Rule("Astro", DIM_FRONTEND, 85, any_detector(
        meta_detector("generator", r"^astro\s+v?[\d.]+", "astro generator meta"),
        body_detector(r"astro-island|data-astro-cid-|/_astro/", "astro marker", True),
        script_url_detector(r"/_astro/"),
    )),
    Rule("Astro", DIM_FRONTEND, 75, global_detector(r"Astro")),
    Rule("Stimulus", DIM_FRONTEND, 80, body_detector(r"data-controller=", "stimulus controller marker")),
    Rule("htmx", DIM_FRONTEND, 80, any_detector(
        body_detector(r"\bhx-[a-z-]+=|htmx(?:\.min)?\.js|htmx\.org@", "htmx html marker", True),
        script_body_detector(r"htmx\.defineExtension|htmx\.process|htmx\.org@", "script body"),
        script_url_detector(r"htmx(?:\.min)?\.js"),
    )),
    Rule("htmx", DIM_FRONTEND, 75, global_detector(r"^htmx$")),
    Rule("Qwik", DIM_FRONTEND, 90, any_detector(
        body_detector(r"\sq:(?:render|container|version|base|manifest-hash|instance)=", "qwik html attribute marker", True),
        script_body_detector(r"\bqrl\b|_qwikjson_|qDev|qRuntimeQrl|q:container", "script body"),
        script_url_detector(r"/build/q-[A-Za-z0-9_-]+\.js|@builder\.io/qwik|qwik(?:\.min)?\.js"),
    )),
    Rule("Qwik", DIM_FRONTEND, 75, global_detector(r"Qwik|qwik")),
    Rule("Polymer", DIM_FRONTEND, 80, any_detector(
        body_detector(r"<polymer-[^>]+|/polymer\.html", "polymer marker", True),
        script_body_detector(r"Polymer\(|Polymer\.Element", "script body"),
        script_url_detector(r"polymer\.js"),
    )),
    Rule("Polymer", DIM_FRONTEND, 75, global_detector(r"Polymer")),
    Rule("Svelte", DIM_FRONTEND, 75, any_detector(
        body_detector(r"__svelte", "svelte marker", True),
        script_body_detector(r"new\s+[A-Za-z_$][\w$]*\s*\(\s*\{\s*target:|svelte/internal", "script body"),
    )),
    Rule("Svelte", DIM_FRONTEND, 75, global_detector(r"Svelte")),
    Rule("SvelteKit", DIM_FRONTEND, 85, any_detector(
        meta_detector("generator", r"sveltekit", "sveltekit generator meta"),
        body_detector(r"/_app/immutable/|data-sveltekit-", "sveltekit marker", True),
        script_url_detector(r"/_app/immutable/"),
    )),
    Rule("Next.js", DIM_FRONTEND, 90, any_detector(
        header_detector("x-powered-by", r"\bnext\.js\b"),
        body_detector(r"/_next/|__NEXT_DATA__|window\.__NEXT", "next.js marker", True),
        script_body_detector(r"__NEXT_DATA__|self\.__BUILD_MANIFEST|next/dist", "script body"),
        script_url_detector(r"/_next/"),
    )),
    Rule("Next.js", DIM_FRONTEND, 75, global_detector(r"__NEXT")),
    Rule("Nuxt", DIM_FRONTEND, 90, any_detector(
        body_detector(r"/_nuxt/|__NUXT__|window\.__NUXT", "nuxt marker", True),
        script_body_detector(r"__NUXT__|window\.__NUXT|nuxt\.config", "script body"),
        script_url_detector(r"/_nuxt/"),
    )),
    Rule("Nuxt", DIM_FRONTEND, 75, global_detector(r"__NUXT")),
    Rule("Remix", DIM_FRONTEND, 80, any_detector(
        body_detector(r"__remixContext|id=[\"']rmx-data[\"']|@remix-run", "remix marker", True),
        script_body_detector(r"__remixContext|@remix-run", "script body"),
        global_detector(r"__remixContext"),
    )),
    Rule("Gatsby", DIM_FRONTEND, 85, any_detector(
        body_detector(r"___gatsby|gatsby-browser|gatsby-focus-wrapper", "gatsby marker", True),
        script_body_detector(r"___gatsby|gatsby-browser|webpackJsonp.*gatsby", "script body"),
        script_url_detector(r"gatsby-(?:browser|app)|/page-data/"),
    )),
    Rule("jQuery", DIM_FRONTEND, 80, any_detector(
        body_detector(r"window\.jQuery", "jquery script/global", True),
        script_body_detector(r"jQuery\.fn\.jquery|\$\.fn\.jquery", "script body"),
        script_url_detector(r"jquery(?:-[0-9.]+)?(?:\.min)?\.js"),
    )),
    Rule("jQuery", DIM_FRONTEND, 75, global_detector(r"jQuery")),
]
