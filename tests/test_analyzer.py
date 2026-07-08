from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import tempfile
import unittest
import zipfile
import json
from pathlib import Path

from apksleuth.cli import main as cli_main
from apksleuth.core.analyzer import analyze_apk
from apksleuth.core.batch import run_batch_scan
from apksleuth.core.diff import diff_apks, render_diff
from apksleuth.core.report_generator import render_report
from apksleuth.core.string_extractor import extract_strings
from apksleuth.core.web import (
    WebConfig,
    _create_job,
    _delete_analysis,
    _job_payload,
    _parse_multipart,
    _recent_analyses,
    _render_analysis,
    _render_index,
    _render_job,
    _run_analysis_job,
    _split_local_paths,
    create_web_reports,
)


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo"
    android:versionName="1.2.0"
    android:versionCode="120">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:name=".DemoApp"
        android:label="Demo"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="demo" android:host="open" />
            </intent-filter>
        </activity>
        <activity-alias
            android:name=".DisabledAlias"
            android:targetActivity=".MainActivity"
            android:enabled="false"
            android:exported="true" />
        <provider android:name=".DemoProvider" android:authorities="com.example.demo.provider" />
    </application>
</manifest>
"""

MEDIA_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.media"
    android:versionName="1.0"
    android:versionCode="1">
    <application android:label="Media">
        <service android:name=".PlaybackService" android:exported="true">
            <intent-filter>
                <action android:name="android.media.browse.MediaBrowserService" />
            </intent-filter>
        </service>
        <receiver android:name=".MediaButtonReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MEDIA_BUTTON" />
            </intent-filter>
        </receiver>
        <activity android:name=".RouterActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

STANDARD_COMPONENT_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.standard"
    android:versionName="1.0"
    android:versionCode="1">
    <application android:label="Standard">
        <service android:name=".BrowserCustomTabsService" android:exported="true">
            <intent-filter>
                <action android:name="android.support.customtabs.action.CustomTabsService" />
            </intent-filter>
        </service>
        <service android:name=".CarAppService" android:exported="true">
            <intent-filter>
                <action android:name="androidx.car.app.CarAppService" />
            </intent-filter>
        </service>
        <service android:name=".TileService" android:exported="true" android:permission="android.permission.BIND_QUICK_SETTINGS_TILE" />
        <service android:name=".AutofillService" android:exported="true" android:permission="android.permission.BIND_AUTOFILL_SERVICE" />
        <provider android:name=".DocsProvider" android:exported="true" android:permission="android.permission.MANAGE_DOCUMENTS" android:authorities="com.example.standard.docs" />
        <provider android:name=".PublicFileProvider" android:exported="true" android:authorities="com.example.standard.fileprovider" />
        <receiver android:name=".WidgetProvider" android:exported="true">
            <intent-filter>
                <action android:name="android.appwidget.action.APPWIDGET_UPDATE" />
            </intent-filter>
        </receiver>
        <activity android:name=".ShareActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="text/plain" />
            </intent-filter>
        </activity>
        <activity android:name=".ShareAndDeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="text/plain" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="standard" android:host="open" />
            </intent-filter>
        </activity>
        <activity android:name=".FileViewActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="content" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

OLD_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo"
    android:versionName="1.0.0"
    android:versionCode="100">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="Demo" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

NEW_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo"
    android:versionName="1.1.0"
    android:versionCode="110">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:label="Demo" android:allowBackup="false" android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="demo" android:host="open" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


class AnalyzerTests(unittest.TestCase):
    def test_analyze_plain_xml_apk_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "demo.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", MANIFEST)
                apk.writestr("assets/config.json", '{"api_key":"abc123456789SECRET","url":"http://api.example.com/login"}')
                apk.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELFfake-binary")

            report = analyze_apk(apk_path)

        self.assertEqual(report.apk.package_name, "com.example.demo")
        self.assertEqual(report.apk.version_name, "1.2.0")
        self.assertIn("android.permission.READ_SMS", report.manifest.permissions)
        self.assertEqual(len(report.native_libraries), 1)
        self.assertTrue(any(item.id == "android-debuggable-enabled" for item in report.findings))
        self.assertTrue(any(item.id == "http-url-found" for item in report.findings))
        self.assertTrue(any(item.id == "hardcoded-secret" for item in report.findings))
        self.assertTrue(any(item.id == "exported-deep-link-activity" for item in report.findings))
        self.assertFalse(any("DisabledAlias" in item.evidence for item in report.findings))

        markdown = render_report(report, "markdown")
        self.assertIn("# ApkSleuth 分析报告", markdown)
        self.assertIn("com.example.demo", markdown)

        summary = render_report(report, "summary")
        self.assertIn("# ApkSleuth 简报", summary)
        self.assertIn("高危风险:", summary)
        self.assertIn("高置信风险项:", summary)
        self.assertIn("Deep Link", summary)
        self.assertIn("scheme=demo", summary)

        english_summary = render_report(report, "summary", language="en")
        self.assertIn("# ApkSleuth Brief Report", english_summary)
        self.assertIn("High findings:", english_summary)

        summary_json = json.loads(render_report(report, "summary-json"))
        self.assertEqual(summary_json["language"], "zh")
        self.assertEqual(summary_json["apk"]["package_name"], "com.example.demo")
        self.assertIn("confidence", summary_json)
        self.assertGreater(summary_json["confidence"]["high"], 0)
        self.assertEqual(summary_json["deep_link_samples"][0]["scheme"], "demo")
        self.assertEqual(summary_json["deep_link_samples"][0]["host"], "open")
        self.assertTrue(any(item["id"] == "exported-deep-link-activity" for item in summary_json["top_findings"]))
        self.assertTrue(all("confidence" in item for item in summary_json["top_findings"]))
        self.assertTrue(all("review_hint" in item for item in summary_json["top_findings"]))

        html = render_report(report, "html")
        self.assertIn("<!doctype html>", html)
        self.assertIn("ApkSleuth 分析报告", html)
        self.assertIn("id=\"finding-search\"", html)
        self.assertIn("id=\"finding-severity\"", html)
        self.assertIn("data-finding-row", html)
        self.assertIn("<details class=\"section\"", html)
        self.assertIn("可信度", html)
        self.assertIn("复核提示", html)
        self.assertIn("scheme=demo", html)

    def test_cli_logo_goes_to_stderr_without_polluting_report_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "cli.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", MANIFEST)

            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                cli_main(["scan", str(apk_path), "--format", "summary-json"])

        self.assertTrue(stdout.getvalue().lstrip().startswith("{"))
        self.assertIn("ApkSleuth v", stderr.getvalue())

    def test_string_extraction_filters_common_code_noise(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "noise.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", MANIFEST)
                apk.writestr(
                    "assets/app.js",
                    "password=o.password\n"
                    "apiKey:\"createBannerAd\"\n"
                    "secret:e.sdkSecret\n"
                    "api_key=abc123456789SECRET\n"
                    "password:'password-new'\n"
                    "url='http://api.example.com/login'\n",
                )
                apk.writestr("res/layout/noise.xml", b"http://schemas.android.com/apk/res/android\x00binary")
                apk.writestr("META-INF/LICENSE.txt", "http://www.apache.org/licenses/")
                apk.writestr("assets/logbox/static/js/app.LICENSE.txt", "http://opensource.org/licenses/MIT")
                apk.writestr("assets/fonts/licences/OFL.txt", "http://scripts.sil.org/OFL")
                apk.writestr("assets/composeResources/files/fonts/README-Font.txt", "http://font-readme.example.com")
                apk.writestr("assets/font.ttf", "http://fonts.example.com/noise")
                apk.writestr("assets/cacerts.bks", "http://crl.example.com/root.crl")
                apk.writestr("assets/apache2.html", "http://www.apache.org/licenses/")
                apk.writestr("assets/gpl_3.html", "http://www.gnu.org/licenses/gpl.html http://fsf.org/")
                apk.writestr("assets/icon.svg", "http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd")
                apk.writestr("google/protobuf/timestamp.proto", "http://protobuf.dev/programming-guides/enum/#java")
                apk.writestr("assets/docs/lua.txt", "http://lua-users.org/wiki/SandBoxes")
                apk.writestr("org/publicsuffix/list/effective_tld_names.dat", "http://cenpac.net.nr/dns/index.html")
                apk.writestr(
                    "res/M7.json",
                    '{"libraries":[{"uniqueId":"junit:junit","website":"http://junit.org","licenses":["EPL-1.0"]}]}',
                )
                apk.writestr("javax/annotation/concurrent/GuardedBy.java", "http://creativecommons.org/licenses/by/2.5 http://www.jcip.net")
                apk.writestr("org/apache/ftpserver/config/spring/ftpserver-1.0.xsd", "http://mina.apache.org/ftpserver/spring/v1")
                apk.writestr("assets/xml-docs.txt", "http://ns.adobe.com/xap/1.0/ http://xml.org/sax/features/external-general-entities http://xmlpull.org/v1/doc/features.html#indent-output")
                apk.writestr("res/0Q.md", "http://tools.ietf.org/html/rfc4880#section-5.2.1")
                apk.writestr("assets/templates/orgmode-reference.org", "http://google.com/][Google")
                apk.writestr("assets/prism/prism.js", "http://localhost/components/prism-core.js:119:5 http://stackoverflow.com/a/2008444")
                apk.writestr("assets/mermaid/mermaid.min.js", "http://engelschall.com http://commonmark.org/help/")
                apk.writestr("assets/third-party.js", "http://opensource.org/licenses/MIT")
                apk.writestr("assets/orgmode/org-bundle.js", "http://underscorejs.org/LICENSE http://daringfireball.net/2010/07/improved_regex_for_matching_urls http://orgmode.org/manual/Export-options.html")
                apk.writestr("assets/extensions/readerview/readability/readability-0.4.2.js", "http://blog.cdleary.com/2012/01/string-representation-in-spidermonkey/#ropes http://code.google.com/p/arc90labs-readability http://mobile.slate.com http://iovs.arvojournals.org/article.aspx?articleid=2166061")
                apk.writestr("org/pageseeder/diffx/xml/namespaces.properties", "http://www.allette.com.au")
                apk.writestr("assets/copyright.html", "http://antigrain.com/ http://www.boost.org/")
                apk.writestr("META-INF/htmlcompressor.tld", "http://htmlcompressor.googlecode.com/taglib/compressor http://java.sun.com/xml/ns/j2ee")
                apk.writestr("assets/index.android.bundle", "http://etherx.jabber.org/streams http://jabber.org/protocol/muc http://jitsi.org/jitmeet http://fb.me/use-check-prop-types")
                apk.writestr("com/ibm/icu/ICUConfig.properties", "http://www.unicode.org/copyright.html")
                apk.writestr("com/dropbox/core/trusted-certs.raw", "http://certificates.godaddy.com/repository/gdroot.crl0K http://ocsp.godaddy.com")
                apk.writestr("org/checkerframework/checker/interning/com-sun.astub", "http://www.certicom.com/2000/11/xmlecdsig#ecdsa-sha1 http://www.isi.edu/in-notes/iana/assignments/media-types/ http://www.xmlsecurity.org/NS/#configuration")

            with zipfile.ZipFile(apk_path) as apk:
                findings = extract_strings(apk)

        values = [item.value for item in findings]
        self.assertIn("api_key=abc123456789SECRET", values)
        self.assertIn("http://api.example.com/login", values)
        self.assertNotIn("password=o.password", values)
        self.assertNotIn("password:'password-new", values)
        self.assertNotIn('apiKey:"createBannerAd', values)
        self.assertFalse(any(value.startswith("http://schemas.android.com/") for value in values))
        self.assertNotIn("http://www.apache.org/licenses/", values)
        self.assertNotIn("http://opensource.org/licenses/MIT", values)
        self.assertNotIn("http://scripts.sil.org/OFL", values)
        self.assertNotIn("http://font-readme.example.com", values)
        self.assertNotIn("http://fonts.example.com/noise", values)
        self.assertNotIn("http://crl.example.com/root.crl", values)
        self.assertNotIn("http://www.apache.org/licenses/", values)
        self.assertNotIn("http://www.gnu.org/licenses/gpl.html", values)
        self.assertNotIn("http://fsf.org/", values)
        self.assertNotIn("http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd", values)
        self.assertNotIn("http://protobuf.dev/programming-guides/enum/#java", values)
        self.assertNotIn("http://lua-users.org/wiki/SandBoxes", values)
        self.assertNotIn("http://cenpac.net.nr/dns/index.html", values)
        self.assertNotIn("http://junit.org", values)
        self.assertNotIn("http://creativecommons.org/licenses/by/2.5", values)
        self.assertNotIn("http://www.jcip.net", values)
        self.assertNotIn("http://mina.apache.org/ftpserver/spring/v1", values)
        self.assertNotIn("http://ns.adobe.com/xap/1.0/", values)
        self.assertNotIn("http://xml.org/sax/features/external-general-entities", values)
        self.assertNotIn("http://xmlpull.org/v1/doc/features.html#indent-output", values)
        self.assertNotIn("http://tools.ietf.org/html/rfc4880#section-5.2.1", values)
        self.assertNotIn("http://google.com/][Google", values)
        self.assertNotIn("http://localhost/components/prism-core.js:119:5", values)
        self.assertNotIn("http://stackoverflow.com/a/2008444", values)
        self.assertNotIn("http://engelschall.com", values)
        self.assertNotIn("http://opensource.org/licenses/MIT", values)
        self.assertNotIn("http://commonmark.org/help/", values)
        self.assertNotIn("http://underscorejs.org/LICENSE", values)
        self.assertNotIn("http://daringfireball.net/2010/07/improved_regex_for_matching_urls", values)
        self.assertNotIn("http://orgmode.org/manual/Export-options.html", values)
        self.assertNotIn("http://blog.cdleary.com/2012/01/string-representation-in-spidermonkey/#ropes", values)
        self.assertNotIn("http://code.google.com/p/arc90labs-readability", values)
        self.assertNotIn("http://mobile.slate.com", values)
        self.assertNotIn("http://iovs.arvojournals.org/article.aspx?articleid=2166061", values)
        self.assertNotIn("http://www.allette.com.au", values)
        self.assertNotIn("http://antigrain.com/", values)
        self.assertNotIn("http://www.boost.org/", values)
        self.assertNotIn("http://htmlcompressor.googlecode.com/taglib/compressor", values)
        self.assertNotIn("http://java.sun.com/xml/ns/j2ee", values)
        self.assertNotIn("http://etherx.jabber.org/streams", values)
        self.assertNotIn("http://jabber.org/protocol/muc", values)
        self.assertNotIn("http://jitsi.org/jitmeet", values)
        self.assertNotIn("http://fb.me/use-check-prop-types", values)
        self.assertNotIn("http://www.unicode.org/copyright.html", values)
        self.assertNotIn("http://certificates.godaddy.com/repository/gdroot.crl0K", values)
        self.assertNotIn("http://ocsp.godaddy.com", values)
        self.assertNotIn("http://www.certicom.com/2000/11/xmlecdsig#ecdsa-sha1", values)
        self.assertNotIn("http://www.isi.edu/in-notes/iana/assignments/media-types/", values)
        self.assertNotIn("http://www.xmlsecurity.org/NS/#configuration", values)

    def test_media_components_are_low_risk_not_exported_service_noise(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "media.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", MEDIA_MANIFEST)

            report = analyze_apk(apk_path)

        finding_ids = [item.id for item in report.findings]
        self.assertEqual(finding_ids.count("exported-media-component"), 2)
        self.assertNotIn("exported-service", finding_ids)
        self.assertNotIn("exported-receiver", finding_ids)
        summary_json = json.loads(render_report(report, "summary-json"))
        self.assertEqual(summary_json["top_findings"][0]["id"], "exported-deep-link-activity")
        self.assertEqual(next(iter(summary_json["verdict"]["risk_drivers"])), "exported-deep-link-activity")

    def test_standard_exported_components_are_classified_precisely(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "standard.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", STANDARD_COMPONENT_MANIFEST)

            report = analyze_apk(apk_path)

        finding_ids = {item.id for item in report.findings}
        self.assertIn("exported-custom-tabs-service", finding_ids)
        self.assertIn("exported-car-service", finding_ids)
        self.assertIn("exported-quick-settings-tile", finding_ids)
        self.assertIn("exported-autofill-service", finding_ids)
        self.assertIn("exported-documents-provider", finding_ids)
        self.assertIn("exported-file-provider", finding_ids)
        self.assertIn("exported-widget-receiver", finding_ids)
        self.assertIn("exported-share-target-activity", finding_ids)
        self.assertIn("exported-file-handler-activity", finding_ids)
        self.assertTrue(any(item.id == "exported-deep-link-activity" and "ShareAndDeepLinkActivity" in item.evidence for item in report.findings))
        self.assertNotIn("exported-service", finding_ids)
        self.assertNotIn("exported-receiver", finding_ids)
        self.assertNotIn("exported-activity", finding_ids)

    def test_batch_scan_generates_index_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_dir = root / "apks"
            out_dir = root / "reports"
            apk_dir.mkdir()
            for name in ("one.apk", "two.apk"):
                with zipfile.ZipFile(apk_dir / name, "w") as apk:
                    apk.writestr("AndroidManifest.xml", MANIFEST)
                    apk.writestr("assets/config.json", '{"api_key":"abc123456789SECRET","url":"http://api.example.com/login"}')

            payload = run_batch_scan(apk_dir, out_dir, report_format="summary-json", language="zh")

            self.assertEqual(payload["total"], 2)
            self.assertEqual(payload["succeeded"], 2)
            self.assertTrue((out_dir / "index.md").exists())
            self.assertTrue((out_dir / "index.json").exists())
            self.assertEqual(len(list(out_dir.glob("*.summary.json"))), 2)
            index = json.loads((out_dir / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["risk_totals"]["high"], 6)
            self.assertEqual(index["risk_totals"]["medium"], 8)

    def test_diff_detects_version_permission_component_and_url_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_apk = root / "old.apk"
            new_apk = root / "new.apk"
            with zipfile.ZipFile(old_apk, "w") as apk:
                apk.writestr("AndroidManifest.xml", OLD_MANIFEST)
            with zipfile.ZipFile(new_apk, "w") as apk:
                apk.writestr("AndroidManifest.xml", NEW_MANIFEST)
                apk.writestr("assets/config.json", '{"url":"http://api.example.com/v2"}')

            payload = diff_apks(old_apk, new_apk)

        self.assertEqual(payload["old"]["version_name"], "1.0.0")
        self.assertEqual(payload["new"]["version_name"], "1.1.0")
        self.assertIn("android.permission.CAMERA", payload["permissions"]["added"])
        self.assertTrue(any(item["name"].endswith("DeepLinkActivity") for item in payload["components"]["added"]))
        self.assertIn("http://api.example.com/v2", payload["urls"]["added"])
        self.assertGreater(payload["risk"]["delta"]["high"], 0)

        summary = render_diff(payload, "summary", language="zh")
        self.assertIn("# ApkSleuth Diff 简报", summary)
        self.assertIn("android.permission.CAMERA", summary)

        diff_json = json.loads(render_diff(payload, "summary-json", language="zh"))
        self.assertEqual(diff_json["language"], "zh")
        self.assertEqual(diff_json["new"]["version_name"], "1.1.0")

    def test_web_report_generation_writes_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "web.apk"
            report_dir = root / "web-report"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", MANIFEST)
                apk.writestr("assets/config.json", '{"api_key":"abc123456789SECRET","url":"http://api.example.com/login"}')

            payload = create_web_reports(apk_path, report_dir, language="zh")

            self.assertEqual(payload["apk"]["package_name"], "com.example.demo")
            self.assertTrue((report_dir / "report.summary.md").exists())
            self.assertTrue((report_dir / "report.summary.json").exists())
            self.assertTrue((report_dir / "report.html").exists())
            self.assertTrue((report_dir / "report.json").exists())

    def test_web_analysis_page_renders_interactive_details(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "details.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", MANIFEST)
                apk.writestr("assets/config.json", '{"api_key":"abc123456789SECRET","url":"http://api.example.com/login"}')

            config = WebConfig(workdir=root / "web")
            report_dir = config.workdir / "reports" / "details-1"
            create_web_reports(apk_path, report_dir, language="zh")

            html = _render_analysis(config, "details-1")

        self.assertIn('id="analysis-search"', html)
        self.assertIn('id="analysis-severity"', html)
        self.assertIn("data-analysis-finding-row", html)
        self.assertIn("导出组件样例", html)
        self.assertIn("HTTP URL 样例", html)
        self.assertIn("疑似密钥样例", html)
        self.assertIn("Deep Link 样例", html)
        self.assertIn("高危权限", html)
        self.assertIn("优先修复建议", html)
        self.assertIn("主要风险项", html)
        self.assertIn("高置信风险项", html)
        self.assertIn("可信度", html)
        self.assertIn("复核提示", html)
        self.assertIn("api.example.com/login", html)
        self.assertIn("com.example.demo.MainActivity", html)
        self.assertIn("demo", html)
        self.assertIn("open", html)

    def test_web_background_job_updates_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "job.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("AndroidManifest.xml", MANIFEST)
                apk.writestr("assets/config.json", '{"url":"http://api.example.com/login"}')

            config = WebConfig(workdir=root / "web")
            report_dir = config.workdir / "reports" / "job-1"
            _create_job(config, "job-1", apk_path.name, report_dir)
            self.assertEqual(_job_payload(config, "job-1")["status"], "pending")

            _run_analysis_job(config, "job-1", apk_path, report_dir)

            payload = _job_payload(config, "job-1")
            self.assertEqual(payload["status"], "done")
            self.assertEqual(payload["analysis_url"], "/analysis/job-1")
            self.assertTrue((report_dir / "report.summary.json").exists())
            html = _render_job(config, "job-1")
            self.assertIn("/api/jobs/job-1", html)
            self.assertIn("正在分析 APK", html)

    def test_web_history_supports_search_sort_and_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WebConfig(workdir=root / "web")
            report_dir = config.workdir / "reports" / "history-1"
            report_dir.mkdir(parents=True)
            summary = {
                "tool": {"generated_at": "2026-07-07T06:44:01+00:00"},
                "apk": {
                    "file_name": "demo.apk",
                    "app_name": "Demo",
                    "package_name": "com.example.demo",
                    "version_name": "1.2.0",
                    "version_code": "120",
                    "sha256": "abc123",
                },
                "risk": {"total": 7, "high": 2, "medium": 3, "low": 2},
                "top_findings": [
                    {"id": "exported-service", "title": "导出 Service 未受权限保护", "severity": "high", "severity_label": "高危"}
                ],
            }
            (report_dir / "report.summary.json").write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")

            analyses = _recent_analyses(config)
            html = _render_index(config)

            self.assertEqual(len(analyses), 1)
            self.assertEqual(analyses[0]["high"], 2)
            self.assertIn("exported-service", analyses[0]["search_text"])
            self.assertIn('id="history-search"', html)
            self.assertIn('id="history-sort"', html)
            self.assertIn('data-high="2"', html)
            self.assertIn('action="/delete/history-1"', html)
            self.assertIn('name="apk" accept=".apk,application/vnd.android.package-archive" multiple', html)
            self.assertIn("<textarea name=\"apk_path\"", html)

            self.assertTrue(_delete_analysis(config, "history-1"))
            self.assertFalse(report_dir.exists())

    def test_web_batch_upload_helpers_and_active_jobs(self) -> None:
        boundary = b"test-boundary"
        body = b"\r\n".join(
            [
                b"--test-boundary",
                b'Content-Disposition: form-data; name="apk"; filename="one.apk"',
                b"",
                b"one",
                b"--test-boundary",
                b'Content-Disposition: form-data; name="apk"; filename="two.apk"',
                b"",
                b"two",
                b"--test-boundary--",
                b"",
            ]
        )

        fields, files = _parse_multipart(body, boundary)

        self.assertEqual(fields, {})
        self.assertEqual([item["filename"] for item in files["apk"]], ["one.apk", "two.apk"])
        self.assertEqual(_split_local_paths('C:\\one.apk\r\n"C:\\two.apk"'), ["C:\\one.apk", "C:\\two.apk"])

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WebConfig(workdir=root / "web")
            first = root / "one.apk"
            second = root / "two.apk"
            first.write_bytes(b"apk")
            second.write_bytes(b"apk")
            _create_job(config, "job-one", first.name, config.workdir / "reports" / "job-one", first)
            _create_job(config, "job-two", second.name, config.workdir / "reports" / "job-two", second)

            html = _render_index(config)

        self.assertIn("当前任务", html)
        self.assertIn("data-active-job-row", html)
        self.assertIn("/api/jobs/${jobId}", html)
        self.assertIn('data-job-id="job-one"', html)
        self.assertIn("one.apk", html)

    def test_web_delete_removes_only_managed_upload_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = WebConfig(workdir=root / "web")
            uploads = config.workdir / "uploads"
            uploads.mkdir(parents=True)
            upload_path = uploads / "1234567890-abcdef12-demo.apk"
            upload_path.write_bytes(b"apk")
            report_dir = config.workdir / "reports" / "upload-job"

            _create_job(config, "upload-job", upload_path.name, report_dir, upload_path)

            self.assertTrue((report_dir / "metadata.json").exists())
            self.assertFalse(_delete_analysis(config, ""))
            self.assertTrue(report_dir.exists())
            self.assertTrue(_delete_analysis(config, "upload-job"))
            self.assertFalse(report_dir.exists())
            self.assertFalse(upload_path.exists())

            local_apk = root / "local.apk"
            local_apk.write_bytes(b"apk")
            local_report_dir = config.workdir / "reports" / "local-job"
            _create_job(config, "local-job", local_apk.name, local_report_dir, local_apk)

            self.assertTrue(_delete_analysis(config, "local-job"))
            self.assertTrue(local_apk.exists())


if __name__ == "__main__":
    unittest.main()
