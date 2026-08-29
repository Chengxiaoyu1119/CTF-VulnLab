"""Browser-level smoke and responsive check for the VulnLab web app."""

from __future__ import annotations

import os
import json
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


BASE_URL = os.environ.get("VULNLAB_BASE_URL", "http://127.0.0.1:6710")
OUTPUT_DIR = Path(os.environ.get("VULNLAB_SCREENSHOT_DIR", tempfile.mkdtemp(prefix="vulnlab-browser-")))
PRIMARY_SCREENSHOT = os.environ.get("VULNLAB_PRIMARY_SCREENSHOT")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        # Desktop reference viewport for the fixed 3×3 workspace.
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        console_errors: list[str] = []
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: console_errors.append(str(error)))
        page.goto(BASE_URL, wait_until="networkidle")
        expect(page.get_by_role("heading", name="进入靶场", exact=True)).to_be_visible()
        expect(page.get_by_text("安装、启动和管理本机靶场。", exact=True)).to_have_count(0)
        expect(page.get_by_label("账号")).to_have_value("")
        expect(page.get_by_label("密码")).to_have_value("")
        page.get_by_role("button", name="登录").click()
        expect(page.locator("#login-notice")).to_contain_text("登录失败")
        expect(page.locator("#login-notice")).to_contain_text("请输入账号和密码")
        expect(page.locator(".login-notice-icon")).to_have_count(0)
        expect(page.get_by_role("button", name="关闭提示")).to_be_visible()
        notice_style = page.locator("#login-notice").evaluate(
            "element => ({ position: getComputedStyle(element).position, top: getComputedStyle(element).top, right: getComputedStyle(element).right, width: getComputedStyle(element).width, height: getComputedStyle(element).height, borderRadius: getComputedStyle(element).borderRadius, borderColor: getComputedStyle(element).borderColor, backgroundColor: getComputedStyle(element).backgroundColor, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert notice_style["position"] == "fixed", notice_style
        assert notice_style["top"] == "22px", notice_style
        assert float(notice_style["width"].replace("px", "")) <= 304, notice_style
        assert float(notice_style["height"].replace("px", "")) <= 68, notice_style
        assert notice_style["borderRadius"] == "14px", notice_style
        assert notice_style["borderColor"] == "rgb(224, 233, 240)", notice_style
        assert notice_style["backgroundColor"] == "rgb(255, 255, 255)", notice_style
        assert notice_style["boxShadow"] != "none", notice_style
        assert page.locator(".login-form input[aria-invalid='true']").evaluate_all(
            "elements => elements.every(element => getComputedStyle(element).borderColor !== 'rgb(201, 80, 74)')"
        )
        page.screenshot(path=str(OUTPUT_DIR / "login-notice-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        expect(page.locator("#login-notice")).to_be_visible()
        notice_box = page.locator("#login-notice").bounding_box()
        brand_box = page.locator(".login-mark").bounding_box()
        assert notice_box and brand_box and (
            notice_box["x"] >= brand_box["x"] + brand_box["width"]
            or brand_box["x"] >= notice_box["x"] + notice_box["width"]
            or notice_box["y"] >= brand_box["y"] + brand_box["height"]
            or brand_box["y"] >= notice_box["y"] + notice_box["height"]
        ), {"notice": notice_box, "brand": brand_box}
        page.screenshot(path=str(OUTPUT_DIR / "login-notice-mobile.png"), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 900})
        page.get_by_role("button", name="关闭提示").click()
        expect(page.locator("#login-notice")).to_have_count(0)
        page.get_by_role("button", name="登录").click()
        expect(page.locator("#login-notice")).to_be_visible()
        page.wait_for_timeout(4500)
        expect(page.locator("#login-notice")).to_have_count(0)
        page.get_by_role("button", name="登录").click()
        expect(page.locator("#login-notice")).to_be_visible()
        page.get_by_label("账号").fill("v")
        expect(page.locator("#login-notice")).to_have_count(0)
        expect(page.get_by_role("heading", name="进入靶场", exact=True)).to_be_visible()
        page.get_by_label("账号").focus()
        login_input_style = page.get_by_label("账号").evaluate(
            "element => ({ borderColor: getComputedStyle(element).borderColor, boxShadow: getComputedStyle(element).boxShadow, outline: getComputedStyle(element).outlineStyle })"
        )
        assert login_input_style["borderColor"] != "rgb(61, 91, 194)", login_input_style
        assert login_input_style["boxShadow"] == "none", login_input_style
        assert login_input_style["outline"] == "none", login_input_style
        page.get_by_label("账号").fill("vulnlab")
        page.get_by_label("密码").fill("vulnlab")
        page.get_by_role("button", name="登录").click()
        expect(page.locator("#login-success-notice")).to_contain_text("登录成功")
        expect(page.locator("#login-success-notice")).to_contain_text("身份验证通过，正在进入系统")
        success_notice_style = page.locator("#login-success-notice").evaluate(
            "element => ({ position: getComputedStyle(element).position, backgroundColor: getComputedStyle(element).backgroundColor, borderRadius: getComputedStyle(element).borderRadius, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert success_notice_style["position"] == "fixed", success_notice_style
        assert success_notice_style["backgroundColor"] == "rgb(255, 255, 255)", success_notice_style
        assert success_notice_style["borderRadius"] == "14px", success_notice_style
        assert success_notice_style["boxShadow"] != "none", success_notice_style
        page.screenshot(path=str(OUTPUT_DIR / "login-success-notice-desktop.png"), full_page=True)
        expect(page.get_by_text("DVWA", exact=True)).to_have_count(1)
        expect(page.locator(".labs-screen")).to_be_visible()
        page.set_viewport_size({"width": 390, "height": 844})
        success_box = page.locator("#login-success-notice").bounding_box()
        ascii_box = page.locator(".runtime-ascii").bounding_box()
        assert success_box and ascii_box and (
            success_box["x"] >= ascii_box["x"] + ascii_box["width"]
            or ascii_box["x"] >= success_box["x"] + success_box["width"]
            or success_box["y"] >= ascii_box["y"] + ascii_box["height"]
            or ascii_box["y"] >= success_box["y"] + success_box["height"]
        ), {"notice": success_box, "ascii": ascii_box}
        expect(page.locator(".lab-workspace-head")).to_have_count(0)
        page.set_viewport_size({"width": 1440, "height": 900})
        expect(page.locator(".labs-screen .topbar")).to_have_count(0)
        expect(page.locator(".labs-screen .main-content")).to_have_count(0)
        expect(page.get_by_role("complementary", name="运行状态")).to_be_visible()
        workspace_backgrounds = page.locator(".labs-screen, .runtime-panel, .lab-workspace, .lab-canvas").evaluate_all(
            "elements => elements.map(element => getComputedStyle(element).backgroundColor)"
        )
        assert workspace_backgrounds and all(color == "rgb(255, 255, 255)" for color in workspace_backgrounds), workspace_backgrounds
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        page.wait_for_timeout(4500)
        expect(page.locator("#login-success-notice")).to_have_count(0)
        expect(page.get_by_role("button", name="退出登录")).to_have_text("vulnlab")
        expect(page.locator(".workspace-nav, .workspace-account, .lab-workspace-head")).to_have_count(0)
        expect(page.locator(".runtime-ascii")).to_be_visible()
        expect(page.locator(".runtime-ascii")).to_contain_text("____ _")
        assert "9/9" not in page.locator(".runtime-log").inner_text()
        expect(page.locator(".runtime-signals")).to_have_count(0)
        expect(page.locator(".runtime-log-head")).to_have_count(0)
        expect(page.locator(".runtime-heading")).to_have_count(0)
        expect(page.locator(".runtime-meta")).to_have_count(0)
        expect(page.locator(".runtime-capacity")).to_have_count(0)
        expect(page.locator(".lab-card-head")).to_have_count(0)
        expect(page.locator(".lab-card-status")).to_have_count(0)
        expect(page.locator(".lab-card-title")).to_have_count(9)
        expect(page.locator(".lab-card-caption")).to_have_count(9)
        expect(page.locator(".lab-card-actions")).to_have_count(0)
        expect(page.locator('.lab-grid [data-action="start-instance"]')).to_have_count(0)
        expect(page.locator('.lab-grid [data-action="view-catalog"]')).to_have_count(0)
        page.mouse.move(0, 0)
        expect(page.locator('.lab-card-caption').first).to_be_hidden()
        page.locator('.lab-card-media').first.hover()
        expect(page.locator('.lab-card-caption').first).to_be_visible()
        caption_color = page.locator('.lab-card-caption').first.evaluate(
            "element => ({ color: getComputedStyle(element).color, backgroundImage: getComputedStyle(element).backgroundImage })"
        )
        assert caption_color["color"] == "rgb(245, 251, 255)", caption_color
        assert caption_color["backgroundImage"] != "none", caption_color
        focus_layer = page.locator('.lab-card-media').first.evaluate(
            "element => ({ backgroundImage: getComputedStyle(element, '::after').backgroundImage, backgroundColor: getComputedStyle(element, '::after').backgroundColor })"
        )
        assert focus_layer["backgroundImage"] == "none" and focus_layer["backgroundColor"] == "rgba(0, 0, 0, 0)", focus_layer
        page.mouse.move(0, 0)
        expect(page.locator('.lab-card-caption').first).to_be_hidden()
        desktop_titles = page.locator(".lab-card .lab-card-title").evaluate_all(
            "elements => elements.map(element => element.textContent.trim())"
        )
        assert desktop_titles == [
            "DVWA", "Pikachu", "SQLi-Labs", "Upload-Labs",
            "VulnHub Machines", "OWASP Juice Shop", "OWASP WebGoat", "OWASP Mutillidae II", "OWASP PyGoat",
        ], desktop_titles
        caption_metrics = page.locator('.lab-card-caption').evaluate_all(
            "elements => elements.map(element => ({ width: element.getBoundingClientRect().width, height: element.getBoundingClientRect().height, cardWidth: element.closest('.lab-card').getBoundingClientRect().width }))"
        )
        assert all(item["width"] >= item["cardWidth"] - 4 and 40 <= item["height"] <= 54 for item in caption_metrics), caption_metrics
        card_tops = page.locator('.lab-card').evaluate_all(
            "elements => elements.map(element => element.getBoundingClientRect().top)"
        )
        assert all(max(card_tops[row:row + 3]) - min(card_tops[row:row + 3]) < 0.01 for row in (0, 3, 6)), card_tops
        assert page.locator('.lab-card-caption[title="VulnHub Machines"]').count() == 1
        account_typography = page.locator(".runtime-account").evaluate(
            "element => ({ fontFamily: getComputedStyle(element).fontFamily, fontWeight: getComputedStyle(element).fontWeight })"
        )
        assert "monospace" not in account_typography["fontFamily"], account_typography
        assert int(account_typography["fontWeight"]) >= 600, account_typography
        expect(page.get_by_text("打开项目", exact=True)).to_have_count(0)
        expect(page.get_by_text("添加环境", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="运行", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="资源", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="审计", exact=True)).to_have_count(0)
        desktop_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(desktop_columns.split()) == 3, desktop_columns
        workspace_columns = page.locator(".labs-screen").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(workspace_columns.split()) == 2, workspace_columns
        assert page.locator(".labs-screen").evaluate("element => getComputedStyle(element).gap") == "0px"
        screen_box = page.locator(".labs-screen").bounding_box()
        assert screen_box and abs(screen_box["x"] - 200) <= 1 and abs(screen_box["y"] - 120) <= 1, screen_box
        assert screen_box and abs(screen_box["width"] - 1040) <= 1 and abs(screen_box["height"] - 660) <= 1, screen_box
        desktop_rows = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateRows")
        assert len(desktop_rows.split()) == 3, desktop_rows
        detail_trigger = page.locator(".lab-card-media").first
        detail_trigger.click()
        expect(page.get_by_role("dialog")).to_be_visible()
        expect(page.get_by_role("heading", name="DVWA", exact=True)).to_be_visible()
        expect(page.locator(".lab-detail-cover")).to_be_visible()
        expect(page.get_by_text("经典 Web 漏洞练习环境，覆盖常见输入与认证问题。", exact=True)).to_be_visible()
        page.wait_for_timeout(250)
        page.screenshot(path=str(OUTPUT_DIR / "lab-detail-desktop.png"), full_page=True)
        page.get_by_role("button", name="关闭靶场信息").click()
        expect(detail_trigger).to_be_focused()
        running_detail_trigger = page.locator('.lab-card[data-state="running"] .lab-card-media').first
        if running_detail_trigger.count():
            running_detail_trigger.click()
            expect(page.locator(".lab-detail-running")).to_be_visible()
            detail_dialog = page.get_by_role("dialog")
            expect(detail_dialog.get_by_role("button", name="续期", exact=True)).to_be_visible()
            expect(detail_dialog.get_by_role("button", name="停止", exact=True)).to_be_visible()
            with page.expect_popup() as popup_info:
                detail_dialog.get_by_role("link", name="打开页面", exact=True).click()
            popup_info.value.close()
            expect(page.locator(".lab-detail-dialog")).to_have_count(0)
            expect(running_detail_trigger).to_be_focused()
        detail_start_button = page.locator('.lab-detail-dialog [data-action="start-instance"]').first
        if detail_start_button.count():
            pending_start = {}

            def hold_start(route, request):
                if request.method == "POST":
                    pending_start["route"] = route
                    return
                route.continue_()

            page.route("**/api/labs/*/instances", hold_start)
            detail_start_button.click()
            expect(page.locator('.lab-card[data-state="starting"]')).to_have_count(1)
            expect(page.locator(".lab-detail-dialog")).to_contain_text("启动中…")
            assert "route" in pending_start
            page.get_by_role("button", name="关闭靶场信息").click()
            page.locator(".lab-card-media").nth(1).click()
            expect(page.locator(".lab-detail-dialog")).to_be_visible()
            page.get_by_role("button", name="关闭靶场信息").click()
            pending_start["route"].fulfill(status=200, content_type="application/json", body='{}')
            page.unroute("**/api/labs/*/instances", hold_start)
            page.wait_for_timeout(3800)
        expect(page.get_by_role("button", name="查看机器", exact=True)).to_have_count(0)
        expect(page.locator('.lab-grid [data-action="view-catalog"]')).to_have_count(0)
        page.locator('.lab-card[data-runtime="vm"] .lab-card-media').first.click()
        expect(page.locator(".lab-detail-dialog")).to_be_visible()
        vulnhub_button = page.get_by_role("button", name="选择启动环境", exact=True)
        if vulnhub_button.count() == 0:
            load_catalog_button = page.get_by_role("button", name="加载目录", exact=True)
            expect(load_catalog_button).to_be_visible()
            load_catalog_button.click()
            expect(vulnhub_button).to_be_visible(timeout=120_000)
        vulnhub_button.click()
        expect(page.get_by_role("dialog", name="选择 VulnHub 启动环境")).to_be_visible()
        expect(page.get_by_role("listbox", name="可选 VulnHub 启动环境")).to_be_visible()
        catalog_style = page.locator(".catalog-dialog").evaluate(
            "element => ({ backgroundColor: getComputedStyle(element).backgroundColor, backgroundImage: getComputedStyle(element).backgroundImage })"
        )
        assert catalog_style == {"backgroundColor": "rgb(255, 255, 255)", "backgroundImage": "none"}, catalog_style
        expect(page.locator(".catalog-entry")).to_have_count(12)
        expect(page.locator(".catalog-entry").first).to_contain_text("Matrix-Breakout: 2 Morpheus")
        expect(page.locator(".catalog-entry").first).to_have_attribute("aria-label", "选择启动环境：Matrix-Breakout: 2 Morpheus")
        expect(page.get_by_text("Details", exact=True)).to_have_count(0)
        expect(page.locator(".catalog-detail-title .eyebrow")).to_have_count(0)
        page.screenshot(path=str(OUTPUT_DIR / "catalog-dialog-desktop.png"), full_page=True)
        page.evaluate("window.__catalogDialogBeforeSelection = document.querySelector('.catalog-dialog')")
        page.evaluate("window.__catalogDialogAnimations = 0; document.addEventListener('animationstart', event => { if (event.animationName === 'dialog-in') window.__catalogDialogAnimations += 1 }, { once: false })")
        page.locator(".catalog-entry").nth(1).click()
        expect(page.locator(".catalog-entry").nth(1)).to_have_attribute("aria-selected", "true")
        expect(page.get_by_role("heading", name="Web Machine: (N7)", exact=True)).to_be_visible()
        assert page.evaluate("window.__catalogDialogBeforeSelection === document.querySelector('.catalog-dialog')")
        assert page.evaluate("window.__catalogDialogAnimations === 0")
        page.screenshot(path=str(OUTPUT_DIR / "catalog-dialog-after-switch.png"), full_page=True)
        page.locator(".catalog-entry").first.focus()
        page.keyboard.press("ArrowDown")
        expect(page.locator(".catalog-entry").nth(1)).to_be_focused()
        expect(page.locator(".catalog-entry").nth(1)).to_have_attribute("aria-selected", "true")
        page.keyboard.press("End")
        expect(page.locator(".catalog-entry").last).to_be_focused()
        page.keyboard.press("Home")
        expect(page.locator(".catalog-entry").first).to_be_focused()
        page.get_by_role("button", name="关闭目录").click()
        expect(page.locator('.lab-card[data-runtime="vm"] .lab-card-media').first).to_be_focused()
        page.screenshot(path=str(OUTPUT_DIR / "labs-desktop.png"), full_page=True)
        if PRIMARY_SCREENSHOT:
            primary = Path(PRIMARY_SCREENSHOT)
            primary.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(primary), full_page=True)

        page.set_viewport_size({"width": 768, "height": 1024})
        expect(page.locator(".labs-screen")).to_be_visible()
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        tablet_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(tablet_columns.split()) == 2, tablet_columns
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.screenshot(path=str(OUTPUT_DIR / "labs-tablet.png"), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 900})

        page.evaluate("location.hash = 'settings'")
        page.wait_for_timeout(100)
        expect(page.locator(".lab-grid")).to_be_visible()
        expect(page.get_by_text("环境", exact=True)).to_have_count(0)
        expect(page.locator(".settings-page, .settings-layout, .lab-workspace-head")).to_have_count(0)

        runtime_payload = page.evaluate("async () => await (await fetch('/api/runtime-status')).json()")
        runtime_payload["labs"]["dvwa"] = {"available": False, "missing": ["PHP"]}
        for dependency in runtime_payload["dependencies"]:
            if dependency["id"] == "php":
                dependency.update({"available": False, "detail": "未检测到", "action": "prepare"})

        def runtime_status_with_missing(route, request):
            if request.method == "GET":
                route.fulfill(status=200, content_type="application/json", body=json.dumps(runtime_payload, ensure_ascii=False))
            else:
                route.continue_()

        page.route("**/api/runtime-status", runtime_status_with_missing)
        page.reload(wait_until="networkidle")
        expect(page.locator(".lab-grid")).to_be_visible()
        page.locator('.lab-card-media[data-id]').first.click()
        runtime_trigger = page.get_by_role("button", name="查看启动条件", exact=True)
        expect(runtime_trigger).to_be_visible()
        runtime_trigger.click()
        expect(page.locator(".runtime-dialog")).to_be_visible()
        expect(page.locator(".runtime-dialog")).to_contain_text("PHP")
        expect(page.get_by_role("button", name="准备运行时", exact=True)).to_be_visible()
        page.screenshot(path=str(OUTPUT_DIR / "runtime-requirements-desktop.png"), full_page=True)
        page.keyboard.press("Escape")
        expect(page.locator(".runtime-dialog")).to_have_count(0)
        expect(page.locator(".lab-detail-dialog")).to_be_visible()
        page.get_by_role("button", name="关闭靶场信息").click()
        page.unroute("**/api/runtime-status", runtime_status_with_missing)
        page.evaluate("location.hash = 'labs'")
        page.reload(wait_until="networkidle")
        expect(page.locator(".lab-grid")).to_be_visible()

        page.set_viewport_size({"width": 390, "height": 844})
        expect(page.locator(".lab-grid")).to_be_visible()
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        mobile_titles = page.locator(".lab-card .lab-card-title").evaluate_all(
            "elements => elements.map(element => element.textContent.trim())"
        )
        assert mobile_titles == desktop_titles, mobile_titles
        expect(page.locator(".lab-card-actions")).to_have_count(0)
        expect(page.locator('.lab-grid [data-action="start-instance"]')).to_have_count(0)
        expect(page.locator(".lab-card-caption")).to_have_count(9)
        expect(page.locator('.lab-card-caption').first).to_be_hidden()
        expect(page.locator(".runtime-line:visible")).to_have_count(2)
        runtime_box = page.locator(".runtime-panel").bounding_box()
        assert runtime_box and 87 <= runtime_box["height"] <= 89, runtime_box
        expect(page.locator(".lab-workspace-head, .workspace-nav, .workspace-account")).to_have_count(0)
        page.screenshot(path=str(OUTPUT_DIR / "labs-mobile.png"), full_page=True)

        mobile_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(mobile_columns.split()) == 2, mobile_columns
        mobile_caption_metrics = page.locator('.lab-card-caption').evaluate_all(
            "elements => elements.map(element => ({ visibility: getComputedStyle(element).visibility, opacity: getComputedStyle(element).opacity, width: element.getBoundingClientRect().width, cardWidth: element.closest('.lab-card').getBoundingClientRect().width }))"
        )
        assert mobile_caption_metrics and all(item["visibility"] == "hidden" and item["opacity"] == "0" for item in mobile_caption_metrics), mobile_caption_metrics
        no_horizontal_overflow = page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        assert no_horizontal_overflow
        mobile_detail_trigger = page.locator(".lab-card-media").first
        mobile_detail_trigger.click()
        expect(page.get_by_role("dialog")).to_be_visible()
        detail_box = page.locator(".lab-detail-dialog").bounding_box()
        assert detail_box and detail_box["width"] <= 370, detail_box
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.wait_for_timeout(250)
        page.screenshot(path=str(OUTPUT_DIR / "lab-detail-mobile.png"), full_page=True)
        page.get_by_role("button", name="关闭靶场信息").click()
        expect(mobile_detail_trigger).to_be_focused()
        expect(page.locator(".settings-page, .settings-layout, .lab-workspace-head")).to_have_count(0)
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.screenshot(path=str(OUTPUT_DIR / "labs-mobile-after-detail.png"), full_page=True)

        page.set_viewport_size({"width": 320, "height": 844})
        # Blur the restored card trigger before asserting the touch layout. The
        # caption intentionally remains available for keyboard focus, while a
        # compact touch viewport has no hover affordance.
        page.locator(".lab-canvas").focus()
        page.mouse.move(0, 0)
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        compact_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(compact_columns.split()) == 2, compact_columns
        expect(page.locator(".lab-card-actions")).to_have_count(0)
        expect(page.locator(".lab-card-caption")).to_have_count(9)
        expect(page.locator('.lab-card-caption').first).to_be_hidden()
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.screenshot(path=str(OUTPUT_DIR / "labs-compact.png"), full_page=True)
        page.emulate_media(reduced_motion="reduce")
        reduced_motion = page.locator(".lab-card").first.evaluate(
            "element => ({ transitionDuration: getComputedStyle(element).transitionDuration, hoverTransform: getComputedStyle(element).transform })"
        )
        assert float(reduced_motion["transitionDuration"].replace("s", "")) <= 0.001, reduced_motion
        assert not console_errors, console_errors
        browser.close()
    print(f"VulnLab browser check passed; screenshots: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
