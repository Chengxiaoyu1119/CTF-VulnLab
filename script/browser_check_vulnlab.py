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
        expect(page.get_by_role("heading", name="VulnLab", exact=True)).to_be_visible()
        expect(page.get_by_text("安装、启动和管理本机靶场。", exact=True)).to_have_count(0)
        expect(page.get_by_label("账号")).to_have_value("")
        expect(page.get_by_label("密码")).to_have_value("")
        page.get_by_role("button", name="进入靶场").click()
        expect(page.locator("#login-notice")).to_contain_text("登录失败")
        expect(page.locator("#login-notice")).to_contain_text("请输入账号和密码")
        expect(page.locator(".login-notice-icon")).to_have_count(0)
        expect(page.get_by_role("button", name="关闭提示")).to_be_visible()
        notice_style = page.locator("#login-notice").evaluate(
            "element => ({ position: getComputedStyle(element).position, top: getComputedStyle(element).top, right: getComputedStyle(element).right, width: getComputedStyle(element).width, height: getComputedStyle(element).height, borderRadius: getComputedStyle(element).borderRadius, borderTopColor: getComputedStyle(element).borderTopColor, borderLeftColor: getComputedStyle(element).borderLeftColor, backgroundColor: getComputedStyle(element).backgroundColor, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert notice_style["position"] == "fixed", notice_style
        assert notice_style["top"] == "22px", notice_style
        assert float(notice_style["width"].replace("px", "")) <= 304, notice_style
        assert float(notice_style["height"].replace("px", "")) <= 68, notice_style
        assert notice_style["borderRadius"] == "10px", notice_style
        assert notice_style["borderTopColor"] == "rgb(58, 58, 58)", notice_style
        assert notice_style["borderLeftColor"] == "rgb(224, 93, 84)", notice_style
        assert notice_style["backgroundColor"] == "rgb(30, 30, 30)", notice_style
        assert notice_style["boxShadow"] != "none", notice_style
        assert page.locator(".login-form input[aria-invalid='true']").evaluate_all(
            "elements => elements.every(element => getComputedStyle(element).borderColor !== 'rgb(201, 80, 74)')"
        )
        page.screenshot(path=str(OUTPUT_DIR / "login-notice-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        expect(page.locator("#login-notice")).to_be_visible()
        notice_box = page.locator("#login-notice").bounding_box()
        brand_box = page.locator(".login-brand").bounding_box()
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
        page.get_by_role("button", name="进入靶场").click()
        expect(page.locator("#login-notice")).to_be_visible()
        page.wait_for_timeout(4500)
        expect(page.locator("#login-notice")).to_have_count(0)
        page.get_by_role("button", name="进入靶场").click()
        expect(page.locator("#login-notice")).to_be_visible()
        page.get_by_label("账号").fill("v")
        expect(page.locator("#login-notice")).to_have_count(0)
        expect(page.get_by_role("heading", name="VulnLab", exact=True)).to_be_visible()
        page.get_by_label("账号").focus()
        page.wait_for_timeout(220)
        login_input_style = page.get_by_label("账号").evaluate(
            "element => ({ borderColor: getComputedStyle(element).borderColor, boxShadow: getComputedStyle(element).boxShadow, outline: getComputedStyle(element).outlineStyle })"
        )
        assert login_input_style["borderColor"] == "rgb(255, 127, 42)", login_input_style
        assert "61, 91, 194" not in login_input_style["boxShadow"], login_input_style
        assert login_input_style["outline"] == "none", login_input_style
        page.get_by_label("账号").fill("vulnlab")
        page.get_by_label("密码").fill("vulnlab")
        page.get_by_role("button", name="进入靶场").click()
        expect(page.locator("#login-success-notice")).to_contain_text("登录成功")
        expect(page.locator("#login-success-notice")).to_contain_text("身份验证通过，正在进入系统")
        success_notice_style = page.locator("#login-success-notice").evaluate(
            "element => ({ position: getComputedStyle(element).position, backgroundColor: getComputedStyle(element).backgroundColor, borderRadius: getComputedStyle(element).borderRadius, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert success_notice_style["position"] == "fixed", success_notice_style
        assert success_notice_style["backgroundColor"] == "rgb(30, 30, 30)", success_notice_style
        assert success_notice_style["borderRadius"] == "10px", success_notice_style
        assert success_notice_style["boxShadow"] != "none", success_notice_style
        page.screenshot(path=str(OUTPUT_DIR / "login-success-notice-desktop.png"), full_page=True)
        expect(page.get_by_text("DVWA", exact=True)).to_have_count(1)
        expect(page.locator(".labs-screen")).to_be_visible()
        page.set_viewport_size({"width": 390, "height": 844})
        success_box = page.locator("#login-success-notice").bounding_box()
        first_card_box = page.locator(".lab-card").first.bounding_box()
        assert success_box and success_box["x"] >= 390 - success_box["width"] - 17 and success_box["y"] >= 15, success_box
        assert success_box and first_card_box and (
            success_box["x"] + success_box["width"] <= first_card_box["x"]
            or first_card_box["x"] + first_card_box["width"] <= success_box["x"]
            or success_box["y"] + success_box["height"] <= first_card_box["y"]
            or first_card_box["y"] + first_card_box["height"] <= success_box["y"]
        ), {"notice": success_box, "first_card": first_card_box}
        expect(page.locator(".lab-workspace-head")).to_have_count(0)
        page.set_viewport_size({"width": 1440, "height": 900})
        expect(page.locator(".labs-screen .topbar")).to_have_count(0)
        expect(page.locator(".labs-screen .main-content")).to_have_count(0)
        expect(page.get_by_role("complementary", name="运行状态")).to_have_count(0)
        workspace_backgrounds = page.locator(".labs-screen, .lab-workspace, .lab-canvas").evaluate_all(
            "elements => elements.map(element => getComputedStyle(element).backgroundColor)"
        )
        assert workspace_backgrounds == ["rgb(18, 18, 18)", "rgb(18, 18, 18)", "rgb(18, 18, 18)"], workspace_backgrounds
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        expect(page.locator(".lab-card-cover")).to_have_count(9)
        assert page.locator(".lab-card-cover").evaluate_all(
            "elements => elements.every(element => element.complete && element.naturalWidth > 0)"
        )
        page.wait_for_timeout(4500)
        expect(page.locator("#login-success-notice")).to_have_count(0)
        expect(page.get_by_role("button", name="退出登录")).to_have_count(0)
        expect(page.locator(".workspace-nav, .workspace-account, .lab-workspace-head")).to_have_count(0)
        expect(page.locator(".lab-card-head")).to_have_count(0)
        expect(page.locator(".lab-card-status")).to_have_count(0)
        expect(page.locator(".lab-card-title")).to_have_count(9)
        expect(page.locator(".lab-card-caption")).to_have_count(9)
        expect(page.locator(".lab-card-actions")).to_have_count(0)
        expect(page.locator('.lab-grid [data-action="start-instance"]')).to_have_count(0)
        page.mouse.move(0, 0)
        expect(page.locator('.lab-card-caption').first).to_be_visible()
        page.locator('.lab-card-media').first.hover()
        expect(page.locator('.lab-card-caption').first).to_be_visible()
        caption_color = page.locator('.lab-card-caption').first.evaluate(
            "element => ({ color: getComputedStyle(element).color, backgroundImage: getComputedStyle(element).backgroundImage, backdropFilter: getComputedStyle(element).backdropFilter })"
        )
        assert caption_color["color"] == "rgb(245, 245, 245)", caption_color
        assert caption_color["backgroundImage"] != "none", caption_color
        assert caption_color["backdropFilter"] != "none", caption_color
        focus_layer = page.locator('.lab-card-media').first.evaluate(
            "element => ({ backgroundImage: getComputedStyle(element, '::after').backgroundImage, backgroundColor: getComputedStyle(element, '::after').backgroundColor })"
        )
        assert focus_layer["backgroundImage"] == "none" and focus_layer["backgroundColor"] == "rgba(0, 0, 0, 0)", focus_layer
        page.mouse.move(0, 0)
        expect(page.locator('.lab-card-caption').first).to_be_visible()
        page.wait_for_timeout(250)
        desktop_titles = page.locator(".lab-card .lab-card-title").evaluate_all(
            "elements => elements.map(element => element.textContent.trim())"
        )
        assert desktop_titles == [
            "DVWA", "Pikachu", "SQLi-Labs", "Upload-Labs",
            "XVWA", "OWASP Juice Shop", "OWASP WebGoat", "OWASP Mutillidae II", "OWASP PyGoat",
        ], desktop_titles
        caption_metrics = page.locator('.lab-card-caption').evaluate_all(
            """elements => elements.map(element => {
                const caption = element.getBoundingClientRect()
                const card = element.closest('.lab-card').getBoundingClientRect()
                return { width: caption.width, height: caption.height, left: caption.left, bottom: caption.bottom, cardWidth: card.width, cardLeft: card.left, cardBottom: card.bottom, childCount: element.children.length }
            })"""
        )
        assert all(item["cardWidth"] - 0.1 <= item["width"] <= item["cardWidth"] and 41 <= item["height"] <= 43 and -0.1 <= item["left"] - item["cardLeft"] <= 0.1 and -0.1 <= item["cardBottom"] - item["bottom"] <= 0.1 and item["childCount"] == 1 for item in caption_metrics), caption_metrics
        card_tops = page.locator('.lab-card').evaluate_all(
            "elements => elements.map(element => element.getBoundingClientRect().top)"
        )
        assert all(max(card_tops[row:row + 3]) - min(card_tops[row:row + 3]) < 0.01 for row in (0, 3, 6)), card_tops
        assert page.locator('.lab-card-caption[title="XVWA"]').count() == 1
        card_idle_style = page.locator(".lab-card").first.evaluate(
            "element => ({ borderWidth: getComputedStyle(element).borderWidth, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert card_idle_style["borderWidth"] == "0px", card_idle_style
        assert card_idle_style["boxShadow"] == "none", card_idle_style
        page.locator(".lab-card-media").first.hover()
        page.wait_for_timeout(220)
        card_hover_style = page.locator(".lab-card").first.evaluate(
            "element => ({ boxShadow: getComputedStyle(element).boxShadow, transform: getComputedStyle(element).transform })"
        )
        assert "255, 180, 0" in card_hover_style["boxShadow"], card_hover_style
        assert card_hover_style["transform"] != "none", card_hover_style
        page.mouse.move(0, 0)
        expect(page.get_by_text("打开项目", exact=True)).to_have_count(0)
        expect(page.get_by_text("添加环境", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="运行", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="资源", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="审计", exact=True)).to_have_count(0)
        desktop_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(desktop_columns.split()) == 3, desktop_columns
        workspace_display = page.locator(".labs-screen").evaluate("element => getComputedStyle(element).display")
        assert workspace_display == "block", workspace_display
        screen_box = page.locator(".labs-screen").bounding_box()
        assert screen_box and abs(screen_box["x"] - 160) <= 1 and abs(screen_box["y"] - 90) <= 1, screen_box
        assert screen_box and abs(screen_box["width"] - 1120) <= 1 and abs(screen_box["height"] - 720) <= 1, screen_box
        screen_edge_style = page.locator(".labs-screen").evaluate(
            "element => ({ borderRadius: getComputedStyle(element).borderRadius, borderTopWidth: getComputedStyle(element).borderTopWidth, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert screen_edge_style == {"borderRadius": "0px", "borderTopWidth": "0px", "boxShadow": "none"}, screen_edge_style
        card_corner_style = page.locator(".lab-card").first.evaluate(
            """element => ({
                cardRadius: getComputedStyle(element).borderRadius,
                mediaRadius: getComputedStyle(element.querySelector('.lab-card-media')).borderRadius,
                coverRadius: getComputedStyle(element.querySelector('.lab-card-cover')).borderRadius,
                overflow: getComputedStyle(element).overflow
            })"""
        )
        assert card_corner_style == {"cardRadius": "14px", "mediaRadius": "14px", "coverRadius": "14px", "overflow": "hidden"}, card_corner_style
        desktop_rows = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateRows")
        assert len(desktop_rows.split()) == 3, desktop_rows
        detail_trigger = page.locator(".lab-card-media").first
        detail_trigger.click()
        expect(page.get_by_role("dialog")).to_be_visible()
        expect(page.get_by_role("heading", name="DVWA", exact=True)).to_be_visible()
        expect(page.locator(".lab-detail-cover")).to_be_visible()
        expect(page.get_by_text("经典 Web 漏洞练习环境，覆盖常见输入与认证问题。", exact=True)).to_be_visible()
        page.wait_for_timeout(250)
        detail_box = page.locator(".lab-detail-dialog").bounding_box()
        workspace_box = page.locator(".lab-workspace").bounding_box()
        assert detail_box and workspace_box and abs(
            detail_box["x"] + detail_box["width"] / 2 - (workspace_box["x"] + workspace_box["width"] / 2)
        ) <= 1, {"detail": detail_box, "workspace": workspace_box}
        page.screenshot(path=str(OUTPUT_DIR / "lab-detail-desktop.png"), full_page=True)
        page.get_by_role("button", name="关闭靶场信息").click()
        expect(detail_trigger).to_be_focused()
        detail_trigger.click()
        page.locator(".lab-detail-backdrop").click(position={"x": 5, "y": 5})
        expect(page.locator(".lab-detail-dialog")).to_have_count(0)
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
        tablet_detail_trigger = page.locator(".lab-card-media").first
        tablet_detail_trigger.click()
        tablet_detail_box = page.locator(".lab-detail-dialog").bounding_box()
        tablet_workspace_box = page.locator(".lab-workspace").bounding_box()
        assert tablet_detail_box and tablet_workspace_box and abs(
            tablet_detail_box["x"] + tablet_detail_box["width"] / 2
            - (tablet_workspace_box["x"] + tablet_workspace_box["width"] / 2)
        ) <= 1, {"detail": tablet_detail_box, "workspace": tablet_workspace_box}
        page.get_by_role("button", name="关闭靶场信息").click()
        expect(tablet_detail_trigger).to_be_focused()
        page.set_viewport_size({"width": 1440, "height": 900})

        page.evaluate("location.hash = 'settings'")
        page.wait_for_timeout(100)
        expect(page.locator(".lab-grid")).to_be_visible()
        expect(page.get_by_text("环境", exact=True)).to_have_count(0)
        expect(page.locator(".settings-page, .settings-layout, .lab-workspace-head")).to_have_count(0)

        labs_payload = page.evaluate("async () => await (await fetch('/api/labs')).json()")
        for lab in labs_payload:
            if lab["slug"] == "dvwa":
                lab["status"] = "ready"
                lab["localPath"] = "/tmp/vulnlab-browser-fixture/dvwa"

        def labs_with_ready_dvwa(route, request):
            if request.method == "GET":
                route.fulfill(status=200, content_type="application/json", body=json.dumps(labs_payload, ensure_ascii=False))
            else:
                route.continue_()

        page.route("**/api/labs", labs_with_ready_dvwa)
        page.reload(wait_until="networkidle")
        expect(page.locator(".lab-grid")).to_be_visible()
        page.locator('.lab-card-media[data-id]').first.click()
        expect(page.get_by_role("button", name="启动环境", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="启动条件", exact=True)).to_have_count(0)
        expect(page.get_by_text("待配置", exact=True)).to_have_count(0)
        expect(page.locator(".runtime-dialog, .runtime-requirements")).to_have_count(0)
        page.screenshot(path=str(OUTPUT_DIR / "lab-detail-ready-desktop.png"), full_page=True)
        expect(page.locator(".lab-detail-dialog")).to_be_visible()
        page.get_by_role("button", name="关闭靶场信息").click()
        page.unroute("**/api/labs", labs_with_ready_dvwa)
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
        expect(page.locator(".lab-card-cover")).to_have_count(9)
        expect(page.locator('.lab-card-caption').first).to_be_visible()
        expect(page.get_by_role("complementary", name="运行状态")).to_have_count(0)
        expect(page.locator(".lab-workspace-head, .workspace-nav, .workspace-account")).to_have_count(0)
        page.screenshot(path=str(OUTPUT_DIR / "labs-mobile.png"), full_page=True)

        mobile_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(mobile_columns.split()) == 2, mobile_columns
        mobile_card_box = page.locator(".lab-card").first.bounding_box()
        assert mobile_card_box and mobile_card_box["height"] <= 140, mobile_card_box
        mobile_caption_metrics = page.locator('.lab-card-caption').evaluate_all(
            "elements => elements.map(element => ({ visibility: getComputedStyle(element).visibility, opacity: getComputedStyle(element).opacity, width: element.getBoundingClientRect().width, cardWidth: element.closest('.lab-card').getBoundingClientRect().width }))"
        )
        assert mobile_caption_metrics and all(item["visibility"] == "visible" and item["opacity"] == "1" and item["cardWidth"] - 2.1 <= item["width"] <= item["cardWidth"] for item in mobile_caption_metrics), mobile_caption_metrics
        no_horizontal_overflow = page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        assert no_horizontal_overflow
        mobile_detail_trigger = page.locator(".lab-card-media").first
        mobile_detail_trigger.click()
        expect(page.get_by_role("dialog")).to_be_visible()
        detail_box = page.locator(".lab-detail-dialog").bounding_box()
        mobile_workspace_box = page.locator(".lab-workspace").bounding_box()
        assert detail_box and detail_box["width"] <= 370, detail_box
        assert detail_box and mobile_workspace_box and abs(
            detail_box["x"] + detail_box["width"] / 2 - (mobile_workspace_box["x"] + mobile_workspace_box["width"] / 2)
        ) <= 1, {"detail": detail_box, "workspace": mobile_workspace_box}
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.wait_for_timeout(250)
        page.screenshot(path=str(OUTPUT_DIR / "lab-detail-mobile.png"), full_page=True)
        page.get_by_role("button", name="关闭靶场信息").click()
        expect(mobile_detail_trigger).to_be_focused()
        expect(page.locator(".settings-page, .settings-layout, .lab-workspace-head")).to_have_count(0)
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.screenshot(path=str(OUTPUT_DIR / "labs-mobile-after-detail.png"), full_page=True)

        page.set_viewport_size({"width": 320, "height": 844})
        # Blur the restored trigger before checking the fixed title footer.
        page.locator(".lab-canvas").focus()
        page.mouse.move(0, 0)
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        compact_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(compact_columns.split()) == 2, compact_columns
        compact_card_box = page.locator(".lab-card").first.bounding_box()
        assert compact_card_box and compact_card_box["height"] <= 125, compact_card_box
        expect(page.locator(".lab-card-actions")).to_have_count(0)
        expect(page.locator(".lab-card-caption")).to_have_count(9)
        expect(page.locator('.lab-card-caption').first).to_be_visible()
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
