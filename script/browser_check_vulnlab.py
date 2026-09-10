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
        page.emulate_media(reduced_motion="no-preference")
        page.add_init_script(
            """window.__vulnlabLoginAnimationStarts = 0;
            window.__vulnlabLoginNoticeAnimationStarts = 0;
            document.addEventListener('animationstart', event => {
                if (event.animationName === 'login-form-in') window.__vulnlabLoginAnimationStarts += 1
                if (event.animationName === 'login-notice-in') window.__vulnlabLoginNoticeAnimationStarts += 1
            }, true)"""
        )
        console_errors: list[str] = []
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" and not message.text.startswith("Failed to load resource:") else None)
        page.on("pageerror", lambda error: console_errors.append(str(error)))
        page.goto(BASE_URL, wait_until="networkidle")
        assert page.title() == "攻防控制台"
        expect(page.get_by_role("heading", name="攻防控制台", exact=True)).to_be_visible()
        assert page.evaluate("window.__vulnlabLoginAnimationStarts >= 1")
        expect(page.get_by_text("网络攻防靶场管理系统", exact=True)).to_be_visible()
        assert page.locator(".login-brand img").evaluate("element => element.complete && element.naturalWidth > 0")
        expect(page.get_by_text("安装、启动和管理本机靶场。", exact=True)).to_have_count(0)
        expect(page.get_by_label("账号", exact=True)).to_have_value("")
        expect(page.get_by_label("密码", exact=True)).to_have_value("")
        page.get_by_role("button", name="登录系统").click()
        expect(page.locator("#login-error")).to_have_count(0)
        expect(page.locator(".login-field-error")).to_have_count(2)
        expect(page.locator('[data-field-error="userName"]')).to_contain_text("请输入账号")
        expect(page.locator('[data-field-error="password"]')).to_contain_text("请输入密码")
        expect(page.locator("#login-notice")).to_have_count(0)
        expect(page.get_by_label("账号", exact=True)).to_have_attribute("aria-describedby", "login-error-field-userName")
        expect(page.get_by_label("密码", exact=True)).to_have_attribute("aria-describedby", "login-error-field-password")
        page.wait_for_timeout(250)
        field_inputs = page.locator(".login-field .login-input-wrap")
        field_errors = page.locator(".login-field-error")
        for index in range(field_errors.count()):
            input_box = field_inputs.nth(index).bounding_box()
            error_box = field_errors.nth(index).bounding_box()
            assert input_box and error_box and error_box["y"] >= input_box["y"] + input_box["height"] + 3, (input_box, error_box)
            if index + 1 < field_inputs.count():
                next_input_box = field_inputs.nth(index + 1).bounding_box()
                assert next_input_box and next_input_box["y"] >= error_box["y"] + error_box["height"], (error_box, next_input_box)
        expect(page.locator(".login-field-label")).to_have_count(2)
        assert page.locator(".login-field-label").evaluate_all(
            "elements => elements.every(element => getComputedStyle(element).position === 'absolute' && getComputedStyle(element).width === '1px')"
        )
        assert page.locator(".login-form input[aria-invalid='true']").evaluate_all(
            "elements => elements.every(element => getComputedStyle(element).borderColor !== 'rgb(201, 80, 74)')"
        )
        page.screenshot(path=str(OUTPUT_DIR / "login-validation-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        expect(page.locator(".login-field-error")).to_have_count(2)
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.screenshot(path=str(OUTPUT_DIR / "login-validation-mobile.png"), full_page=True)
        page.set_viewport_size({"width": 320, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        expect(page.locator(".login-field-error")).to_have_count(2)
        page.set_viewport_size({"width": 768, "height": 1024})
        tablet_login_box = page.locator(".login-form").bounding_box()
        assert tablet_login_box and round(tablet_login_box["width"]) == 480 and round(tablet_login_box["height"]) == 516, tablet_login_box
        page.screenshot(path=str(OUTPUT_DIR / "login-validation-tablet.png"), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 900})
        register_requests = []

        def block_register(route, request):
            register_requests.append(request.url)
            route.abort()

        page.route("**/api/auth/register", block_register)
        page.get_by_role("tab", name="注册", exact=True).click()
        expect(page.get_by_role("tab", name="注册", exact=True)).to_have_attribute("aria-selected", "true")
        expect(page.get_by_role("tab", name="登录", exact=True)).to_have_attribute("aria-selected", "false")
        expect(page.get_by_label("确认密码", exact=True)).to_be_visible()
        expect(page.get_by_label("邀请码", exact=True)).to_be_visible()
        expect(page.get_by_label("账号", exact=True)).to_have_attribute("placeholder", "请设置账号")
        expect(page.get_by_label("密码", exact=True)).to_have_attribute("placeholder", "请设置密码")
        expect(page.get_by_label("确认密码", exact=True)).to_have_attribute("placeholder", "请确认密码")
        expect(page.get_by_role("button", name="注册账号", exact=True)).to_be_enabled()
        expect(page.locator('[data-field="confirm"] .login-field-icon svg')).to_have_count(1)
        expect(page.locator('[data-field="confirm"] .login-field-icon svg')).to_have_attribute("viewBox", "0 0 1024 1024")
        page.get_by_role("button", name="注册账号", exact=True).click()
        expect(page.locator("#login-error")).to_have_count(0)
        expect(page.locator(".login-field-error")).to_have_count(4)
        expect(page.locator('[data-field-error="userName"]')).to_contain_text("请输入账号")
        expect(page.locator('[data-field-error="password"]')).to_contain_text("请输入密码")
        expect(page.locator('[data-field-error="passwordConfirm"]')).to_contain_text("请确认密码")
        expect(page.locator('[data-field-error="inviteCode"]')).to_contain_text("请输入邀请码")
        page.screenshot(path=str(OUTPUT_DIR / "register-validation-desktop.png"), full_page=True)
        assert not register_requests
        page.get_by_label("账号", exact=True).fill("new-user")
        page.get_by_label("账号", exact=True).fill("12")
        page.get_by_role("button", name="注册账号", exact=True).click()
        expect(page.locator('[data-field-error="userName"]')).to_contain_text("账号格式不正确")
        assert not register_requests
        page.get_by_label("账号", exact=True).fill("new-user")
        page.get_by_label("密码", exact=True).fill("123")
        page.get_by_role("button", name="注册账号", exact=True).click()
        expect(page.locator('[data-field-error="password"]')).to_contain_text("密码长度至少为")
        assert not register_requests
        page.get_by_label("密码", exact=True).fill("secret123")
        page.get_by_label("确认密码", exact=True).fill("different")
        page.get_by_role("button", name="注册账号", exact=True).click()
        expect(page.locator('[data-field-error="passwordConfirm"]')).to_contain_text("两次密码不一致")
        assert not register_requests
        page.get_by_label("确认密码", exact=True).fill("secret123")
        page.get_by_label("邀请码", exact=True).fill("INVITE-TEST")
        page.get_by_label("邀请码", exact=True).press("Enter")
        expect(page.locator("#login-error")).to_contain_text("网络连接失败，请检查网络后重试")
        assert register_requests
        page.get_by_role("tab", name="登录", exact=True).click()
        expect(page.get_by_role("button", name="登录系统", exact=True)).to_be_visible()
        expect(page.get_by_label("确认密码", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="显示密码")).to_have_count(0)
        page.unroute("**/api/auth/register")

        page.get_by_label("密码", exact=True).fill("secret")
        expect(page.get_by_role("button", name="显示密码")).to_have_count(1)
        page.get_by_role("button", name="显示密码").click()
        expect(page.get_by_label("密码", exact=True)).to_have_attribute("type", "text")
        expect(page.get_by_role("button", name="隐藏密码")).to_have_attribute("aria-pressed", "true")
        expect(page.get_by_label("密码", exact=True)).to_have_value("secret")
        page.get_by_role("button", name="隐藏密码").click()
        expect(page.get_by_label("密码", exact=True)).to_have_attribute("type", "password")
        page.get_by_label("密码", exact=True).fill("")
        expect(page.get_by_role("button", name="显示密码")).to_have_count(0)
        page.get_by_label("账号", exact=True).fill("v")
        expect(page.locator("#login-error")).to_have_count(0)
        expect(page.get_by_role("heading", name="攻防控制台", exact=True)).to_be_visible()
        page.get_by_label("账号", exact=True).focus()
        page.wait_for_timeout(220)
        login_input_style = page.get_by_label("账号", exact=True).evaluate(
            "element => ({ borderColor: getComputedStyle(element).borderColor, boxShadow: getComputedStyle(element).boxShadow, outline: getComputedStyle(element).outlineStyle, backgroundColor: getComputedStyle(element).backgroundColor, fontFamily: getComputedStyle(element).fontFamily })"
        )
        assert login_input_style["borderColor"] == "rgb(76, 77, 79)", login_input_style
        assert login_input_style["boxShadow"] == "none", login_input_style
        assert login_input_style["outline"] == "none", login_input_style
        assert login_input_style["backgroundColor"] == "rgb(0, 0, 0)", login_input_style
        assert login_input_style["fontFamily"].startswith("Arial"), login_input_style
        login_mode_style = page.locator(".login-mode").evaluate(
            "element => ({ borderBottomWidth: getComputedStyle(element).borderBottomWidth, paddingBottom: getComputedStyle(element).paddingBottom, fontFamily: getComputedStyle(element).fontFamily })"
        )
        assert login_mode_style["borderBottomWidth"] == "0px", login_mode_style
        assert login_mode_style["paddingBottom"] == "10px", login_mode_style
        assert "Times New Roman" in login_mode_style["fontFamily"], login_mode_style
        login_mode_button_style = page.locator(".login-mode button[aria-selected='true']").evaluate(
            "element => ({ fontFamily: getComputedStyle(element).fontFamily, fontWeight: getComputedStyle(element).fontWeight })"
        )
        assert login_mode_button_style["fontFamily"].startswith("Arial"), login_mode_button_style
        assert login_mode_button_style["fontWeight"] == "600", login_mode_button_style
        separator_content = page.locator(".login-mode").evaluate(
            "element => getComputedStyle(element, '::before').content"
        )
        assert separator_content == '"|"', separator_content
        login_box = page.locator(".login-form").bounding_box()
        assert login_box and round(login_box["width"]) == 480 and round(login_box["height"]) == 514, login_box
        brand_box = page.locator(".login-brand").bounding_box()
        mode_box = page.locator(".login-mode").bounding_box()
        field_boxes = [locator.bounding_box() for locator in page.locator(".login-field").all()]
        button_box = page.locator(".login-form .button-primary").bounding_box()
        button_style = page.locator(".login-form .button-primary").evaluate(
            "element => ({ fontFamily: getComputedStyle(element).fontFamily, fontSize: getComputedStyle(element).fontSize, fontWeight: getComputedStyle(element).fontWeight })"
        )
        assert brand_box and round(brand_box["height"]) == 154, brand_box
        assert mode_box and round(mode_box["height"]) == 52, mode_box
        assert all(box and round(box["height"]) == 40 for box in field_boxes), field_boxes
        assert button_box and round(button_box["height"]) == 44, button_box
        assert button_box and round(button_box["width"]) == 400, button_box
        assert button_style["fontFamily"].startswith("Arial"), button_style
        assert button_style["fontSize"] == "15px" and button_style["fontWeight"] == "600", button_style
        login_animation_style = page.locator(".login-form").evaluate(
            "element => ({ animationName: getComputedStyle(element).animationName, animationDuration: getComputedStyle(element).animationDuration })"
        )
        assert login_animation_style["animationName"] == "login-form-in", login_animation_style
        assert login_animation_style["animationDuration"] == "0.5s", login_animation_style
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(520)
        mobile_login_box = page.locator(".login-form").bounding_box()
        mobile_brand_box = page.locator(".login-brand").bounding_box()
        mobile_logo_box = page.locator(".login-logo img").bounding_box()
        assert mobile_login_box and round(mobile_login_box["width"]) == 351, mobile_login_box
        assert mobile_brand_box and round(mobile_brand_box["height"]) == 142, mobile_brand_box
        assert mobile_logo_box and round(mobile_logo_box["width"]) == 60 and round(mobile_logo_box["height"]) == 60, mobile_logo_box
        page.set_viewport_size({"width": 1440, "height": 900})
        page.get_by_label("账号", exact=True).fill("wrong")
        page.get_by_label("密码", exact=True).fill("wrong")
        page.get_by_label("密码", exact=True).press("Enter")
        expect(page.locator("#login-error")).to_contain_text("账号或密码错误")
        expect(page.get_by_label("账号", exact=True)).to_be_focused()
        pending_login = {}

        def hold_login(route, request):
            pending_login["route"] = route

        page.route("**/api/auth/login", hold_login)
        page.get_by_label("账号", exact=True).fill("network")
        page.get_by_label("密码", exact=True).fill("network")
        page.get_by_label("密码", exact=True).press("Enter")
        expect(page.get_by_role("button", name="登录中…", exact=True)).to_be_disabled()
        assert "route" in pending_login
        pending_login["route"].abort()
        expect(page.locator("#login-error")).to_contain_text("网络连接失败，请检查网络后重试")
        page.unroute("**/api/auth/login")
        page.get_by_label("账号", exact=True).fill("vulnlab")
        page.get_by_label("密码", exact=True).fill("vulnlab")
        page.get_by_label("密码", exact=True).press("Enter")
        expect(page.locator("#login-success-notice")).to_contain_text("登录成功")
        expect(page.locator("#login-success-notice")).to_contain_text("身份验证通过，正在进入系统")
        success_notice_style = page.locator("#login-success-notice").evaluate(
            "element => ({ position: getComputedStyle(element).position, backgroundColor: getComputedStyle(element).backgroundColor, borderLeftWidth: getComputedStyle(element).borderLeftWidth, borderRadius: getComputedStyle(element).borderRadius, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert success_notice_style["position"] == "fixed", success_notice_style
        assert success_notice_style["backgroundColor"] == "rgb(30, 30, 30)", success_notice_style
        assert success_notice_style["borderLeftWidth"] == "1px", success_notice_style
        assert success_notice_style["borderRadius"] == "10px", success_notice_style
        assert success_notice_style["boxShadow"] != "none", success_notice_style
        assert page.evaluate("window.__vulnlabLoginNoticeAnimationStarts >= 1")
        success_notice_animation = page.locator("#login-success-notice").evaluate(
            "element => ({ animationName: getComputedStyle(element).animationName, animationDuration: getComputedStyle(element).animationDuration })"
        )
        assert success_notice_animation == {"animationName": "login-notice-in", "animationDuration": "0.32s"}, success_notice_animation
        page.screenshot(path=str(OUTPUT_DIR / "login-success-notice-desktop.png"), full_page=True)
        expect(page.get_by_text("DVWA", exact=True)).to_have_count(1)
        expect(page.locator(".labs-screen")).to_be_visible()
        expect(page.locator(".workspace-account")).to_have_count(0)
        expect(page.get_by_role("button", name="vulnlab", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="邀请码管理", exact=True)).to_be_visible()
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
        initial_labs_payload = page.evaluate("async () => await (await fetch('/api/labs')).json()")
        mutillidae_lab = next(lab for lab in initial_labs_payload if lab["slug"] == "mutillidae")
        mutillidae_trigger = page.locator(".lab-card-media").nth(7)
        mutillidae_trigger.click()
        expect(page.get_by_role("heading", name="OWASP Mutillidae II", exact=True)).to_be_visible()
        expect(page.locator(".lab-detail-runtime")).to_have_count(0)
        if mutillidae_lab.get("version"):
            expect(page.get_by_text(mutillidae_lab["version"], exact=True)).to_have_count(0)
        mutillidae_cover_style = page.locator(
            '.lab-detail-cover[data-cover="mutillidae"] .lab-card-cover'
        ).evaluate(
            "element => ({ objectFit: getComputedStyle(element).objectFit, objectPosition: getComputedStyle(element).objectPosition })"
        )
        assert mutillidae_cover_style == {"objectFit": "cover", "objectPosition": "50% 0%"}, mutillidae_cover_style
        page.get_by_role("button", name="关闭靶场信息").click()
        expect(mutillidae_trigger).to_be_focused()
        page.evaluate(
            """() => {
                window.__vulnlabDialogAnimationStarts = 0
                document.addEventListener('animationstart', event => {
                    if (event.animationName === 'dialog-in' || event.animationName === 'dialog-backdrop-in') {
                        window.__vulnlabDialogAnimationStarts += 1
                    }
                }, true)
            }"""
        )
        notice_canvas = page.locator(".lab-canvas").element_handle()
        notice_card = page.locator(".lab-card").first.element_handle()
        notice_cover = page.locator(".lab-card-cover").first.element_handle()
        notice_detail_trigger = page.locator(".lab-card-media").first
        notice_detail_trigger.click()
        expect(page.locator(".lab-detail-dialog")).to_be_visible()
        page.wait_for_timeout(250)
        notice_dialog = page.locator(".lab-detail-dialog").element_handle()
        notice_focusables = page.locator(".lab-detail-dialog button, .lab-detail-dialog a[href]")
        assert notice_focusables.count() >= 2
        notice_focus_target = notice_focusables.last.element_handle()
        notice_focusables.last.focus()
        notice_animation_count = page.evaluate("window.__vulnlabDialogAnimationStarts")
        page.wait_for_timeout(4500)
        expect(page.locator("#login-success-notice")).to_have_count(0)
        assert page.locator(".lab-canvas").evaluate("(element, previous) => element === previous", notice_canvas)
        assert page.locator(".lab-card").first.evaluate("(element, previous) => element === previous", notice_card)
        assert page.locator(".lab-card-cover").first.evaluate("(element, previous) => element === previous", notice_cover)
        assert page.locator(".lab-detail-dialog").evaluate("(element, previous) => element === previous", notice_dialog)
        assert notice_focus_target.evaluate("element => element.isConnected && document.activeElement === element")
        assert page.evaluate("window.__vulnlabDialogAnimationStarts") == notice_animation_count
        page.keyboard.press("Escape")
        expect(page.locator(".lab-detail-dialog")).to_have_count(0)
        expect(notice_detail_trigger).to_be_focused()
        admin_trigger = page.get_by_role("button", name="邀请码管理", exact=True)
        admin_trigger.click()
        expect(page.get_by_role("dialog", name="邀请码管理")).to_be_visible()
        expect(page.get_by_text("当前没有可用的邀请码。", exact=True)).to_be_visible()
        page.get_by_role("button", name="生成邀请码", exact=True).click()
        invitation_code = page.locator(".invitation-card code")
        expect(invitation_code).to_have_count(1)
        assert len(invitation_code.inner_text()) == 32
        page.get_by_role("button", name="复制邀请码", exact=True).click()
        expect(page.get_by_role("status")).to_contain_text("邀请码已复制")
        page.get_by_role("button", name="撤销", exact=True).click()
        expect(page.get_by_role("dialog", name="撤销邀请码")).to_be_visible()
        page.get_by_role("button", name="撤销邀请码", exact=True).click()
        expect(page.locator(".invitation-card")).to_have_count(0)
        page.get_by_role("button", name="关闭邀请码管理", exact=True).click()
        expect(admin_trigger).to_be_focused()
        expect(page.locator(".toast")).to_have_count(0, timeout=5000)
        poll_requests = {"count": 0}

        def track_detail_poll(route, request):
            if request.method == "GET":
                poll_requests["count"] += 1
                route.fulfill(status=200, content_type="application/json", body="[]")
            else:
                route.continue_()

        page.route("**/api/instances", track_detail_poll)
        poll_trigger = page.locator(".lab-card-media").first
        poll_trigger.click()
        expect(page.locator(".lab-detail-dialog")).to_be_visible()
        initial_poll_requests = poll_requests["count"]
        page.wait_for_timeout(5200)
        assert poll_requests["count"] > initial_poll_requests, poll_requests
        page.get_by_role("button", name="关闭靶场信息").click()
        closed_poll_requests = poll_requests["count"]
        page.wait_for_timeout(5200)
        assert poll_requests["count"] == closed_poll_requests, poll_requests
        page.unroute("**/api/instances", track_detail_poll)
        expect(poll_trigger).to_be_focused()
        page.locator(".lab-canvas").focus()
        expect(page.get_by_role("button", name="退出登录")).to_have_count(0)
        expect(page.locator(".workspace-nav, .lab-workspace-head")).to_have_count(0)
        expect(page.locator(".workspace-account")).to_have_count(0)
        expect(page.get_by_role("button", name="邀请码管理", exact=True)).to_be_visible()
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
        assert card_hover_style == {"boxShadow": "none", "transform": "none"}, card_hover_style
        hover_cover_style = page.locator(".lab-card-cover").first.evaluate(
            "element => ({ filter: getComputedStyle(element).filter, transform: getComputedStyle(element).transform })"
        )
        assert hover_cover_style == {"filter": "saturate(0.96) contrast(1.02)", "transform": "none"}, hover_cover_style
        hover_overlay_opacity = page.locator(".lab-card-media").first.evaluate(
            "element => getComputedStyle(element, '::before').opacity"
        )
        assert hover_overlay_opacity == "0.68", hover_overlay_opacity
        page.mouse.move(0, 0)
        expect(page.get_by_text("打开项目", exact=True)).to_have_count(0)
        expect(page.get_by_text("添加环境", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="运行", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="资源", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="审计", exact=True)).to_have_count(0)
        desktop_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(desktop_columns.split()) == 3, desktop_columns
        workspace_display = page.locator(".labs-screen").evaluate("element => getComputedStyle(element).display")
        assert workspace_display == "flex", workspace_display
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
                captionRadius: getComputedStyle(element.querySelector('.lab-card-caption')).borderBottomLeftRadius,
                mediaBackground: getComputedStyle(element.querySelector('.lab-card-media')).backgroundColor,
                coverClipPath: getComputedStyle(element.querySelector('.lab-card-cover')).clipPath,
                cardBackground: getComputedStyle(element).backgroundColor,
                captionBackground: getComputedStyle(element.querySelector('.lab-card-caption')).backgroundColor,
                overflow: getComputedStyle(element).overflow
            })"""
        )
        assert card_corner_style == {"cardRadius": "14px", "mediaRadius": "0px", "coverRadius": "0px", "captionRadius": "0px", "mediaBackground": "rgb(24, 24, 24)", "coverClipPath": "inset(0px 0px 42px)", "cardBackground": "rgb(24, 24, 24)", "captionBackground": "rgb(24, 24, 24)", "overflow": "hidden"}, card_corner_style
        all_card_corner_styles = page.locator(".lab-card").evaluate_all(
            """elements => elements.map(element => {
                const media = element.querySelector('.lab-card-media')
                const caption = element.querySelector('.lab-card-caption')
                const cover = element.querySelector('.lab-card-cover')
                return {
                    cardRadius: getComputedStyle(element).borderRadius,
                    mediaRadius: getComputedStyle(media).borderRadius,
                    coverRadius: getComputedStyle(cover).borderRadius,
                    captionRadius: getComputedStyle(caption).borderBottomRightRadius,
                    mediaBackground: getComputedStyle(media).backgroundColor,
                    coverClipPath: getComputedStyle(cover).clipPath,
                    cardBackground: getComputedStyle(element).backgroundColor,
                    captionBackground: getComputedStyle(caption).backgroundColor,
                    overflow: getComputedStyle(element).overflow
                }
            })"""
        )
        assert all(
            item["cardRadius"] == "14px"
            and item["mediaRadius"] == item["coverRadius"] == "0px"
            and item["captionRadius"] == "0px"
            and item["mediaBackground"] == "rgb(24, 24, 24)"
            and item["coverClipPath"] == "inset(0px 0px 42px)"
            and item["cardBackground"] == "rgb(24, 24, 24)"
            and item["captionBackground"] == "rgb(24, 24, 24)"
            and item["overflow"] == "hidden"
            for item in all_card_corner_styles
        ), all_card_corner_styles
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
        detail_focusables = page.locator(".lab-detail-dialog button, .lab-detail-dialog a[href]")
        assert detail_focusables.count() >= 2
        expect(detail_focusables.first).to_be_focused()
        page.keyboard.press("Shift+Tab")
        expect(detail_focusables.last).to_be_focused()
        page.keyboard.press("Tab")
        expect(detail_focusables.first).to_be_focused()
        page.keyboard.press("Escape")
        expect(page.locator(".lab-detail-dialog")).to_have_count(0)
        expect(detail_trigger).to_be_focused()
        detail_trigger.click()
        page.get_by_role("button", name="关闭靶场信息").click()
        expect(detail_trigger).to_be_focused()
        detail_trigger.click()
        page.locator(".lab-detail-backdrop").click(position={"x": 5, "y": 5})
        expect(page.locator(".lab-detail-dialog")).to_have_count(0)
        expect(detail_trigger).to_be_focused()
        page.locator(".lab-canvas").focus()
        running_detail_trigger = page.locator('.lab-card[data-state="running"] .lab-card-media').first
        if running_detail_trigger.count():
            running_detail_trigger.click()
            expect(page.locator(".lab-detail-running")).to_be_visible()
            expect(page.locator(".lab-detail-state")).to_have_count(0)
            detail_dialog = page.get_by_role("dialog")
            expect(detail_dialog.get_by_role("button", name="续期", exact=True)).to_be_visible()
            expect(detail_dialog.get_by_role("button", name="停止", exact=True)).to_be_visible()
            with page.expect_popup() as popup_info:
                open_page = detail_dialog.get_by_role("link", name="打开页面", exact=True)
                open_page_style = open_page.evaluate(
                    "element => ({ display: getComputedStyle(element).display, alignItems: getComputedStyle(element).alignItems, justifyContent: getComputedStyle(element).justifyContent, textAlign: getComputedStyle(element).textAlign })"
                )
                assert open_page_style["display"] in {"flex", "inline-flex"} and open_page_style["alignItems"] == "center" and open_page_style["justifyContent"] == "center" and open_page_style["textAlign"] == "center", open_page_style
                open_page.click()
            popup_info.value.close()
            expect(page.locator(".lab-detail-dialog")).to_have_count(0)
            expect(running_detail_trigger).to_be_focused()
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
        tablet_canvas = page.locator(".lab-canvas").element_handle()
        tablet_card = page.locator(".lab-card").last.element_handle()
        tablet_cover = page.locator(".lab-card-cover").first.element_handle()
        tablet_detail_trigger = page.locator(".lab-card-media").last
        tablet_detail_trigger.scroll_into_view_if_needed()
        tablet_scroll_top = page.locator(".lab-canvas").evaluate("element => element.scrollTop")
        assert tablet_scroll_top > 0
        tablet_detail_trigger.click()
        assert page.locator(".lab-canvas").evaluate("(element, previous) => element === previous", tablet_canvas)
        assert page.locator(".lab-card").last.evaluate("(element, previous) => element === previous", tablet_card)
        assert page.locator(".lab-card-cover").first.evaluate("(element, previous) => element === previous", tablet_cover)
        assert page.locator(".lab-canvas").evaluate("element => element.scrollTop") == tablet_scroll_top
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
        dvwa_lab = next(lab for lab in labs_payload if lab["slug"] == "dvwa")
        dvwa_lab["status"] = "ready"
        dvwa_lab["localPath"] = "/tmp/vulnlab-browser-fixture/dvwa"
        start_state = {"completed": False}

        def labs_with_ready_dvwa(route, request):
            if request.method == "GET":
                route.fulfill(status=200, content_type="application/json", body=json.dumps(labs_payload, ensure_ascii=False))
            else:
                route.continue_()

        def instances_after_start(route, request):
            if request.method == "GET":
                instances = [{
                    "id": "browser-instance",
                    "labId": dvwa_lab["id"],
                    "status": "running",
                    "endpoint": "http://127.0.0.1:65535/",
                    "expiresAt": "2099-01-01T00:00:00.000Z",
                }] if start_state["completed"] else []
                route.fulfill(status=200, content_type="application/json", body=json.dumps(instances))
            else:
                route.continue_()

        page.route("**/api/labs", labs_with_ready_dvwa)
        page.route("**/api/instances", instances_after_start)
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
        dvwa_lab["status"] = "cataloged"
        page.reload(wait_until="networkidle")
        page.locator('.lab-card-media[data-id]').first.click()
        expect(page.get_by_role("button", name="准备并启动", exact=True)).to_be_visible()
        expect(page.get_by_text("待准备", exact=True)).to_be_visible()
        page.get_by_role("button", name="关闭靶场信息").click()
        dvwa_lab["status"] = "importing"
        preparing_job = {
            "id": "browser-preparing-job",
            "labId": dvwa_lab["id"],
            "sourceUrl": dvwa_lab["sourceUrl"],
            "requestedBy": "system",
            "status": "importing",
            "stage": "extracting",
            "message": "正在解压靶场资源。",
            "progress": 42,
            "error": None,
            "manifest": None,
            "createdAt": "2026-09-06T00:00:00.000Z",
            "updatedAt": "2026-09-06T00:00:00.000Z",
        }

        def preparing_jobs(route, request):
            if request.method == "GET":
                route.fulfill(status=200, content_type="application/json", body=json.dumps([preparing_job], ensure_ascii=False))
            else:
                route.continue_()

        page.route("**/api/import-jobs", preparing_jobs)
        page.reload(wait_until="networkidle")
        page.locator('.lab-card-media[data-id]').first.click()
        expect(page.locator(".lab-detail-progress")).to_be_visible()
        expect(page.locator(".lab-detail-progress")).to_contain_text("解压资源")
        expect(page.locator(".lab-detail-progress")).to_contain_text("42%")
        expect(page.locator(".lab-detail-progress")).to_contain_text("正在解压靶场资源")
        expect(page.get_by_role("button", name="准备中…", exact=True)).to_have_count(0)
        expect(page.get_by_text("准备中…", exact=True)).to_be_visible()
        page.screenshot(path=str(OUTPUT_DIR / "lab-detail-preparing-desktop.png"), full_page=True)
        page.get_by_role("button", name="关闭靶场信息").click()
        page.unroute("**/api/import-jobs", preparing_jobs)
        dvwa_lab["status"] = "ready"
        page.reload(wait_until="networkidle")
        page.locator('.lab-card-media[data-id]').first.click()
        expect(page.get_by_role("button", name="启动环境", exact=True)).to_be_visible()
        detail_start_button = page.locator('.lab-detail-dialog [data-action="start-instance"]')
        expect(detail_start_button).to_have_count(1)
        page.wait_for_timeout(250)
        pending_start = {}

        def hold_start(route, request):
            if request.method == "POST":
                pending_start["route"] = route
                return
            route.continue_()

        page.evaluate(
            """() => {
                window.__vulnlabDetailUpdateAnimations = 0
                document.addEventListener('animationstart', event => {
                    if (event.animationName === 'dialog-in' || event.animationName === 'dialog-backdrop-in') {
                        window.__vulnlabDetailUpdateAnimations += 1
                    }
                }, true)
            }"""
        )
        page.route("**/api/labs/*/instances", hold_start)
        detail_start_button.click()
        expect(page.locator('.lab-card[data-state="starting"]')).to_have_count(1)
        expect(page.locator(".lab-detail-dialog")).to_contain_text("启动中…")
        expect(page.locator(".lab-detail-state")).to_have_count(0)
        starting_action_style = page.locator(".lab-detail-action").evaluate(
            "element => ({ display: getComputedStyle(element).display, alignItems: getComputedStyle(element).alignItems, justifyContent: getComputedStyle(element).justifyContent, textAlign: getComputedStyle(element).textAlign })"
        )
        assert starting_action_style["display"] in {"flex", "inline-flex"} and starting_action_style["alignItems"] == "center" and starting_action_style["justifyContent"] == "center" and starting_action_style["textAlign"] == "center", starting_action_style
        page.wait_for_timeout(1200)
        expect(page.get_by_role("button", name="关闭靶场信息")).to_be_focused()
        assert page.evaluate("window.__vulnlabDetailUpdateAnimations") == 0
        assert "route" in pending_start
        start_state["completed"] = True
        pending_start["route"].fulfill(status=201, content_type="application/json", body='{"status":"running"}')
        expect(page.locator(".lab-detail-running")).to_be_visible()
        expect(page.locator('.lab-card[data-state="running"]')).to_have_count(1)
        expect(page.get_by_role("button", name="关闭靶场信息")).to_be_focused()
        assert page.evaluate("window.__vulnlabDetailUpdateAnimations") == 0
        page.get_by_role("button", name="关闭靶场信息").click()
        page.locator(".lab-card-media").nth(1).click()
        expect(page.locator(".lab-detail-dialog")).to_be_visible()
        page.get_by_role("button", name="关闭靶场信息").click()
        page.unroute("**/api/labs/*/instances", hold_start)
        start_state["completed"] = False
        dvwa_lab["status"] = "error"
        failed_job = {
            "id": "browser-failed-job",
            "labId": dvwa_lab["id"],
            "sourceUrl": dvwa_lab["sourceUrl"],
            "requestedBy": "system",
            "status": "error",
            "stage": "reconcile",
            "message": "内置靶场本地资源路径已失效，等待重新安装。",
            "progress": 0,
            "error": "内置靶场本地资源路径已失效，等待重新安装。",
            "manifest": None,
            "createdAt": "2026-09-06T00:00:00.000Z",
            "updatedAt": "2026-09-06T00:00:00.000Z",
        }

        def labs_with_failed_dvwa(route, request):
            if request.method == "GET":
                route.fulfill(status=200, content_type="application/json", body=json.dumps(labs_payload, ensure_ascii=False))
            else:
                route.continue_()

        def failed_jobs(route, request):
            if request.method == "GET":
                route.fulfill(status=200, content_type="application/json", body=json.dumps([failed_job], ensure_ascii=False))
            else:
                route.continue_()

        page.unroute("**/api/labs", labs_with_ready_dvwa)
        page.route("**/api/labs", labs_with_failed_dvwa)
        page.route("**/api/import-jobs", failed_jobs)
        page.reload(wait_until="networkidle")
        expect(page.locator(".lab-grid")).to_be_visible()
        page.locator('.lab-card-media[data-id]').first.click()
        expect(page.locator(".lab-detail-error")).to_contain_text("内置靶场本地资源路径已失效")
        expect(page.locator(".lab-detail-runtime")).to_have_count(0)
        expect(page.locator(".lab-detail-error")).not_to_contain_text("C:\\Users\\")
        failed_detail_style = page.locator(".lab-detail-error").evaluate(
            "element => ({ borderLeftWidth: getComputedStyle(element).borderLeftWidth, borderRadius: getComputedStyle(element).borderRadius })"
        )
        assert failed_detail_style == {"borderLeftWidth": "1px", "borderRadius": "6px"}, failed_detail_style
        expect(page.get_by_role("button", name="重试启动", exact=True)).to_be_visible()
        page.screenshot(path=str(OUTPUT_DIR / "lab-detail-error-desktop.png"), full_page=True)
        page.get_by_role("button", name="关闭靶场信息").click()
        page.unroute("**/api/import-jobs", failed_jobs)
        page.unroute("**/api/labs", labs_with_failed_dvwa)
        page.wait_for_timeout(3800)
        page.unroute("**/api/instances", instances_after_start)
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
        expect(page.locator(".lab-workspace-head, .workspace-nav")).to_have_count(0)
        expect(page.locator(".workspace-account")).to_have_count(0)
        page.screenshot(path=str(OUTPUT_DIR / "labs-mobile.png"), full_page=True)

        mobile_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(mobile_columns.split()) == 2, mobile_columns
        mobile_card_box = page.locator(".lab-card").first.bounding_box()
        assert mobile_card_box and mobile_card_box["height"] <= 140, mobile_card_box
        mobile_corner_style = page.locator(".lab-card").first.evaluate(
            """element => ({
                cardRadius: getComputedStyle(element).borderRadius,
                mediaRadius: getComputedStyle(element.querySelector('.lab-card-media')).borderRadius,
                coverRadius: getComputedStyle(element.querySelector('.lab-card-cover')).borderRadius,
                captionRadius: getComputedStyle(element.querySelector('.lab-card-caption')).borderBottomRightRadius,
                mediaBackground: getComputedStyle(element.querySelector('.lab-card-media')).backgroundColor,
                coverClipPath: getComputedStyle(element.querySelector('.lab-card-cover')).clipPath,
                cardBackground: getComputedStyle(element).backgroundColor,
                captionBackground: getComputedStyle(element.querySelector('.lab-card-caption')).backgroundColor
            })"""
        )
        assert mobile_corner_style == {"cardRadius": "12px", "mediaRadius": "0px", "coverRadius": "0px", "captionRadius": "0px", "mediaBackground": "rgb(24, 24, 24)", "coverClipPath": "inset(0px 0px 38px)", "cardBackground": "rgb(24, 24, 24)", "captionBackground": "rgb(24, 24, 24)"}, mobile_corner_style
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
        reduced_context = browser.new_context(viewport={"width": 739, "height": 953}, device_scale_factor=1)
        reduced_page = reduced_context.new_page()
        reduced_page.emulate_media(reduced_motion="reduce")
        reduced_page.add_init_script(
            """window.__vulnlabReducedLoginAnimationStarts = 0;
            document.addEventListener('animationstart', event => {
                if (event.animationName === 'login-form-in') window.__vulnlabReducedLoginAnimationStarts += 1
            }, true)"""
        )
        reduced_page.goto(BASE_URL, wait_until="networkidle")
        expect(reduced_page.locator(".login-form")).to_be_visible()
        reduced_login_animation = reduced_page.locator(".login-form").evaluate(
            "element => ({ animationName: getComputedStyle(element).animationName, animationDuration: getComputedStyle(element).animationDuration })"
        )
        assert reduced_login_animation == {"animationName": "login-form-in", "animationDuration": "0.5s"}, reduced_login_animation
        assert reduced_page.evaluate("window.__vulnlabReducedLoginAnimationStarts >= 1")
        reduced_page.close()
        reduced_context.close()
        assert not console_errors, console_errors
        browser.close()
    print(f"VulnLab browser check passed; screenshots: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
