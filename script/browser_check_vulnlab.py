"""Browser-level smoke and responsive check for the VulnLab web app."""

from __future__ import annotations

import os
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
        expect(page.get_by_role("button", name="关闭提示")).to_be_visible()
        notice_style = page.locator("#login-notice").evaluate(
            "element => ({ position: getComputedStyle(element).position, top: getComputedStyle(element).top, right: getComputedStyle(element).right, width: getComputedStyle(element).width, height: getComputedStyle(element).height, borderRadius: getComputedStyle(element).borderRadius, borderColor: getComputedStyle(element).borderColor, backgroundColor: getComputedStyle(element).backgroundColor, boxShadow: getComputedStyle(element).boxShadow })"
        )
        assert notice_style["position"] == "fixed", notice_style
        assert notice_style["top"] in {"24px", "16px"}, notice_style
        assert float(notice_style["width"].replace("px", "")) <= 320, notice_style
        assert float(notice_style["height"].replace("px", "")) <= 68, notice_style
        assert notice_style["borderRadius"] == "12px", notice_style
        assert notice_style["borderColor"] == "rgb(228, 235, 242)", notice_style
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
        assert success_notice_style["borderRadius"] == "12px", success_notice_style
        assert success_notice_style["boxShadow"] != "none", success_notice_style
        page.screenshot(path=str(OUTPUT_DIR / "login-success-notice-desktop.png"), full_page=True)
        expect(page.get_by_role("button", name="靶场", exact=True)).to_be_visible()
        expect(page.get_by_text("DVWA", exact=True)).to_be_visible()
        expect(page.locator(".labs-screen")).to_be_visible()
        expect(page.locator(".labs-screen .topbar")).to_have_count(0)
        expect(page.locator(".labs-screen .main-content")).to_have_count(0)
        expect(page.get_by_role("complementary", name="运行状态")).to_be_visible()
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        page.wait_for_timeout(4500)
        expect(page.locator("#login-success-notice")).to_have_count(0)
        expect(page.get_by_role("button", name="退出登录")).to_have_text("vulnlab")
        expect(page.locator(".runtime-ascii")).to_be_visible()
        expect(page.locator(".runtime-ascii")).to_contain_text("____ _")
        expect(page.locator(".runtime-signals")).to_have_count(0)
        expect(page.locator(".runtime-log-head")).to_have_count(0)
        expect(page.locator(".runtime-heading")).to_have_count(0)
        expect(page.locator(".runtime-meta")).to_have_count(0)
        expect(page.locator(".runtime-capacity")).to_have_count(0)
        expect(page.locator(".lab-card-head small")).to_have_count(0)
        desktop_titles = page.locator(".lab-card .lab-card-head > span").evaluate_all(
            "elements => elements.map(element => element.textContent.trim())"
        )
        assert desktop_titles == [
            "DVWA", "Pikachu", "SQLi-Labs", "Upload-Labs",
            "VulnHub Machines", "OWASP Juice Shop", "OWASP WebGoat", "OWASP Mutillidae II", "OWASP PyGoat",
        ], desktop_titles
        account_typography = page.locator(".workspace-account").evaluate(
            "element => ({ fontFamily: getComputedStyle(element).fontFamily, fontWeight: getComputedStyle(element).fontWeight })"
        )
        assert "monospace" not in account_typography["fontFamily"], account_typography
        assert int(account_typography["fontWeight"]) >= 600, account_typography
        expect(page.get_by_text("打开项目", exact=True)).to_have_count(0)
        expect(page.get_by_text("添加环境", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="资源", exact=True)).to_have_count(0)
        expect(page.get_by_role("button", name="审计", exact=True)).to_have_count(0)
        desktop_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(desktop_columns.split()) == 3, desktop_columns
        workspace_columns = page.locator(".labs-screen").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(workspace_columns.split()) == 2, workspace_columns
        screen_box = page.locator(".labs-screen").bounding_box()
        assert screen_box and abs(screen_box["x"] - 18) <= 1 and abs(screen_box["y"] - 18) <= 1, screen_box
        assert screen_box and abs(screen_box["width"] - 1404) <= 1 and abs(screen_box["height"] - 864) <= 1, screen_box
        desktop_rows = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateRows")
        assert len(desktop_rows.split()) == 3, desktop_rows
        page.get_by_role("button", name="查看机器", exact=True).click()
        expect(page.get_by_role("dialog", name="VulnHub 机器目录")).to_be_visible()
        expect(page.locator(".catalog-entry")).to_have_count(12)
        expect(page.locator(".catalog-entry").first).to_contain_text("Matrix-Breakout: 2 Morpheus")
        expect(page.get_by_text("Details", exact=True)).to_have_count(0)
        expect(page.locator(".catalog-detail-title .eyebrow")).to_have_count(0)
        page.get_by_role("button", name="关闭目录").click()
        page.screenshot(path=str(OUTPUT_DIR / "labs-desktop.png"), full_page=True)
        if PRIMARY_SCREENSHOT:
            primary = Path(PRIMARY_SCREENSHOT)
            primary.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(primary), full_page=True)

        page.get_by_role("button", name="环境", exact=True).click()
        expect(page.get_by_role("heading", name="环境", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="运行依赖", exact=True)).to_be_visible()
        expect(page.get_by_role("link", name="打开 Node.js 官方源")).to_be_visible()
        expect(page.get_by_text("Node.js 22.23.1", exact=True)).to_be_visible()
        save_color = page.locator(".settings-save").evaluate("element => getComputedStyle(element).backgroundColor")
        assert save_color == "rgb(46, 127, 146)", save_color
        expect(page.get_by_text("Provider", exact=True)).to_have_count(0)
        page.screenshot(path=str(OUTPUT_DIR / "settings-desktop.png"), full_page=True)

        page.get_by_role("button", name="运行", exact=True).click()
        expect(page.get_by_role("heading", name="运行", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="实例列表", exact=True)).to_be_visible()

        page.set_viewport_size({"width": 390, "height": 844})
        page.get_by_role("button", name="靶场", exact=True).click()
        expect(page.locator(".lab-grid")).to_be_visible()
        expect(page.locator(".lab-grid .lab-card")).to_have_count(9)
        mobile_titles = page.locator(".lab-card .lab-card-head > span").evaluate_all(
            "elements => elements.map(element => element.textContent.trim())"
        )
        assert mobile_titles == desktop_titles, mobile_titles
        expect(page.locator(".runtime-line:visible")).to_have_count(2)
        runtime_box = page.locator(".runtime-panel").bounding_box()
        workspace_head_box = page.locator(".lab-workspace-head").bounding_box()
        assert runtime_box and 95 <= runtime_box["height"] <= 97, runtime_box
        assert workspace_head_box and 47 <= workspace_head_box["height"] <= 49, workspace_head_box
        page.screenshot(path=str(OUTPUT_DIR / "labs-mobile.png"), full_page=True)

        mobile_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(mobile_columns.split()) == 2, mobile_columns
        mobile_widths = page.locator(".card-primary-button").evaluate_all(
            "elements => elements.filter(element => getComputedStyle(element).display !== 'none').map(element => element.getBoundingClientRect().height)"
        )
        assert mobile_widths and min(mobile_widths) >= 44, mobile_widths
        no_horizontal_overflow = page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        assert no_horizontal_overflow
        page.get_by_role("button", name="环境", exact=True).click()
        expect(page.get_by_role("heading", name="运行依赖", exact=True)).to_be_visible()
        expect(page.get_by_role("link", name="打开 Node.js 官方源")).to_be_visible()
        mobile_settings_columns = page.locator(".settings-layout").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(mobile_settings_columns.split()) == 1, mobile_settings_columns
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.screenshot(path=str(OUTPUT_DIR / "settings-mobile.png"), full_page=True)

        page.get_by_role("button", name="运行", exact=True).click()
        expect(page.get_by_role("heading", name="实例列表", exact=True)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        page.screenshot(path=str(OUTPUT_DIR / "instances-mobile.png"), full_page=True)
        assert not console_errors, console_errors
        browser.close()
    print(f"VulnLab browser check passed; screenshots: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
