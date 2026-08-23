"""Browser-level smoke and responsive check for the VulnLab web app."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


BASE_URL = os.environ.get("VULNLAB_BASE_URL", "http://127.0.0.1:6710")
OUTPUT_DIR = Path(os.environ.get("VULNLAB_SCREENSHOT_DIR", tempfile.mkdtemp(prefix="vulnlab-browser-")))


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        # The approved desktop reference is 1440x900. Keeping the regression
        # viewport identical prevents the 3x3 workspace from being mistaken
        # for a different layout when the viewport is taller.
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        console_errors: list[str] = []
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.on("pageerror", lambda error: console_errors.append(str(error)))
        page.goto(BASE_URL, wait_until="networkidle")
        page.get_by_label("账号").fill("vulnlab-admin")
        page.get_by_label("密码").fill("VulnLabAdmin123!")
        page.get_by_role("button", name="登录").click()
        expect(page.get_by_role("heading", name="靶场", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="查看 DVWA", exact=True)).to_be_visible()
        expect(page.locator(".labs-screen")).to_be_visible()
        # The approved lab page is a focused workspace, not the generic
        # management shell used by the other work pages.
        expect(page.locator(".labs-screen .topbar")).to_have_count(0)
        expect(page.locator(".labs-screen .main-content")).to_have_count(0)
        expect(page.get_by_role("complementary", name="运行状态")).to_be_visible()
        expect(page.locator(".lab-grid .lab-card:not(.lab-card-add)")).to_have_count(8)
        expect(page.locator(".lab-grid .lab-card-add")).to_have_count(1)
        expect(page.get_by_role("button", name="添加靶场环境")).to_be_visible()
        expect(page.locator(".runtime-ascii")).to_be_visible()
        expect(page.locator(".runtime-ascii")).to_contain_text("____ _")
        expect(page.locator(".runtime-signals")).to_have_count(0)
        expect(page.locator(".runtime-log-head")).to_have_count(0)
        expect(page.locator(".runtime-heading")).to_have_count(0)
        expect(page.locator(".runtime-meta")).to_have_count(0)
        expect(page.locator(".runtime-capacity")).to_have_count(0)
        expect(page.locator(".lab-card-head small")).to_have_count(0)
        desktop_titles = page.locator(".lab-card:not(.lab-card-add) .lab-card-head > span").evaluate_all(
            "elements => elements.map(element => element.textContent.trim())"
        )
        assert desktop_titles == [
            "DVWA", "Pikachu", "SQLi-Labs", "Upload-Labs",
            "VulnHub Machines", "Vulhub", "OWASP Juice Shop", "OWASP WebGoat",
        ], desktop_titles
        add_slot_alignment = page.locator(".lab-card-add").evaluate(
            "element => ({ justifyContent: getComputedStyle(element).justifyContent, paddingTop: getComputedStyle(element).paddingTop })"
        )
        assert add_slot_alignment == {"justifyContent": "flex-start", "paddingTop": "16px"}, add_slot_alignment
        desktop_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(desktop_columns.split()) == 3, desktop_columns
        workspace_columns = page.locator(".labs-screen").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(workspace_columns.split()) == 2, workspace_columns
        screen_box = page.locator(".labs-screen").bounding_box()
        assert screen_box and abs(screen_box["x"] - 18) <= 1 and abs(screen_box["y"] - 18) <= 1, screen_box
        assert screen_box and abs(screen_box["width"] - 1404) <= 1 and abs(screen_box["height"] - 864) <= 1, screen_box
        desktop_rows = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateRows")
        assert len(desktop_rows.split()) == 3, desktop_rows
        page.screenshot(path=str(OUTPUT_DIR / "labs-desktop.png"), full_page=True)

        page.get_by_role("button", name="添加靶场环境", exact=True).click()
        expect(page.get_by_role("heading", name="导入", exact=True)).to_be_visible()
        page.get_by_role("button", name="环境", exact=True).click()
        expect(page.get_by_role("heading", name="环境", exact=True)).to_be_visible()
        expect(page.get_by_text("这里只配置运行参数，不混入靶场 3×3 展示。", exact=True)).to_be_visible()
        page.screenshot(path=str(OUTPUT_DIR / "settings-desktop.png"), full_page=True)

        page.get_by_role("button", name="导入", exact=True).click()
        expect(page.get_by_role("heading", name="导入", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="登记导入任务", exact=True)).to_be_visible()
        catalog_buttons = page.get_by_role("button", name="查看机器", exact=True)
        if catalog_buttons.count():
            catalog_buttons.first.click()
            expect(page.get_by_role("heading", name="VulnHub 机器目录", exact=True)).to_be_visible()
            expect(page.get_by_role("listbox", name="VulnHub 机器", exact=True)).to_be_visible()
            expect(page.locator(".catalog-entry.is-selected")).to_have_count(1)
            page.get_by_role("button", name="关闭目录", exact=True).click()

        page.set_viewport_size({"width": 390, "height": 844})
        page.get_by_role("button", name="靶场", exact=True).click()
        expect(page.locator(".lab-grid")).to_be_visible()
        expect(page.locator(".lab-grid .lab-card:not(.lab-card-add)")).to_have_count(8)
        mobile_titles = page.locator(".lab-card:not(.lab-card-add) .lab-card-head > span").evaluate_all(
            "elements => elements.map(element => element.textContent.trim())"
        )
        assert mobile_titles == desktop_titles, mobile_titles
        expect(page.locator(".runtime-line:visible")).to_have_count(2)
        runtime_box = page.locator(".runtime-panel").bounding_box()
        workspace_head_box = page.locator(".lab-workspace-head").bounding_box()
        assert runtime_box and 95 <= runtime_box["height"] <= 97, runtime_box
        assert workspace_head_box and 41 <= workspace_head_box["height"] <= 43, workspace_head_box
        page.screenshot(path=str(OUTPUT_DIR / "labs-mobile.png"), full_page=True)

        mobile_columns = page.locator(".lab-grid").evaluate("element => getComputedStyle(element).gridTemplateColumns")
        assert len(mobile_columns.split()) == 2, mobile_columns
        assert not console_errors, console_errors
        browser.close()
    print(f"VulnLab browser check passed; screenshots: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
