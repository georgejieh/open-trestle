import assert from "node:assert/strict";

async function checkVisibleControl(control, label) {
  assert.equal(await control.count(), 1, `${label} is unique`);
  const metrics = await control.evaluate((element) => {
    const style = getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    return {
      fontSize: Number.parseFloat(style.fontSize),
      width: bounds.width,
      height: bounds.height,
      display: style.display,
      visibility: style.visibility,
      fits: element.scrollWidth <= element.clientWidth,
    };
  });
  assert.ok(metrics.fontSize >= 12, `${label} retains readable text`);
  assert.ok(
    metrics.width >= 44 && metrics.height >= 44,
    `${label} has a touch target`,
  );
  assert.notEqual(metrics.display, "none", `${label} is displayed`);
  assert.notEqual(metrics.visibility, "hidden", `${label} is visible`);
  assert.ok(metrics.fits, `${label} does not clip`);
  await control.focus();
  assert.ok(
    await control.evaluate((element) => element === document.activeElement),
    `${label} accepts keyboard focus`,
  );
}

export async function checkTabletNavigation(page) {
  assert.equal(
    page.viewportSize().width,
    800,
    "tablet check uses 800 CSS pixels",
  );
  const navigation = page.getByRole("navigation", {
    name: "Console",
    exact: true,
  });
  for (const destination of ["Overview", "Tasks", "Findings", "Runtime"]) {
    await checkVisibleControl(
      navigation.getByRole("button", {
        name: new RegExp(`^${destination}(?: |$)`),
      }),
      destination,
    );
  }
}

export async function checkMobileSetupNavigation(page) {
  assert.ok(
    page.viewportSize().width <= 680,
    "setup check uses the mobile breakpoint",
  );
  const link = page.getByRole("link", { name: "Review console", exact: true });
  assert.equal(await link.getAttribute("href"), "/console/");
  await checkVisibleControl(link, "Review console");
}

export async function checkMobileBrandContrast(page) {
  assert.ok(page.viewportSize().width <= 680, "brand check uses mobile layout");
  const colors = await page.locator(".mobile-head").evaluate((header) => ({
    background: getComputedStyle(header).backgroundColor,
    foregrounds: [
      header.querySelector(".brand strong"),
      header.querySelector(".brand small"),
    ].map((element) => getComputedStyle(element).color),
  }));
  const rgb = (color) => color.match(/[\d.]+/g).map(Number);
  const background = rgb(colors.background);
  assert.ok(
    background.length === 3 || background[3] === 1,
    "mobile header background is opaque",
  );
  const luminance = (values) =>
    values
      .slice(0, 3)
      .map((value) => {
        const channel = value / 255;
        return channel <= 0.04045
          ? channel / 12.92
          : ((channel + 0.055) / 1.055) ** 2.4;
      })
      .reduce(
        (sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index],
        0,
      );
  for (const color of colors.foregrounds) {
    const foreground = rgb(color);
    const alpha = foreground[3] ?? 1;
    const composed = foreground
      .slice(0, 3)
      .map((value, index) => value * alpha + background[index] * (1 - alpha));
    const a = luminance(composed),
      b = luminance(background);
    assert.ok(
      (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) >= 4.5,
      "mobile brand text meets AA contrast",
    );
  }
}
