const header = document.querySelector("[data-header]");
const menuButton = document.querySelector("[data-menu-button]");
const mobileMenu = document.querySelector("[data-mobile-menu]");
const copyButton = document.querySelector("[data-copy-command]");
const main = document.querySelector("main");
const footer = document.querySelector("footer");
const menuLinks = [...(mobileMenu?.querySelectorAll("a") ?? [])];

const setMenuState = (open) => {
  if (!menuButton || !mobileMenu) return;

  menuButton.setAttribute("aria-expanded", String(open));
  menuButton.querySelector(".visually-hidden").textContent = open
    ? "Close navigation"
    : "Open navigation";
  mobileMenu.hidden = !open;
  document.body.classList.toggle("menu-open", open);
  main?.toggleAttribute("inert", open);
  footer?.toggleAttribute("inert", open);
};

menuButton?.addEventListener("click", () => {
  const open = menuButton.getAttribute("aria-expanded") !== "true";
  setMenuState(open);
  if (open) menuLinks[0]?.focus();
});

menuLinks.forEach((link) => {
  link.addEventListener("click", () => setMenuState(false));
});

window.addEventListener("keydown", (event) => {
  if (menuButton?.getAttribute("aria-expanded") !== "true") return;

  if (event.key === "Escape") {
    setMenuState(false);
    menuButton.focus();
    return;
  }

  if (event.key !== "Tab") return;
  const focusable = [menuButton, ...menuLinks];
  const first = focusable[0];
  const last = focusable.at(-1);
  if (!first || !last) return;

  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  } else if (!focusable.includes(document.activeElement)) {
    event.preventDefault();
    first.focus();
  }
});

window.matchMedia("(min-width: 941px)").addEventListener("change", (event) => {
  if (event.matches) setMenuState(false);
});

window.addEventListener(
  "scroll",
  () => header?.classList.toggle("scrolled", window.scrollY > 12),
  { passive: true },
);

document.querySelectorAll("[data-year]").forEach((year) => {
  year.textContent = String(new Date().getFullYear());
});

const revealElements = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window) {
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    },
    { rootMargin: "0px 0px -7%", threshold: 0.08 },
  );

  revealElements.forEach((element) => observer.observe(element));
} else {
  revealElements.forEach((element) => element.classList.add("is-visible"));
}

const quickStart = `git clone https://github.com/cad07/parimit.git
cd parimit
npm start`;

copyButton?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(quickStart);
    copyButton.textContent = "Copied";
    window.setTimeout(() => {
      copyButton.textContent = "Copy";
    }, 1600);
  } catch {
    copyButton.textContent = "Select text";
  }
});
