const dirty = () => document.querySelector('[data-console-dirty="true"]');
let discardUntil = 0;
const mayDiscard = () => !dirty() || Date.now() < discardUntil || (() => {
  const accepted = window.confirm(document.documentElement.lang.startsWith('zh')
    ? '有未保存的更改。离开将丢弃这些更改，是否继续？'
    : 'You have unsaved changes. Discard them and continue?');
  if (accepted) discardUntil = Date.now() + 1000;
  return accepted;
})();

window.addEventListener('beforeunload', event => {
  if (dirty() && Date.now() >= discardUntil) {
    event.preventDefault();
    event.returnValue = '';
  }
});

// Some desktop native pickers select/dismiss on the opening mouse release.
// For explicitly marked controls, open after the complete click instead.
// Keep native keyboard behavior and fall back in unsupported browsers.
let clickPicker = null;
document.addEventListener('mousedown', event => {
  clickPicker = null;
  const select = event.target instanceof HTMLSelectElement ? event.target : null;
  if (event.button !== 0 || !select?.hasAttribute('data-console-click-picker')
    || typeof select.showPicker !== 'function' || !CSS.supports('selector(select:open)')
    || select.matches(':disabled')
    || select.closest('[inert]') || select.matches(':open')) return;
  event.preventDefault();
  select.focus({ preventScroll: true });
  clickPicker = select;
}, true);
document.addEventListener('click', event => {
  const select = clickPicker;
  clickPicker = null;
  if (!select || !event.isTrusted || event.detail === 0 || event.target !== select || !select.isConnected
    || select.matches(':disabled') || select.closest('[inert]')) return;
  event.preventDefault();
  select.showPicker();
}, true);
document.addEventListener('pointercancel', () => { clickPicker = null; }, true);
window.addEventListener('blur', () => { clickPicker = null; });

const submissionInProgress = () => [...document.querySelectorAll(
  '[role="dialog"][aria-modal="true"],[role="alertdialog"][aria-modal="true"]'
)].filter(node => node.isConnected && node.getClientRects().length > 0 && node.getAttribute('aria-hidden') !== 'true')
  .at(-1)?.querySelector('[data-console-submitting="true"]') != null
  || document.querySelector('.access-page [data-console-submitting="true"]') != null;

document.addEventListener('click', event => {
  const target = event.target instanceof Element ? event.target : null;
  const link = target?.closest('a[href]');
  if (link && !link.hasAttribute('download') && !link.href.includes('/export?')) {
    const url = new URL(link.href, location.href);
    if (url.origin === location.origin && url.pathname === location.pathname && url.search === location.search && url.hash) {
      const section = document.getElementById(decodeURIComponent(url.hash.slice(1)));
      if (section) {
        for (let parent = section; parent; parent = parent.parentElement) {
          if (parent.tagName === 'DETAILS') parent.open = true;
        }
        section.scrollIntoView({ block: 'start' });
        event.preventDefault();
        return;
      }
    }
    if (link.href !== location.href && !mayDiscard()) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }
  if (target?.classList.contains('overlay-backdrop')
    || target?.closest('button[aria-label="Close / 关闭"]')
    || target?.closest('.console-drawer .segmented button')
    || target?.closest('[data-console-dismiss]')) {
    if (submissionInProgress() || !mayDiscard()) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }
}, true);

const modalSelector = '[role="dialog"][aria-modal="true"],[role="alertdialog"][aria-modal="true"]';
const isVisible = node => node?.isConnected && node.getClientRects().length > 0 && node.getAttribute('aria-hidden') !== 'true';
const focusable = dialog => [...dialog.querySelectorAll(
  'button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),summary,[contenteditable="true"],[tabindex]'
)].filter(node => node.tabIndex >= 0 && node.getClientRects().length && !node.closest('[inert]'));
const focusHistory = new Map();
const modalInertHistory = new Map();

const focusSnapshot = node => {
  if (!(node instanceof HTMLElement)) return { node: null, selector: null };
  const key = node.dataset.consoleFocusKey;
  if (key) return { node, selector: `[data-console-focus-key="${CSS.escape(key)}"]` };
  if (node.id) return { node, selector: `#${CSS.escape(node.id)}` };
  return { node, selector: null };
};

const focusSnapshotTarget = snapshot => {
  const direct = snapshot?.node;
  if (direct?.isConnected && !direct.closest('[inert]')) return direct;
  if (!snapshot?.selector) return null;
  const replacement = document.querySelector(snapshot.selector);
  return replacement instanceof HTMLElement && replacement.getClientRects().length && !replacement.closest('[inert]')
    ? replacement
    : null;
};

const syncModalInert = dialog => {
  const background = new Set();
  if (dialog) {
    let branch = dialog;
    for (let parent = dialog.parentElement; parent; parent = parent.parentElement) {
      for (const sibling of parent.children) {
        if (sibling !== branch && sibling instanceof HTMLElement) background.add(sibling);
      }
      branch = parent;
    }
  }
  // Keep unchanged background nodes inert while async dialog content updates.
  // Avoid temporarily re-enabling the background on every content update.
  for (const [node, wasInert] of modalInertHistory) {
    if (background.has(node)) continue;
    if (node.isConnected) node.toggleAttribute('inert', wasInert);
    modalInertHistory.delete(node);
  }
  for (const node of background) {
    if (!modalInertHistory.has(node)) modalInertHistory.set(node, node.hasAttribute('inert'));
    if (!node.hasAttribute('inert')) node.setAttribute('inert', '');
  }
};

const syncDialogs = () => {
  // Initial route dialogs are already present in SSR. Wait until Dioxus removes
  // its hydration locks before recording the background's original inert state.
  const workspace = document.querySelector('main[data-console-ready]');
  if (workspace && workspace.dataset.consoleReady !== 'true') return;
  const visibleDialogs = [...document.querySelectorAll(modalSelector)].filter(isVisible);
  const closedFocusTargets = [];

  for (const [dialog, previous] of focusHistory) {
    if (!visibleDialogs.includes(dialog)) {
      focusHistory.delete(dialog);
      closedFocusTargets.push(previous);
    }
  }

  for (const dialog of visibleDialogs) {
    if (!focusHistory.has(dialog)) focusHistory.set(dialog, focusSnapshot(document.activeElement));
  }

  const activeDialog = visibleDialogs.at(-1);
  syncModalInert(activeDialog);

  const restore = closedFocusTargets.reverse().map(focusSnapshotTarget).find(Boolean);
  if (restore) restore.focus();

  if (activeDialog && !activeDialog.contains(document.activeElement)) {
    (activeDialog.querySelector('[autofocus]') ?? focusable(activeDialog)[0] ?? activeDialog).focus();
  }
};

new MutationObserver(syncDialogs).observe(document.getElementById('main') ?? document.body, {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ['hidden', 'aria-hidden', 'class', 'data-console-ready'],
});
syncDialogs();

const closeOpenMenu = () => {
  const menu = [...document.querySelectorAll('details.account-menu[open],details.network-switcher[open],details.toolbar-more[open],details.device-more[open]')].at(-1);
  if (!menu) return false;
  menu.open = false;
  menu.querySelector('summary')?.focus();
  return true;
};

const moveTabFocus = (event, target) => {
  const tab = target?.closest('[role="tab"]');
  const list = tab?.closest('[role="tablist"]');
  if (!tab || !list) return false;
  const tabs = [...list.querySelectorAll('[role="tab"]')]
    .filter(node => !node.disabled && node.getClientRects().length);
  if (tabs.length < 2) return false;
  const current = Math.max(0, tabs.indexOf(tab));
  let next = current;
  if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (current + 1) % tabs.length;
  else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (current - 1 + tabs.length) % tabs.length;
  else if (event.key === 'Home') next = 0;
  else if (event.key === 'End') next = tabs.length - 1;
  else return false;
  event.preventDefault();
  if (next === current) {
    tab.focus();
    return true;
  }
  if (submissionInProgress() || !mayDiscard()) return true;
  tabs[next].click();
  tabs[next].focus();
  return true;
};

document.addEventListener('keydown', event => {
  const target = event.target instanceof Element ? event.target : null;
  if (moveTabFocus(event, target)) return;

  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    const search = document.querySelector('button[aria-label="全局搜索"],button[aria-label="Global search"]');
    if (search) {
      event.preventDefault();
      search.click();
    }
  }

  const visibleDialogs = [...focusHistory.keys()].filter(isVisible);
  const dialog = visibleDialogs.at(-1);
  if (event.key === 'Escape') {
    if (dialog && (submissionInProgress() || !mayDiscard())) {
      event.preventDefault();
      event.stopImmediatePropagation();
      return;
    }
    if (!dialog && closeOpenMenu()) {
      event.preventDefault();
      return;
    }
  }

  if (event.key !== 'Tab' || !dialog) return;
  const nodes = focusable(dialog);
  if (!nodes.length) {
    event.preventDefault();
    dialog.focus();
    return;
  }
  if (event.shiftKey && (document.activeElement === nodes[0] || !dialog.contains(document.activeElement))) {
    event.preventDefault();
    nodes.at(-1).focus();
  } else if (!event.shiftKey && (document.activeElement === nodes.at(-1) || !dialog.contains(document.activeElement))) {
    event.preventDefault();
    nodes[0].focus();
  }
}, true);

const revealHash = () => {
  if (!location.hash) return;
  let id;
  try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
  const section = document.getElementById(id);
  if (!section) return;
  for (let parent = section; parent; parent = parent.parentElement) {
    if (parent.tagName === 'DETAILS') parent.open = true;
  }
};
window.addEventListener('hashchange', revealHash);
new MutationObserver(revealHash).observe(document.body, { childList: true, subtree: true });
revealHash();

const previousSelections = new WeakMap();
document.addEventListener('focusin', event => {
  const select = event.target instanceof HTMLSelectElement ? event.target : null;
  if (select) previousSelections.set(select, select.value);
}, true);
document.addEventListener('change', event => {
  const select = event.target instanceof HTMLSelectElement ? event.target : null;
  if (!select || !(select.matches('[data-console-selection]')
    || ['live-mesh-selection', 'live-resource-selection'].includes(select.id))) return;
  if (submissionInProgress() || !mayDiscard()) {
    select.value = previousSelections.get(select) ?? '';
    event.stopImmediatePropagation();
  } else {
    previousSelections.set(select, select.value);
  }
}, true);

// Icon-only copy controls announce success only after the Clipboard API resolves.
document.addEventListener('click', async (event) => {
  const button = event.target.closest?.('button.copy-value[data-copy-value]');
  if (!button) return;
  event.preventDefault();
  event.stopPropagation();
  if (button.dataset.copyState === 'busy') return;
  button.dataset.copyState = 'busy';
  const feedback = button.querySelector('.copy-feedback');
  if (feedback) feedback.textContent = '';
  try {
    await navigator.clipboard.writeText(button.dataset.copyValue);
    button.dataset.copyState = 'done';
    button.title = button.dataset.copyDone;
    if (feedback) feedback.textContent = button.dataset.copyDone;
  } catch {
    button.dataset.copyState = 'error';
    button.title = button.dataset.copyError;
    if (feedback) feedback.textContent = button.dataset.copyError;
  }
  setTimeout(() => {
    if (!button.isConnected || button.dataset.copyState === 'busy') return;
    delete button.dataset.copyState;
    button.title = button.dataset.copyReady;
    if (feedback) feedback.textContent = '';
  }, 2400);
}, true);
