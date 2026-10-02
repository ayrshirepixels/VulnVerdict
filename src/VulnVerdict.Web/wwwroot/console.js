// Colour theme and the phone menu. Loaded from <head> as a plain blocking script so the stored theme is on <html>
// before the first paint (the CSP allows no inline script, so this is the earliest it can run).
(function () {
    'use strict';
    var KEY = 'vv.theme';
    var root = document.documentElement;

    // ---- theme: auto (follow the browser), light or dark, remembered per browser
    function stored() {
        try {
            var v = localStorage.getItem(KEY);
            return v === 'light' || v === 'dark' ? v : 'auto';
        } catch (e) { return 'auto'; }   // storage blocked: follow the browser
    }

    function apply() {
        var theme = stored();
        if (root.getAttribute('data-theme') !== theme) root.setAttribute('data-theme', theme);
        // the browser picks the theme-color tag by its media query; an explicit choice has to win over that
        var metas = document.querySelectorAll('meta[name="theme-color"]');
        for (var i = 0; i < metas.length; i++) {
            var own = metas[i].getAttribute('data-' + (theme === 'auto' ? metas[i].getAttribute('data-scheme') : theme));
            if (own && metas[i].getAttribute('content') !== own) metas[i].setAttribute('content', own);
        }
        var buttons = document.querySelectorAll('[data-theme-set]');
        for (var j = 0; j < buttons.length; j++)
            buttons[j].setAttribute('aria-pressed', buttons[j].getAttribute('data-theme-set') === theme ? 'true' : 'false');
    }

    apply();
    document.addEventListener('DOMContentLoaded', apply);
    // Blazor's enhanced navigation rewrites <html> and <head> from the server's copy, which knows nothing of the choice
    new MutationObserver(apply).observe(root, { attributes: true, attributeFilter: ['data-theme'] });
    // another tab changed it
    window.addEventListener('storage', function (e) { if (e.key === KEY || e.key === null) apply(); });

    // ---- phone menu: the sidebar is a drawer while <html> has .nav-open
    function setNav(open) {
        root.classList.toggle('nav-open', open);
        var toggle = document.querySelector('[data-nav-toggle]');
        if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (open) apply();   // the theme buttons inside may have been rendered again since the page loaded
    }

    document.addEventListener('click', function (e) {
        if (!(e.target instanceof Element)) return;
        var choice = e.target.closest('[data-theme-set]');
        if (choice) {
            var theme = choice.getAttribute('data-theme-set');
            try {
                if (theme === 'light' || theme === 'dark') localStorage.setItem(KEY, theme);
                else localStorage.removeItem(KEY);
            } catch (err) { }
            apply();
            return;
        }
        if (e.target.closest('[data-nav-toggle]')) { setNav(!root.classList.contains('nav-open')); return; }
        // a tap outside the drawer, or on a link inside it, closes it; the link still navigates
        if (e.target.closest('[data-nav-close]') || e.target.closest('.sidebar a')) setNav(false);
    });
    // the layout is rendered again without the pressed state when the circuit starts, so refresh it as focus arrives
    document.addEventListener('focusin', function (e) {
        if (e.target instanceof Element && e.target.closest('[data-theme-set]')) apply();
    });
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || !root.classList.contains('nav-open')) return;
        setNav(false);
        var toggle = document.querySelector('[data-nav-toggle]');
        if (toggle) toggle.focus();
    });
    window.addEventListener('popstate', function () { setNav(false); });
})();
