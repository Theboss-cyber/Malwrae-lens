/* MalwareLens shared client JS: app-shell sidebar toggle + profile menu.
   Loaded on every app page (and the home page for profile + legacy nav). */
(function () {
    'use strict';

    function isMobile() { return window.innerWidth < 1024; }

    // --- App-shell sidebar (authed app pages) ---
    var shell = document.querySelector('.app-shell');
    var toggle = document.querySelector('.nav-toggle');
    var sidebar = document.querySelector('.sidebar');
    var backdrop = document.querySelector('.sidebar-backdrop');

    function setOpen(open) {
        if (!shell) return;
        shell.classList.toggle('sidebar-open', open);
        if (toggle) {
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            if (isMobile()) toggle.textContent = open ? '✕' : '☰';
        }
    }

    if (shell && toggle) {
        toggle.addEventListener('click', function () {
            setOpen(!shell.classList.contains('sidebar-open'));
        });
    }

    // Close on backdrop click (mobile drawer)
    if (shell && backdrop) {
        backdrop.addEventListener('click', function () { setOpen(false); });
    }

    // Close on Escape + close when a sidebar link is tapped (mobile drawer)
    if (shell) {
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && shell.classList.contains('sidebar-open')) {
                setOpen(false);
                if (toggle) toggle.focus();
            }
        });
    }
    if (sidebar) {
        sidebar.addEventListener('click', function (e) {
            if (isMobile() && e.target.closest('a[href]')) setOpen(false);
        });
        // Immediate active-item switching for visual feedback
        sidebar.querySelectorAll('.side-link').forEach(function (link) {
            link.addEventListener('click', function () {
                sidebar.querySelectorAll('.side-link.active').forEach(function (x) {
                    x.classList.remove('active');
                    x.removeAttribute('aria-current');
                });
                link.classList.add('active');
                link.setAttribute('aria-current', 'page');
            });
        });
    }

    // --- Legacy mobile top-nav toggle (home page only) ---
    var nav = document.querySelector('.main-nav');
    if (!shell && toggle && nav) {
        toggle.addEventListener('click', function () {
            var open = nav.classList.toggle('nav-open');
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            toggle.textContent = open ? '✕' : '☰';
        });
        nav.addEventListener('click', function (e) {
            if (window.innerWidth <= 900 && e.target.closest('a[href]')) {
                nav.classList.remove('nav-open');
                toggle.setAttribute('aria-expanded', 'false');
                toggle.textContent = '☰';
            }
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && nav.classList.contains('nav-open')) {
                nav.classList.remove('nav-open');
                toggle.setAttribute('aria-expanded', 'false');
                toggle.textContent = '☰';
                toggle.focus();
            }
        });
    }

    // --- Mark the current page link for assistive tech ---
    if (sidebar) {
        sidebar.querySelectorAll('.side-link.active').forEach(function (link) {
            link.setAttribute('aria-current', 'page');
        });
    }
    if (nav) {
        nav.querySelectorAll('.nav-link.active').forEach(function (link) {
            if (!link.hasAttribute('aria-current')) link.setAttribute('aria-current', 'page');
        });
    }

    // --- Profile dropdown ---
    var profileBtn = document.querySelector('.nav-profile-btn');
    var profileMenu = profileBtn ? profileBtn.nextElementSibling : null;
    if (profileBtn && profileMenu) {
        profileBtn.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            var open = profileMenu.classList.toggle('open');
            profileBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
        document.addEventListener('click', function (e) {
            if (!profileBtn.contains(e.target) && profileMenu.classList.contains('open')) {
                profileMenu.classList.remove('open');
                profileBtn.setAttribute('aria-expanded', 'false');
            }
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && profileMenu.classList.contains('open')) {
                profileMenu.classList.remove('open');
                profileBtn.setAttribute('aria-expanded', 'false');
            }
        });
    }
    // Prevent logout form click from closing dropdown early
    var profileForm = document.querySelector('.profile-menu form');
    if (profileForm) {
        profileForm.addEventListener('click', function (e) { e.stopPropagation(); });
    }
})();
