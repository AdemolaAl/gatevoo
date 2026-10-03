/* Gatevoo checkout pop-up.
 * <script src="https://gatevoo.com/gatevoo.js"></script>
 * Gatevoo.open(checkoutUrl, { onPaid(invoiceId) {}, onClose() {} })
 */
(function () {
  var BASE = '__GATEVOO_BASE__';
  var overlay = null, opts = {};

  function close() {
    if (!overlay) return;
    overlay.remove(); overlay = null;
    document.documentElement.style.overflow = '';
    window.removeEventListener('message', onMsg);
    if (opts.onClose) opts.onClose();
  }
  function onMsg(e) {
    if (BASE.indexOf('__') !== 0 && e.origin !== new URL(BASE).origin) return;
    if (e.data && e.data.type === 'gatevoo:paid' && opts.onPaid) opts.onPaid(e.data.invoice_id);
  }

  function open(url, options) {
    opts = options || {};
    if (!/^https?:\/\//.test(url)) url = BASE + '/pay/' + url; // allow passing just the invoice id
    close();
    overlay = document.createElement('div');
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483000;background:rgba(18,17,16,.62);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:16px;opacity:0;transition:opacity .25s';
    var box = document.createElement('div');
    box.style.cssText = 'position:relative;width:100%;max-width:460px;height:min(760px,100%);border-radius:30px;overflow:hidden;transform:translateY(16px);transition:transform .35s cubic-bezier(.2,.8,.2,1)';
    var frame = document.createElement('iframe');
    frame.src = url + (url.indexOf('?') > -1 ? '&' : '?') + 'embed=1';
    frame.title = 'Gatevoo checkout';
    frame.allow = 'clipboard-write';
    frame.style.cssText = 'width:100%;height:100%;border:0;background:transparent';
    var x = document.createElement('button');
    x.type = 'button'; x.setAttribute('aria-label', 'Close checkout'); x.textContent = '×';
    x.style.cssText = 'position:absolute;top:10px;right:10px;width:34px;height:34px;border-radius:50%;border:0;background:rgba(0,0,0,.55);color:#fff;font:600 20px/1 system-ui;cursor:pointer;z-index:2';
    x.onclick = close;
    box.appendChild(frame); box.appendChild(x); overlay.appendChild(box);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', function esc(e) { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); } });
    window.addEventListener('message', onMsg);
    document.documentElement.style.overflow = 'hidden';
    document.body.appendChild(overlay);
    requestAnimationFrame(function () { overlay.style.opacity = '1'; box.style.transform = 'none'; });
  }

  window.Gatevoo = { open: open, close: close };
})();
