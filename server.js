'use strict';
/***********************************************************************
 *  نظام إدارة أوردرات المطبعة — خادم Node.js مستقل (بدون مكتبات خارجية)
 *  يعمل محليًا على جهازك، وجاهز للرفع على أي استضافة تدعم Node.js.
 ***********************************************************************/
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

/* ------------------------- الإعدادات (من ملف .env أو متغيرات البيئة) ------------------------- */
(function loadEnv() {
  try {
    fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(function (line) {
      if (/^\s*#/.test(line)) return;
      var m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
      if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    });
  } catch (e) { /* لا يوجد ملف .env */ }
})();
const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const MAX_UPLOAD_MB = +process.env.MAX_UPLOAD_MB || 50;
const MAX_UPLOAD = MAX_UPLOAD_MB * 1048576;
const OWNER_NAME = process.env.OWNER_NAME || 'المالك';
const OWNER_PIN = process.env.OWNER_PIN || '123456';
const TOKEN_DAYS = 14;

const FILES_DIR = path.join(DATA_DIR, 'files');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const DB_FILE = path.join(DATA_DIR, 'db.json');
fs.mkdirSync(FILES_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });

/* ------------------------- ثوابت ------------------------- */
const ROLE_LIST = ['owner', 'admin', 'sales', 'designer', 'production'];
const LITE = { designer: 1, production: 1 };                                   // أدوار بدون أسعار
const LITE_VIEW = { designer: ['proof', 'review'], production: ['production', 'ready'] };
const STAGE_KEYS = ['new', 'proof', 'review', 'deposit', 'production', 'ready', 'done', 'cancelled'];
const FORBID = 'ليس لديك صلاحية لهذا الإجراء';
const INLINE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf'];

/* ------------------------- قاعدة البيانات (ملف JSON بكتابة آمنة + نسخ احتياطي يومي) ------------------------- */
var db;
function emptyDB() {
  return { orders: {}, purchases: {}, staff: [], settings: {}, files: {}, stock: { items: {}, log: [] }, meta: { ver: 1, seq: 0, secret: '' } };
}
function loadDB() {
  var raw = null;
  try { raw = fs.readFileSync(DB_FILE, 'utf8'); } catch (e) { /* أول تشغيل */ }
  if (raw) {
    try { db = JSON.parse(raw); } catch (e) {
      console.error('⚠️ ملف قاعدة البيانات تالف، سيتم استعادة آخر نسخة احتياطية.');
      var bks = fs.readdirSync(BACKUP_DIR).filter(function (f) { return /^db-.*\.json$/.test(f); }).sort().reverse();
      db = null;
      for (var i = 0; i < bks.length && !db; i++) { try { db = JSON.parse(fs.readFileSync(path.join(BACKUP_DIR, bks[i]), 'utf8')); console.error('تمت الاستعادة من ' + bks[i]); } catch (e2) {} }
      if (!db) throw new Error('تعذّرت استعادة قاعدة البيانات. راجع مجلد backups يدويًا.');
    }
  } else db = emptyDB();
  var d = emptyDB();
  Object.keys(d).forEach(function (k) { if (!db[k]) db[k] = d[k]; });
  if (!db.stock.items) db.stock.items = {};
  if (!db.stock.log) db.stock.log = [];
  if (!db.meta.secret) db.meta.secret = process.env.SECRET || crypto.randomBytes(32).toString('hex');
  if (process.env.SECRET) db.meta.secret = process.env.SECRET;
}
function backupDaily() {
  try {
    var f = path.join(BACKUP_DIR, 'db-' + new Date().toISOString().slice(0, 10) + '.json');
    if (!fs.existsSync(f)) {
      fs.copyFileSync(DB_FILE, f);
      var all = fs.readdirSync(BACKUP_DIR).filter(function (x) { return /^db-.*\.json$/.test(x); }).sort();
      while (all.length > 30) fs.unlinkSync(path.join(BACKUP_DIR, all.shift()));
    }
  } catch (e) { console.error('تعذّر النسخ الاحتياطي:', e.message); }
}
function commit() {
  db.meta.ver++;
  var tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
  backupDaily();
}
const own = function (o, k) { return Object.prototype.hasOwnProperty.call(o, k); };
const getOrder = function (id) { return own(db.orders, id) ? db.orders[id] : null; };
const clone = function (o) { return JSON.parse(JSON.stringify(o)); };
const err = function (m) { var e = new Error(m); e.user = true; return e; };
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{2,39}$/;

/* ------------------------- الموظفون والدخول ------------------------- */
const normName = function (n) { return String(n || '').trim().toLowerCase(); };
const validPin = function (p) { p = String(p || ''); return p.length >= 4 && p.length <= 20; };
function hashPin(salt, pin) { return crypto.scryptSync(String(pin), salt, 32).toString('hex'); }
function verifyPin(u, pin) {
  var a = Buffer.from(hashPin(u.salt, pin), 'hex'), b = Buffer.from(u.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function findStaff(name) {
  var n = normName(name);
  for (var i = 0; i < db.staff.length; i++) if (normName(db.staff[i].name) === n) return db.staff[i];
  return null;
}
function newStaff(name, role, pin, active) {
  var salt = crypto.randomBytes(16).toString('hex');
  return { name: name, role: role, salt: salt, hash: hashPin(salt, pin), active: active !== false, createdAt: Date.now() };
}
function ensureOwner() {
  if (db.staff.some(function (s) { return s.role === 'owner'; })) return;
  db.staff.push(newStaff(OWNER_NAME, 'owner', OWNER_PIN, true));
  commit();
  console.log('تم إنشاء حساب المالك: "' + OWNER_NAME + '" — غيّر الرقم السري من داخل البرنامج بعد أول دخول.');
}
const sign = function (p) { return crypto.createHmac('sha256', db.meta.secret).update(p).digest('hex'); };
function makeToken(u) {
  var p = Buffer.from(JSON.stringify({ u: u.name, exp: Date.now() + TOKEN_DAYS * 864e5 }), 'utf8').toString('base64url');
  return p + '.' + sign(p);
}
function auth(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) throw err('AUTH');
  var parts = token.split('.'), a = Buffer.from(sign(parts[0])), b = Buffer.from(String(parts[1] || ''));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw err('AUTH');
  var d;
  try { d = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch (e) { throw err('AUTH'); }
  if (!d.exp || d.exp < Date.now()) throw err('AUTH');
  var u = findStaff(d.u);
  if (!u || !u.active) throw err('AUTH');
  return u;
}
const fails = new Map(), ipFails = new Map();
function login(a, ip) {
  var name = String(a.name || '').trim(), pin = String(a.pin || ''), now = Date.now();
  if (!name || !pin) throw err('اكتب الاسم والرقم السري');
  var k = normName(name), f = fails.get(k) || { n: 0, until: 0 }, g = ipFails.get(ip) || { n: 0, until: 0 };
  if (f.until > now || g.until > now) throw err('محاولات كثيرة خاطئة. انتظر 5 دقائق وحاول مرة أخرى');
  var u = findStaff(name), ok = false;
  if (u) ok = u.active && verifyPin(u, pin); else hashPin('0000000000000000', pin);
  if (!ok) {
    f.n++; g.n++;
    if (f.n >= 5) { f.until = now + 300000; f.n = 0; }
    if (g.n >= 30) { g.until = now + 600000; g.n = 0; }
    fails.set(k, f); ipFails.set(ip, g);
    throw err('الاسم أو الرقم السري غير صحيح');
  }
  fails.delete(k);
  return { token: makeToken(u), me: { name: u.name, role: u.role } };
}
function need(u, role) { if (u.role !== role) throw err(FORBID); }

/* ------------------------- الأوردرات ------------------------- */
function nextCode() {
  if (!db.meta.seq) {
    Object.keys(db.orders).forEach(function (id) {
      var n = parseInt(String(db.orders[id].code || '').replace(/\D/g, ''), 10) || 0;
      if (n > db.meta.seq) db.meta.seq = n;
    });
  }
  db.meta.seq++;
  return 'PO-' + ('0000' + db.meta.seq).slice(-4);
}
/** نسخة الأوردر للأدوار التي لا ترى الأسعار — تُنفَّذ على الخادم. */
function strip(o, u) {
  var c = clone(o);
  c.items = (c.items || []).map(function (i) { return { desc: i.desc, specs: i.specs, qty: i.qty }; });
  ['discount', 'shipCost', 'depositPct', 'deposit', 'final', 'invoiceAt', 'approval', 'cancelledFrom'].forEach(function (k) { delete c[k]; });
  var cu = o.customer || {};
  c.customer = { name: cu.name || '' };
  if (u.role === 'production') c.customer.phone = cu.phone || ''; else delete c.address;
  c.history = (c.history || []).filter(function (h) { return !/ج\.م|عربون|تحصيل|فاتورة/.test(h.text); });
  delete c.materials; delete c.newMaterials;
  return c;
}
function sanitizeFile(f, u, now) {
  var out = {
    id: String(f.id || ('f' + now.toString(36))).slice(0, 40),
    kind: ['proof', 'source', 'final', 'other'].indexOf(f.kind) >= 0 ? f.kind : 'other',
    name: String(f.name || 'ملف').slice(0, 150),
    by: String(f.by || u.name).slice(0, 60), at: +f.at || now
  };
  if (f.link) out.link = String(f.link).slice(0, 600);
  if (f.fileId && /^[a-f0-9]{24}$/.test(String(f.fileId))) {
    out.fileId = String(f.fileId); out.type = String(f.type || '').slice(0, 80); out.size = +f.size || 0;
  }
  return out;
}
function appendHistory(o, u, texts) {
  o.history = o.history || [];
  texts.forEach(function (t) { o.history.push({ at: Date.now(), by: u.name, text: t }); });
  if (o.history.length > 250) o.history = o.history.slice(-250);
}
function dropFile(f) {
  if (f && f.fileId && own(db.files, f.fileId)) {
    delete db.files[f.fileId];
    try { fs.unlinkSync(path.join(FILES_DIR, f.fileId)); } catch (e) { /* غير موجود */ }
  }
}
function saveOrder(u, a) {
  var inc = a.order;
  if (!inc || !ID_RE.test(String(inc.id || ''))) throw err('بيانات غير صحيحة');
  var old = getOrder(inc.id);
  if (LITE[u.role]) return liteSave(u, inc, old);
  if (['owner', 'admin', 'sales'].indexOf(u.role) < 0) throw err(FORBID);
  if (STAGE_KEYS.indexOf(inc.stage) < 0) throw err('مرحلة غير صحيحة');
  var now = Date.now(), o = clone(inc);
  if (!o.customer || !String(o.customer.name || '').trim()) throw err('اسم العميل مطلوب');
  var oldHist = old ? (old.history || []).length : 0;
  o.history = (Array.isArray(o.history) ? o.history : []).slice(-250);
  for (var i = Math.min(oldHist, o.history.length); i < o.history.length; i++) { o.history[i].by = u.name; o.history[i].at = now; }
  var oldFiles = old ? (old.files || []) : [];
  o.files = (Array.isArray(o.files) ? o.files : []).slice(0, 80).map(function (f) { return sanitizeFile(f, u, now); })
    .filter(function (f) { return !f.fileId || oldFiles.some(function (x) { return x.fileId === f.fileId; }); });
  if (old) {
    if ((old.rev || 0) !== (inc.rev || 0)) return { conflict: true, order: view(old, u) };
    o.materials = old.materials || [];
    oldFiles.forEach(function (f) { if (!o.files.some(function (x) { return x.id === f.id; })) dropFile(f); });
    o.code = old.code; o.createdAt = old.createdAt; o.rev = (old.rev || 0) + 1;
  } else { o.createdAt = now; o.rev = 1; }
  o.updatedAt = now;
  if (JSON.stringify(o).length > 300000) throw err('بيانات الأوردر كبيرة جدًا');
  var newMats = o.newMaterials; delete o.newMaterials;
  if (!old) { o.materials = applyMaterials(u, o, newMats, now); o.code = nextCode(); }
  db.orders[o.id] = o; commit();
  return { order: view(o, u) };
}
function liteSave(u, inc, old) {
  if (!old) throw err(FORBID);
  var view = LITE_VIEW[u.role], now = Date.now();
  if (view.indexOf(old.stage) < 0) throw err(FORBID);
  if ((old.rev || 0) !== (inc.rev || 0)) return { conflict: true, order: strip(old, u) };
  var o = clone(old), notes = [];
  var oldF = old.files || [], incF = Array.isArray(inc.files) ? inc.files : [], incIds = {}, oldIds = {};
  incF.forEach(function (f) { incIds[f.id] = 1; });
  oldF.forEach(function (f) { oldIds[f.id] = 1; });
  var kept = oldF.filter(function (f) {
    if (incIds[f.id]) return true;
    if (f.by === u.name) { dropFile(f); notes.push('تم حذف ملف: ' + f.name); return false; }
    return true;
  });
  incF.forEach(function (f) {
    if (!oldIds[f.id] && f.link && /^https:\/\//i.test(String(f.link)) && kept.length < 80) {
      var nf = sanitizeFile({ id: f.id, kind: f.kind, name: f.name, link: f.link }, u, now);
      nf.by = u.name; nf.at = now; kept.push(nf); notes.push('تمت إضافة رابط: ' + nf.name);
    }
  });
  o.files = kept;
  if (u.role === 'designer') {
    if (!old.designer && inc.designer) { o.designer = u.name; notes.push('تم استلام التصميم بواسطة ' + u.name); }
    if (old.stage === 'proof' && inc.proofReady && !old.proofReady) {
      if (!kept.some(function (f) { return f.kind === 'proof'; })) throw err('ارفع ملف البروفة (أو رابطها) بنوع «بروفة» أولًا');
      o.proofReady = { at: now, by: u.name };
      notes.push('المصمم أعلن جاهزية البروفة');
    }
  }
  if (u.role === 'production' && old.stage === 'production' && inc.stage === 'ready') {
    o.stage = 'ready'; o.stageAt = now; notes.push('انتقل الأوردر إلى: جاهز للتسليم');
  }
  appendHistory(o, u, notes);
  o.rev = (old.rev || 0) + 1; o.updatedAt = now;
  db.orders[o.id] = o; commit();
  return { order: strip(o, u) };
}

/* ------------------------- المخزن والخامات ------------------------- */
const r3 = function (x) { return Math.round(x * 1000) / 1000; };
const r2 = function (x) { return Math.round(x * 100) / 100; };
const numv = function (v) { var n = parseFloat(v); return isFinite(n) ? n : 0; };
const newId = function (p) { return p + crypto.randomBytes(5).toString('hex'); };
const todayStr = function () { var d = new Date(); return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2); };
const getItem = function (id) { return own(db.stock.items, id) ? db.stock.items[id] : null; };
function findItemByName(name) {
  var n = normName(name), ks = Object.keys(db.stock.items);
  for (var i = 0; i < ks.length; i++) if (normName(db.stock.items[ks[i]].name) === n) return db.stock.items[ks[i]];
  return null;
}
function logMove(m) {
  m.id = newId('mv'); m.at = Date.now();
  db.stock.log.push(m);
  if (db.stock.log.length > 3000) db.stock.log = db.stock.log.slice(-3000);
}
function addToStock(it, qty, unitCost) {
  var tq = it.qty + qty;
  it.avgCost = tq > 0 ? Math.round(((it.qty * it.avgCost + qty * unitCost) / tq) * 10000) / 10000 : unitCost;
  it.qty = r3(tq);
}
/** نسخة الأوردر حسب الدور: غير المالك لا يرى تكلفة الخامات. */
function view(o, u) {
  if (LITE[u.role]) return strip(o, u);
  if (u.role === 'owner') return o;
  var c = clone(o);
  if (c.materials) c.materials = c.materials.map(function (m) { var x = Object.assign({}, m); delete x.unitCost; return x; });
  return c;
}
/** يحوّل سطور الخامات: سحب من المخزن أو مشتريات خارجية. يتحقق من الكل أولًا ثم ينفّذ (كله أو لا شيء). */
function applyMaterials(u, order, lines, now) {
  lines = (Array.isArray(lines) ? lines : []).slice(0, 40);
  var need = {};
  var parsed = lines.map(function (l) {
    if (l && l.source === 'stock') {
      var it = getItem(String(l.itemId || ''));
      if (!it) throw err('صنف المخزن غير موجود');
      var q = numv(l.qty);
      if (!(q > 0)) throw err('كمية السحب لازم تكون أكبر من صفر');
      need[it.id] = (need[it.id] || 0) + q;
      return { source: 'stock', it: it, qty: q };
    }
    var name = String((l && (l.name || l.desc)) || '').trim().slice(0, 100);
    if (!name) throw err('اكتب وصف المشتريات الخارجية');
    return { source: 'external', name: name, qty: Math.max(0, numv(l.qty)), cost: Math.max(0, numv(l.cost)), supplier: String(l.supplier || '').trim().slice(0, 60) };
  });
  Object.keys(need).forEach(function (id) {
    var it = db.stock.items[id];
    if (need[id] > it.qty + 1e-9) throw err('الكمية المتاحة من "' + it.name + '" هي ' + it.qty + ' ' + it.unit + ' فقط');
  });
  var out = [];
  parsed.forEach(function (p) {
    if (p.source === 'stock') {
      var unitCost = p.it.avgCost;
      p.it.qty = r3(p.it.qty - p.qty);
      logMove({ itemId: p.it.id, type: 'out', qty: p.qty, unitCost: unitCost, orderId: order.id, by: u.name });
      out.push({ id: newId('m'), source: 'stock', itemId: p.it.id, name: p.it.name, unit: p.it.unit, qty: p.qty, unitCost: unitCost, status: 'out', at: now, by: u.name });
      appendHistory(order, u, ['سُحب من المخزن: ' + p.it.name + ' (' + p.qty + ' ' + p.it.unit + ')']);
    } else {
      var pid = '';
      if (p.cost > 0) {
        pid = newId('p');
        db.purchases[pid] = { id: pid, date: todayStr(), supplier: p.supplier, desc: 'مشتريات خارجية: ' + p.name, category: 'مشتريات خارجية للأوردر', total: r2(p.cost), paid: r2(p.cost), method: '', orderId: order.id, page: '', notes: '', by: u.name, createdAt: now };
      }
      out.push({ id: newId('m'), source: 'external', name: p.name, unit: '', qty: p.qty, supplier: p.supplier, purchaseId: pid, at: now, by: u.name });
      appendHistory(order, u, ['مشتريات خارجية للأوردر: ' + p.name]);
    }
  });
  return out;
}
function materialAdd(u, a) {
  var o = getOrder(String(a.orderId || ''));
  if (!o) throw err('الأوردر غير موجود');
  if (o.stage === 'done' || o.stage === 'cancelled') throw err('لا يمكن إضافة خامات لأوردر مسلَّم أو ملغي');
  var c = clone(o), now = Date.now();
  var lines = applyMaterials(u, c, a.lines, now);
  if (!lines.length) throw err('أضف خامة واحدة على الأقل');
  c.materials = (c.materials || []).concat(lines);
  c.rev = (c.rev || 0) + 1; c.updatedAt = now;
  db.orders[c.id] = c; commit();
  return { order: view(c, u) };
}
function materialReturn(u, a) {
  var o = getOrder(String(a.orderId || ''));
  if (!o) throw err('الأوردر غير موجود');
  if (o.stage === 'done') throw err('لا يمكن إرجاع خامات من أوردر مسلَّم');
  var c = clone(o), m = (c.materials || []).filter(function (x) { return x.id === a.lineId; })[0];
  if (!m || m.source !== 'stock' || m.status === 'returned') throw err('لا يوجد ما يُرجَع');
  var it = getItem(m.itemId);
  if (!it) throw err('الصنف غير موجود في المخزن');
  addToStock(it, m.qty, m.unitCost || it.avgCost);
  logMove({ itemId: it.id, type: 'return', qty: m.qty, unitCost: m.unitCost, orderId: c.id, by: u.name });
  m.status = 'returned'; m.returnedAt = Date.now();
  appendHistory(c, u, ['أُرجع إلى المخزن: ' + m.name + ' (' + m.qty + ' ' + m.unit + ')']);
  c.rev = (c.rev || 0) + 1; c.updatedAt = Date.now();
  db.orders[c.id] = c; commit();
  return { order: view(c, u) };
}
function stockReceive(u, a) {
  var lines = (Array.isArray(a.lines) ? a.lines : []).slice(0, 60);
  if (!lines.length) throw err('أضف صنفًا واحدًا على الأقل');
  var norm = lines.map(function (l) {
    var name = String(l.name || '').trim().slice(0, 80), qty = numv(l.qty), price = numv(l.price);
    if (!name) throw err('اسم الصنف مطلوب');
    if (!(qty > 0)) throw err('الكمية لازم تكون أكبر من صفر');
    if (price < 0) throw err('سعر غير صحيح');
    return { name: name, unit: String(l.unit || '').trim().slice(0, 20) || 'وحدة', qty: qty, price: price };
  });
  var now = Date.now(), total = 0, plines = [];
  norm.forEach(function (l) {
    var it = findItemByName(l.name);
    if (!it) {
      it = { id: newId('it'), name: l.name, unit: l.unit, qty: 0, avgCost: 0, minQty: 0, notes: '', createdAt: now };
      db.stock.items[it.id] = it;
    }
    addToStock(it, l.qty, l.price);
    total += l.qty * l.price;
    plines.push({ itemId: it.id, name: it.name, unit: it.unit, qty: l.qty, price: l.price });
    logMove({ itemId: it.id, type: 'in', qty: l.qty, unitCost: l.price, by: u.name, note: 'توريد' });
  });
  total = r2(total);
  var paid = (a.paid === '' || a.paid == null) ? total : Math.min(total, Math.max(0, numv(a.paid)));
  var date = /^\d{4}-\d{2}-\d{2}$/.test(String(a.date || '')) ? a.date : todayStr();
  var pid = newId('p');
  db.purchases[pid] = {
    id: pid, date: date, supplier: String(a.supplier || '').trim().slice(0, 60),
    desc: ('توريد مخزن: ' + plines.map(function (x) { return x.name; }).join('، ')).slice(0, 140),
    category: 'مخزون', total: total, paid: r2(paid), method: String(a.method || '').slice(0, 30), orderId: '', page: '', notes: '',
    by: u.name, createdAt: now, stock: true, lines: plines
  };
  commit();
  return { ok: true };
}
function stockPurchaseDelete(u, a) {
  var p = own(db.purchases, a.id) ? db.purchases[a.id] : null;
  if (!p || !p.stock) throw err('ليس توريد مخزن');
  (p.lines || []).forEach(function (l) {
    var it = getItem(l.itemId);
    if (it && it.qty + 1e-9 < l.qty) throw err('لا يمكن حذف التوريد: تم سحب جزء من "' + l.name + '" (المتاح ' + it.qty + ' والمورَّد ' + l.qty + ')');
  });
  (p.lines || []).forEach(function (l) {
    var it = getItem(l.itemId);
    if (!it) return;
    var nq = r3(it.qty - l.qty);
    it.avgCost = nq > 0 ? Math.max(0, Math.round(((it.qty * it.avgCost - l.qty * l.price) / nq) * 10000) / 10000) : it.avgCost;
    it.qty = nq;
    logMove({ itemId: it.id, type: 'adjust', qty: -l.qty, unitCost: l.price, by: u.name, note: 'حذف توريد' });
  });
  delete db.purchases[p.id];
  commit();
  return { ok: true };
}
function stockAdjust(u, a) {
  var it = getItem(String(a.itemId || ''));
  if (!it) throw err('الصنف غير موجود');
  var nq = r3(numv(a.qty));
  if (nq < 0) throw err('الكمية لا تكون سالبة');
  var delta = r3(nq - it.qty);
  if (delta === 0) return { ok: true };
  it.qty = nq;
  logMove({ itemId: it.id, type: 'adjust', qty: delta, unitCost: it.avgCost, by: u.name, note: String(a.note || 'تسوية جرد').slice(0, 100) });
  commit();
  return { ok: true };
}
function stockItemSave(u, a) {
  var name = String(a.name || '').trim().slice(0, 80);
  if (!name) throw err('اسم الصنف مطلوب');
  var dup = findItemByName(name), it = a.id ? getItem(String(a.id)) : null;
  if (dup && (!it || dup.id !== it.id)) throw err('يوجد صنف بنفس الاسم');
  if (!it) { it = { id: newId('it'), name: name, unit: 'وحدة', qty: 0, avgCost: 0, minQty: 0, notes: '', createdAt: Date.now() }; db.stock.items[it.id] = it; }
  it.name = name; it.unit = String(a.unit || '').trim().slice(0, 20) || 'وحدة';
  it.minQty = Math.max(0, r3(numv(a.minQty))); it.notes = String(a.notes || '').slice(0, 200);
  commit();
  return { ok: true };
}
function stockItemDelete(u, a) {
  var it = getItem(String(a.id || ''));
  if (!it) return { ok: true };
  if (it.qty > 0) throw err('لا يمكن حذف صنف رصيده أكبر من صفر. اعمل تسوية للكمية أولًا');
  delete db.stock.items[it.id]; commit();
  return { ok: true };
}

/* ------------------------- المشتريات (للمالك فقط) ------------------------- */
function savePurchase(a) {
  var p = a.p;
  if (!p || !ID_RE.test(String(p.id || ''))) throw err('بيانات غير صحيحة');
  if (JSON.stringify(p).length > 20000) throw err('بيانات كبيرة');
  if (own(db.purchases, p.id) && db.purchases[p.id].stock) throw err('توريدات المخزن لا تُعدَّل من هنا');
  p = clone(p); delete p.stock; delete p.lines;
  db.purchases[p.id] = p; commit();
  return { ok: true };
}
function deletePurchase(a) {
  if (own(db.purchases, a.id)) {
    if (db.purchases[a.id].stock) throw err('توريد مخزن: احذفه من شاشة المخزن');
    delete db.purchases[a.id]; commit();
  }
  return { ok: true };
}

/* ------------------------- الإعدادات والموظفون ------------------------- */
function publicSettings(u) {
  if (LITE[u.role]) return { company: db.settings.company || '' };
  return db.settings;
}
function saveSettings(u, a) {
  if (['owner', 'admin'].indexOf(u.role) < 0) throw err(FORBID);
  var s = a.settings || {};
  if (JSON.stringify(s).length > 400000) throw err('حجم الإعدادات (الشعارات) كبير');
  db.settings = s; commit();
  return { ok: true };
}
const listStaff = function () { return db.staff.map(function (r) { return { name: r.name, role: r.role, active: r.active }; }); };
const designerNames = function () { return db.staff.filter(function (r) { return r.role === 'designer' && r.active; }).map(function (r) { return r.name; }); };
function staffSave(a) {
  var name = String(a.name || '').trim(), role = String(a.role || '');
  if (!name || name.length > 40) throw err('اكتب اسم الموظف');
  if (ROLE_LIST.indexOf(role) < 0 || role === 'owner') throw err('دور غير صحيح');
  var ex = findStaff(name), active = a.active !== false;
  if (ex && ex.role === 'owner') throw err('لا يمكن تعديل المالك من هنا');
  if (ex) {
    ex.role = role; ex.active = active;
    if (a.pin) { if (!validPin(a.pin)) throw err('الرقم السري من 4 إلى 20 حرف'); ex.salt = crypto.randomBytes(16).toString('hex'); ex.hash = hashPin(ex.salt, a.pin); }
  } else {
    if (!validPin(a.pin)) throw err('اكتب رقمًا سريًا من 4 إلى 20 حرف');
    db.staff.push(newStaff(name, role, a.pin, active));
  }
  commit();
  return { ok: true };
}
function staffDelete(a) {
  var ex = findStaff(a.name);
  if (!ex) return { ok: true };
  if (ex.role === 'owner') throw err('لا يمكن حذف المالك');
  db.staff.splice(db.staff.indexOf(ex), 1); commit();
  return { ok: true };
}
function changePin(u, a) {
  if (!validPin(a.newPin)) throw err('الرقم السري الجديد من 4 إلى 20 حرف');
  if (!verifyPin(u, String(a.oldPin || ''))) throw err('الرقم السري الحالي غير صحيح');
  u.salt = crypto.randomBytes(16).toString('hex'); u.hash = hashPin(u.salt, a.newPin); commit();
  return { ok: true };
}
function sync(u, a) {
  var ver = db.meta.ver, base = { me: { name: u.name, role: u.role }, ver: ver, cfg: { maxUploadMB: MAX_UPLOAD_MB } };
  if (a.ver === ver && a.role === u.role) { base.same = true; return base; }
  var orders = Object.keys(db.orders).map(function (k) { return db.orders[k]; });
  if (LITE[u.role]) {
    var vw = LITE_VIEW[u.role];
    orders = orders.filter(function (o) { return vw.indexOf(o.stage) >= 0; }).map(function (o) { return strip(o, u); });
  } else orders = orders.map(function (o) { return view(o, u); });
  base.orders = orders;
  base.settings = publicSettings(u);
  base.designers = designerNames();
  if (!LITE[u.role]) base.stock = Object.keys(db.stock.items).map(function (k) { var x = Object.assign({}, db.stock.items[k]); if (u.role !== 'owner') delete x.avgCost; return x; });
  if (u.role === 'owner') { base.purchases = Object.keys(db.purchases).map(function (k) { return db.purchases[k]; }); base.staff = listStaff(); base.stockLog = db.stock.log.slice(-300).reverse(); }
  return base;
}

/* ------------------------- HTTP ------------------------- */
function send(res, code, body, headers) {
  res.writeHead(code, Object.assign({
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'SAMEORIGIN', 'Cache-Control': 'no-store'
  }, headers || {}));
  res.end(body);
}
function sendJson(res, obj, headers) {
  send(res, 200, JSON.stringify(obj), Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, headers || {}));
}
function parseCookies(req) {
  var out = {};
  String(req.headers.cookie || '').split(';').forEach(function (p) {
    var i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
function cookieHeader(req, token, clear) {
  var secure = req.headers['x-forwarded-proto'] === 'https' || process.env.COOKIE_SECURE === '1';
  return 'po_t=' + (clear ? '' : token) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (clear ? 0 : TOKEN_DAYS * 86400) + (secure ? '; Secure' : '');
}
function readBody(req, limit) {
  return new Promise(function (resolve, reject) {
    var chunks = [], size = 0, done = false;
    req.on('data', function (c) {
      if (done) return;
      size += c.length;
      if (size > limit) { done = true; reject(err('الملف أكبر من الحد المسموح (' + Math.round(limit / 1048576) + ' ميجا)')); req.resume(); return; }
      chunks.push(c);
    });
    req.on('end', function () { if (!done) resolve(Buffer.concat(chunks)); });
    req.on('error', reject);
  });
}
const clientIp = function (req) {
  // لا نثق في X-Forwarded-For إلا لو التشغيل خلف وسيط (Nginx مثلًا) وتم ضبط TRUST_PROXY=1
  var xf = process.env.TRUST_PROXY === '1' ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '';
  return xf || req.socket.remoteAddress || 'ip';
};

async function handleApi(req, res) {
  var body, data;
  try { body = JSON.parse((await readBody(req, 2 * 1048576)).toString('utf8') || '{}'); } catch (e) { throw err(e.user ? e.message : 'طلب غير صالح'); }
  var m = body.m, a = body.a || {};
  if (m === 'login') {
    var r = login(a, clientIp(req));
    return sendJson(res, { ok: true, data: r }, { 'Set-Cookie': cookieHeader(req, r.token) });
  }
  if (m === 'logout') return sendJson(res, { ok: true }, { 'Set-Cookie': cookieHeader(req, '', true) });
  var token = body.token || req.headers['x-token'] || parseCookies(req).po_t;
  var u = auth(token);
  switch (m) {
    case 'sync': data = sync(u, a); break;
    case 'saveOrder': data = saveOrder(u, a); break;
    case 'savePurchase': need(u, 'owner'); data = savePurchase(a); break;
    case 'deletePurchase': need(u, 'owner'); data = deletePurchase(a); break;
    case 'saveSettings': data = saveSettings(u, a); break;
    case 'staffSave': need(u, 'owner'); data = staffSave(a); break;
    case 'staffDelete': need(u, 'owner'); data = staffDelete(a); break;
    case 'changePin': data = changePin(u, a); break;
    case 'stockReceive': need(u, 'owner'); data = stockReceive(u, a); break;
    case 'stockAdjust': need(u, 'owner'); data = stockAdjust(u, a); break;
    case 'stockItemSave': need(u, 'owner'); data = stockItemSave(u, a); break;
    case 'stockItemDelete': need(u, 'owner'); data = stockItemDelete(u, a); break;
    case 'stockPurchaseDelete': need(u, 'owner'); data = stockPurchaseDelete(u, a); break;
    case 'materialAdd': if (LITE[u.role]) throw err(FORBID); data = materialAdd(u, a); break;
    case 'materialReturn': if (LITE[u.role]) throw err(FORBID); data = materialReturn(u, a); break;
    default: throw err('طلب غير معروف');
  }
  sendJson(res, { ok: true, data: data }, m === 'sync' ? { 'Set-Cookie': cookieHeader(req, token) } : {});
}

async function handleUpload(req, res, url) {
  var u = auth(req.headers['x-token'] || parseCookies(req).po_t);
  var q = url.searchParams, orderId = q.get('orderId') || '';
  var len = +req.headers['content-length'] || 0;
  if (len > MAX_UPLOAD) { req.resume(); throw err('الملف أكبر من الحد المسموح (' + MAX_UPLOAD_MB + ' ميجا)'); }
  var old = getOrder(orderId);
  if (!old) { req.resume(); throw err('الأوردر غير موجود'); }
  if (LITE[u.role] && LITE_VIEW[u.role].indexOf(old.stage) < 0) { req.resume(); throw err(FORBID); }
  if (['owner', 'admin', 'sales', 'designer', 'production'].indexOf(u.role) < 0) { req.resume(); throw err(FORBID); }
  var buf = await readBody(req, MAX_UPLOAD);
  if (!buf.length) throw err('الملف فارغ');
  var name = String(q.get('name') || 'file').replace(/[\\\/:*?"<>|\u0000-\u001f]/g, '_').slice(0, 120);
  var mime = String(req.headers['content-type'] || 'application/octet-stream').split(';')[0].slice(0, 80);
  var fid = crypto.randomBytes(12).toString('hex'), now = Date.now();
  fs.writeFileSync(path.join(FILES_DIR, fid), buf);
  db.files[fid] = { orderId: orderId, name: name, mime: mime, size: buf.length };
  var o = clone(old);
  o.files = (o.files || []).concat([sanitizeFile({
    id: 'f' + now.toString(36) + Math.random().toString(36).slice(2, 5), kind: q.get('kind'), name: name, fileId: fid, type: mime, size: buf.length, by: u.name, at: now
  }, u, now)]);
  appendHistory(o, u, ['تم رفع ملف: ' + name]);
  o.rev = (o.rev || 0) + 1; o.updatedAt = now;
  db.orders[o.id] = o; commit();
  sendJson(res, { ok: true, data: { order: view(o, u) } });
}

function serveFile(req, res, url) {
  var u;
  try { u = auth(req.headers['x-token'] || parseCookies(req).po_t); } catch (e) { return send(res, 401, 'غير مصرّح — سجّل الدخول أولًا'); }
  var fid = url.pathname.split('/')[2] || '';
  if (!/^[a-f0-9]{24}$/.test(fid) || !own(db.files, fid)) return send(res, 404, 'غير موجود');
  var meta = db.files[fid], order = getOrder(meta.orderId);
  if (!order) return send(res, 404, 'غير موجود');
  if (LITE[u.role] && LITE_VIEW[u.role].indexOf(order.stage) < 0) return send(res, 403, FORBID);
  var fp = path.join(FILES_DIR, fid);
  if (!fs.existsSync(fp)) return send(res, 404, 'الملف غير موجود على القرص');
  var inline = INLINE_TYPES.indexOf(meta.mime) >= 0 && url.searchParams.get('dl') !== '1';
  res.writeHead(200, {
    'Content-Type': inline ? meta.mime : 'application/octet-stream',
    'Content-Length': fs.statSync(fp).size,
    'Content-Disposition': (inline ? 'inline' : 'attachment') + "; filename*=UTF-8''" + encodeURIComponent(meta.name),
    'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, no-cache', 'Content-Security-Policy': "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'"
  });
  fs.createReadStream(fp).pipe(res);
}

const INDEX_FILE = path.join(__dirname, 'public', 'index.html');
const server = http.createServer(async function (req, res) {
  try {
    var url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html'))
      return send(res, 200, fs.readFileSync(INDEX_FILE), { 'Content-Type': 'text/html; charset=utf-8' });
    if (req.method === 'GET' && url.pathname === '/favicon.ico') return send(res, 204, '');
    if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, 'ok', { 'Content-Type': 'text/plain' });
    if (req.method === 'POST' && url.pathname === '/api') return await handleApi(req, res);
    if (req.method === 'POST' && url.pathname === '/upload') return await handleUpload(req, res, url);
    if (req.method === 'GET' && url.pathname.indexOf('/files/') === 0) return serveFile(req, res, url);
    send(res, 404, 'Not found');
  } catch (e) {
    if (!e.user) console.error(e);
    if (!res.headersSent) sendJson(res, { ok: false, err: e.user ? e.message : 'حدث خطأ في الخادم' });
  }
});

server.on('error', function (e) {
  if (e.code === 'EADDRINUSE') {
    console.error('\n❌ المنفذ ' + PORT + ' مستخدم بالفعل. غالبًا النظام شغّال في نافذة تانية، أو برنامج تاني بيستخدم نفس المنفذ.');
    console.error('   اقفل النافذة التانية، أو غيّر PORT في ملف .env (مثلًا PORT=3001) وشغّل تاني.\n');
  } else console.error('❌ تعذّر تشغيل الخادم:', e.message);
  process.exit(1);
});
loadDB();
ensureOwner();
server.listen(PORT, HOST, function () {
  console.log('\n✅ النظام شغّال');
  console.log('   على هذا الجهاز:   http://localhost:' + PORT);
  var nets = os.networkInterfaces();
  Object.keys(nets).forEach(function (n) {
    nets[n].forEach(function (i) { if (i.family === 'IPv4' && !i.internal) console.log('   من أجهزة الشبكة: http://' + i.address + ':' + PORT); });
  });
  console.log('   مجلد البيانات:    ' + DATA_DIR + '\n');
});
function shutdown() { console.log('إيقاف النظام…'); server.close(function () { process.exit(0); }); setTimeout(function () { process.exit(0); }, 1500); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
