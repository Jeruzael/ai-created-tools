/* Small offline DOM port. It parses only the local fragment; it is not visual QA. */
const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
const decode = value => String(value).replace(/&(?:amp|lt|gt|quot|#39);/g,
    token => ({'&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'"})[token]);

class Element {
    constructor(tag, attributes, doc) {
        this.tagName = tag.toUpperCase(); this.attributes = {...attributes}; this.ownerDocument = doc;
        this._nodes = []; this.parentElement = null; this.listeners = {}; this.style = {};
        if (attributes.id && doc?.ids) doc.ids.set(attributes.id, this);
        this.scrollTop = 0; this.scrollLeft = 0; this.inert = false; this._value = null;
        this.hidden = 'hidden' in attributes; this.disabled = 'disabled' in attributes;
        this.checked = 'checked' in attributes;
        this.classList = {
            contains: name => this.className.split(/\s+/).includes(name),
            toggle: (name, on) => {
                const set = new Set(this.className.split(/\s+/).filter(Boolean));
                if (on === undefined) on = !set.has(name);
                if (on) set.add(name); else set.delete(name);
                this.attributes.class = [...set].join(' '); return on;
            },
            add: name => this.classList.toggle(name, true),
            remove: name => this.classList.toggle(name, false),
        };
    }
    get id() { return this.attributes.id || ''; }
    get children() { return this._nodes.filter(child => typeof child !== 'string'); }
    get className() { return this.attributes.class || ''; }
    get dataset() {
        return Object.fromEntries(Object.entries(this.attributes).filter(([key]) => key.startsWith('data-'))
            .map(([key, value]) => [key.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()), value]));
    }
    get tabIndex() {
        if ('tabindex' in this.attributes) return Number(this.attributes.tabindex);
        return ['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'A'].includes(this.tagName) ? 0 : -1;
    }
    set tabIndex(value) { this.setAttribute('tabindex', value); }
    get value() {
        if (this._value !== null) return this._value;
        if (this.tagName === 'SELECT') {
            const options = this.querySelectorAll('option');
            const first = options.find(option => option.hasAttribute('selected')) || options[0];
            return first ? first.value : '';
        }
        return this.attributes.value ?? (this.tagName === 'OPTION' ? this.textContent : '');
    }
    set value(value) { this._value = String(value); }
    get isConnected() { for (let e = this; e; e = e.parentElement) if (e === this.ownerDocument.body) return true; return false; }
    get textContent() { return this._nodes.map(child => typeof child === 'string' ? child : child.textContent).join(''); }
    set textContent(value) { this.detach(); this._nodes = [String(value)]; }
    get innerHTML() { return this._html || ''; }
    set innerHTML(value) { this.detach(); this._nodes = []; this._html = String(value); parse(this._html, this, this.ownerDocument); }
    detach() { this.children.forEach(child => { if (typeof child !== 'string') child.parentElement = null; }); }
    appendChild(child) { this._nodes.push(child); child.parentElement = this; return child; }
    remove() { const p = this.parentElement; if (p) p._nodes = p._nodes.filter(child => child !== this); this.parentElement = null; }
    getAttribute(name) { return this.attributes[name] ?? null; }
    hasAttribute(name) { return name in this.attributes; }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    removeAttribute(name) { delete this.attributes[name]; }
    contains(other) { return this === other || this.children.some(child => typeof child !== 'string' && child.contains(other)); }
    matches(selector) {
        return selector.split(',').some(part => {
            let simple = part.trim();
            if (!simple || /\s/.test(simple.replace(/\[[^\]]*\]/g, ''))) throw Error('Unsupported fixture selector: ' + simple);
            const tag = simple.match(/^[a-z][a-z0-9-]*/i);
            if (tag && this.tagName !== tag[0].toUpperCase()) return false;
            const id = simple.match(/#([\w-]+)/); if (id && this.id !== id[1]) return false;
            for (const match of simple.matchAll(/\.([\w-]+)/g)) if (!this.classList.contains(match[1])) return false;
            for (const match of simple.matchAll(/\[([\w-]+)(?:=["']?([^\]"']*)["']?)?\]/g)) {
                if (!this.hasAttribute(match[1])) return false;
                if (match[2] !== undefined && this.getAttribute(match[1]) !== match[2]) return false;
            }
            return true;
        });
    }
    closest(selector) { for (let e = this; e; e = e.parentElement) if (e.matches(selector)) return e; return null; }
    querySelectorAll(selector) {
        const found = [];
        for (const child of this.children) if (typeof child !== 'string') {
            if (child.matches(selector)) found.push(child);
            found.push(...child.querySelectorAll(selector));
        }
        return found;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
    removeEventListener(type, handler) { this.listeners[type] = (this.listeners[type] || []).filter(item => item !== handler); }
    dispatchEvent(event) {
        event.target ||= this; event.currentTarget = this;
        for (const handler of this.listeners[event.type] || []) handler(event);
        if (!event.stopped && event.bubbles !== false) {
            if (this.parentElement) this.parentElement.dispatchEvent(event);
            else if (this !== this.ownerDocument) this.ownerDocument.dispatchEvent(event);
        }
        return !event.defaultPrevented;
    }
    focus() { this.ownerDocument.activeElement = this; this.ownerDocument.dispatchEvent(makeEvent('focusin', {target: this})); }
    click() { if (!this.disabled) this.dispatchEvent(makeEvent('click')); }
}

function parse(source, root, doc) {
    const stack = [root];
    for (const token of source.match(/<!--[\s\S]*?-->|<[^>]*>|[^<]+/g) || []) {
        if (token.startsWith('<!--')) continue;
        if (token.startsWith('</')) {
            const tag = token.match(/^<\/([\w-]+)/)?.[1].toUpperCase();
            const index = stack.findLastIndex(element => element.tagName === tag);
            if (index > 0) stack.length = index;
            continue;
        }
        if (token.startsWith('<')) {
            const tag = token.match(/^<([\w-]+)/)?.[1]; if (!tag) continue;
            const attributes = {};
            const rest = token.slice(tag.length + 1).replace(/\/?\s*>$/, '');
            for (const match of rest.matchAll(/([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+)))?/g))
                attributes[match[1]] = decode(match[2] ?? match[3] ?? match[4] ?? '');
            const element = new Element(tag, attributes, doc);
            stack[stack.length - 1].appendChild(element);
            if (!voidTags.has(tag) && !token.endsWith('/>')) stack.push(element);
        } else stack[stack.length - 1]._nodes.push(decode(token));
    }
}

function makeEvent(type, extra = {}) {
    return {type, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; },
        stopPropagation() { this.stopped = true; }, ...extra};
}

function createFixture(source) {
    const doc = new Element('document', {}, null); doc.ownerDocument = doc; doc.ids = new Map();
    doc.body = new Element('body', {}, doc); doc.appendChild(doc.body);
    doc.getElementById = id => { const element = doc.ids.get(id); return element?.isConnected ? element : null; };
    doc.createElement = tag => new Element(tag, {}, doc);
    parse('<main id="fixtureBackground"><button id="fixtureOpener">Open</button>' + source + '</main>', doc.body, doc);
    doc.activeElement = doc.body;
    const win = {document: doc, innerWidth: 1440};
    return {doc, win, event: makeEvent, key(element, key, extra = {}) {
        const event = makeEvent('keydown', {key, ...extra}); element.dispatchEvent(event); return event;
    }};
}

module.exports = {createFixture};
