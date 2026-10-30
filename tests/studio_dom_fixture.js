/* Minimal deterministic DOM ports for controller unit tests, not a browser/layout engine. */
'use strict';

function createFixture(metadata, narrow = false, saved = null) {
    let doc;
    class Element {
        constructor(tag, attrs = {}) {
            this.nodeType = 1; this.tagName = tag.toUpperCase(); this.attrs = {...attrs};
            this.id = attrs.id || ''; this.dataset = {}; this.childNodes = []; this.listeners = {};
            this.value = attrs.value || ''; this.checked = 'checked' in attrs; this.disabled = 'disabled' in attrs;
            this.open = 'open' in attrs; this.scrollTop = 0; this.inert = false; this.replacements = 0;
            this._text = ''; this._html = ''; this.htmlWrites = 0; this.style = {}; this.offsetParent = {};
            for (const [key,value] of Object.entries(attrs)) if(key.startsWith('data-'))
                this.dataset[key.slice(5).replace(/-([a-z])/g,(_,c)=>c.toUpperCase())] = value;
            const owner = this;
            this.classList = {
                contains(name) { return owner.className.split(/\s+/).includes(name); },
                toggle(name,force) { const all=new Set(owner.className.split(/\s+/).filter(Boolean)); const enabled=force??!all.has(name); if(enabled)all.add(name);else all.delete(name);owner.className=[...all].join(' ');return enabled; },
                add(name) {this.toggle(name,true);},remove(name){this.toggle(name,false);},
                [Symbol.iterator]() {return owner.className.split(/\s+/).filter(Boolean)[Symbol.iterator]();}
            };
            if(tag==='template')this.content={childNodes:doc.templateChildren};
        }
        get className(){return this.attrs.class || '';}
        set className(value){this.attrs.class=value;}
        get innerHTML(){return this._html+this.childNodes.map(n=>n.innerHTML??n.textContent).join('');}
        set innerHTML(value){this._html=value;this._text='';this.childNodes=[];this.htmlWrites++;}
        get textContent(){return this._text+this.childNodes.map(child=>child.textContent).join('');}
        set textContent(value){this._text='';this._html='';this.childNodes=String(value)?[{nodeType:3,textContent:String(value)}]:[];}
        setAttribute(key,value){this.attrs[key]=String(value);}
        getAttribute(key){return this.attrs[key]??null;}
        removeAttribute(key){delete this.attrs[key];}
        hasAttribute(key){return key in this.attrs;}
        focus(){doc.activeElement=this;}
        addEventListener(name,callback){(this.listeners[name]??=[]).push(callback);}
        dispatch(name,values={}){const event={target:this,key:'',shiftKey:false,prevented:false,preventDefault(){this.prevented=true;},...values};for(const callback of this.listeners[name]||[])callback(event);return event;}
        appendChild(node){this.childNodes.push(node);node.parentNode=this;return node;}
        prepend(node){this.childNodes.unshift(node);node.parentNode=this;}
        remove(){if(this.parentNode)this.parentNode.childNodes=this.parentNode.childNodes.filter(n=>n!==this);}
        contains(node){return node===this||this.childNodes.some(child=>child.contains?.(node));}
        replaceChildren(...nodes){this.childNodes=[];this._text='';this._html='';for(const node of nodes)if(node.nodeType===11)node.childNodes.forEach(child=>this.appendChild(child));else this.appendChild(node);this.replacements++;}
        querySelectorAll(selector){const all=[];const walk=node=>{for(const child of node.childNodes||[])if(child.nodeType===1){all.push(child);walk(child);}};walk(this);return all.filter(node=>matches(node,selector));}
        querySelector(selector){return this.querySelectorAll(selector).at(0)||null;}
        closest(selector){return matches(this,selector)?this:this.parentNode?.closest(selector)||null;}
    }
    function matches(node,selector){
        if(selector==='summary .tree-path')return node.classList.contains('tree-path');
        if(selector==='details.tree-node')return node.tagName==='DETAILS'&&node.classList.contains('tree-node');
        if(selector.startsWith('.'))return node.classList.contains(selector.slice(1));
        if(selector==='button:not([disabled]),a[href]')return node.tagName==='BUTTON'&&!node.disabled;
        if(selector.startsWith('['))return node.hasAttribute(selector.slice(1,-1));
        return false;
    }
    doc={activeElement:null,templateChildren:[],listeners:{},elements:{},
        getElementById(id){if(!this.elements[id])throw Error('Missing HTML element: '+id);return this.elements[id];},
        querySelectorAll(selector){return Object.values(this.elements).filter(node=>matches(node,selector));},
        createElement(tag){return new Element(tag);},
        createTextNode(value){return {nodeType:3,textContent:value};},
        createDocumentFragment(){const node=new Element('fragment');node.nodeType=11;return node;},
        addEventListener(name,callback){(this.listeners[name]??=[]).push(callback);},
        dispatch(name,event){for(const callback of this.listeners[name]||[])callback(event);}
    };
    doc.body=new Element('body');
    for(const [id,[tag,attrs]] of Object.entries(metadata))doc.elements[id]=new Element(tag,attrs);
    const sidebar=doc.getElementById('sidebar');
    sidebar.childNodes=[doc.getElementById('closeSidebar'),...doc.querySelectorAll('.tab'),doc.getElementById('collapseSidebar')];
    if(narrow)doc.getElementById('collapseSidebar').offsetParent=null;
    let stored=saved===null?null:JSON.stringify(saved);
    const callbacks=[];
    const media={matches:narrow,addEventListener(name,callback){callbacks.push(callback);},change(value){this.matches=value;callbacks.forEach(callback=>callback(this));}};
    const timers=new Map();let timer=0;
    const win={localStorage:{getItem(){return stored;},setItem(key,value){stored=value;}},matchMedia(){return media;},
        setTimeout(callback){timers.set(++timer,callback);return timer;},clearTimeout(id){timers.delete(id);}};
    const node=(tag,classes,value='')=>{const n=new Element(tag,{class:classes});n.textContent=value;return n;};
    function tree(path='Z:/Fixture'){
        const root=node('details','tree-node depth-0');root.setAttribute('open','');root.open=true;
        const summary=node('summary','');summary.appendChild(node('span','tree-name','Fixture'));
        summary.appendChild(node('span','tree-path',path));root.appendChild(summary);return root;
    }
    return {doc,win,media,timers,tree,node,element:id=>doc.getElementById(id),preferences:()=>JSON.parse(stored)};
}

module.exports = {createFixture};
