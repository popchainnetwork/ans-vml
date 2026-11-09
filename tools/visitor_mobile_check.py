# SPDX-License-Identifier: Apache-2.0
# Headless layout/behaviour check of the local visitor page (needs python playwright + Chromium).
# Usage: VISITOR_URL=http://127.0.0.1:37121/ CHROME=/usr/bin/google-chrome SCREENS_DIR=screens python3 tools/visitor_mobile_check.py
import json, sys
from playwright.sync_api import sync_playwright
import os
U=os.environ.get("VISITOR_URL","http://127.0.0.1:37121/")
OUT=os.environ.get("SCREENS_DIR","screens")+"/"; os.makedirs(OUT,exist_ok=True)
report={}
def overflow(pg):
    return pg.evaluate("""()=>{const w=document.documentElement.clientWidth;const bad=[];for(const n of document.querySelectorAll('body *')){const r=n.getBoundingClientRect();if(r.width&&(r.right>w+0.5||r.left<-0.5)){let p=n.parentElement,clipped=false;while(p&&p!==document.body){const s=getComputedStyle(p);if(['auto','scroll','hidden'].includes(s.overflowX)){clipped=true;break}p=p.parentElement}if(!clipped&&getComputedStyle(n).position!=='absolute')bad.push(n.tagName+'.'+n.className+'#'+n.id+' '+Math.round(r.right))}}return {scrollW:document.documentElement.scrollWidth,clientW:w,bad:bad.slice(0,10)}}""")
def small_targets(pg):
    return pg.evaluate("""()=>[...document.querySelectorAll('a,button,input,textarea,summary,label.btn')].filter(n=>{const r=n.getBoundingClientRect();const s=getComputedStyle(n);return r.width>0&&s.visibility!=='hidden'&&!n.classList.contains('skip')&&(r.height<44||r.width<44)}).map(n=>n.tagName+'#'+n.id+'.'+n.className+' '+Math.round(n.getBoundingClientRect().width)+'x'+Math.round(n.getBoundingClientRect().height))""")
with sync_playwright() as p:
    b=p.chromium.launch(executable_path=os.environ.get("CHROME") or None,args=["--no-sandbox"])
    for name,vp,mobile,scheme in [("mobile-390",(390,844),True,"dark"),("mobile-360",(360,780),True,"dark"),("mobile-390-light",(390,844),True,"light"),("desktop-1280",(1280,800),False,"dark"),("desktop-1280-light",(1280,800),False,"light")]:
        ctx=b.new_context(viewport={"width":vp[0],"height":vp[1]},device_scale_factor=2 if mobile else 1,is_mobile=mobile,has_touch=mobile,color_scheme=scheme)
        pg=ctx.new_page(); errs=[]
        pg.on("console",lambda m: errs.append(m.text) if m.type in("error","warning") else None)
        pg.on("pageerror",lambda e: errs.append(str(e)))
        pg.goto(U); pg.wait_for_selector(".entry-title",timeout=15000)
        r={"title":pg.title(),"status":pg.text_content("#status-title"),"overflow":overflow(pg),"small_targets":small_targets(pg)}
        pg.screenshot(path=OUT+name+"-top.png")
        pg.screenshot(path=OUT+name+"-full.png",full_page=True)
        if name in("mobile-390","desktop-1280","mobile-360"):
            pg.click(".glance .g >> nth=0"); pg.wait_for_selector(".entry-title:text-is('o')"); r["glance"]=pg.text_content("#glance")
            pg.click("#use-served"); pg.wait_for_selector("#proof-meta:has-text('loaded')")
            pg.click("#use-demo-key"); pg.click("#verify-btn")
            pg.wait_for_selector("#verify-result:not([hidden])",timeout=20000)
            r["verify_ok"]=pg.text_content("#verify-result h3")
            pg.locator("#verify-result").scroll_into_view_if_needed(); pg.screenshot(path=OUT+name+"-verify-valid.png")
            pg.click("#use-wrong-key"); pg.click("#verify-btn")
            pg.wait_for_selector("#verify-result.bad",timeout=20000)
            r["verify_wrong"]=pg.text_content("#verify-result")
            pg.wait_for_timeout(2500); pg.locator("#verify-result").scroll_into_view_if_needed(); pg.screenshot(path=OUT+name+"-verify-invalid.png")
            pg.fill("#proof-text",'{"broken": tru'); pg.click("#verify-btn"); r["verify_badjson"]=pg.text_content("#verify-result h3")
            # select a letter via dependency chip
            pg.click("#entries button:has-text('oak')")
            pg.click(".dep >> nth=0"); pg.wait_for_selector(".entry-title:text-is('o')")
            r["dep_nav"]=pg.text_content(".entry-title")
            pg.screenshot(path=OUT+name+"-explore-letter.png")
            pg.fill("#search","k"); r["search_k"]=pg.text_content("#catalog-status")
            r["overflow_after"]=overflow(pg)
            r["pkg"]=pg.text_content("#pkg-note"); r["dl_visible"]=pg.is_visible("#pkg-download")
            pg.evaluate("document.getElementById('download').scrollIntoView()"); pg.wait_for_timeout(300); pg.screenshot(path=OUT+name+"-download.png")
        r["errors"]=errs
        report[name]=r; ctx.close()
    b.close()
print(json.dumps(report,indent=1,ensure_ascii=False))
json.dump(report,open(OUT+"check-report.json","w"),indent=1,ensure_ascii=False)
problems=[]
for name,r in report.items():
    for key in ("overflow","overflow_after"):
        o=r.get(key)
        if o and (o["scrollW"]>o["clientW"] or o["bad"]): problems.append(f"{name}: horizontal overflow {o}")
    if [t for t in r["small_targets"] if "visually-hidden" not in t]: problems.append(f"{name}: small touch targets {r['small_targets']}")
    if r["errors"]: problems.append(f"{name}: console errors {r['errors']}")
    if "verify_ok" in r and (not r["verify_ok"].startswith("Valid proof") or not r["verify_wrong"].startswith("Not valid")): problems.append(f"{name}: verify flow")
if problems:
    print("\n".join(problems)); sys.exit(1)
print("visitor layout check: OK")
