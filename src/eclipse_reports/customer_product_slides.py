"""Customer-facing concise Japanese ECLIPSE PowerPoint, no internal codes or raw JSON.
Source: ECLIPSE customer-product-report.json; optional human-approved Japanese summaries.
"""
from __future__ import annotations
import argparse
import json
import re
from collections import OrderedDict
from pathlib import Path
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN

COL={'navy':(18,34,59),'blue':(23,95,166),'cyan':(29,148,161),'dark':(34,48,64),'gray':(101,115,129),
     'bg':(246,249,252),'white':(255,255,255),'line':(224,232,239),'red':(189,58,63),'amber':(167,99,20)}
FONTS='Noto Sans CJK JP'

def rgb(key):return RGBColor(*COL[key])

def text(s,txt,x,y,w,h,size=12,col='dark',bold=False,align=None):
    sh=s.shapes.add_textbox(Inches(x),Inches(y),Inches(w),Inches(h)); tf=sh.text_frame
    tf.word_wrap=True;tf.margin_top=tf.margin_bottom=Inches(.02);tf.margin_left=tf.margin_right=Inches(.02)
    for j,line in enumerate(str(txt).split('\n')):
        p=tf.paragraphs[0] if j==0 else tf.add_paragraph();p.text=line
        p.font.name=FONTS;p.font.size=Pt(size);p.font.bold=bold;p.font.color.rgb=rgb(col)
        p.space_after=Pt(2)
        if align:p.alignment=align
    return sh

def rect(s,x,y,w,h,fill='white',border=False,radius=False):
    sh=s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
        Inches(x),Inches(y),Inches(w),Inches(h));sh.fill.solid();sh.fill.fore_color.rgb=rgb(fill)
    if border:sh.line.color.rgb=rgb('line')
    else:sh.line.fill.background()
    return sh

def truncate(s,n):
    v=' '.join(str(s or '').split());return v if len(v)<=n else v[:n-1]+'…'

def base(prs,title,sub=''):
    s=prs.slides.add_slide(prs.slide_layouts[6]);s.background.fill.solid();s.background.fill.fore_color.rgb=rgb('bg')
    rect(s,0,0,13.333,.10,'cyan');text(s,'ECLIPSE',.6,.30,3.0,.32,10,'blue',True)
    text(s,title,.62,.90,12.0,.65,25,'navy',True)
    if sub:text(s,sub,.65,1.57,12.0,.40,11,'gray')
    rect(s,.62,7.06,12.06,.018,'line')
    text(s,'ECLIPSE  ／  '+ '2026-10-10',.69,7.12,10.3,.23,8,'gray')
    text(s,f'{len(prs.slides):02d}',12.25,7.10,.4,.25,9,'gray')
    return s

def jpversion(sources):
    # Prefer the responsible CNA publisher's version assertions. ADP rows can
    # restate overlapping ranges with different interval notation.
    official=[x for x in sources if x.get('container')=='cna' and isinstance(x.get('versions_raw'),list)]
    if official:sources=official
    ranges=[];unusable=0;seen=set()
    for x in sources:
        values=x.get('versions_raw')
        if not isinstance(values,list):unusable+=1;continue
        for v in values:
            if not isinstance(v,dict) or v.get('status')!='affected':continue
            lo=v.get('version');lte=v.get('lessThanOrEqual');lt=v.get('lessThan')
            if not isinstance(lo,str) or not lo.strip() or len(lo)>45:unusable+=1;continue
            if lo in ('*','n/a','0') and not (lte or lt):unusable+=1;continue
            if isinstance(lte,str) and lte.strip() and lte!='*': val=f'{lo} ～ {lte}'
            elif isinstance(lt,str) and lt.strip() and lt!='*': val=f'{lo} 以上、{lt} 未満'
            else:val=lo
            if val not in seen:
                seen.add(val);ranges.append(val)
    if len(ranges)>9:
        return '複数のバージョンが対象です。詳細は一次情報をご確認ください。'
    if ranges:
        out='、'.join(ranges)
        if len(out)>115:
            return '、'.join(ranges[:5]) + ' ほか。全範囲は一次情報をご確認ください。'
        return out
    return '影響バージョンの範囲は一次情報をご確認ください。'

def qa_ja_summary(src):
    if not isinstance(src,dict):return {}
    validated={}
    for cve,x in src.items():
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):raise ValueError('Invalid CVE brief ID')
        if not isinstance(x,str) or not 12<=len(x.strip())<=220 or re.search(r'[\x00-\x1f]',x):
            raise ValueError('Japanese brief must be vetted and 12-220 chars')
        if not re.search(r'[\u3040-\u30ff\u3400-\u9fff]',x):raise ValueError('Japanese summary missing')
        validated[cve]=x.strip()
    return validated

def clean_version(v):
    if not isinstance(v,str) or not v.strip() or v.startswith('EXAMPLE-ONLY') or v.lower() in ('unknown','none','n/a'):
        return '未確認'
    return truncate(v,42)

def reason(item):
    if item.get('kev_in_snapshot'):return '悪用確認済み（KEV掲載）'
    mapping={'RECENT_CVE_PUBLICATION_OR_UPDATE':'最近公開・更新','CNA_HIGH_SEVERITY_REVIEW':'重大度が高い',
             'EPSS_FORECAST_REVIEW':'悪用予測が高い','HISTORICAL_INFORMATION_REVIEW':'製品への関連情報あり'}
    return mapping.get(item.get('review_queue'),'確認対象')

def create(report_path:Path,out:Path,*,briefs_path:Path|None=None,max_details=8,max_list=24):
    if not 0<=max_details<=15 or not 0<=max_list<=50:raise ValueError('Unbounded report')
    d=json.loads(report_path.read_text(encoding='utf-8'))
    if d.get('classification')!='CUSTOMER_PRODUCT_REFERENCE_REPORT_NOT_VERIFIED_ASSET_EXPOSURE':
        raise ValueError('Unexpected evidence report')
    if not isinstance(d.get('preview'),list) or not isinstance(d.get('products'),list):
        raise ValueError('Missing report evidence')
    approved=qa_ja_summary(json.loads(briefs_path.read_text(encoding='utf-8'))) if briefs_path else {}
    prs=Presentation();prs.slide_width=Inches(13.333);prs.slide_height=Inches(7.5)
    prs.core_properties.title='ECLIPSE 製品別脆弱性レポート'
    prs.core_properties.subject='CVE公開情報に基づく製品別の要確認事項'
    s=prs.slides.add_slide(prs.slide_layouts[6]);s.background.fill.solid();s.background.fill.fore_color.rgb=rgb('navy')
    rect(s,.8,1.0,.65,.10,'cyan');text(s,'ECLIPSE',.86,1.39,10,.65,23,'cyan',True)
    text(s,'製品別 脆弱性レポート',.84,2.22,11.9,1.12,35,'white',True)
    customer='サンプル企業' if d.get('synthetic_demo') else truncate(d.get('customer_name','顧客'),65)
    text(s,customer,.87,3.93,11.8,.66,24,'white',True)
    text(s,'対象日：'+d['as_of'],.9,4.82,10,.45,15,'white')
    if d.get('synthetic_demo'):text(s,'サンプル（架空の企業・製品登録情報を使用）',.9,6.3,11.4,.37,11,'cyan')

    summary=d['summary'];s=base(prs,'全体サマリー')
    for x,value,label,color in [(.76,summary['monitored_inventory_entries'],'確認対象の製品数','blue'),
                                (4.84,summary['product_cve_rows_in_report'],'関連するCVE件数','cyan'),
                                (8.92,summary['kev_listed_product_cve_rows'],'悪用確認済みのCVE件数','red')]:
        rect(s,x,2.20,3.67,1.65,'white',True,True)
        text(s,str(value),x+.24,2.40,3.1,.60,32,color,True)
        text(s,label,x+.25,3.18,3.14,.38,13)
    rect(s,.80,4.41,11.68,1.1,'white',True,True)
    text(s,'確認のポイント',1.05,4.58,3.0,.36,16,'navy',True)
    text(s,'影響判定：未判定（導入バージョン・設定は別途確認）',1.06,5.03,10.8,.34,13)

    prod=d['products']
    for offset in range(0,max(1,len(prod)),9):
        part=prod[offset:offset+9];s=base(prs,'製品別の確認状況')
        rect(s,.82,2.05,11.65,.53,'navy');text(s,'製品',1.06,2.15,6.35,.35,11,'white',True)
        text(s,'関連CVE',8.03,2.15,1.76,.35,11,'white',True)
        text(s,'悪用確認済み',10.03,2.15,2.15,.35,11,'white',True)
        if not part:text(s,'対象となる製品はありません。',1.1,2.95,10,.6,14)
        for i,p in enumerate(part):
            y=2.73+i*.41
            if i%2==0:rect(s,.83,y-.03,11.6,.41,'white')
            text(s,truncate(f"{p['vendor']} / {p['product']}",78),1.07,y,5.8,.35,11)
            text(s,str(p['included_product_cve_rows']),8.14,y,1.6,.33,12,'blue',True)
            text(s,str(p['kev_listed_included']),10.31,y,1.35,.33,12,'red' if p['kev_listed_included'] else 'gray',True)
        if any(p['included_product_cve_rows']==0 for p in part):
            text(s,'※ 0件の製品についても、脆弱性がないことを示すものではありません。',.98,6.78,11.1,.30,10,'gray')

    listing=d['preview'][:max_list]
    for offset in range(0,max(1,len(listing)),9):
        part=listing[offset:offset+9];s=base(prs,'優先的に確認する脆弱性','製品と関連があるCVEを、悪用情報や深刻度などから整理')
        rect(s,.83,2.04,11.63,.55,'navy')
        for x,w,lbl in [(1.05,2.25,'CVE'),(3.5,3.16,'製品'),(7.11,1.0,'CVSS'),(8.27,3.9,'確認理由')]:
            text(s,lbl,x,2.16,w,.35,11,'white',True)
        if not part:text(s,'報告対象のCVEはありません。',1.05,3,11,.47,14)
        for i,item in enumerate(part):
            y=2.76+i*.41
            if i%2==0:rect(s,.85,y-.03,11.6,.39,'white')
            text(s,item['cve_id'],1.02,y,2.42,.34,10,'blue',True)
            text(s,truncate(f"{item['vendor']} / {item['product']}",42),3.48,y,3.33,.34,10)
            val=item.get('cvss_score');text(s,('—' if val is None else str(val)),7.21,y,.84,.34,11,'red' if val is not None and val>=9 else 'dark',True)
            text(s,reason(item),8.28,y,3.68,.34,10,'red' if item.get('kev_in_snapshot') else 'dark')

    detail=[item for item in d['preview'] if item['cve_id'] in approved][:max_details]
    for offset in range(0,len(detail),2):
        chunk=detail[offset:offset+2];s=base(prs,'重要な脆弱性の詳細')
        for i,item in enumerate(chunk):
            y=2.12+i*2.18
            rect(s,.8,y,11.73,2.05,'white',True,True)
            text(s,item['cve_id'],1.07,y+.16,2.92,.38,15,'blue',True)
            text(s,truncate(f"{item['vendor']} / {item['product']}",60),4.11,y+.18,4.10,.35,13,'navy',True)
            text(s,'悪用確認済み' if item['kev_in_snapshot'] else '確認対象',9.80,y+.18,2.25,.35,12,'red' if item['kev_in_snapshot'] else 'blue',True)
            text(s,approved[item['cve_id']],1.07,y+.61,10.95,.65,12,'dark')
            version=jpversion(item.get('publisher_version_statements') or [])
            text(s,'影響バージョン：'+truncate(version,118),1.07,y+1.38,10.95,.55,11,'gray')
        text(s,'対応：製品の導入バージョンと設定を確認し、メーカーの修正情報に照らして判断してください。',.92,6.71,11.2,.35,11,'navy')

    if not detail:
        s=base(prs,'確認・対応事項')
        text(s,'1. 製品の導入バージョンを確認',1.02,2.26,10.7,.50,19,'navy',True)
        text(s,'2. 一次情報にある影響バージョンとの照合',1.02,3.13,10.7,.50,19,'navy',True)
        text(s,'3. 影響がある場合は、メーカーの修正情報を確認',1.02,4.0,10.7,.50,19,'navy',True)

    # Minimal source references; no JSON, English workflow codes or internal definitions.
    s=base(prs,'一次情報・連絡事項')
    text(s,'確認先',1.04,2.32,10.5,.48,17,'navy',True)
    text(s,'CVE公開情報：https://www.cve.org/',1.09,2.99,10.8,.48,14)
    text(s,'CISA 悪用確認リスト：https://www.cisa.gov/known-exploited-vulnerabilities-catalog',1.09,3.63,10.8,.57,13)
    text(s,'メーカーの公式セキュリティ情報：対象製品ごとに確認',1.09,4.32,10.8,.47,14)
    rect(s,.93,5.46,11.27,.87,'white',True,True)
    text(s,'最終的な影響の有無・対応要否は、導入バージョンや設定を確認したうえで判断します。',1.16,5.76,10.7,.40,13,'navy',True)
    out.parent.mkdir(parents=True,exist_ok=True)
    prs.save(out)
    manifest={'pptx_file':out.name,'slides':len(prs.slides),
              'reported_product_cve_rows':summary['product_cve_rows_in_report'],
              'slide_count':len(prs.slides),'selected_cves_in_list':len(listing),
              'approved_japanese_descriptions':len(detail),'source_report':report_path.name,
              'not_customer_exposure_claim':True}
    out.with_suffix('.manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf8')
    return manifest

def render_report(report_path:Path,output_path:Path,*,max_details:int=8,max_list:int=24,briefs_ja:Path|None=None):
    return create(report_path,output_path,briefs_path=briefs_ja,max_details=max_details,max_list=max_list)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--report-json',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--briefs-ja',type=Path);p.add_argument('--max-details',type=int,default=8)
    p.add_argument('--max-list',type=int,default=24)
    a=p.parse_args();print(json.dumps(create(a.report_json,a.out,briefs_path=a.briefs_ja,max_details=a.max_details,max_list=a.max_list),ensure_ascii=False))
