// Exercise chart rendering against missing data, offline nodes and reporting gaps.
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/app.js','utf8');
const context=vm.createContext({formatRate:n=>n==null?'—':n+' bps',formatBytes:n=>n==null?'—':n+' B',Date,Number,Math});
vm.runInContext(source.slice(source.indexOf('const metricNames=')),context);
function data(){return {now:3600,seconds:3600,bucket:15,online:true,current:{cpu_percent:25,tcp:12},traffic:{},points:[{stamp:100,cpu:20,tcp:10,rx_bps:100,tx_bps:200},{stamp:115,cpu:30,tcp:12,rx_bps:120,tx_bps:220},{stamp:300,cpu:40,tcp:null,rx_bps:140,tx_bps:null}]};}
test('gaps produce separate curve segments, with a shared percentage scale',()=>{const html=context.monitorMarkup(data(),'cpu');assert.equal((html.match(/vector-effect=/g)||[]).length,2);assert.match(html,/100.0%/);assert.match(html,/25.0%/);assert.doesNotMatch(html,/NaN|Infinity/);});
test('offline current values remain unavailable while history is preserved',()=>{const d=data();d.online=false;d.current={};const html=context.monitorMarkup(d,'tcp');assert.match(html,/<strong>—<\/strong>/);assert.match(html,/服务器离线/);assert.match(html,/12/);});
test('network shows both directions and handles partial series',()=>{const html=context.monitorMarkup(data(),'network');assert.match(html,/↓ 下行/);assert.match(html,/↑ 上行/);assert.equal((html.match(/class="monitor-stat"/g)||[]).length,2);assert.doesNotMatch(html,/NaN|Infinity/);});
test('all-null and empty history render empty state without fabricated samples',()=>{for(const points of [[],[{stamp:200,cpu:null}]]){const d=data();d.points=points;const html=context.monitorMarkup(d,'cpu');assert.match(html,/暂无历史数据/);assert.doesNotMatch(html,/id="monitorSVG"/);assert.doesNotMatch(html,/NaN|Infinity/);}});
