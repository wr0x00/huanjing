/* ===========================================================
   图表组件库：纯 SVG / CSS 实现，零外部依赖，可离线运行
   主题色统一使用蜂蜜橙系（与控制台主题一致）
   =========================================================== */
(function(){
  const PALETTE = ["#fa8c16","#ffc069","#d46b08","#ffb74d","#b45309","#ffd8a8",
                   "#ff9c6e","#e8890c","#f0a95c","#c2610a"];

  /* ---------- 环形图（事件分布 / 存储占比） ---------- */
  function arcPath(cx, cy, ro, ri, a0, a1){
    const p=(r,a)=>[cx+r*Math.sin(a), cy-r*Math.cos(a)];
    const large=(a1-a0)>Math.PI?1:0;
    const [x1,y1]=p(ro,a0), [x2,y2]=p(ro,a1), [x3,y3]=p(ri,a1), [x4,y4]=p(ri,a0);
    return `M${x1.toFixed(2)} ${y1.toFixed(2)} A${ro} ${ro} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} `
         + `L${x3.toFixed(2)} ${y3.toFixed(2)} A${ri} ${ri} 0 ${large} 0 ${x4.toFixed(2)} ${y4.toFixed(2)} Z`;
  }

  /* 大数缩写：8.68 → "8.68"；≥1000 → "1.2k"；≥1e6 → "3.4M"；≥1e9 → "5.6G" */
  function fmtNum(n){
    const v = +n || 0;
    if (v >= 1e9) return (v/1e9).toFixed(1)+"G";
    if (v >= 1e6) return (v/1e6).toFixed(1)+"M";
    if (v >= 1e4) return (v/1e3).toFixed(1)+"k";
    return String(Math.round(v*100)/100);
  }

  const DonutChart = {
    props:{
      data:{type:Array,default:()=>[]},
      size:{type:Number,default:210},
      thick:{type:Number,default:30},
      unit:{type:String,default:"总计"},
      legend:{type:Boolean,default:true},
    },
    data(){return{hover:-1}},
    computed:{
      total(){return this.data.reduce((s,d)=>s+(+d.value||0),0)},
      segs(){
        const total=this.total, cx=this.size/2, cy=this.size/2;
        const ro=this.size/2-4, ri=ro-this.thick;
        if(!total) return [];
        let acc=0;
        return this.data.map((d,i)=>{
          const frac=(+d.value||0)/total;
          const gap=this.data.length>1?Math.min(0.035, frac*0.18):0;
          const a0=acc*Math.PI*2 + gap/2, a1=(acc+frac)*Math.PI*2 - gap/2;
          acc+=frac;
          return {name:d.name, value:d.value, color:PALETTE[i%PALETTE.length],
                  d:arcPath(cx,cy,ro,ri,a0,Math.max(a1,a0+0.001)),
                  pct:(frac*100).toFixed(1)};
        });
      },
    },
    template:`
<div class="donut-wrap">
  <svg :viewBox="'0 0 '+size+' '+size" :width="size" :height="size" class="donut">
    <g v-for="(s,i) in segs" :key="s.name" class="donut-seg"
       @mouseenter="hover=i" @mouseleave="hover=-1">
      <path :d="s.d" :fill="s.color" :opacity="(hover<0||hover===i)?1:.28">
        <title>{{s.name}} · {{s.value}} ({{s.pct}}%)</title></path>
    </g>
    <circle v-if="!segs.length" :cx="size/2" :cy="size/2" :r="(size/2-4-this.thick)"
            fill="none" stroke="var(--border-strong)" stroke-width="2"/>
    <text :x="size/2" :y="size/2-2" text-anchor="middle" class="donut-big">
      {{hover<0?fmt(total):fmt(segs[hover]?segs[hover].value:0)}}</text>
    <text :x="size/2" :y="size/2+18" text-anchor="middle" class="donut-sub">
      {{hover<0?unit:segs[hover]?segs[hover].name:''}}</text>
  </svg>
  <ul class="donut-legend" v-if="legend">
    <li v-for="(s,i) in segs" :key="'l'+i" @mouseenter="hover=i" @mouseleave="hover=-1"
        :class="{on:hover===i}">
      <i :style="{background:s.color}"></i>
      <span class="dl-name">{{s.name}}</span>
      <b>{{fmt(s.value)}}</b><em>{{s.pct}}%</em></li>
  </ul>
</div>`,
    methods:{ fmt: fmtNum },
  };

  /* ---------- 面积趋势图（24h 流量） ---------- */
  const AreaChart = {
    props:{
      labels:{type:Array,default:()=>[]},
      series:{type:Array,default:()=>[]},   // [{name,color,values:[..]}]
      height:{type:Number,default:210},
      area:{type:Boolean,default:true},
    },
    data(){return{hover:-1, mx:0}},
    computed:{
      max(){return Math.max(1,...this.series.flatMap(s=>s.values||[]))},
      W(){return 720}, H(){return this.height},
      pts(){ return this.series.map(s=>{
        const v=s.values||[], n=Math.max(1,v.length-1);
        return v.map((y,i)=>{
          const x=this.W*(v.length>1?i/n:0.5);
          const yy=this.H-24-(this.H-46)*(y/this.max);
          return [x,yy];
        });
      });},
      paths(){ return this.pts.map((p,i)=>{
        if(!p.length) return {line:"", area:"", color:this.series[i].color};
        let line="M"+p[0][0].toFixed(1)+" "+p[0][1].toFixed(1);
        for(let k=1;k<p.length;k++){
          const [px,py]=p[k-1], [cx2,cy2]=p[k];
          const mx=(px+cx2)/2;
          line+=` C${mx.toFixed(1)} ${py.toFixed(1)} ${mx.toFixed(1)} ${cy2.toFixed(1)} ${cx2.toFixed(1)} ${cy2.toFixed(1)}`;
        }
        const area=this.area
          ? line+` L${p[p.length-1][0].toFixed(1)} ${this.H-24} L${p[0][0].toFixed(1)} ${this.H-24} Z`
          : "";
        return {line, area, color:this.series[i].color, pts:p};
      });},
      hoverInfo(){
        if(this.hover<0||!this.labels.length) return null;
        const i=this.hover;
        return {label:this.labels[i],
                items:this.series.map(s=>({name:s.name,color:s.color,value:(s.values||[])[i]||0}))};
      },
    },
    methods:{
      onMove(e){
        const r=e.currentTarget.getBoundingClientRect();
        const fx=(e.clientX-r.left)/r.width;
        const n=this.labels.length;
        if(!n) return;
        let i=Math.round(fx*(n-1));
        this.hover=Math.max(0,Math.min(n-1,i));
      },
    },
    template:`
<div class="area-wrap">
  <div class="area-legend">
    <span v-for="s in series" :key="s.name"><i :style="{background:s.color}"></i>{{s.name}}</span>
    <span class="sp"></span>
    <span v-if="hoverInfo" class="area-tip">
      <b>{{hoverInfo.label}}</b>
      <span v-for="it in hoverInfo.items" :key="it.name">
        <i :style="{background:it.color}"></i>{{it.name}} {{it.value}}</span>
    </span>
  </div>
  <svg :viewBox="'0 0 '+W+' '+H" class="area" preserveAspectRatio="none"
       @mousemove="onMove" @mouseleave="hover=-1">
    <defs>
      <linearGradient v-for="(p,i) in paths" :id="'ag'+i" :key="i" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" :stop-color="p.color" stop-opacity=".55"/>
        <stop offset="100%" :stop-color="p.color" stop-opacity=".02"/>
      </linearGradient>
    </defs>
    <line v-for="k in 4" :key="'g'+k" :x1="0" :x2="W"
          :y1="24+(k-1)*((H-46)/3)" :y2="24+(k-1)*((H-46)/3)"
          stroke="var(--border)" stroke-width="1" vector-effect="non-scaling-stroke"/>
    <path v-for="(p,i) in paths" :key="'a'+i" :d="p.area" :fill="'url(#ag'+i+')'"/>
    <path v-for="(p,i) in paths" :key="'l'+i" :d="p.line" fill="none" :stroke="p.color"
          stroke-width="2" vector-effect="non-scaling-stroke" stroke-linejoin="round"/>
    <g v-if="hover>=0">
      <line :x1="labels.length>1?W*hover/(labels.length-1):W/2" :x2="labels.length>1?W*hover/(labels.length-1):W/2"
            y1="16" :y2="H-24" stroke="var(--primary)" stroke-width="1"
            stroke-dasharray="3 3" vector-effect="non-scaling-stroke"/>
      <circle v-for="(p,si) in paths" :key="'p'+si"
              :cx="p.pts[hover]?p.pts[hover][0]:0" :cy="p.pts[hover]?p.pts[hover][1]:0"
              r="4" :fill="p.color" stroke="var(--bg)" stroke-width="1.5"/>
    </g>
  </svg>
  <div class="area-axis">
    <span v-for="(l,i) in labels" :key="'x'+i" v-show="i%4===0||i===labels.length-1">{{l}}</span>
  </div>
</div>`,
  };

  /* ---------- 柱状图（纯 HTML/CSS，柱体渐变 + 悬浮动效） ---------- */
  const BarChart = {
    props:{
      data:{type:Array,default:()=>[]},   // [{name,value}]
      unit:{type:String,default:""},
      color:{type:String,default:"#fa8c16"},
      max:Number,
    },
    data(){return{hover:-1}},
    computed:{
      maxV(){return this.max||Math.max(1,...this.data.map(d=>+d.value||0))},
    },
    methods:{
      h(v){const pct=(+v||0)/this.maxV*100; return Math.max(pct, (+v||0)>0?3:0)},
    },
    template:`
<div class="bars">
  <div class="bar-row" v-for="(d,i) in data" :key="'b'+i"
       @mouseenter="hover=i" @mouseleave="hover=-1" :class="{on:hover===i}">
    <span class="bar-name" :title="d.name">{{d.name}}</span>
    <span class="bar-track">
      <i class="bar-fill" :style="{width:h(d.value)+'%', background: hover===i?color:'linear-gradient(90deg,'+color+','+color+'99)'}"></i>
    </span>
    <b class="bar-val">{{d.value}}<em v-if="unit">{{unit}}</em></b>
  </div>
  <div v-if="!data.length" class="empty">暂无数据</div>
</div>`,
  };

  /* ---------- 迷你仪表（高危占比） ---------- */
  const Gauge = {
    props:{value:{type:Number,default:0}, max:{type:Number,default:100}, label:{type:String,default:""},
           color:{type:String,default:"#fa8c16"}},
    computed:{
      pct(){return Math.max(0,Math.min(100,(this.value/this.max)*100))},
      dash(){return `${(this.pct/100)*176} 176`},
    },
    template:`
<div class="gauge">
  <svg viewBox="0 0 120 74" class="gauge-svg">
    <path d="M12 66 A48 48 0 0 1 108 66" fill="none" stroke="var(--border-strong)"
          stroke-width="10" stroke-linecap="round"/>
    <path d="M12 66 A48 48 0 0 1 108 66" fill="none" :stroke="color" stroke-width="10"
          stroke-linecap="round" :stroke-dasharray="dash" class="gauge-arc"/>
  </svg>
  <div class="gauge-txt"><b>{{value}}</b><span>{{label}}</span></div>
</div>`,
  };

  window.ChartKit = {DonutChart, AreaChart, BarChart, Gauge, PALETTE};
})();
