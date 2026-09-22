/* Vue is vendored locally; no external services or build step are required. */
const {createApp} = Vue;
createApp({
  data: () => ({token:'',connected:false,error:'',busy:false,tab:'Monitor',metrics:{},network:{},interfaces:[],capture:'',packets:[],history:[],flows:[],interval:'60',rates:[],socket:null,timer:null,ack:'0',validation:'',vlan:'',refreshing:false,
    config:{outer_interface:'',inner_interface:'',device_ipv4:'10.0.0.5',inner_gateway_ipv4:'10.0.0.1',inner_prefix:24,outer_ipv4:'',outer_prefix:24,outer_gateway_ipv4:'',outer_mac:''},
    fields:[['outer_interface','Outer interface'],['inner_interface','Inner interface'],['device_ipv4','Protected device IPv4'],['inner_gateway_ipv4','Inner gateway IPv4'],['inner_prefix','Inner prefix',true],['outer_ipv4','Outer IPv4'],['outer_prefix','Outer prefix',true],['outer_gateway_ipv4','Outer gateway IPv4'],['outer_mac','Outer MAC']].map(([key,label,number])=>({key,label,number}))}),
  computed:{chart(){const max=Math.max(1,...this.rates);return this.rates.map((n,i)=>`${i*800/59},${115-n/max*110}`).join(' ')}},
  methods:{
    async api(path,method='GET',body){const response=await fetch('/api/v1/'+path,{method,headers:{Authorization:'Bearer '+this.token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});const json=await response.json();if(!response.ok)throw new Error(json.error||response.statusText);return json},
    async action(fn){this.error='';this.busy=true;try{await fn()}catch(e){this.error=e.message}finally{this.busy=false}},
    async connect(){await this.action(async()=>{const status=await this.api('status');this.metrics=status.metrics;this.network=status.network;this.interfaces=await this.api('interfaces');this.capture=status.capture_interface||'';if(this.network.config){this.config={...this.network.config};this.vlan=this.config.vlan_id == null ? '' : this.config.vlan_id;delete this.config.vlan_id}this.connected=true;this.openSocket();this.timer=setInterval(()=>this.refresh(),1000)})},
    openSocket(){this.ack='0';this.socket=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/api/v1/live');this.socket.onmessage=event=>{const data=JSON.parse(event.data);this.ack=data.sequence;if(data.error){this.error=data.error;return}this.metrics=data;this.network=data.network;this.rates.push(data.bits_per_second||0);if(this.rates.length>60)this.rates.shift()};this.socket.onclose=()=>{if(this.connected)this.error='Live connection closed. Lock and reconnect.'}},
    async refresh(){if(this.refreshing)return;this.refreshing=true;try{if(this.socket && this.socket.readyState===WebSocket.OPEN)this.socket.send(JSON.stringify({token:this.token,ack:this.ack}));if(this.tab==='Monitor')this.packets=(await this.api('packets')).reverse()}catch(e){this.error=e.message}finally{this.refreshing=false}},
    disconnect(){this.connected=false;clearInterval(this.timer);this.socket && this.socket.close();this.token='';this.packets=[];this.metrics={};this.error=''},
    payload(){return {...this.config,inner_prefix:Number(this.config.inner_prefix),outer_prefix:Number(this.config.outer_prefix),vlan_id:this.vlan===''?null:Number(this.vlan)}},
    async startCapture(){await this.action(async()=>{await this.api('capture','PUT',{interface:this.capture})})},
    async stopCapture(){await this.action(async()=>{await this.api('capture','DELETE')})},
    async validateConfig(){await this.action(async()=>{await this.api('config/validate','POST',this.payload());this.validation='Address and syntax checks passed. Apply also checks actual interface state.'})},
    async apply(){await this.action(async()=>{this.network=await this.api('config','PUT',this.payload())})},
    async confirm(){await this.action(async()=>{this.network=await this.api('config/confirm','POST',{})})},
    async rollback(){await this.action(async()=>{this.network=await this.api('config/rollback','POST',{})})},
    async loadHistory(){await this.action(async()=>{const now=Math.floor(Date.now()/1000);this.history=await this.api(`history?from=${now-86400}&to=${now+1}&interval=${this.interval}`);this.flows=await this.api('flows')})},
    rate(value){return ((value||0)/1e6).toFixed(2)+' Mbit/s'}
  }
}).mount('#app');
