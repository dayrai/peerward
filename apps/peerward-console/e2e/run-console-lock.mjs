// Invoked only inside scripts/with-postgres.sh. Owns every process it starts.
import {spawn,spawnSync} from 'node:child_process';
import {mkdtemp,rm,open} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {startOidcProvider} from './oidc-provider.mjs';
const here=path.dirname(fileURLToPath(import.meta.url)),repo=path.resolve(here,'../../..');
if(!process.env.PEERWARD_TEST_DATABASE_URL?.endsWith('/peerward_test'))throw new Error('fresh disposable database required');
const work=await mkdtemp(path.join(tmpdir(),'peerward-console-lock-')),children=[],logs=[];
async function port(){const server=createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const result=server.address().port;await new Promise(resolve=>server.close(resolve));return result;}
async function start(binary,env,name){const log=await open(path.join(work,name+'.log'),'w');logs.push(log);const child=spawn(path.join(repo,binary),[],{cwd:repo,env,stdio:['ignore',log.fd,log.fd]});children.push(child);return child;}
let provider,passed=false;
try {
 const apiPort=await port(),consolePort=await port(),origin=`http://127.0.0.1:${consolePort}`;
 provider=await startOidcProvider(origin+'/auth/callback',0);
 const binding=spawnSync('wasm-bindgen',['target/wasm32-unknown-unknown/debug/peerward-console-web.wasm','--target','web','--out-dir',work,'--out-name','peerward-console-web'],{cwd:repo,stdio:'inherit'});
 if(binding.status!==0)throw new Error('wasm bindings failed');
 const env={...process.env};delete env.PEERWARD_DEV_BEARER;
 await start('target/debug/examples/console_review_fixture',{...env,PEERWARD_CONSOLE_FIXTURE_LISTEN:`127.0.0.1:${apiPort}`,PEERWARD_CONSOLE_FIXTURE_OIDC_ISSUER:provider.issuer,PEERWARD_CONSOLE_FIXTURE_OIDC_REDIRECT:provider.redirectUri},'control');
 await start('target/debug/peerward-console',{...env,PEERWARD_CONTROL_URL:`http://127.0.0.1:${apiPort}`,PEERWARD_CONSOLE_LISTEN:`127.0.0.1:${consolePort}`,PEERWARD_CONSOLE_ASSET_DIR:work},'console');
 let ready=false;
 for(let i=0;i<60;i++){
  if(children.some(child=>child.exitCode!==null))throw new Error('fixture exited');
  try{const response=await fetch(origin+'/auth/session');if(response.status===401){ready=true;break;}}catch{}
  await new Promise(resolve=>setTimeout(resolve,500));
 }
 if(!ready)throw new Error('fixture timeout');
 const test=spawn(process.execPath,[path.join(here,'node_modules/@playwright/test/cli.js'),'test','console-lock.spec.mjs','--reporter=line'],{cwd:here,env:{...env,PEERWARD_CONSOLE_E2E_URL:origin,PEERWARD_CONSOLE_LOCK_E2E:'1',PEERWARD_OIDC_PROVIDER_URL:provider.issuer},stdio:'inherit'});children.push(test);
 const code=await new Promise(resolve=>test.on('exit',resolve));if(code!==0)throw new Error('OIDC browser regression failed');passed=true;
} finally {
 for(const child of children.toReversed())if(child.exitCode===null&&child.signalCode===null)child.kill('SIGINT');
 await Promise.all(children.map(child=>child.exitCode!==null||child.signalCode!==null?Promise.resolve():new Promise(resolve=>child.once('exit',resolve))));
 if(provider)await provider.close();await Promise.all(logs.map(log=>log.close()));
 if(passed)await rm(work,{recursive:true,force:true});else console.error('Fixture logs:',work);
}
