import {defineConfig} from '@playwright/test';
import {randomUUID} from 'node:crypto';
import {resolve} from 'node:path';
const backendPython = process.env.BACKEND_PYTHON || resolve('../backend/.venv/bin/python');
export default defineConfig({
  testDir:'./tests', fullyParallel:false, workers:1, timeout:30000,
  use:{baseURL:'http://127.0.0.1:3001',headless:true,trace:'retain-on-failure', ...(process.env.PLAYWRIGHT_WS_ENDPOINT ? {connectOptions:{wsEndpoint:process.env.PLAYWRIGHT_WS_ENDPOINT}} : {})},
  webServer:[
    {command:`${JSON.stringify(backendPython)} -m uvicorn app.main:app --app-dir ../backend --host 127.0.0.1 --port 8001`,url:'http://127.0.0.1:8001/api/health',reuseExistingServer:false,env:{DATABASE_URL:`sqlite:////tmp/secureaccess-browser-${randomUUID()}.db`,DEMO_MODE:'true',ALLOWED_ORIGINS:'["http://127.0.0.1:3001"]'},timeout:30000},
    {command:'npm run dev -- --host 127.0.0.1 --port 3001 --strictPort',url:'http://127.0.0.1:3001',reuseExistingServer:false,env:{API_PROXY_TARGET:'http://127.0.0.1:8001'}},
  ],
});
